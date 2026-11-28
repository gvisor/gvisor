// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inet

import (
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/nsfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Namespace represents a network namespace. See network_namespaces(7).
//
// +stateify savable
type Namespace struct {
	inode *nsfs.Inode

	// stack is the network stack implementation of this network namespace.
	stack Stack

	// creator allows kernel to create new network stack for network namespaces.
	// If nil, no networking will function if network is namespaced.
	creator NetworkStackCreator

	// isRoot indicates whether this is the root network namespace.
	isRoot bool

	// root is the root network namespace. Only set for non-root namespaces.
	root *Namespace

	// childrenMu protects children. Only used on the root network namespace.
	childrenMu sync.Mutex `state:"nosave"`

	// children tracks active non-root network namespaces in creation order.
	// +checklocks:childrenMu
	children []*Namespace

	// destroying counts the Stack teardowns of child namespaces that have not
	// completed. Only used on the root network namespace. A child namespace is
	// never destroyed while the kernel saves: tasks are stopped, sockets hold
	// references on their network namespace, and save holds Kernel.extMu,
	// which excludes the control paths that create and release tasks.
	destroying sync.WaitGroup `state:"nosave"`

	userNS *auth.UserNamespace

	// abstractSockets tracks abstract sockets that are in use.
	abstractSockets AbstractSocketNamespace

	// netlinkMcastTable manages multicast group membership for netlink sockets.
	netlinkMcastTable *McastTable
}

// NewRootNamespace creates the root network namespace, with creator
// allowing new network namespaces to be created. If creator is nil, no
// networking will function if the network is namespaced.
func NewRootNamespace(stack Stack, creator NetworkStackCreator, userNS *auth.UserNamespace) *Namespace {
	n := &Namespace{
		stack:             stack,
		creator:           creator,
		isRoot:            true,
		userNS:            userNS,
		netlinkMcastTable: NewNetlinkMcastTable(),
	}
	if eventPublishingStack, ok := stack.(InterfaceEventPublisher); ok {
		eventPublishingStack.AddInterfaceEventSubscriber(n.netlinkMcastTable)
	}
	n.abstractSockets.init()
	return n
}

// UserNamespace returns the user namespace associated with this namespace.
func (n *Namespace) UserNamespace() *auth.UserNamespace {
	return n.userNS
}

// SetInode sets the nsfs `inode` to the namespace.
func (n *Namespace) SetInode(inode *nsfs.Inode) {
	n.inode = inode
}

// GetInode returns the nsfs inode associated with this namespace.
func (n *Namespace) GetInode() *nsfs.Inode {
	return n.inode
}

// NewNamespace creates a new child network namespace from parent (which may be
// the root namespace or an existing child namespace) and registers it with the
// root network namespace.
func NewNamespace(parent *Namespace, userNS *auth.UserNamespace) *Namespace {
	root := parent
	if !root.isRoot {
		root = parent.root
	}
	n := &Namespace{
		root:              root,
		creator:           parent.creator,
		userNS:            userNS,
		netlinkMcastTable: NewNetlinkMcastTable(),
	}
	n.abstractSockets.init()
	if n.creator != nil {
		var err error
		n.stack, err = n.creator.CreateStack()
		if err != nil {
			panic(err)
		}
		if eventPublishingStack, ok := n.stack.(InterfaceEventPublisher); ok {
			eventPublishingStack.AddInterfaceEventSubscriber(n.netlinkMcastTable)
		}
	}
	root.childrenMu.Lock()
	root.children = append(root.children, n)
	root.childrenMu.Unlock()
	return n
}

// AsyncDestroyer is optionally implemented by Stack implementations whose
// Destroy method completes asynchronously in the background.
type AsyncDestroyer interface {
	// DestroyAsync starts to destroy the stack and calls done once all
	// background teardown work is complete. done must not be nil.
	DestroyAsync(done func())
}

// Destroy implements nsfs.Namespace.Destroy.
func (n *Namespace) Destroy(ctx context.Context) {
	s := n.Stack()
	if n.isRoot {
		if s != nil {
			s.Destroy()
		}
		return
	}
	ad, async := s.(AsyncDestroyer)
	n.root.childrenMu.Lock()
	n.root.children = slices.DeleteFunc(n.root.children, func(c *Namespace) bool {
		return c == n
	})
	if async {
		n.root.destroying.Add(1)
	}
	n.root.childrenMu.Unlock()
	switch {
	case async:
		ad.DestroyAsync(n.root.destroying.Done)
	case s != nil:
		s.Destroy()
	}
}

// Type implements nsfs.Namespace.Type.
func (n *Namespace) Type() string {
	return "net"
}

// IncRef increments the Namespace's refcount.
func (n *Namespace) IncRef() {
	n.inode.IncRef()
}

// DecRef decrements the Namespace's refcount.
func (n *Namespace) DecRef(ctx context.Context) {
	n.inode.DecRef(ctx)
}

// Stack returns the network stack of n. Stack may return nil if no network
// stack is configured.
func (n *Namespace) Stack() Stack {
	return n.stack
}

// IsRoot returns whether n is the root network namespace.
func (n *Namespace) IsRoot() bool {
	return n.isRoot
}

// RestoreRootStack restores the root network namespace with stack. This should
// only be called when restoring kernel.
func (n *Namespace) RestoreRootStack(stack Stack) {
	if !n.isRoot {
		panic("RestoreRootStack can only be called on root network namespace")
	}
	if n.stack != nil {
		panic("RestoreRootStack called after a stack has already been set")
	}
	n.stack = stack
}

// ResetStack resets the stack in the network namespace to nil. This should
// only be called when restoring kernel.
func (n *Namespace) ResetStack() {
	n.stack = nil
}

func (n *Namespace) allStacks() []Stack {
	children := n.childStacks()
	if n.stack == nil {
		return children
	}
	return append([]Stack{n.stack}, children...)
}

// childStacks returns the stacks of all descendant network namespaces. n must
// be the root network namespace.
func (n *Namespace) childStacks() []Stack {
	if !n.isRoot {
		panic("multi-stack operations can only be called on root network namespace")
	}
	n.childrenMu.Lock()
	defer n.childrenMu.Unlock()
	stacks := make([]Stack, 0, len(n.children))
	for _, child := range n.children {
		if s := child.Stack(); s != nil {
			stacks = append(stacks, s)
		}
	}
	return stacks
}

// CheckRestorableStacks calls CheckRestorable on the root network namespace
// stack and all descendant network namespace stacks, and returns the first
// error. n must be the root network namespace.
func (n *Namespace) CheckRestorableStacks() error {
	// Wait until child stacks that are being destroyed have removed their
	// network devices, which can include devices in other stacks.
	n.destroying.Wait()
	children := n.childStacks()
	if n.stack != nil {
		if err := n.stack.CheckRestorable(true /* isRoot */); err != nil {
			return err
		}
	}
	for _, s := range children {
		if err := s.CheckRestorable(false /* isRoot */); err != nil {
			return err
		}
	}
	return nil
}

// SetRemoveConfStacks sets removeConf on the root network namespace stack and
// all descendant network namespace stacks. n must be the root network
// namespace.
func (n *Namespace) SetRemoveConfStacks(removeConf bool) {
	for _, s := range n.allStacks() {
		s.SetRemoveConf(removeConf)
	}
}

// PauseStacks pauses the root network namespace stack and all descendant
// network namespace stacks. n must be the root network namespace.
func (n *Namespace) PauseStacks() {
	n.destroying.Wait()
	for _, s := range n.allStacks() {
		s.Pause()
	}
}

// ResumeStacks resumes the root network namespace stack and all descendant
// network namespace stacks. n must be the root network namespace.
//
// ResumeStacks resumes the endpoints of all stacks before it resumes any link
// endpoint. A link endpoint can deliver queued packets to another stack, for
// example through a veth pair, and that stack must accept them.
func (n *Namespace) ResumeStacks() {
	stacks := n.allStacks()
	for _, s := range stacks {
		s.ResumeEndpoints()
	}
	for _, s := range stacks {
		s.ResumeLinkEndpoints()
	}
}

// RestoreStacks restores the root network namespace stack and all descendant
// network namespace stacks after checkpoint load. n must be the root network
// namespace.
func (n *Namespace) RestoreStacks() {
	stacks := n.allStacks()
	for _, s := range stacks {
		s.RestoreNICsAndEndpoints()
	}
	tcpip.AsyncLoading.Wait()
	for _, s := range stacks {
		s.RestoreBackgroundWorkers()
	}
}

// AbstractSockets returns AbstractSocketNamespace.
func (n *Namespace) AbstractSockets() *AbstractSocketNamespace {
	return &n.abstractSockets
}

// NetlinkMcastTable returns the netlink multicast group table.
func (n *Namespace) NetlinkMcastTable() *McastTable {
	return n.netlinkMcastTable
}

// HasCapability checks if ctx has the given capability with respect to the network namespace n.
func (n *Namespace) HasCapability(ctx context.Context, cp linux.Capability) bool {
	creds := auth.CredentialsFromContext(ctx)
	return creds.HasCapabilityIn(cp, n.userNS)
}

// NetworkStackCreator allows new instances of a network stack to be created. It
// is used by the kernel to create new network namespaces when requested.
type NetworkStackCreator interface {
	// CreateStack creates a new network stack for a network namespace.
	CreateStack() (Stack, error)
}
