// Copyright 2026 The gVisor Authors.
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

package netfilter

import (
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// natTargetClass classifies a target of a NAT table.
type natTargetClass int

const (
	// natTargetFilters is a target that can drop packets, or an unknown
	// target.
	natTargetFilters natTargetClass = iota
	natTargetAccept
	natTargetReturn
	// natTargetSourceNAT is a SNAT or MASQUERADE target.
	natTargetSourceNAT
	natTargetJump
	// natTargetChainHead marks the first rule of a user chain.
	natTargetChainHead
	// natTargetTableEnd marks the end of a table.
	natTargetTableEnd
)

func natTargetClassOf(t stack.Target) natTargetClass {
	switch t.(type) {
	case *acceptTarget, *stack.AcceptTarget:
		return natTargetAccept
	case *returnTarget, *stack.ReturnTarget:
		return natTargetReturn
	case *snatTarget, *stack.SNATTarget, *masqueradeTarget, *stack.MasqueradeTarget:
		return natTargetSourceNAT
	case *JumpTarget:
		return natTargetJump
	case *userChainTarget, *stack.UserChainTarget:
		return natTargetChainHead
	case *errorTarget, *stack.ErrorTarget:
		return natTargetTableEnd
	default:
		return natTargetFilters
	}
}

// isUnconditional reports whether r matches every packet.
func isUnconditional(r *stack.Rule) bool {
	return len(r.Matchers) == 0 && (r.Filter == stack.EmptyFilter4() || r.Filter == stack.EmptyFilter6())
}

// NATTableCanFilter reports whether table, a NAT table, can filter packets.
//
// The NAT table accepts DROP rules and DROP policies, like the filter table.
// NAT targets also drop some packets, for example a packet that conntrack
// does not track, and matchers can drop packets. Thus NATTableCanFilter
// returns false only for a table that does not filter packets:
//   - Every rule target is ACCEPT, RETURN, a jump to a user chain, SNAT or
//     MASQUERADE. The policy of each built-in chain is a rule, so every
//     policy is ACCEPT.
//   - Every SNAT and MASQUERADE rule applies only to TCP or UDP packets.
//   - No rule has a matcher.
//   - The table ends with an ERROR rule, and a packet can reach a rule that
//     marks a user chain or the end of the table only after an unconditional
//     ACCEPT or RETURN rule.
//   - Jumps between user chains have no cycle, and no path of jumps from any
//     chain is as long as stack.MaxJumps.
//
// Such a table can still drop a TCP or UDP packet that has no transport
// header, for example a fragment that is not the first fragment. If restore
// loses the table, these packets pass, so the loss adds connectivity only.
func NATTableCanFilter(table stack.Table) bool {
	rules := table.Rules
	if len(rules) == 0 || natTargetClassOf(rules[len(rules)-1].Target) != natTargetTableEnd {
		return true
	}
	isMarker := func(i int) bool {
		c := natTargetClassOf(rules[i].Target)
		return c == natTargetChainHead || c == natTargetTableEnd
	}
	// chainOf[i] is the index of the marker of the user chain that holds
	// rule i, or -1 for the built-in chains.
	chainOf := make([]int, len(rules))
	chain := -1
	// jumps maps a chain to the chains that its rules jump to.
	jumps := make(map[int][]int)
	for i := range rules {
		if natTargetClassOf(rules[i].Target) == natTargetChainHead {
			chain = i
		}
		chainOf[i] = chain
	}
	for i := range rules {
		r := &rules[i]
		if len(r.Matchers) != 0 {
			return true
		}
		switch c := natTargetClassOf(r.Target); c {
		case natTargetAccept, natTargetReturn:
		case natTargetSourceNAT:
			if !r.Filter.CheckProtocol {
				return true
			}
			switch r.Filter.Protocol {
			case header.TCPProtocolNumber, header.UDPProtocolNumber:
			default:
				return true
			}
		case natTargetJump:
			n := r.Target.(*JumpTarget).RuleNum
			if n < 0 || n >= len(rules) || isMarker(n) {
				return true
			}
			jumps[chainOf[i]] = append(jumps[chainOf[i]], chainOf[n])
		case natTargetChainHead, natTargetTableEnd:
			// Rules run in order until a rule returns a verdict. A
			// marker rule is not reached if the rule before it is an
			// unconditional ACCEPT or RETURN.
			if i == 0 {
				return true
			}
			prev := &rules[i-1]
			prevClass := natTargetClassOf(prev.Target)
			prevStops := isUnconditional(prev) && (prevClass == natTargetAccept || prevClass == natTargetReturn)
			if !prevStops {
				return true
			}
			if c == natTargetTableEnd && i != len(rules)-1 {
				return true
			}
		default:
			return true
		}
	}
	return jumpsCanFilter(jumps)
}

// jumpsCanFilter reports whether the jump graph has a cycle, or a path of
// jumps from any chain that is at least stack.MaxJumps long. A built-in chain
// can start after the marker of a user chain, so every chain counts.
func jumpsCanFilter(jumps map[int][]int) bool {
	const (
		visiting = iota + 1
		done
	)
	state := make(map[int]int)
	// depth[c] is the length of the longest path of jumps from chain c.
	depth := make(map[int]int)
	var visit func(c int) bool
	visit = func(c int) bool {
		switch state[c] {
		case visiting:
			return true
		case done:
			return false
		}
		state[c] = visiting
		for _, next := range jumps[c] {
			if visit(next) {
				return true
			}
			depth[c] = max(depth[c], depth[next]+1)
		}
		state[c] = done
		return false
	}
	for c := range jumps {
		if visit(c) {
			return true
		}
	}
	for _, d := range depth {
		if d >= stack.MaxJumps {
			return true
		}
	}
	return false
}
