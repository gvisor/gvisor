# Kubernetes Quick Start

gVisor can be used to run Kubernetes pods and has several integration points
with Kubernetes.

## Using GKE Sandbox

[GKE Sandbox][gke-sandbox] is available in [Google Kubernetes Engine][gke]. You
just need to deploy a node pool with gVisor enabled in your cluster, and it will
run pods annotated with `runtimeClassName: gvisor` inside a gVisor sandbox for
you. [Here][wordpress-quick] is a quick example showing how to deploy a
WordPress site. You can view the full documentation [here][gke-sandbox-docs].

## Using Minikube

gVisor can run sandboxed containers in a Kubernetes cluster with Minikube. After
the gVisor addon is enabled, pods with a `gvisor` [Runtime Class][runtimeclass]
set to true will execute with `runsc`. Follow [these instructions][minikube] to
enable gVisor addon.

## Using gvisor-deploy (experimental)

[gvisor-deploy][gvisor-deploy] installs gVisor on the nodes of an existing
cluster with Helm, and creates a `runsc` [Runtime Class][runtimeclass]. See
its [supported nodes][gvisor-deploy-supported]. On other nodes, it does not
change anything.

Install gVisor with Helm 3.8 or later:

```shell
helm install gvisor oci://ghcr.io/gvisor/charts/gvisor-deploy -n kube-system --wait
kubectl -n kube-system rollout status daemonset/gvisor-installer
```

Run a pod in gVisor:

```shell
kubectl run gvisor-test --image=busybox --restart=Never --overrides='{"spec":{"runtimeClassName":"runsc"}}' -- dmesg
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/gvisor-test --timeout=2m
kubectl logs gvisor-test
```

The first line of the output ends with `Starting gVisor...`. To build the
installer image yourself, see [Building the installer image][gvisor-deploy-building].

To uninstall, delete the gVisor pods, then run
`helm uninstall gvisor -n kube-system --wait`. This restores the nodes.

To try it on a local [kind][kind] cluster, run
`kind create cluster --name gvisor` first. To remove the cluster, run
`kind delete cluster --name gvisor`.

## Using Containerd

You can also setup Kubernetes nodes to run pods in gVisor using
[containerd][containerd] and the gVisor containerd shim. You can find
instructions in the [Containerd Quick Start][gvisor-containerd].

[containerd]: https://containerd.io/
[minikube]: https://github.com/kubernetes/minikube/blob/master/deploy/addons/gvisor/README.md
[gke]: https://cloud.google.com/kubernetes-engine/
[kind]: https://kind.sigs.k8s.io/
[gke-sandbox]: https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods
[gke-sandbox-docs]: https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods
[gvisor-containerd]: /docs/user_guide/containerd/quick_start/
[gvisor-deploy]: https://github.com/gvisor/gvisor/tree/master/deploy/kubernetes
[gvisor-deploy-building]: https://github.com/gvisor/gvisor/blob/master/deploy/kubernetes/BUILDING.md
[gvisor-deploy-supported]: https://github.com/gvisor/gvisor/tree/master/deploy/kubernetes#supported-nodes
[runtimeclass]: https://kubernetes.io/docs/concepts/containers/runtime-class/
[wordpress-quick]: /docs/tutorials/kubernetes/
