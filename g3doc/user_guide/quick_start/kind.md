# kind Quick Start

This guide runs pods in gVisor on a local [kind][kind] cluster, with
[gvisor-deploy][gvisor-deploy]. kind runs a Kubernetes cluster in Docker
containers.

You need Docker, kind, kubectl and Helm 3.8 or later.

## Create a cluster

```shell
kind create cluster --name gvisor
```

## Install gVisor

```shell
helm install gvisor oci://ghcr.io/gvisor/charts/gvisor-deploy -n kube-system --wait
kubectl -n kube-system rollout status daemonset/gvisor-installer
```

## Run a pod in gVisor

```shell
kubectl run gvisor-test --image=busybox --restart=Never --overrides='{"spec":{"runtimeClassName":"runsc"}}' -- dmesg
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/gvisor-test --timeout=2m
kubectl logs gvisor-test
```

The first line of the output ends with `Starting gVisor...`.

## Clean up

```shell
kind delete cluster --name gvisor
```

[gvisor-deploy]: https://github.com/gvisor/gvisor/tree/master/deploy/kubernetes
[kind]: https://kind.sigs.k8s.io/
