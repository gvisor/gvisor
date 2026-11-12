# gvisor-deploy (experimental)

gvisor-deploy installs gVisor on the nodes of a Kubernetes cluster and creates
a `runsc` RuntimeClass.

## Install

You need Helm 3.8 or later.

```shell
helm install gvisor oci://ghcr.io/gvisor/charts/gvisor-deploy -n kube-system --wait
kubectl -n kube-system rollout status daemonset/gvisor-installer
```

## Run a pod in gVisor

`gvisor-test.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gvisor-test
spec:
  runtimeClassName: runsc
  restartPolicy: Never
  containers:
    - name: test
      image: busybox
      command: ["dmesg"]
```

```shell
kubectl apply -f gvisor-test.yaml
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/gvisor-test --timeout=2m
kubectl logs gvisor-test
```

The output is the gVisor kernel log. Its first line ends with
`Starting gVisor...`.

## Uninstall

Delete the pods that use gVisor first.

```shell
kubectl delete pod gvisor-test
helm uninstall gvisor -n kube-system --wait
```

## Details

### Versions

Each gVisor release publishes a chart. Its version is the release with `.0`
appended: release `20261116.0` has chart version `20261116.0.0`. By default,
`helm install` uses the newest one. To install a specific release, add
`--version <chart version>`. To see the chart values, run
`helm show values oci://ghcr.io/gvisor/charts/gvisor-deploy`.

### Supported nodes

| Cluster                                    | Tested with                                        |
| ------------------------------------------ | -------------------------------------------------- |
| Kubernetes with containerd (kubeadm, kind) | Kubernetes 1.31 and 1.37; containerd 1.7.18, 2.3.4 |
| k3s (server node)                          | k3s v1.37.2+k3s1                                   |

On other nodes, the installer does not change or label the node; its log says
why (`NOT INSTALLING gVisor`). It runs only on Linux amd64 and arm64 nodes.

Kubernetes 1.30 or later is needed. On older versions, add
`--set restrictNodeUpdates=false`, which removes the policy that limits the
installer to its own node.

Do not use gvisor-deploy on GKE Sandbox node pools: for those, see
[`tools/gvisor_k8s_tool`](../../tools/gvisor_k8s_tool).

### How it works

A privileged DaemonSet runs the installer on each node. The installer:

1.  Copies the release files to `/opt/gvisor/versions/<hash>/`.
2.  Writes `/etc/gvisor/runsc.toml` from the `runscFlags` chart value.
3.  Adds the `runsc` handler to the containerd config, between
    `# BEGIN gvisor-deploy` and `# END gvisor-deploy` lines. On k3s, it
    edits the containerd config template instead.
4.  Restarts containerd (or k3s) if the config changed, and checks that the
    CRI plugin loaded. If it did not, it restores the previous config.
5.  Labels the node `gvisor.dev/runsc=installed`. The RuntimeClass schedules
    gVisor pods only on labeled nodes.

`helm uninstall` removes everything that the installer added, and restarts
containerd.

### Upgrade

```shell
helm upgrade gvisor oci://ghcr.io/gvisor/charts/gvisor-deploy -n kube-system --wait
```

The installer adds the new binaries next to the old ones, and running
containers keep the old binaries. Known limitation: a new container in a pod
that started before the upgrade uses the new `runsc` with the old sandbox;
restart such pods.

### Build your own image

See [BUILDING.md](BUILDING.md).

### Testing

Without a cluster: `test/chart_test.sh` (needs helm), `test/image_test.sh`
(needs Docker with Buildx), and `test/build_image_test.sh`.

`test/e2e.sh` tests install, upgrade and uninstall on a kind cluster, and
checks that the nodes are unchanged after uninstall:

```shell
./deploy/kubernetes/test/e2e.sh <release-dir> [<upgrade-release-dir>]
```

For k3s, put a k3s binary in `test/k3s-node/`, then:

```shell
docker build -t gd-k3s-node:latest deploy/kubernetes/test/k3s-node
CLUSTER_TYPE=k3s ./deploy/kubernetes/test/e2e.sh <release-dir> [<upgrade-release-dir>]
```
