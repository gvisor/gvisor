# Building the installer image

Build your own installer image to test a change to gVisor or to the
installer, or to install another gVisor release.

The image contains a gVisor release (the contents of its release tarball) and
the installer binary from `installer/`. The `Dockerfile` expects them in the
build context as `gvisor/` and `gvisor-installer`.

Give each image that you build a new tag: `helm upgrade` restarts the
installer pods only if a value changes, and nodes do not pull a tag again
(except "latest").

## Build

`build-image.sh` builds an image for one architecture, from a gVisor release
and the installer source in your gVisor clone. Run it on Linux. It needs
Docker with Buildx, Go 1.21 or later, curl, sha512sum, and tar with zstd.

Set `RELEASE` to a gVisor release (see the [releases][releases]). The
release, the git commit and the time are part of the image tag:

```shell
RELEASE=20261109.0
TAG=${RELEASE}-$(git describe --always --dirty)-$(date +%Y%m%d%H%M%S)
deploy/kubernetes/build-image.sh --release ${RELEASE} --image <registry>/gvisor-installer:${TAG} --push
```

The image is for the architecture of the Docker server. For another
architecture, add `--arch amd64` or `--arch arm64`.

## Using your image

```shell
helm install gvisor deploy/kubernetes/chart/gvisor-deploy -n kube-system --wait \
  --set image.repository=<repository> --set-string image.tag=<tag> \
  --set nodeSelector."kubernetes\.io/arch"=<arch>
```

Set `<arch>` to the architecture of the image: `amd64` or `arm64`.

On kind, you do not need a registry: use `--kind-cluster <name>` instead of
`--push`, and add `--set image.pullPolicy=Never` to `helm install`.

## Publishing

For each gVisor release, the `gvisor-deploy Release` workflow
(`.github/workflows/gvisor_deploy.yml`) builds the image for amd64 and arm64
with `build-image.sh`, from the release tarballs and the installer at the
release tag. It pushes `ghcr.io/gvisor/gvisor-installer:<release>` and the
chart `oci://ghcr.io/gvisor/charts/gvisor-deploy`, version `<release>.0`. The
newest release is also tagged `latest`. A published chart version does not
change, unless the workflow is run by hand with `force`.

The first publish creates both packages as private: an organization admin
must make them public once. After a manual Release Mirror run, run the
workflow by hand for that tag.

[releases]: https://gvisor.dev/docs/user_guide/install/
