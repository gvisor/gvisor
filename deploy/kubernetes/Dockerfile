# Installer image for gvisor-deploy, built by build-image.sh.
#
# The build context contains, for the architecture of the image:
#   gvisor/            The contents of a gVisor release tarball.
#   gvisor-installer   The installer binary (//deploy/kubernetes/installer).
#
# Do not add RUN instructions: without them, the image builds for any
# architecture on any host, without emulation.
#
# busybox provides nsenter, which the installer uses to restart containerd
# in the host namespaces.
FROM busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
COPY gvisor/ /opt/gvisor-artifacts/
COPY gvisor-installer /usr/local/bin/gvisor-installer
ENTRYPOINT ["/usr/local/bin/gvisor-installer"]
CMD ["run"]
