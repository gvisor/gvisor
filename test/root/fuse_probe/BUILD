load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "fuse_probe",
    testonly = 1,
    srcs = ["fuse_probe.go"],
    pure = True,
    static = True,
    visibility = ["//test/root:__pkg__"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
