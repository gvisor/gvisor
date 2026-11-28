load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "installer",
    srcs = [
        "containerd.go",
        "kube.go",
        "main.go",
        "runtime.go",
    ],
    pure = True,
    static = True,
    visibility = ["//visibility:public"],
    deps = ["@com_github_burntsushi_toml//:go_default_library"],
)

go_test(
    name = "installer_test",
    size = "medium",
    srcs = ["installer_test.go"],
    data = [":installer"],
    deps = ["//pkg/test/testutil"],
)
