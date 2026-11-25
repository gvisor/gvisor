load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "hello",
    srcs = ["hello.proto"],
    visibility = ["//visibility:public"],
)

go_library(
    name = "hello",
    srcs = [
        "hello.go",
        "validate.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":hello_go_proto",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)

go_test(
    name = "hello_test",
    size = "small",
    srcs = [
        "fuzz_test.go",
        "hello_test.go",
        "validate_test.go",
    ],
    embed = [":hello"],
    deps = [
        ":hello_go_proto",
        "@org_golang_google_protobuf//encoding/protowire:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
