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

#include "test/util/fuse_util.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fuse.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <functional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "test/util/file_descriptor.h"
#include "test/util/posix_error.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

ssize_t WriteFuseReply(int fd, uint64_t unique, const void* payload,
                       size_t size, int error) {
  fuse_out_header out_hdr = {
      .len = static_cast<uint32_t>(sizeof(out_hdr) + size),
      .error = error,
      .unique = unique,
  };
  struct iovec iov[] = {
      {.iov_base = &out_hdr, .iov_len = sizeof(out_hdr)},
      {.iov_base = const_cast<void*>(payload), .iov_len = size},
  };
  return writev(fd, iov, payload ? 2 : 1);
}

}  // namespace

PosixError FuseWriteReply(int fd, uint64_t unique, const void* payload,
                          size_t size, int error) {
  if (WriteFuseReply(fd, unique, payload, size, error) < 0) {
    return PosixError(errno, "writev");
  }
  return NoError();
}

void FuseRespond(int fd, uint64_t unique, const void* payload, size_t size,
                 int error) {
  ASSERT_THAT(WriteFuseReply(fd, unique, payload, size, error),
              SyscallSucceedsWithValue(sizeof(fuse_out_header) + size));
}

void FuseInit(int fd) {
  alignas(fuse_in_header) char req_buf[FUSE_MIN_READ_BUFFER];
  ASSERT_THAT(read(fd, req_buf, sizeof(req_buf)),
              SyscallSucceedsWithValue(::testing::Ge(sizeof(fuse_in_header))));

  fuse_in_header* in_hdr = reinterpret_cast<fuse_in_header*>(req_buf);
  ASSERT_EQ(in_hdr->opcode, FUSE_INIT);

  fuse_init_out out_payload = {
      .major = FUSE_KERNEL_VERSION,
      .minor = FUSE_KERNEL_MINOR_VERSION,
  };
  FuseRespond(fd, in_hdr->unique, &out_payload, sizeof(out_payload));
}

void RunFuseServer(
    int device_fd, int stop_fd,
    const std::function<bool(int, const fuse_in_header&)>& respond) {
  const FileDescriptor fd(device_fd);
  ASSERT_THAT(fcntl(fd.get(), F_SETFL, O_NONBLOCK), SyscallSucceeds());
  alignas(fuse_in_header) char req_buf[65536];
  while (!::testing::Test::HasFatalFailure()) {
    struct pollfd fds[] = {
        {.fd = fd.get(), .events = POLLIN},
        {.fd = stop_fd, .events = POLLIN},
    };
    ASSERT_THAT(RetryEINTR(poll)(fds, 2, -1), SyscallSucceeds());
    if (fds[1].revents & POLLIN) break;
    ssize_t res = RetryEINTR(read)(fd.get(), req_buf, sizeof(req_buf));
    if (res < 0 && errno == EAGAIN) continue;
    ASSERT_THAT(
        res, SyscallSucceedsWithValue(::testing::Ge(sizeof(fuse_in_header))));
    const auto& in = *reinterpret_cast<fuse_in_header*>(req_buf);
    if (in.opcode == FUSE_FORGET) continue;
    SCOPED_TRACE(absl::StrFormat("FUSE opcode %u", in.opcode));
    if (!respond(fd.get(), in)) break;
  }
}

}  // namespace testing
}  // namespace gvisor
