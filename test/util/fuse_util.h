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

#ifndef GVISOR_TEST_UTIL_FUSE_UTIL_H_
#define GVISOR_TEST_UTIL_FUSE_UTIL_H_

#include <linux/fuse.h>

#include <cstddef>
#include <cstdint>
#include <functional>

#include "test/util/posix_error.h"

namespace gvisor {
namespace testing {

// Writes a reply to the FUSE request with the given unique ID to the FUSE
// device fd. error is 0 or a negated errno to return to the requester.
PosixError FuseWriteReply(int fd, uint64_t unique,
                          const void* payload = nullptr, size_t size = 0,
                          int error = 0);

// As FuseWriteReply, but fails the test if the reply can't be written.
void FuseRespond(int fd, uint64_t unique, const void* payload = nullptr,
                 size_t size = 0, int error = 0);

// Reads the FUSE_INIT request from the FUSE device fd and replies to it.
void FuseInit(int fd);

// Takes ownership of an initialized device. The callback returns false to stop
// serving requests; a fatal assertion also stops the loop. Closing the device
// on exit aborts any client still waiting for a reply.
void RunFuseServer(
    int device_fd, int stop_fd,
    const std::function<bool(int, const fuse_in_header&)>& respond);

}  // namespace testing
}  // namespace gvisor
#endif  // GVISOR_TEST_UTIL_FUSE_UTIL_H_
