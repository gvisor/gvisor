// Copyright 2022 The gVisor Authors.
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

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/fuse.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "test/util/cleanup.h"
#include "test/util/eventfd_util.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/fuse_util.h"
#include "test/util/io_uring_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/memory_util.h"
#include "test/util/mount_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

namespace gvisor {
namespace testing {

namespace {

bool IOUringAvailable() {
  if (IsRunningOnGvisor()) {
    return true;
  }

  // io_uring is relatively new and may not be available on all kernels. Probe
  // using an intentionally invalid call to io_uring_enter.
  errno = 0;
  int rc = syscall(kIOUringEnterSyscall, -1, 1, 1, 0, nullptr);
  if (rc != -1) {
    // How did this succeed?
    std::cerr << "Probe io_uring_enter(2) with invalid FD somehow succeeded..."
              << std::endl;
    return false;
  }
  return errno != ENOSYS;
}

// IOVecContainsString checks that a tuple argument of (struct iovec *, int)
// corresponding to an iovec array and its length, contains data that matches
// the string length strlen and the string value str.
MATCHER_P(IOVecContainsString, str, "") {
  struct iovec* iovs = arg.first;
  int len = strlen(str);
  int niov = arg.second;
  int offset = 0;

  for (int i = 0; i < niov; i++) {
    struct iovec iov = iovs[i];
    if (len < offset) {
      *result_listener << "strlen " << len << " < offset " << offset;
      return false;
    }
    if (strncmp(static_cast<char*>(iov.iov_base), &str[offset], iov.iov_len)) {
      absl::string_view iovec_string(static_cast<char*>(iov.iov_base),
                                     iov.iov_len);
      *result_listener << iovec_string << " @offset " << offset;
      return false;
    }
    offset += iov.iov_len;
  }
  if (offset != len) {
    *result_listener << offset;
    return false;
  }

  return true;
}

// Testing that io_uring_setup(2) successfully returns a valid file descriptor.
TEST(IOUringTest, ValidFD) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));
}

// Testing that io_uring_setup(2) fails with EINVAL on non-zero params.
TEST(IOUringTest, ParamsNonZeroResv) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  memset(&params, 0, sizeof(params));
  params.resv[1] = 1;
  ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

TEST(IOUringTest, ZeroCQEntries) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  params.cq_entries = 0;
  params.flags = IORING_SETUP_CQSIZE;
  ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

TEST(IOUringTest, ZeroCQEntriesLessThanSQEntries) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  params.cq_entries = 16;
  params.flags = IORING_SETUP_CQSIZE;
  ASSERT_THAT(IOUringSetup(32, &params), SyscallFailsWithErrno(EINVAL));
}

// Testing that io_uring_setup(2) fails with EINVAL on unsupported flags.
TEST(IOUringTest, UnsupportedFlags) {
  // Gvisor only test, since linux supports all flags.
  SKIP_IF(!IsRunningOnGvisor());

  IOUringParams params = {};
  memset(&params, 0, sizeof(params));
  params.flags |= IORING_SETUP_SQPOLL;
  ASSERT_THAT(IOUringSetup(1, &params), SyscallFailsWithErrno(EINVAL));
}

// Testing that both mmap and munmap calls succeed and subsequent access to
// unmapped memory results in SIGSEGV.
TEST(IOUringTest, MMapMUnMapWork) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  void* ptr = nullptr;
  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);

  ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
             iouringfd.get(), IORING_OFF_SQ_RING);

  EXPECT_NE(ptr, MAP_FAILED);

  const auto rest = [&] {
    // N.B. we must be in a single-threaded subprocess to ensure that another
    // thread doesn't racily remap at ptr.
    TEST_PCHECK_MSG(MunmapSafe(ptr, sring_sz) == 0, "munmap failed");
    // This should SIGSEGV.
    *reinterpret_cast<volatile int*>(ptr) = 42;
  };

  int child_exit_status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess(rest));
  EXPECT_TRUE(WIFSIGNALED(child_exit_status) &&
              WTERMSIG(child_exit_status) == SIGSEGV)
      << "exit status: " << child_exit_status;
}

// Testing that both mmap fails with EINVAL when an invalid offset is passed.
TEST(IOUringTest, MMapWrongOffset) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);

  EXPECT_THAT(reinterpret_cast<uintptr_t>(
                  mmap(0, sring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, iouringfd.get(), 66)),
              SyscallFailsWithErrno(EINVAL));
}

// Testing that mmap() handles all three IO_URING-specific offsets and that
// returned addresses are page aligned.
TEST(IOUringTest, MMapOffsets) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  void* sq_ptr = nullptr;
  void* cq_ptr = nullptr;
  void* sqe_ptr = nullptr;

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz = params.cq_off.cqes + params.cq_entries * sizeof(IOUringCqe);

  sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                iouringfd.get(), IORING_OFF_SQ_RING);

  cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                iouringfd.get(), IORING_OFF_CQ_RING);

  sqe_ptr = mmap(0, sizeof(IOUringSqe), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_POPULATE, iouringfd.get(), IORING_OFF_SQES);

  EXPECT_NE(sq_ptr, MAP_FAILED);
  EXPECT_NE(cq_ptr, MAP_FAILED);
  EXPECT_NE(sqe_ptr, MAP_FAILED);

  EXPECT_EQ(reinterpret_cast<uintptr_t>(sq_ptr) % kPageSize, 0);
  EXPECT_EQ(reinterpret_cast<uintptr_t>(cq_ptr) % kPageSize, 0);
  EXPECT_EQ(reinterpret_cast<uintptr_t>(sqe_ptr) % kPageSize, 0);

  ASSERT_THAT(munmap(sq_ptr, sring_sz), SyscallSucceeds());
  ASSERT_THAT(munmap(cq_ptr, cring_sz), SyscallSucceeds());
  ASSERT_THAT(munmap(sqe_ptr, sizeof(IOUringSqe)), SyscallSucceeds());
}

// Testing that IOUringParams are populated with correct values.
TEST(IOUringTest, ReturnedParamsValues) {
  SKIP_IF(!IsRunningOnGvisor());

  IOUringParams params = {};
  FileDescriptor iouringfd = ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(1, params));

  EXPECT_EQ(params.sq_entries, 1);
  EXPECT_EQ(params.cq_entries, 2);

  EXPECT_EQ(params.sq_off.head, 0);
  EXPECT_EQ(params.sq_off.tail, 64);
  EXPECT_EQ(params.sq_off.ring_mask, 256);
  EXPECT_EQ(params.sq_off.ring_entries, 264);
  EXPECT_EQ(params.sq_off.flags, 276);
  EXPECT_EQ(params.sq_off.dropped, 272);
  EXPECT_EQ(params.sq_off.array, 384);

  EXPECT_EQ(params.cq_off.head, 128);
  EXPECT_EQ(params.cq_off.tail, 192);
  EXPECT_EQ(params.cq_off.ring_mask, 260);
  EXPECT_EQ(params.cq_off.ring_entries, 268);
  EXPECT_EQ(params.cq_off.overflow, 284);
  EXPECT_EQ(params.cq_off.cqes, 320);
  EXPECT_EQ(params.cq_off.flags, 280);

  // gVisor should support IORING_FEAT_SINGLE_MMAP.
  EXPECT_NE((params.features & IORING_FEAT_SINGLE_MMAP), 0);
}

// Testing that offset of SQE indices array is cacheline aligned.
TEST(IOUringTest, SqeIndexArrayCacheAligned) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  for (uint32_t i = 1; i < 10; ++i) {
    FileDescriptor iouringfd =
        ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(i, params));
    ASSERT_EQ(params.sq_off.array % 64, 0);
  }
}

// Testing that io_uring_enter(2) successfully handles a single NOP operation.
TEST(IOUringTest, SingleNOPTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  IOUringSqe* sqe = io_uring->get_sqes();
  sqe->opcode = IORING_OP_NOP;
  sqe->user_data = 42;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  IOUringCqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->user_data, 42);
  ASSERT_EQ(cqe->res, 0);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully queueing NOP operations.
TEST(IOUringTest, QueueingNOPTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned* sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe* sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 4; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  ASSERT_EQ(sq_tail, 0);
  io_uring->store_sq_tail(sq_tail + 4);

  int ret = io_uring->Enter(2, 2, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 2);

  IOUringCqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 2);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 2);

  for (size_t i = 0; i < 2; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 2);

  ret = io_uring->Enter(2, 2, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 2);

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 4);

  cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 4);

  for (size_t i = 2; i < 4; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 2);
}

// Testing that io_uring_enter(2) successfully multiple NOP operations.
TEST(IOUringTest, MultipleNOPTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned* sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe* sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 3; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  ASSERT_EQ(sq_tail, 0);
  io_uring->store_sq_tail(sq_tail + 3);

  int ret = io_uring->Enter(3, 3, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 3);

  IOUringCqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 3);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 3);

  for (size_t i = 0; i < 3; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 3);
}

// Testing that io_uring_enter(2) successfully handles multiple threads
// submitting NOP operations.
TEST(IOUringTest, MultiThreadedNOPTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned* sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe* sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 4; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 4);

  for (int i = 0; i < 4; i++) {
    ScopedThread t([&] {
      IOUring* io_uring_ptr = io_uring.get();
      int ret = io_uring_ptr->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
      ASSERT_EQ(ret, 1);
    });
  }

  IOUringCqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 4);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 4);

  for (size_t i = 0; i < 4; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 4);
}

// Testing that io_uring_enter(2) successfully consumes submission with an
// invalid opcode and returned CQE contains EINVAL in its result field.
TEST(IOUringTest, InvalidOpCodeTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  IOUringSqe* sqe = io_uring->get_sqes();
  sqe->opcode = 255;  // maximum value for one-byte unsigned integer
  sqe->user_data = 42;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  IOUringCqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->user_data, 42);
  ASSERT_EQ(cqe->res, -EINVAL);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Tests that filling the shared memory region with garbage data doesn't cause a
// kernel panic.
TEST(IOUringTest, CorruptRingHeader) {
  SKIP_IF(!IOUringAvailable());

  const int kEntries = 64;

  IOUringParams params = {};
  FileDescriptor iouringfd =
      ASSERT_NO_ERRNO_AND_VALUE(NewIOUringFD(kEntries, params));

  int sring_sz = params.sq_off.array + params.sq_entries * sizeof(unsigned);
  int cring_sz = params.cq_off.cqes + params.cq_entries * sizeof(IOUringCqe);
  int sqes_sz = params.sq_entries * sizeof(IOUringSqe);

  void* sq_ptr =
      mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd.get(), IORING_OFF_SQ_RING);

  void* cq_ptr =
      mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd.get(), IORING_OFF_CQ_RING);

  void* sqe_ptr =
      mmap(0, sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
           iouringfd.get(), IORING_OFF_SQES);

  EXPECT_NE(sq_ptr, MAP_FAILED);
  EXPECT_NE(cq_ptr, MAP_FAILED);
  EXPECT_NE(sqe_ptr, MAP_FAILED);

  // Corrupt all the buffers.
  memset(sq_ptr, 0xff, sring_sz);
  memset(cq_ptr, 0xff, cring_sz);
  memset(sqe_ptr, 0xff, sqes_sz);

  IOUringEnter(iouringfd.get(), 1, 0, IORING_ENTER_GETEVENTS, nullptr);

  // If kernel hasn't panicked, the test succeeds.

  EXPECT_THAT(munmap(sq_ptr, sring_sz), SyscallSucceeds());
  EXPECT_THAT(munmap(cq_ptr, cring_sz), SyscallSucceeds());
  EXPECT_THAT(munmap(sqe_ptr, sizeof(IOUringSqe)), SyscallSucceeds());
}

// Testing that io_uring_enter(2) successfully consumes submission and SQE ring
// buffers wrap around.
TEST(IOUringTest, SQERingBuffersWrapAroundTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned* sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe* sqe = io_uring->get_sqes();
  for (size_t i = 0; i < 4; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 42 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 4);

  int ret = io_uring->Enter(4, 4, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 4);

  IOUringCqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 4);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 4);

  for (size_t i = 0; i < 4; ++i) {
    ASSERT_EQ(cqe[i].res, 0);
    ASSERT_EQ(cqe[i].user_data, 42 + i);
  }

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 4);

  for (size_t i = 0; i < 4; ++i) {
    sqe[i].user_data = 42 + 2 * (i + 1);
  }

  sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 4);

  ret = io_uring->Enter(4, 4, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 4);

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 8);

  cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 8);

  for (size_t i = 0; i < 4; ++i) {
    ASSERT_EQ(cqe[4 + i].res, 0);
    ASSERT_EQ(cqe[4 + i].user_data, 42 + 2 * (i + 1));
  }

  cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 4);
}

// Testing that io_uring_enter(2) fails with EFAULT when non-null sigset_t has
// been passed as we currently don't support replacing signal mask.
TEST(IOUringTest, NonNullSigsetTest) {
  SKIP_IF(!IsRunningOnGvisor());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  IOUringSqe* sqe = io_uring->get_sqes();
  sqe->opcode = IORING_OP_NOP;
  sqe->user_data = 42;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  sigset_t non_null_sigset;
  EXPECT_THAT(io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, &non_null_sigset),
              SyscallFailsWithErrno(EFAULT));
}

// Testing that completion queue overflow counter is incremented when the
// completion queue is not drained by the user and completion queue entries are
// not overwritten.
TEST(IOUringTest, OverflowCQTest) {
  // Gvisor's completion queue overflow behaviour is different from Linux.
  SKIP_IF(!IsRunningOnGvisor());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  unsigned* sq_array = io_uring->get_sq_array();
  unsigned index = 0;
  IOUringSqe* sqe = io_uring->get_sqes();
  IOUringCqe* cqe = io_uring->get_cqes();

  for (size_t submission_round = 0; submission_round < 2; ++submission_round) {
    for (size_t i = 0; i < 4; ++i) {
      sqe[i].opcode = IORING_OP_NOP;
      sqe[i].user_data = 42 + i + submission_round;
      index = i & io_uring->get_sq_mask();
      sq_array[index] = index;
    }

    uint32_t sq_tail = io_uring->load_sq_tail();
    ASSERT_EQ(sq_tail, 4 * submission_round);
    io_uring->store_sq_tail(sq_tail + 4);

    int ret = io_uring->Enter(4, 4, IORING_ENTER_GETEVENTS, nullptr);
    ASSERT_EQ(ret, 4);

    sq_head = io_uring->load_sq_head();
    ASSERT_EQ(sq_head, 4 * (submission_round + 1));

    uint32_t dropped = io_uring->load_sq_dropped();
    ASSERT_EQ(dropped, 0);

    uint32_t cq_overflow_counter = io_uring->load_cq_overflow();
    ASSERT_EQ(cq_overflow_counter, 0);

    uint32_t cq_tail = io_uring->load_cq_tail();
    ASSERT_EQ(cq_tail, 4 * (submission_round + 1));

    for (size_t i = 0; i < 4; ++i) {
      ASSERT_EQ(cqe[i + 4 * submission_round].res, 0);
      ASSERT_EQ(cqe[i + 4 * submission_round].user_data,
                42 + i + submission_round);
    }
  }

  for (size_t i = 0; i < 2; ++i) {
    sqe[i].opcode = IORING_OP_NOP;
    sqe[i].user_data = 52 + i;
    index = i & io_uring->get_sq_mask();
    sq_array[index] = index;
  }

  uint32_t sq_tail = io_uring->load_sq_tail();
  ASSERT_EQ(sq_tail, 8);
  io_uring->store_sq_tail(sq_tail + 2);

  int ret = io_uring->Enter(2, 2, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 2);

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 10);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 8);

  ASSERT_EQ(cqe[0].res, 0);
  ASSERT_EQ(cqe[0].user_data, 42);
  ASSERT_EQ(cqe[1].res, 0);
  ASSERT_EQ(cqe[1].user_data, 43);

  uint32_t dropped = io_uring->load_sq_dropped();
  ASSERT_EQ(dropped, 0);

  uint32_t cq_overflow_counter = io_uring->load_cq_overflow();
  ASSERT_EQ(cq_overflow_counter, 2);
}

// Testing that io_uring_enter(2) successfully handles single READV operation.
TEST(IOUringTest, SingleREADVTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  off_t file_sz = st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned* sq_array = io_uring->get_sq_array();
  struct io_uring_sqe* sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void* buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, file_sz);

  struct iovec* fi = reinterpret_cast<struct iovec*>(cqe->user_data);

  std::pair<struct iovec*, int> iovec_desc(fi, num_blocks);
  EXPECT_THAT(iovec_desc, IOVecContainsString(contents.c_str()));

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Tests that IORING_OP_READV handles EOF on an empty file correctly.
TEST(IOUringTest, ReadvEmptyFile) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  uint32_t sq_head = io_uring->load_sq_head();

  std::string file_name = NewTempAbsPath();
  ASSERT_NO_ERRNO(CreateWithContents(file_name, "", 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  unsigned* sq_array = io_uring->get_sq_array();
  struct io_uring_sqe* sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = 0;
  void* buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = 1;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, 0);  // 0 length read, EOF.

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully handles three READV operations
// from three different files submitted through a single invocation.
TEST(IOUringTest, ThreeREADVSingleEnterTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(4, params));

  ASSERT_EQ(params.sq_entries, 4);
  ASSERT_EQ(params.cq_entries, 8);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  FileDescriptor filefd[3];
  unsigned* sq_array = io_uring->get_sq_array();
  struct io_uring_sqe* sqe = io_uring->get_sqes();
  off_t file_sz[3];
  int num_blocks[3];
  struct iovec iov[3];

  for (size_t i = 0; i < 3; i++) {
    std::string file_name = NewTempAbsPath();
    std::string contents("DEADBEEF");
    for (size_t j = 0; j < i; ++j) {
      contents.append(" DEADBEEF");
    }
    ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

    filefd[i] = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
    ASSERT_GE(filefd[i].get(), 0);

    struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
    file_sz[i] = st.st_size;
    ASSERT_GT(file_sz[i], 0);

    num_blocks[i] = (file_sz[i] + BLOCK_SZ - 1) / BLOCK_SZ;
    ASSERT_EQ(num_blocks[i], 1);

    iov[i].iov_len = file_sz[i];
    void* buf;
    ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
    iov[i].iov_base = buf;

    sqe[i].flags = 0;
    sqe[i].fd = filefd[i].get();
    sqe[i].opcode = IORING_OP_READV;
    sqe[i].addr = reinterpret_cast<uint64_t>(&iov[i]);
    sqe[i].len = num_blocks[i];
    sqe[i].off = 0;
    sqe[i].user_data = reinterpret_cast<uint64_t>(&iov[i]);
    sq_array[i] = i;

    uint32_t sq_tail = io_uring->load_sq_tail();
    io_uring->store_sq_tail(sq_tail + 1);
  }

  ASSERT_EQ(file_sz[0], 8);
  ASSERT_EQ(file_sz[1], 17);
  ASSERT_EQ(file_sz[2], 26);

  int ret = io_uring->Enter(3, 3, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 3);

  struct io_uring_cqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 3);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 3);

  ASSERT_EQ(cqe[0].res, file_sz[0]);
  ASSERT_EQ(cqe[1].res, file_sz[1]);
  ASSERT_EQ(cqe[2].res, file_sz[2]);

  for (size_t i = 0; i < 3; i++) {
    struct iovec* fi = reinterpret_cast<struct iovec*>(cqe->user_data);

    std::string contents("DEADBEEF");
    for (size_t j = 0; j < i; ++j) {
      contents.append(" DEADBEEF");
    }

    std::pair<struct iovec*, int> iovec_desc(&fi[i], num_blocks[i]);
    EXPECT_THAT(iovec_desc, IOVecContainsString(contents.c_str()));

    uint32_t cq_head = io_uring->load_cq_head();
    io_uring->store_cq_head(cq_head + 1);
  }
}

// Testing that io_uring_enter(2) works with closed FDs.
TEST(IOUringTest, ReadClosedFD) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  auto file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));
  auto filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  unsigned* sq_array = io_uring->get_sq_array();
  struct io_uring_sqe* sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = contents.size();
  void* buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe[0].flags = 0;
  sqe[0].fd = filefd.get();
  sqe[0].opcode = IORING_OP_READV;
  sqe[0].addr = reinterpret_cast<uint64_t>(&iov);
  sqe[0].len = 1;
  sqe[0].off = 0;
  sqe[0].user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  filefd.reset();

  IOUring* io_uring_ptr = io_uring.get();
  int ret = io_uring_ptr->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_TRUE(cqe[0].res == -EBADF);
  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully handles single READV operation
// with short read situation.
TEST(IOUringTest, ShortReadREADVTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  // Set file size to be twice of its actual size to mimic the short read.
  off_t file_sz = 2 * st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned* sq_array = io_uring->get_sq_array();
  struct io_uring_sqe* sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void* buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, file_sz / 2);

  struct iovec* fi = reinterpret_cast<struct iovec*>(cqe->user_data);
  fi->iov_len = file_sz / 2;

  std::pair<struct iovec*, int> iovec_desc(fi, num_blocks);
  EXPECT_THAT(iovec_desc, IOVecContainsString(contents.c_str()));

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Testing that io_uring_enter(2) successfully handles single READV operation
// when there file does not have read permissions.
TEST(IOUringTest, NoReadPermissionsREADVTest) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_WRONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  off_t file_sz = st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned* sq_array = io_uring->get_sq_array();
  struct io_uring_sqe* sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void* buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, -EBADF);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

struct SqeFieldsUT {
  uint16_t ioprio;
  uint16_t buf_index;
};

class IOUringSqeFieldsTest : public ::testing::Test,
                             public ::testing::WithParamInterface<SqeFieldsUT> {
};

// Testing that io_uring_enter(2) successfully handles single READV operation
// and returns EINVAL error in the CQE when ioprio is set.
TEST(IOUringTest, READVWithInvalidSqeFieldValue) {
  SKIP_IF(!IOUringAvailable());

  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));

  ASSERT_EQ(params.sq_entries, 1);
  ASSERT_EQ(params.cq_entries, 2);

  uint32_t sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 0);

  std::string file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));

  FileDescriptor filefd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDONLY));
  ASSERT_GE(filefd.get(), 0);

  struct stat st = ASSERT_NO_ERRNO_AND_VALUE(Stat(file_name));
  off_t file_sz = st.st_size;
  ASSERT_GT(file_sz, 0);

  int num_blocks = (file_sz + BLOCK_SZ - 1) / BLOCK_SZ;
  ASSERT_EQ(num_blocks, 1);

  unsigned* sq_array = io_uring->get_sq_array();
  struct io_uring_sqe* sqe = io_uring->get_sqes();

  struct iovec iov;
  iov.iov_len = file_sz;
  void* buf;
  ASSERT_THAT(posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ), SyscallSucceeds());
  iov.iov_base = buf;

  sqe->flags = 0;
  sqe->fd = filefd.get();
  sqe->opcode = IORING_OP_READV;
  sqe->addr = reinterpret_cast<uint64_t>(&iov);
  sqe->len = num_blocks;
  sqe->off = 0;
  sqe->user_data = reinterpret_cast<uint64_t>(&iov);
  sqe->ioprio = 1;
  sqe->buf_index = 0;
  sq_array[0] = 0;

  uint32_t sq_tail = io_uring->load_sq_tail();
  io_uring->store_sq_tail(sq_tail + 1);

  int ret = io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr);
  ASSERT_EQ(ret, 1);

  struct io_uring_cqe* cqe = io_uring->get_cqes();

  sq_head = io_uring->load_sq_head();
  ASSERT_EQ(sq_head, 1);

  uint32_t cq_tail = io_uring->load_cq_tail();
  ASSERT_EQ(cq_tail, 1);

  ASSERT_EQ(cqe->res, -EINVAL);

  uint32_t cq_head = io_uring->load_cq_head();
  io_uring->store_cq_head(cq_head + 1);
}

// Submits a single IORING_OP_READV of iovcnt iovecs from fd, waits for it to
// complete, and stores the CQE result in res.
void SubmitREADV(int fd, const struct iovec* iov, int iovcnt, int32_t* res) {
  IOUringParams params = {};
  std::unique_ptr<IOUring> io_uring =
      ASSERT_NO_ERRNO_AND_VALUE(IOUring::InitIOUring(1, params));
  IOUringSqe* sqe = io_uring->get_sqes();
  memset(sqe, 0, sizeof(*sqe));
  sqe->opcode = IORING_OP_READV;
  sqe->fd = fd;
  sqe->addr = reinterpret_cast<uint64_t>(iov);
  sqe->len = iovcnt;
  sqe->user_data = 1;
  io_uring->get_sq_array()[0] = 0;
  io_uring->store_sq_tail(io_uring->load_sq_tail() + 1);

  ASSERT_EQ(io_uring->Enter(1, 1, IORING_ENTER_GETEVENTS, nullptr), 1)
      << "errno=" << errno;
  ASSERT_EQ(io_uring->load_cq_tail(), 1);
  const IOUringCqe* cqe = io_uring->get_cqes();
  EXPECT_EQ(cqe->user_data, 1);
  *res = cqe->res;
  io_uring->store_cq_head(io_uring->load_cq_head() + 1);
}

// A READV that faults after copying some bytes completes with the number of
// bytes copied, as readv(2) returns.
TEST(IOUringTest, READVPartialReadThenFault) {
  SKIP_IF(!IOUringAvailable());

  const std::string contents(64, 'a');
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), contents, 0644));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(file.path(), O_RDONLY));

  constexpr size_t kCopied = 6;
  char buf[kCopied] = {};
  const Mapping inaccessible =
      ASSERT_NO_ERRNO_AND_VALUE(MmapAnon(kPageSize, PROT_NONE, MAP_PRIVATE));
  struct iovec iov[] = {
      {.iov_base = buf, .iov_len = sizeof(buf)},
      {.iov_base = inaccessible.ptr(), .iov_len = contents.size() - kCopied},
  };
  int32_t res;
  ASSERT_NO_FATAL_FAILURE(SubmitREADV(fd.get(), iov, 2, &res));
  ASSERT_EQ(res, kCopied);
  EXPECT_EQ(absl::string_view(buf, res), contents.substr(0, kCopied));
}

// A READV request interrupted while it waits for a FUSE server completes with
// EINTR, never with a syscall restart errno: a submitted request can't be
// restarted like a syscall. In gVisor, checkpointing the sandbox interrupts
// such waits. Checkpoints only occur in save variants; otherwise (including on
// Linux), the read completes normally.
TEST(IOUringTest, READVInterruptedFUSERead) {
  SKIP_IF(!IOUringAvailable());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  // Save only at the explicit checkpoint below, while the read is waiting.
  std::optional<DisableSave> ds(std::in_place);

  FileDescriptor dev = ASSERT_NO_ERRNO_AND_VALUE(Open("/dev/fuse", O_RDWR));
  const TempPath mount_point = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string mount_opts =
      absl::StrFormat("fd=%d,user_id=0,group_id=0,rootmode=40000", dev.get());
  const Cleanup mount = ASSERT_NO_ERRNO_AND_VALUE(
      Mount("fuse", mount_point.path(), "fuse", 0 /* mountflags */, mount_opts,
            0 /* umountflags */));
  ASSERT_NO_FATAL_FAILURE(FuseInit(dev.get()));
  const FileDescriptor stop_fd =
      ASSERT_NO_ERRNO_AND_VALUE(NewEventFD(0, EFD_CLOEXEC));

  constexpr absl::string_view kData = "io_uring FUSE read";
  // The result of the server's reply to the first FUSE_READ request.
  std::optional<PosixError> read_reply;
  ScopedThread server([&, server_fd = dev.release()] {
    RunFuseServer(
        server_fd, stop_fd.get(), [&](int fd, const fuse_in_header& in) {
          switch (in.opcode) {
            case FUSE_LOOKUP: {
              fuse_entry_out out = {.nodeid = 2, .generation = 1};
              out.attr = {.ino = 2,
                          .size = kData.size(),
                          .mode = S_IFREG | 0644,
                          .nlink = 1};
              FuseRespond(fd, in.unique, &out, sizeof(out));
              break;
            }
            case FUSE_GETATTR: {
              fuse_attr_out out = {};
              out.attr = {
                  .ino = in.nodeid,
                  .size = in.nodeid == 1 ? 0 : kData.size(),
                  .mode = in.nodeid == 1 ? S_IFDIR | 0755U : S_IFREG | 0644U,
                  .nlink = 1};
              FuseRespond(fd, in.unique, &out, sizeof(out));
              break;
            }
            case FUSE_OPEN: {
              fuse_open_out out = {.fh = 1};
              FuseRespond(fd, in.unique, &out, sizeof(out));
              break;
            }
            case FUSE_READ: {
              const auto& read_in =
                  *reinterpret_cast<const fuse_read_in*>(&in + 1);
              const size_t n =
                  read_in.offset == 0
                      ? std::min<size_t>(read_in.size, kData.size())
                      : 0;
              if (read_reply.has_value()) {
                FuseRespond(fd, in.unique, kData.data(), n);
                break;
              }
              // Checkpoint while the READV waits for this reply.
              ds.reset();
              MaybeSave();
              ds.emplace();
              read_reply = FuseWriteReply(fd, in.unique, kData.data(), n);
              break;
            }
            case FUSE_INTERRUPT:
              // Interrupt requests need no reply.
              break;
            case FUSE_FLUSH:
            case FUSE_RELEASE:
              FuseRespond(fd, in.unique);
              break;
            default:
              FuseRespond(fd, in.unique, nullptr, 0, -ENOSYS);
              break;
          }
          return in.opcode != FUSE_RELEASE;
        });
  });
  // An assertion before the file is opened cannot rely on a RELEASE request to
  // stop the server. Wake its poll before ScopedThread's destructor joins it.
  const Cleanup stop_server([&] {
    const uint64_t stop = 1;
    EXPECT_THAT(RetryEINTR(write)(stop_fd.get(), &stop, sizeof(stop)),
                SyscallSucceedsWithValue(sizeof(stop)));
  });

  FileDescriptor file = ASSERT_NO_ERRNO_AND_VALUE(
      Open(JoinPath(mount_point.path(), "file"), O_RDONLY));
  char buf[64] = {};
  struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
  int32_t res;
  ASSERT_NO_FATAL_FAILURE(SubmitREADV(file.get(), &iov, 1, &res));
  file.reset();
  server.Join();

  ASSERT_TRUE(read_reply.has_value()) << "res=" << res;
  if (read_reply->errno_value() == ENOENT) {
    // The checkpoint abandoned the FUSE request before the server replied.
    EXPECT_EQ(res, -EINTR);
  } else {
    EXPECT_NO_ERRNO(*read_reply);
    ASSERT_EQ(res, kData.size());
    EXPECT_EQ(absl::string_view(buf, res), kData);
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
