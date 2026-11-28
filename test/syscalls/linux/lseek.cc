// Copyright 2018 The gVisor Authors.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <limits>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/memory_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LseekTest, InvalidWhence) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  ASSERT_THAT(lseek(fd.get(), 0, -1), SyscallFailsWithErrno(EINVAL));
}

TEST(LseekTest, NegativeOffset) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  EXPECT_THAT(lseek(fd.get(), -(kFileData.length() + 1), SEEK_CUR),
              SyscallFailsWithErrno(EINVAL));
}

// A 32-bit off_t is not large enough to represent an offset larger than
// maximum file size on standard file systems, so it isn't possible to cause
// overflow.
#if defined(__x86_64__) || defined(__aarch64__)
TEST(LseekTest, Overflow) {
  // HA! Classic Linux. We really should have an EOVERFLOW
  // here, since we're seeking to something that cannot be
  // represented.. but instead we are given an EINVAL.
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));
  EXPECT_THAT(lseek(fd.get(), 0x7fffffffffffffff, SEEK_END),
              SyscallFailsWithErrno(EINVAL));
}
#endif

TEST(LseekTest, Set) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  char buf = '\0';
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[0]);
  EXPECT_THAT(lseek(fd.get(), 6, SEEK_SET), SyscallSucceedsWithValue(6));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[6]);
}

TEST(LseekTest, Cur) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  char buf = '\0';
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[0]);
  EXPECT_THAT(lseek(fd.get(), 3, SEEK_CUR), SyscallSucceedsWithValue(4));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[4]);
}

TEST(LseekTest, End) {
  const std::string kFileData = "hello world\n";
  const TempPath path = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileWith(
      GetAbsoluteTestTmpdir(), kFileData, TempPath::kDefaultFileMode));
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR, 0644));

  char buf = '\0';
  EXPECT_THAT(lseek(fd.get(), 0, SEEK_SET), SyscallSucceedsWithValue(0));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[0]);
  EXPECT_THAT(lseek(fd.get(), -2, SEEK_END), SyscallSucceedsWithValue(10));
  ASSERT_THAT(read(fd.get(), &buf, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(buf, kFileData.c_str()[kFileData.length() - 2]);
}

TEST(LseekTest, InvalidFD) {
  EXPECT_THAT(lseek(-1, 0, SEEK_SET), SyscallFailsWithErrno(EBADF));
}

TEST(LseekTest, DirCurEnd) {
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(
      Open(GetAbsoluteTestTmpdir().c_str(), O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
}

TEST(LseekTest, ProcDir) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/self", O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceeds());
}

TEST(LseekTest, ProcFile) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/meminfo", O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallFailsWithErrno(EINVAL));
}

TEST(LseekTest, SysDir) {
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/sys/devices", O_RDONLY));
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END), SyscallSucceeds());
}

TEST(LseekTest, SeekCurrentDir) {
  // From include/linux/fs.h.
  constexpr loff_t MAX_LFS_FILESIZE = 0x7fffffffffffffff;

  char* dir = getcwd(NULL, 0);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(dir, O_RDONLY));

  ASSERT_THAT(lseek(fd.get(), 0, SEEK_CUR), SyscallSucceeds());
  ASSERT_THAT(lseek(fd.get(), 0, SEEK_END),
              // Some filesystems (like ext4) allow lseek(SEEK_END) on a
              // directory and return MAX_LFS_FILESIZE, others return EINVAL.
              AnyOf(SyscallSucceedsWithValue(MAX_LFS_FILESIZE),
                    SyscallFailsWithErrno(EINVAL)));
  free(dir);
}

TEST(LseekTest, ProcStatTwice) {
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/stat", O_RDONLY));
  const FileDescriptor fd2 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/stat", O_RDONLY));

  ASSERT_THAT(lseek(fd1.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  ASSERT_THAT(lseek(fd1.get(), 0, SEEK_END), SyscallFailsWithErrno(EINVAL));
  ASSERT_THAT(lseek(fd1.get(), 1000, SEEK_CUR), SyscallSucceeds());
  // Check that just because we moved fd1, fd2 doesn't move.
  ASSERT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));

  const FileDescriptor fd3 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/stat", O_RDONLY));
  ASSERT_THAT(lseek(fd3.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
}

TEST(LseekTest, EtcPasswdDup) {
  const FileDescriptor fd1 =
      ASSERT_NO_ERRNO_AND_VALUE(Open("/etc/passwd", O_RDONLY));
  const FileDescriptor fd2 = ASSERT_NO_ERRNO_AND_VALUE(fd1.Dup());

  ASSERT_THAT(lseek(fd1.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  ASSERT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  ASSERT_THAT(lseek(fd1.get(), 1000, SEEK_CUR), SyscallSucceeds());
  // Check that just because we moved fd1, fd2 doesn't move.
  ASSERT_THAT(lseek(fd2.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(1000));

  const FileDescriptor fd3 = ASSERT_NO_ERRNO_AND_VALUE(fd1.Dup());
  ASSERT_THAT(lseek(fd3.get(), 0, SEEK_CUR), SyscallSucceedsWithValue(1000));
}

TEST(LseekTest, SeekDataAndSeekHole) {
  auto file_name = NewTempAbsPath();
  std::string contents("DEADBEEF");
  ASSERT_NO_ERRNO(CreateWithContents(file_name, contents, 0666));
  auto fd = ASSERT_NO_ERRNO_AND_VALUE(Open(file_name, O_RDWR));

  // Not all filesystems support SEEK_DATA and SEEK_HOLE yet.
  SKIP_IF(lseek(fd.get(), 0, SEEK_DATA) == -1 && errno == EINVAL);

  int mid = contents.size() / 2, end = contents.size();
  ASSERT_THAT(lseek(fd.get(), mid, SEEK_DATA), SyscallSucceedsWithValue(mid));
  ASSERT_THAT(lseek(fd.get(), mid, SEEK_HOLE), SyscallSucceedsWithValue(end));

  // "ENXIO   whence is SEEK_DATA or SEEK_HOLE, and offset is beyond the end of
  //          the file"  - lseek(2)
  ASSERT_THAT(lseek(fd.get(), end, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  ASSERT_THAT(lseek(fd.get(), end, SEEK_HOLE), SyscallFailsWithErrno(ENXIO));
}

void VerifySparseSeekDataAndSeekHole(int fd) {
  const blkcnt_t kBlocksPerPage = kPageSize / 512;
  const off_t kMaxOff = std::numeric_limits<off_t>::max();
  struct stat st;

  // Empty file: all SEEK_DATA / SEEK_HOLE calls fail with ENXIO and st_blocks
  // is 0.
  ASSERT_THAT(fstat(fd, &st), SyscallSucceeds());
  SKIP_IF(!IsRunningOnGvisor() && st.st_blksize != kPageSize);
  EXPECT_EQ(st.st_blocks, 0);
  EXPECT_THAT(lseek(fd, 0, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_HOLE), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, -1, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, -1, SEEK_HOLE), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 1, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 1, SEEK_HOLE), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, kMaxOff, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, kMaxOff, SEEK_HOLE), SyscallFailsWithErrno(ENXIO));

  // Pure hole file: st_blocks stays 0 and failed seeks leave fd offset intact.
  ASSERT_THAT(ftruncate(fd, 4 * kPageSize), SyscallSucceeds());
  ASSERT_THAT(fstat(fd, &st), SyscallSucceeds());
  EXPECT_EQ(st.st_blocks, 0);
  ASSERT_THAT(lseek(fd, 42, SEEK_SET), SyscallSucceedsWithValue(42));
  EXPECT_THAT(lseek(fd, -1, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(42));
  EXPECT_THAT(lseek(fd, -1, SEEK_HOLE), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(42));
  EXPECT_THAT(lseek(fd, 0, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(42));
  EXPECT_THAT(lseek(fd, 4 * kPageSize, SEEK_HOLE),
              SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(42));
  EXPECT_THAT(lseek(fd, kMaxOff, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(42));
  EXPECT_THAT(lseek(fd, kMaxOff, SEEK_HOLE), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(42));

  EXPECT_THAT(lseek(fd, 0, SEEK_HOLE), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd, kPageSize + 123, SEEK_HOLE),
              SyscallSucceedsWithValue(kPageSize + 123));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR),
              SyscallSucceedsWithValue(kPageSize + 123));
  EXPECT_THAT(lseek(fd, 4 * kPageSize - 1, SEEK_HOLE),
              SyscallSucceedsWithValue(4 * kPageSize - 1));

  // Sparse layout:
  //   [0, 1p)   hole
  //   [1p, 2p)  data
  //   [2p, 4p)  hole
  //   [4p, 5p)  data
  //   [5p, 6p)  hole
  ASSERT_THAT(ftruncate(fd, 6 * kPageSize), SyscallSucceeds());
  const char kA = 'A';
  const char kB = 'B';
  ASSERT_THAT(pwrite(fd, &kA, 1, kPageSize), SyscallSucceedsWithValue(1));
  ASSERT_THAT(pwrite(fd, &kB, 1, 4 * kPageSize), SyscallSucceedsWithValue(1));
  ASSERT_THAT(fstat(fd, &st), SyscallSucceeds());
  EXPECT_EQ(st.st_blocks, 2 * kBlocksPerPage);

  EXPECT_THAT(lseek(fd, 0, SEEK_DATA), SyscallSucceedsWithValue(kPageSize));
  EXPECT_THAT(lseek(fd, 0, SEEK_CUR), SyscallSucceedsWithValue(kPageSize));
  char c = '\0';
  ASSERT_THAT(read(fd, &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_EQ(c, kA);

  EXPECT_THAT(lseek(fd, kPageSize - 1, SEEK_DATA),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_THAT(lseek(fd, kPageSize, SEEK_DATA),
              SyscallSucceedsWithValue(kPageSize));
  EXPECT_THAT(lseek(fd, kPageSize + 100, SEEK_DATA),
              SyscallSucceedsWithValue(kPageSize + 100));
  EXPECT_THAT(lseek(fd, 2 * kPageSize - 1, SEEK_DATA),
              SyscallSucceedsWithValue(2 * kPageSize - 1));
  EXPECT_THAT(lseek(fd, 2 * kPageSize, SEEK_DATA),
              SyscallSucceedsWithValue(4 * kPageSize));
  EXPECT_THAT(lseek(fd, 4 * kPageSize, SEEK_DATA),
              SyscallSucceedsWithValue(4 * kPageSize));
  EXPECT_THAT(lseek(fd, 5 * kPageSize, SEEK_DATA),
              SyscallFailsWithErrno(ENXIO));

  EXPECT_THAT(lseek(fd, 0, SEEK_HOLE), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd, kPageSize - 1, SEEK_HOLE),
              SyscallSucceedsWithValue(kPageSize - 1));
  EXPECT_THAT(lseek(fd, kPageSize, SEEK_HOLE),
              SyscallSucceedsWithValue(2 * kPageSize));
  EXPECT_THAT(lseek(fd, kPageSize + 100, SEEK_HOLE),
              SyscallSucceedsWithValue(2 * kPageSize));
  EXPECT_THAT(lseek(fd, 2 * kPageSize, SEEK_HOLE),
              SyscallSucceedsWithValue(2 * kPageSize));
  EXPECT_THAT(lseek(fd, 4 * kPageSize, SEEK_HOLE),
              SyscallSucceedsWithValue(5 * kPageSize));
  EXPECT_THAT(lseek(fd, 5 * kPageSize, SEEK_HOLE),
              SyscallSucceedsWithValue(5 * kPageSize));
  EXPECT_THAT(lseek(fd, 6 * kPageSize, SEEK_HOLE),
              SyscallFailsWithErrno(ENXIO));

  // Fill middle pages in reverse order so backing pages are non-contiguous
  // segments, and verify SEEK_HOLE skips across adjacent segments.
  ASSERT_THAT(pwrite(fd, &kA, 1, 3 * kPageSize), SyscallSucceedsWithValue(1));
  ASSERT_THAT(pwrite(fd, &kB, 1, 2 * kPageSize), SyscallSucceedsWithValue(1));
  EXPECT_THAT(lseek(fd, kPageSize, SEEK_HOLE),
              SyscallSucceedsWithValue(5 * kPageSize));
  ASSERT_THAT(fstat(fd, &st), SyscallSucceeds());
  EXPECT_EQ(st.st_blocks, 4 * kBlocksPerPage);

  // Unaligned file size inside a data page: SEEK_HOLE clamps to EOF.
  const off_t unaligned_size = 4 * kPageSize + 100;
  ASSERT_THAT(ftruncate(fd, unaligned_size), SyscallSucceeds());
  EXPECT_THAT(lseek(fd, 4 * kPageSize, SEEK_HOLE),
              SyscallSucceedsWithValue(unaligned_size));
  EXPECT_THAT(lseek(fd, unaligned_size - 1, SEEK_HOLE),
              SyscallSucceedsWithValue(unaligned_size));
  EXPECT_THAT(lseek(fd, unaligned_size, SEEK_HOLE),
              SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, unaligned_size, SEEK_DATA),
              SyscallFailsWithErrno(ENXIO));

  // Writing a zero byte allocates the page and reports it as data.
  const char kZero = '\0';
  ASSERT_THAT(pwrite(fd, &kZero, 1, 0), SyscallSucceedsWithValue(1));
  EXPECT_THAT(lseek(fd, 0, SEEK_DATA), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd, 0, SEEK_HOLE),
              SyscallSucceedsWithValue(unaligned_size));
  ASSERT_THAT(fstat(fd, &st), SyscallSucceeds());
  EXPECT_EQ(st.st_blocks, 5 * kBlocksPerPage);

  // Shrink then grow across a partial page: page 0 remains allocated, while
  // pages past the shrunk EOF are freed.
  ASSERT_THAT(ftruncate(fd, 100), SyscallSucceeds());
  ASSERT_THAT(ftruncate(fd, 2 * kPageSize), SyscallSucceeds());
  EXPECT_THAT(lseek(fd, 0, SEEK_DATA), SyscallSucceedsWithValue(0));
  EXPECT_THAT(lseek(fd, 0, SEEK_HOLE), SyscallSucceedsWithValue(kPageSize));
  EXPECT_THAT(lseek(fd, kPageSize, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  ASSERT_THAT(fstat(fd, &st), SyscallSucceeds());
  EXPECT_EQ(st.st_blocks, kBlocksPerPage);

  // Shrink to 0 then grow: page 0 is freed and becomes a hole.
  ASSERT_THAT(ftruncate(fd, 0), SyscallSucceeds());
  ASSERT_THAT(ftruncate(fd, 2 * kPageSize), SyscallSucceeds());
  EXPECT_THAT(lseek(fd, 0, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
  EXPECT_THAT(lseek(fd, 0, SEEK_HOLE), SyscallSucceedsWithValue(0));
  ASSERT_THAT(fstat(fd, &st), SyscallSucceeds());
  EXPECT_EQ(st.st_blocks, 0);
}

TEST(LseekTest, SeekDataAndSeekHoleTmpfs) {
  const TempPath path =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/dev/shm"));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(path.path())));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR));
  VerifySparseSeekDataAndSeekHole(fd.get());
}

TEST(LseekTest, SeekDataAndSeekHoleMemfd) {
  int raw_fd;
  ASSERT_THAT(raw_fd = syscall(SYS_memfd_create, "lseek_sparse", 0),
              SyscallSucceeds());
  const FileDescriptor fd(raw_fd);
  VerifySparseSeekDataAndSeekHole(fd.get());
}

TEST(LseekTest, SeekDataAndSeekHoleWriteOnlyFD) {
  const TempPath path =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/dev/shm"));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(path.path())));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_WRONLY));
  ASSERT_THAT(ftruncate(fd.get(), 4 * kPageSize), SyscallSucceeds());
  const char kX = 'X';
  ASSERT_THAT(pwrite(fd.get(), &kX, 1, 2 * kPageSize),
              SyscallSucceedsWithValue(1));

  EXPECT_THAT(lseek(fd.get(), 0, SEEK_DATA),
              SyscallSucceedsWithValue(2 * kPageSize));
  EXPECT_THAT(lseek(fd.get(), 2 * kPageSize, SEEK_HOLE),
              SyscallSucceedsWithValue(3 * kPageSize));
  EXPECT_THAT(lseek(fd.get(), 3 * kPageSize, SEEK_DATA),
              SyscallFailsWithErrno(ENXIO));
}

// Linux tmpfs marks unwritten fallocate(2) pages as holes for
// SEEK_DATA/SEEK_HOLE, whereas gVisor tmpfs reports all allocated pages as
// data. Both report the allocated blocks in st_blocks.
TEST(LseekTest, SeekDataAndSeekHoleFallocateTmpfs) {
  const TempPath path =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/dev/shm"));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(path.path())));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR));
  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  SKIP_IF(!IsRunningOnGvisor() && st.st_blksize != kPageSize);

  ASSERT_THAT(ftruncate(fd.get(), 16 * kPageSize), SyscallSucceeds());
  ASSERT_THAT(RetryEINTR(fallocate)(fd.get(), 0, 4 * kPageSize, 4 * kPageSize),
              SyscallSucceeds());

  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_blocks, static_cast<blkcnt_t>(4 * (kPageSize / 512)));

  if (IsRunningOnGvisor()) {
    EXPECT_THAT(lseek(fd.get(), 0, SEEK_DATA),
                SyscallSucceedsWithValue(4 * kPageSize));
    EXPECT_THAT(lseek(fd.get(), 4 * kPageSize, SEEK_HOLE),
                SyscallSucceedsWithValue(8 * kPageSize));
  } else {
    EXPECT_THAT(lseek(fd.get(), 0, SEEK_DATA), SyscallFailsWithErrno(ENXIO));
    EXPECT_THAT(lseek(fd.get(), 4 * kPageSize, SEEK_HOLE),
                SyscallSucceedsWithValue(4 * kPageSize));
  }
}

// Counts allocated data pages reported by SEEK_DATA/SEEK_HOLE across [0, size).
blkcnt_t CountDataPages(int fd, off_t size) {
  blkcnt_t pages = 0;
  off_t off = 0;
  while (off < size) {
    const off_t data_off = lseek(fd, off, SEEK_DATA);
    if (data_off < 0) {
      EXPECT_EQ(errno, ENXIO);
      break;
    }
    const off_t hole_off = lseek(fd, data_off, SEEK_HOLE);
    EXPECT_GE(hole_off, data_off);
    if (hole_off < 0) {
      break;
    }
    pages += (hole_off - data_off) / kPageSize;
    off = hole_off;
  }
  return pages;
}

// On Linux tmpfs, a single-page MAP_SHARED read or write fault allocates only
// that page, whereas gVisor tmpfs fills a fault-around window (64 KiB by
// default, or hugepage size) around the faulted page.
TEST(LseekTest, SeekDataAndSeekHoleMmapFaultTmpfs) {
  const TempPath path =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/dev/shm"));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(IsTmpfs(path.path())));

  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path.path(), O_RDWR));
  struct stat st;
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  SKIP_IF(!IsRunningOnGvisor() && st.st_blksize != kPageSize);

  const blkcnt_t kBlocksPerPage = kPageSize / 512;
  const off_t kFileSize = 64 * kPageSize;
  ASSERT_THAT(ftruncate(fd.get(), kFileSize), SyscallSucceeds());

  const Mapping m = ASSERT_NO_ERRNO_AND_VALUE(Mmap(
      nullptr, kFileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd.get(), 0));
  auto* bytes = static_cast<volatile char*>(m.ptr());

  // Read fault on page 5.
  EXPECT_EQ(bytes[5 * kPageSize], '\0');
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  if (IsRunningOnGvisor()) {
    const off_t data_off = lseek(fd.get(), 0, SEEK_DATA);
    ASSERT_THAT(data_off, SyscallSucceeds());
    EXPECT_LE(data_off, static_cast<off_t>(5 * kPageSize));
    const off_t hole_off = lseek(fd.get(), 5 * kPageSize, SEEK_HOLE);
    ASSERT_THAT(hole_off, SyscallSucceeds());
    EXPECT_GE(hole_off, static_cast<off_t>(6 * kPageSize));
    EXPECT_GE(st.st_blocks, kBlocksPerPage);
    EXPECT_EQ(st.st_blocks,
              CountDataPages(fd.get(), kFileSize) * kBlocksPerPage);
  } else {
    EXPECT_THAT(lseek(fd.get(), 0, SEEK_DATA),
                SyscallSucceedsWithValue(5 * kPageSize));
    EXPECT_THAT(lseek(fd.get(), 5 * kPageSize, SEEK_HOLE),
                SyscallSucceedsWithValue(6 * kPageSize));
    EXPECT_EQ(st.st_blocks, kBlocksPerPage);
  }

  // Write fault on page 37.
  bytes[37 * kPageSize] = 'Z';
  ASSERT_THAT(fstat(fd.get(), &st), SyscallSucceeds());
  if (IsRunningOnGvisor()) {
    EXPECT_THAT(lseek(fd.get(), 37 * kPageSize, SEEK_DATA),
                SyscallSucceedsWithValue(37 * kPageSize));
    const off_t hole_off = lseek(fd.get(), 37 * kPageSize, SEEK_HOLE);
    ASSERT_THAT(hole_off, SyscallSucceeds());
    EXPECT_GE(hole_off, static_cast<off_t>(38 * kPageSize));
    EXPECT_GE(st.st_blocks, 2 * kBlocksPerPage);
    EXPECT_EQ(st.st_blocks,
              CountDataPages(fd.get(), kFileSize) * kBlocksPerPage);
  } else {
    EXPECT_THAT(lseek(fd.get(), 6 * kPageSize, SEEK_DATA),
                SyscallSucceedsWithValue(37 * kPageSize));
    EXPECT_THAT(lseek(fd.get(), 37 * kPageSize, SEEK_HOLE),
                SyscallSucceedsWithValue(38 * kPageSize));
    EXPECT_EQ(st.st_blocks, 2 * kBlocksPerPage);
  }
}

// TODO(magi): Add tests where we have donated in sockets.

}  // namespace

}  // namespace testing
}  // namespace gvisor
