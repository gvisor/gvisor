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

#include <asm-generic/errno-base.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <numeric>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/synchronization/notification.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/signal_util.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

// This file contains tests specific to connecting to host UDS managed outside
// the sandbox / test.
//
// A set of ultity sockets will be created externally in $TEST_UDS_TREE and
// $TEST_UDS_ATTACH_TREE for these tests to interact with.

namespace gvisor {
namespace testing {

namespace {

struct ProtocolSocket {
  int protocol;
  std::string name;
};

// Parameter is pipe/UDS root dir.
using HostPipeTest = ::testing::TestWithParam<std::string>;

TEST_P(HostPipeTest, Read) {
  const std::string env = GetParam();

  const char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  const std::string root(val);

  const std::string path = JoinPath(root, "in");
  FileDescriptor reader = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY));

  char lastValue = 0;
  ssize_t length = 0;
  while (length < 1024 * 1024) {
    char buf[1024];

    ssize_t read = ReadFd(reader.get(), buf, sizeof(buf));
    ASSERT_THAT(read, SyscallSucceeds());
    for (uint i = 0; i < read; ++i) {
      ASSERT_EQ(static_cast<char>(lastValue + i), buf[i]);
    }
    lastValue += read;
    length += read;
  }
}

TEST_P(HostPipeTest, Write) {
  const std::string env = GetParam();

  const char* val = getenv(env.c_str());
  ASSERT_NE(val, nullptr);
  const std::string root(val);

  const std::string path = JoinPath(root, "out");
  FileDescriptor writer = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_WRONLY));

  char lastValue = 0;
  ssize_t length = 0;
  while (length < 1024 * 1024) {
    char buf[1024];
    for (unsigned int i = 0; i < sizeof(buf); ++i) {
      buf[i] = i + lastValue;
    }

    ASSERT_THAT(WriteFd(writer.get(), buf, sizeof(buf)),
                SyscallSucceedsWithValue(sizeof(buf)));
    lastValue += sizeof(buf);
    length += sizeof(buf);
  }
}

// More than the default pipe buffer, which is 16 pages: 64 KiB with 4 KiB
// pages and 1 MiB with 64 KiB pages.
constexpr size_t kMoreThanPipeBuffer = 2 << 20;

TEST_P(HostPipeTest, WriteLargerThanPipeBuffer) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "out");
  FileDescriptor writer = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_WRONLY));

  // The host reader checks that the bytes count up from 0. The write is
  // larger than the pipe buffer, so it must wait for the reader and still
  // write all of it.
  std::vector<char> buf(kMoreThanPipeBuffer);
  for (size_t i = 0; i < buf.size(); ++i) {
    buf[i] = static_cast<char>(i);
  }
  EXPECT_THAT(write(writer.get(), buf.data(), buf.size()),
              SyscallSucceedsWithValue(buf.size()));
}

// How long a test waits for a call that returns at once on Linux, or once
// another thread of the test acts. Calls that wait for a signal wait up to
// kSignalWait. The longest wait in one case (kSignalWait, or kChildBlockDelay
// plus kPassingWait) plus the sandbox start must stay shorter than the delay
// after which the host releases calls that block on the "idle" FIFO
// (idlePipeReleaseDelay in test/uds/uds.go).
constexpr absl::Duration kPassingWait = absl::Seconds(3);
constexpr absl::Duration kSignalWait = absl::Seconds(5);

// Runs f in a new thread and waits up to timeout for f to return. While it
// waits, calls poke with the thread's TID every 100 ms. Returns whether f
// returned in time. If it did not, waits for f to return anyway.
bool ReturnsInTime(absl::Duration timeout, const std::function<void()>& f,
                   const std::function<void(pid_t)>& poke) {
  std::atomic<pid_t> tid{0};
  absl::Notification done;
  ScopedThread thread([&] {
    tid = gettid();
    f();
    done.Notify();
  });
  const absl::Time deadline = absl::Now() + timeout;
  while (!done.WaitForNotificationWithTimeout(absl::Milliseconds(100)) &&
         absl::Now() < deadline) {
    if (pid_t t = tid.load(); t != 0) {
      poke(t);
    }
  }
  const bool returned = done.HasBeenNotified();
  thread.Join();
  return returned;
}

void NoPoke(pid_t) {}

std::atomic<bool> got_sigusr1;

// Sends SIGUSR1 to thread tid. A signal that arrives before the thread blocks
// only runs the handler, so a caller sends it until the call returns.
void SignalThread(pid_t tid) {
  // The thread can exit between the caller's check and tgkill.
  EXPECT_THAT(tgkill(getpid(), tid, SIGUSR1),
              AnyOf(SyscallSucceeds(), SyscallFailsWithErrno(ESRCH)));
}

// Installs a SIGUSR1 handler without SA_RESTART, so that the signal makes a
// blocking call fail with EINTR, or return what it has done so far. The
// handler sets got_sigusr1.
PosixErrorOr<Cleanup> InterruptOnSIGUSR1() {
  got_sigusr1 = false;
  struct sigaction sa = {};
  sa.sa_handler = +[](int) { got_sigusr1 = true; };
  return ScopedSigaction(SIGUSR1, sa);
}

// How long ExpectSigkillEndsChild waits for its child to block.
constexpr absl::Duration kChildBlockDelay = absl::Seconds(1);

// Forks a child that runs f, which must block on the FIFO, and sends it
// SIGKILL. Expects the child to die within kPassingWait, as on Linux.
void ExpectSigkillEndsChild(const std::function<void()>& f) {
  const pid_t child = fork();
  if (child == 0) {
    f();
    _exit(0);
  }
  ASSERT_THAT(child, SyscallSucceeds());
  // Nothing shows that the child is blocked in the call, so give it time to
  // get there. If SIGKILL arrives earlier, the test passes without testing
  // the call; it can't fail because of that.
  absl::SleepFor(kChildBlockDelay);
  ASSERT_THAT(kill(child, SIGKILL), SyscallSucceeds());

  int status = 0;
  pid_t ret = 0;
  const absl::Time deadline = absl::Now() + kPassingWait;
  while ((ret = waitpid(child, &status, WNOHANG)) == 0 &&
         absl::Now() < deadline) {
    absl::SleepFor(absl::Milliseconds(10));
  }
  ASSERT_THAT(ret, SyscallSucceeds());
  EXPECT_EQ(ret, child) << "SIGKILL did not end the child within kPassingWait";
  if (ret == 0) {
    // The host releases the child's call after a delay.
    ASSERT_THAT(waitpid(child, &status, 0), SyscallSucceedsWithValue(child));
  }
  EXPECT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
      << "status " << status;
}

// Writes to fd, a non-blocking FD for a FIFO that nothing reads, until the
// pipe is full.
void FillPipe(int fd) {
  std::vector<char> buf(kMoreThanPipeBuffer);
  ASSERT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        EXPECT_THAT(write(fd, buf.data(), buf.size()), SyscallSucceeds());
        EXPECT_THAT(write(fd, buf.data(), 1), SyscallFailsWithErrno(EAGAIN));
      },
      NoPoke))
      << "write() on an O_NONBLOCK FD blocked on a full FIFO";
}

TEST_P(HostPipeTest, NonblockingReadOpenWithoutWriter) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");

  EXPECT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        const FileDescriptor fd =
            ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY | O_NONBLOCK));
        char c;
        EXPECT_THAT(read(fd.get(), &c, 1), SyscallSucceedsWithValue(0));
      },
      NoPoke))
      << "open(O_RDONLY|O_NONBLOCK) or read() blocked without a writer";
}

TEST_P(HostPipeTest, BlockingReadOpenInterruptedBySignal) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const auto restore_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(InterruptOnSIGUSR1());

  EXPECT_TRUE(ReturnsInTime(
      kSignalWait,
      [&] {
        EXPECT_THAT(Open(path, O_RDONLY), PosixErrorIs(EINTR, ::testing::_));
      },
      SignalThread))
      << "a signal did not interrupt open(O_RDONLY)";
}

TEST_P(HostPipeTest, BlockingReadOpenReturnsWhenWriterOpens) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");

  // Keep the writer open until the open returns.
  FileDescriptor writer;
  EXPECT_TRUE(ReturnsInTime(
      kPassingWait, [&] { EXPECT_NO_ERRNO(Open(path, O_RDONLY)); },
      [&](pid_t) {
        if (writer.get() >= 0) {
          return;
        }
        // Linux fails with ENXIO until the reader is in open(2); try again on
        // the next poke.
        PosixErrorOr<FileDescriptor> w = Open(path, O_WRONLY | O_NONBLOCK);
        if (w.ok()) {
          writer = std::move(w).ValueOrDie();
        } else {
          EXPECT_THAT(w, PosixErrorIs(ENXIO, ::testing::_));
        }
      }))
      << "open(O_RDONLY) did not return after a writer opened";
}

TEST_P(HostPipeTest, BlockingReadOpenGetsDataOfEarlyWriter) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");

  // A writer opens the FIFO, writes one byte and closes it, as soon as it
  // can: Linux fails its open with ENXIO until a reader exists, but runsc may
  // let it open first. The reader's blocking open must still return and get
  // the byte.
  bool wrote = false;
  const auto write_byte = [&] {
    if (wrote) {
      return;
    }
    PosixErrorOr<FileDescriptor> w = Open(path, O_WRONLY | O_NONBLOCK);
    if (!w.ok()) {
      EXPECT_THAT(w, PosixErrorIs(ENXIO, ::testing::_));
      return;
    }
    EXPECT_THAT(write(w.ValueOrDie().get(), "x", 1),
                SyscallSucceedsWithValue(1));
    wrote = true;
  };
  write_byte();
  EXPECT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        const FileDescriptor fd =
            ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY));
        char c = 0;
        EXPECT_THAT(read(fd.get(), &c, 1), SyscallSucceedsWithValue(1));
        EXPECT_EQ(c, 'x');
        EXPECT_THAT(read(fd.get(), &c, 1), SyscallSucceedsWithValue(0));
      },
      [&](pid_t) { write_byte(); }))
      << "open(O_RDONLY) did not return after a writer wrote and closed";
}

TEST_P(HostPipeTest, SigkillEndsBlockingReadOpen) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  ExpectSigkillEndsChild(
      [&] { TEST_PCHECK(open(path.c_str(), O_RDONLY) >= 0); });
}

TEST_P(HostPipeTest, SigkillEndsBlockingRead) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR));
  ExpectSigkillEndsChild([&] {
    char c;
    TEST_PCHECK(read(fd.get(), &c, 1) >= 0);
  });
}

TEST_P(HostPipeTest, SigkillEndsBlockingWrite) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR | O_NONBLOCK));
  ASSERT_NO_FATAL_FAILURE(FillPipe(fd.get()));
  ASSERT_THAT(fcntl(fd.get(), F_SETFL, 0), SyscallSucceeds());
  ExpectSigkillEndsChild([&] {
    char c = 0;
    TEST_PCHECK(write(fd.get(), &c, 1) >= 0);
  });
}

TEST_P(HostPipeTest, NonblockingReadWithoutData) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR | O_NONBLOCK));

  EXPECT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        char c;
        EXPECT_THAT(read(fd.get(), &c, 1), SyscallFailsWithErrno(EAGAIN));
      },
      NoPoke))
      << "read() on an O_NONBLOCK FD blocked on an empty FIFO";
}

TEST_P(HostPipeTest, BlockingReadInterruptedBySignal) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR));
  const auto restore_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(InterruptOnSIGUSR1());

  EXPECT_TRUE(ReturnsInTime(
      kSignalWait,
      [&] {
        char c;
        EXPECT_THAT(read(fd.get(), &c, 1), SyscallFailsWithErrno(EINTR));
      },
      SignalThread))
      << "a signal did not interrupt read() on an empty FIFO";
}

TEST_P(HostPipeTest, NonblockingWriteLargerThanPipeBuffer) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR | O_NONBLOCK));

  // Nothing reads the FIFO, so the write fills the pipe and returns the
  // number of bytes that fit.
  std::vector<char> buf(kMoreThanPipeBuffer);
  EXPECT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        const ssize_t n = write(fd.get(), buf.data(), buf.size());
        EXPECT_THAT(n, SyscallSucceeds());
        EXPECT_LT(n, static_cast<ssize_t>(buf.size()));
      },
      NoPoke))
      << "write() on an O_NONBLOCK FD blocked on a full FIFO";
}

TEST_P(HostPipeTest, PollReader) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");

  FileDescriptor reader;
  ASSERT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        reader = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY | O_NONBLOCK));
      },
      NoPoke))
      << "open(O_RDONLY|O_NONBLOCK) blocked without a writer";
  ASSERT_GE(reader.get(), 0);

  // No writer has opened the FIFO yet.
  struct pollfd pfd = {.fd = reader.get(), .events = POLLIN};
  EXPECT_THAT(poll(&pfd, 1, 100), SyscallSucceedsWithValue(0));

  // A writer writes one byte and closes.
  {
    const FileDescriptor writer =
        ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_WRONLY | O_NONBLOCK));
    ASSERT_THAT(write(writer.get(), "x", 1), SyscallSucceedsWithValue(1));
  }
  pfd.revents = 0;
  EXPECT_THAT(poll(&pfd, 1, 1000), SyscallSucceedsWithValue(1));
  EXPECT_EQ(pfd.revents, POLLIN | POLLHUP);
  char c;
  EXPECT_THAT(read(reader.get(), &c, 1), SyscallSucceedsWithValue(1));
  EXPECT_THAT(read(reader.get(), &c, 1), SyscallSucceedsWithValue(0));
  pfd.revents = 0;
  EXPECT_THAT(poll(&pfd, 1, 1000), SyscallSucceedsWithValue(1));
  EXPECT_EQ(pfd.revents, POLLHUP);
}

TEST_P(HostPipeTest, NonblockingReadWithoutDataAfterSetfl) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR));
  ASSERT_THAT(fcntl(fd.get(), F_SETFL, O_NONBLOCK), SyscallSucceeds());

  EXPECT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        char c;
        EXPECT_THAT(read(fd.get(), &c, 1), SyscallFailsWithErrno(EAGAIN));
      },
      NoPoke))
      << "read() blocked on an empty FIFO after F_SETFL O_NONBLOCK";
}

TEST_P(HostPipeTest, BlockingWriteToFullPipeInterruptedBySignal) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd =
      ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR | O_NONBLOCK));
  const auto restore_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(InterruptOnSIGUSR1());

  ASSERT_NO_FATAL_FAILURE(FillPipe(fd.get()));
  ASSERT_THAT(fcntl(fd.get(), F_SETFL, 0), SyscallSucceeds());

  EXPECT_TRUE(ReturnsInTime(
      kSignalWait,
      [&] {
        char c = 0;
        EXPECT_THAT(write(fd.get(), &c, 1), SyscallFailsWithErrno(EINTR));
      },
      SignalThread))
      << "a signal did not interrupt write() on a full FIFO";
}

TEST_P(HostPipeTest, BlockingWriteLargerThanPipeBufferInterruptedBySignal) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDWR));
  const auto restore_sigaction =
      ASSERT_NO_ERRNO_AND_VALUE(InterruptOnSIGUSR1());

  // Nothing reads the FIFO, so the write fills the pipe and waits. The
  // signal makes it return the number of bytes that fit.
  std::vector<char> buf(kMoreThanPipeBuffer);
  EXPECT_TRUE(ReturnsInTime(
      kSignalWait,
      [&] {
        const ssize_t n = write(fd.get(), buf.data(), buf.size());
        EXPECT_TRUE(got_sigusr1) << "write() returned before the signal";
        EXPECT_THAT(n, SyscallSucceeds());
        EXPECT_LT(n, static_cast<ssize_t>(buf.size()));
      },
      SignalThread))
      << "a signal did not interrupt write() on a full FIFO";
}

TEST_P(HostPipeTest, WriteLargerThanPipeBufferToReaderInSandbox) {
  const char* val = getenv(GetParam().c_str());
  ASSERT_NE(val, nullptr);
  const std::string path = JoinPath(val, "idle");

  FileDescriptor reader;
  ASSERT_TRUE(ReturnsInTime(
      kPassingWait,
      [&] {
        reader = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY | O_NONBLOCK));
      },
      NoPoke))
      << "open(O_RDONLY|O_NONBLOCK) blocked without a writer";
  ASSERT_GE(reader.get(), 0);
  ASSERT_THAT(fcntl(reader.get(), F_SETFL, 0), SyscallSucceeds());
  FileDescriptor writer = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_WRONLY));

  // Each word holds its own index, so a lost, repeated or reordered chunk
  // shows up in what the reader gets.
  std::vector<uint32_t> out(kMoreThanPipeBuffer / sizeof(uint32_t));
  std::iota(out.begin(), out.end(), 0);
  std::vector<uint32_t> in(out.size());
  const size_t size = out.size() * sizeof(uint32_t);
  ScopedThread read_all([&] {
    char* const buf = reinterpret_cast<char*>(in.data());
    size_t done = 0;
    while (done < size) {
      const ssize_t n = read(reader.get(), buf + done, size - done);
      if (n <= 0) {
        EXPECT_THAT(n, SyscallSucceeds());
        break;
      }
      done += n;
    }
    EXPECT_EQ(done, size);
  });
  // Write in four iovecs, so that a short write can end inside any of them.
  char* const data = reinterpret_cast<char*>(out.data());
  struct iovec iov[4];
  for (int i = 0; i < 4; ++i) {
    iov[i] = {.iov_base = data + i * size / 4, .iov_len = size / 4};
  }
  EXPECT_THAT(writev(writer.get(), iov, 4), SyscallSucceedsWithValue(size));
  // Close the write end, so that the reader sees EOF if the write was short.
  writer.reset();
  read_all.Join();
  EXPECT_TRUE(in == out) << "the reader got different bytes";
}

INSTANTIATE_TEST_SUITE_P(Paths, HostPipeTest,
                         // Test access via standard path and attach point.
                         ::testing::Values("TEST_FIFO_TREE",
                                           "TEST_FIFO_ATTACH_TREE"));

}  // namespace

}  // namespace testing
}  // namespace gvisor
