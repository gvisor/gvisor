// Copyright 2026 The gVisor Authors.
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

// Landlock syscall tests (ABI v1).

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <mqueue.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/capability_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"
#include "test/util/thread_util.h"

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

namespace gvisor {
namespace testing {

namespace {

TEST(LandlockV1Test, CreateRulesetEmptyFsWithUnknownNetBitsIsNotEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_net = (1ULL << 63);
  int rc = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_LT(rc, 0);
  EXPECT_NE(errno, ENOMSG) << "empty handled_access_fs was reported before "
                              "the unknown bits elsewhere in the attr";
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
}

TEST(LandlockV1Test, HostFdsAreInternal) {
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open("/proc/self/fd/2", O_WRONLY);
    _exit(fd >= 0 ? kAllowed : kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = 2;
  EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADFD));
  close(ruleset_fd);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    int fd = open("/proc/self/fd/2", O_WRONLY);
    if (fd >= 0) {
      _exit(kAllowed);
    }
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictionInheritedAcrossFork) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    pid_t pid = fork();
    if (pid == 0) {
      _exit(TryReadOpen(target));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0) {
      _exit(kSetup);
    }
    _exit(WIFEXITED(st) ? WEXITSTATUS(st) : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, IoctlOnlyOpenRequiresNoRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE |
                            LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_ACCMODE);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MkdirOverExistingFileReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string target;
  target = existing.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyErrno(mkdir(target.c_str(), 0755)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrExist)
      << "exit status " << status;
}

TEST(LandlockV1Test, DeniedTruncatingOpenLeavesFileIntact) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(dir.path(), "contents", 0644));
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY | O_TRUNC);
    if (fd >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    struct stat st;
    if (stat(target.c_str(), &st) != 0) {
      _exit(kSetup);
    }
    _exit(st.st_size == 8 ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnixBindRequiresMakeSock) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();

  auto bind_at = [](const std::string& name) -> ChildResult {
    if (chdir(allowed.c_str()) != 0) {
      return kSetup;
    }
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
      return kSetup;
    }
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, name.c_str(), name.size() + 1);
    int rc = bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int err = errno;
    close(sock);
    if (rc == 0) {
      return kAllowed;
    }
    return err == EACCES ? kDenied : kOther;
  };

  int denied = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_SOCK);
    _exit(bind_at("denied.sock"));
  }));
  EXPECT_TRUE(WIFEXITED(denied) && WEXITSTATUS(denied) == kDenied)
      << "exit status " << denied;

  int granted = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_SOCK, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_SOCK);
    _exit(bind_at("granted.sock"));
  }));
  EXPECT_TRUE(WIFEXITED(granted) && WEXITSTATUS(granted) == kAllowed)
      << "exit status " << granted;
}

TEST(LandlockV1Test, FailedUnixBindRemovesSocketFileWithoutRemoveFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  allowed = dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    TEST_PCHECK(chdir(allowed.c_str()) == 0);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    TEST_PCHECK(sock >= 0);
    auto bind_to = [sock](const std::string& name) {
      sockaddr_un addr = {};
      addr.sun_family = AF_UNIX;
      memcpy(addr.sun_path, name.c_str(), name.size() + 1);
      return bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    };
    TEST_PCHECK(bind_to("first.sock") == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_REMOVE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_SOCK);
    if (bind_to("second.sock") == 0 || errno != EINVAL) {
      _exit(kSetup);
    }
    struct stat st;
    _exit(lstat("second.sock", &st) != 0 && errno == ENOENT ? kAllowed
                                                            : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkOfMissingFileReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string target;
  target = JoinPath(dir.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfMissingDirReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string target;
  target = JoinPath(dir.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkOfDirectoryReportsEaccesNotEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string target;
  target = victim_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfNonDirectoryReportsEaccesNotEnotdir) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string target;
  target = victim.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, RmdirOfNonEmptyDirReportsEaccesNotEnotempty) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath occupant =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(victim_dir.path()));
  static std::string target;
  target = victim_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkInStickyDirReportsEaccesNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath sticky_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn("/tmp"));
  const TempPath victim =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(sticky_dir.path()));
  ASSERT_THAT(chmod(sticky_dir.path().c_str(), 01777), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  static std::string target;
  target = victim.path();

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kErrPerm));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, MkdirOnReadOnlyProcMountReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string target = JoinPath(root, "newdir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("proc", root.c_str(), "proc", MS_RDONLY, nullptr) != 0) {
      _exit(kUnsupported);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyErrno(mkdir(target.c_str(), 0755)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif

constexpr int kEexist = 108;

constexpr int kNoReplaceUnsupported = 106;

int ClassifyNoReplace(int rc) {
  if (rc == 0) {
    return kAllowed;
  }
  switch (errno) {
    case EEXIST:
      return kEexist;
    case ENOSYS:
    case EINVAL:
      return kNoReplaceUnsupported;
    case EACCES:
      return kDenied;
    case EXDEV:
      return kExdev;
    default:
      return kOther;
  }
}

TEST(LandlockV1Test, RenameNoReplaceOverExistingReportsEexistNotExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  TempPath dst_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(to_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = dst_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from_dir.path(), kFsAccessV1, to_dir.path(),
                      kFsAccessV1);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kEexist, kNoReplaceUnsupported));
}

TEST(LandlockV1Test, RenameNoReplaceOverExistingReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = dir.path();
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  TempPath dst_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed));
  const std::string src = src_file.path();
  const std::string dst = dst_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG |
                           LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kEexist, kNoReplaceUnsupported));
}

TEST(LandlockV1Test, RenameNoReplaceOntoMissingStillRefusedWithExdev) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath from_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath to_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(from_dir.path()));
  const std::string src = src_file.path();
  const std::string dst = JoinPath(to_dir.path(), "moved");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyTwoDirPolicy(kFsAccessV1, from_dir.path(), kFsAccessV1, to_dir.path(),
                      kFsAccessV1);
    _exit(ClassifyNoReplace(renameat2(AT_FDCWD, src.c_str(), AT_FDCWD,
                                      dst.c_str(), RENAME_NOREPLACE)));
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_THAT(WEXITSTATUS(status),
              ::testing::AnyOf(kExdev, kNoReplaceUnsupported));
}

TEST(LandlockV1Test, RenameOverNonEmptyDirReportsEaccesNotEnotempty) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath occupant =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dst_dir.path()));
  static std::string src;
  static std::string dst;
  src = src_dir.path();
  dst = dst_dir.path();

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  ASSERT_TRUE(WIFEXITED(control) && WEXITSTATUS(control) == kErrNotempty)
      << "control exit status " << control;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkOfUnsafeSourceReportsEpermNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn("/tmp"));
  TempPath src_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  ASSERT_THAT(chmod(src_file.path().c_str(), 0644), SyscallSucceeds());
  ASSERT_THAT(chmod(dir.path().c_str(), 0777), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  static std::string src;
  static std::string dst;
  src = src_file.path();
  dst = JoinPath(dir.path(), "hardlink");

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(link(src.c_str(), dst.c_str())));
  }));
  SKIP_IF(!WIFEXITED(control) || WEXITSTATUS(control) != kErrPerm);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(link(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrPerm)
      << "exit status " << status;
}

void CreateFile(const std::string& path) {
  int fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
}

TEST(LandlockV1Test, RuleReachesFileThroughHardLink) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath other_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));

  const std::string target = JoinPath(covered_dir.path(), "target");
  ASSERT_NO_FATAL_FAILURE(CreateFile(target));
  const std::string link_path = JoinPath(other_dir.path(), "link");
  ASSERT_THAT(link(target.c_str(), link_path.c_str()), SyscallSucceeds());

  const std::string uncovered = JoinPath(other_dir.path(), "uncovered");
  ASSERT_NO_FATAL_FAILURE(CreateFile(uncovered));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, target,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(uncovered) != kDenied) {
      _exit(kOther);
    }
    _exit(TryReadOpen(link_path));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleSurvivesRenameOfCoveredDirectory) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string parent = root.path();
  const std::string dir = covered_dir.release();
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));
  const std::string renamed = JoinPath(parent, "renamed");

  constexpr uint64_t kHandled = LANDLOCK_ACCESS_FS_READ_FILE |
                                LANDLOCK_ACCESS_FS_MAKE_DIR |
                                LANDLOCK_ACCESS_FS_REMOVE_DIR;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kHandled);
    AddPathRule(fd, dir, LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, parent,
                LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR);
    EnforceOrDie(fd);

    if (rename(dir.c_str(), renamed.c_str()) != 0) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(JoinPath(renamed, "f")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleSurvivesUnlinkOfOneHardLink) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string first;
  first = file.release();
  static std::string second;
  second = JoinPath(dir.path(), "second");
  ASSERT_THAT(link(first.c_str(), second.c_str()), SyscallSucceeds());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, first,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (unlink(first.c_str()) != 0) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(second));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OpenCreatOnExistingFileDoesNotRequireMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string existing_path;
  existing_path = existing.path();
  static std::string missing_path;
  missing_path = JoinPath(dir.path(), "newfile");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(existing_path.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
      _exit(ClassifyFs(fd));
    }
    close(fd);
    _exit(ClassifyFs(open(missing_path.c_str(), O_CREAT | O_WRONLY, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, OpenCreatOnExistingFileStillRequiresOpenRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string existing_path;
  existing_path = existing.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyFs(open(existing_path.c_str(), O_CREAT | O_WRONLY, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, PreEnforcementFdsKeepWorking) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(target.c_str(), O_RDWR);
    if (fd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    if (pwrite(fd, "x", 1, 0) != 1) {
      _exit(kOther);
    }
    char c;
    if (pread(fd, &c, 1, 0) != 1 || c != 'x') {
      _exit(kOther);
    }
    _exit(TryReadOpen(target) == kDenied ? kAllowed : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleOnMountPointReachesMountedFilesystem) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath mount_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string mount_point = mount_dir.path();
  const std::string file = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", mount_point.c_str(), "tmpfs", 0, nullptr) == 0);
    int fd = open(file.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(close(fd) == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, mount_point,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(file));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleOnCoveredDirectoryDoesNotReachMountedFilesystem) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath mount_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string mount_point = mount_dir.path();
  const std::string file = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    int covered_fd = open(mount_point.c_str(), O_PATH | O_CLOEXEC);
    TEST_PCHECK(covered_fd >= 0);
    TEST_PCHECK(mount("tmpfs", mount_point.c_str(), "tmpfs", 0, nullptr) == 0);
    int fd = open(file.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(close(fd) == 0);

    int ruleset_fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    landlock_path_beneath_attr attr = {};
    attr.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
    attr.parent_fd = covered_fd;
    TEST_PCHECK(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr,
                                  0) == 0);
    TEST_PCHECK(close(covered_fd) == 0);
    EnforceOrDie(ruleset_fd);
    _exit(TryReadOpen(file));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MountWithMissingTargetReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string from = src_dir.path();
  const std::string missing = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, from, kFsAccessV1);
    _exit(ClassifyErrno(
        mount(from.c_str(), missing.c_str(), nullptr, MS_BIND, nullptr)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, Umount2OfNonMountpointReportsEinvalNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath plain_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string plain = plain_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, plain, kFsAccessV1);
    _exit(ClassifyErrno(umount2(plain.c_str(), MNT_DETACH)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrInval)
      << "exit status " << status;
}

TEST(LandlockV1Test, PivotRootWithMissingNewRootReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = root.path();
  const std::string missing = JoinPath(dir, "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, dir, kFsAccessV1);
    _exit(ClassifyErrno(PivotRoot(missing, dir)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, PivotRootWithNonDirectoryNewRootReportsEnotdirNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = root.path();
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir));
  const std::string nondir = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, dir, kFsAccessV1);
    _exit(ClassifyErrno(PivotRoot(nondir, dir)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNotdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, MoveMountResolvesTargetBeforeSource) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  const std::string bad_source = JoinPath(file.path(), "x");
  const std::string missing_target = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, root.path(), kFsAccessV1);
    _exit(ClassifyErrno(
        MoveMount(AT_FDCWD, bad_source, AT_FDCWD, missing_target, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, MoveMountWithMissingSourceReportsEnoentNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  MoveMount(-1, "", -1, "", 0);
  SKIP_IF(errno == ENOSYS);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath dst_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string to = dst_dir.path();
  const std::string missing = JoinPath(root.path(), "missing");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);

    ApplyFsPolicy(kFsAccessV1, to, kFsAccessV1);
    _exit(ClassifyErrno(MoveMount(AT_FDCWD, missing, AT_FDCWD, to, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayUnlinkOfMissingFileReportsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string missing_file = JoinPath(merged, "missing");
  const std::string missing_dir = JoinPath(merged, "missing_dir");
  const std::string data =
      "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
    TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);
    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kUnsupported);
    }

    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR);
    int rc = ClassifyErrno(unlink(missing_file.c_str()));
    if (rc != kErrNoent) {
      _exit(rc);
    }
    _exit(ClassifyErrno(rmdir(missing_dir.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayLowerHardLinksAreDistinctFiles) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string lower2 = JoinPath(root, "lower2");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string merged_a = JoinPath(merged, "a");
  const std::string merged_b = JoinPath(merged, "b");
  const std::string upper_data = "lowerdir=" + lower + ",upperdir=" + upper +
                                 ",workdir=" + work +
                                 (IsRunningOnGvisor() ? "" : ",index=off");
  const std::string lower_only_data = "lowerdir=" + lower + ":" + lower2;

  auto check = [&](bool with_upper, bool copy_up_b, const std::string& target) {
    return InForkedProcess([&] {
      TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
      TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                  0);
      TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
      for (const std::string& dir : {lower, lower2, upper, work, merged}) {
        TEST_PCHECK(mkdir(dir.c_str(), 0777) == 0);
      }
      const std::string lower_a = JoinPath(lower, "a");
      int fd = open(lower_a.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
      TEST_PCHECK(fd >= 0);
      TEST_PCHECK(close(fd) == 0);
      TEST_PCHECK(link(lower_a.c_str(), JoinPath(lower, "b").c_str()) == 0);
      const std::string& data = with_upper ? upper_data : lower_only_data;
      if (mount("overlay", merged.c_str(), "overlay",
                with_upper ? 0 : MS_RDONLY, data.c_str()) != 0) {
        _exit(kUnsupported);
      }

      const uint64_t rw =
          LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
      int ruleset_fd = CreateRuleset(rw);
      AddPathRule(ruleset_fd, merged_a, rw);
      if (copy_up_b) {
        fd = open(merged_b.c_str(), O_WRONLY);
        TEST_PCHECK(fd >= 0);
        TEST_PCHECK(close(fd) == 0);
      }
      EnforceOrDie(ruleset_fd);
      _exit(TryReadOpen(target));
    });
  };
  struct Leg {
    bool with_upper;
    bool copy_up_b;
    const std::string& target;
    ChildResult want;
    const char* what;
  };
  const Leg legs[] = {
      {true, false, merged_a, kAllowed, "the rule reaches a"},
      {true, false, merged_b, kDenied,
       "the rule for a must not reach its lower hard link b"},
      {true, true, merged_b, kDenied,
       "the rule for a must not reach b once b is copied up"},
      {false, false, merged_b, kAllowed,
       "without an upper layer, a and b are one file"},
  };
  for (const Leg& leg : legs) {
    int status = ASSERT_NO_ERRNO_AND_VALUE(
        check(leg.with_upper, leg.copy_up_b, leg.target));
    SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == leg.want)
        << leg.what << ": exit status " << status;
  }
}

constexpr int kRaceIterations = 300;

void MakeRaceDirs(const std::string& root, std::string* covered,
                  std::string* uncovered, std::string* swap_dir,
                  std::string* link) {
  *covered = JoinPath(root, "covered");
  *uncovered = JoinPath(root, "uncovered");
  *swap_dir = JoinPath(root, "swap");
  *link = JoinPath(*swap_dir, "link");
  ASSERT_THAT(mkdir(covered->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(mkdir(uncovered->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(mkdir(swap_dir->c_str(), 0777), SyscallSucceeds());
  ASSERT_THAT(symlink(covered->c_str(), link->c_str()), SyscallSucceeds());
}

void SwapLinkUntilStopped(const std::string& link, const std::string& covered,
                          const std::string& uncovered,
                          std::atomic<bool>* stop) {
  const std::string tmp = link + ".tmp";
  bool to_covered = false;
  while (!stop->load(std::memory_order_relaxed)) {
    unlink(tmp.c_str());
    if (symlink(to_covered ? covered.c_str() : uncovered.c_str(),
                tmp.c_str()) != 0) {
      continue;
    }
    if (rename(tmp.c_str(), link.c_str()) != 0) {
      continue;
    }
    to_covered = !to_covered;
  }
}

void RemoveSwapLinks(const std::string& link) {
  EXPECT_THAT(unlink(link.c_str()), SyscallSucceeds());
  unlink((link + ".tmp").c_str());
}

TEST(LandlockV1Test, CreateThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    AddPathRule(fd, covered,
                LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, uncovered, LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, swap_dir,
                LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);

    std::atomic<bool> stop(false);
    ScopedThread swapper(
        [&] { SwapLinkUntilStopped(link, covered, uncovered, &stop); });

    int created = 0;
    for (int i = 0; i < kRaceIterations; i++) {
      const std::string victim = JoinPath(link, "victim." + std::to_string(i));
      int victim_fd =
          open(victim.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
      if (victim_fd >= 0) {
        created++;
        close(victim_fd);
      }
    }
    stop.store(true, std::memory_order_relaxed);
    swapper.Join();

    _exit(created > 0 ? kAllowed : kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;

  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, true)),
              ::testing::IsEmpty());
  RemoveSwapLinks(link);
}

TEST(LandlockV1Test, UnlinkThroughSwappedSymlinkStaysUnderRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  std::string covered, uncovered, swap_dir, link;
  ASSERT_NO_FATAL_FAILURE(
      MakeRaceDirs(base.path(), &covered, &uncovered, &swap_dir, &link));

  for (int i = 0; i < kRaceIterations; i++) {
    const std::string name = "victim." + std::to_string(i);
    ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(covered, name)));
    ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(uncovered, name)));
  }

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kFsAccessV1);
    AddPathRule(fd, covered, LANDLOCK_ACCESS_FS_REMOVE_FILE);
    AddPathRule(fd, swap_dir,
                LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EnforceOrDie(fd);

    std::atomic<bool> stop(false);
    ScopedThread swapper(
        [&] { SwapLinkUntilStopped(link, covered, uncovered, &stop); });

    int removed = 0;
    for (int i = 0; i < kRaceIterations; i++) {
      const std::string victim = JoinPath(link, "victim." + std::to_string(i));
      if (unlink(victim.c_str()) == 0) {
        removed++;
      }
    }
    stop.store(true, std::memory_order_relaxed);
    swapper.Join();

    _exit(removed > 0 ? kAllowed : kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;

  EXPECT_THAT(ASSERT_NO_ERRNO_AND_VALUE(ListDir(uncovered, true)),
              ::testing::SizeIs(kRaceIterations));
  RemoveSwapLinks(link);
}

TEST(LandlockV1Test, RulesNameProcPidFiles) {
  SKIP_IF(LandlockAbiVersion() < 1);

  auto check = [](const char* rule_path, const char* target) {
    return InForkedProcess([&] {
      ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, rule_path,
                    LANDLOCK_ACCESS_FS_READ_FILE);
      _exit(TryReadOpen(target));
    });
  };
  struct Leg {
    const char* rule_path;
    const char* target;
    ChildResult want;
  };
  const Leg legs[] = {
      {"/proc/self", "/proc/self/status", kAllowed},
      {"/proc/self/status", "/proc/self/status", kAllowed},
      {"/proc/self/status", "/proc/self/stat", kDenied},
      {"/proc/self", "/proc/meminfo", kDenied},
  };
  for (const Leg& leg : legs) {
    int status = ASSERT_NO_ERRNO_AND_VALUE(check(leg.rule_path, leg.target));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == leg.want)
        << "rule on " << leg.rule_path << ", open of " << leg.target
        << ": exit status " << status;
  }
}

TEST(LandlockV1Test, MemfdIsReopenableThroughProcFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int memfd = syscall(__NR_memfd_create, "landlock-test", 0);
    if (memfd < 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/fd/" + std::to_string(memfd)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, SocketProcFdIsNotDeniedByLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    const std::string path = "/proc/self/fd/" + std::to_string(sock);
    int fd = open(path.c_str(), O_RDONLY);
    if (fd >= 0) {
      close(fd);
      _exit(kAllowed);
    }
    _exit(errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_denied";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(ClassifyFs(mq_open(name.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenAllowedWhenRightsUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_unhandled";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));
    mqd_t fd = mq_open(name.c_str(), O_RDWR);
    if (fd == static_cast<mqd_t>(-1)) {
      _exit(ClassifyFs(-1));
    }
    mq_close(fd);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenAllowedByRuleOnMqueueMount) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string mountpoint = dir.path();
  const std::string name = "/landlock_mq_open_allowed";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("mqueue", mountpoint.c_str(), "mqueue", 0, nullptr) != 0) {
      _exit(kUnsupported);
    }
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  mountpoint,
                  LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
    mqd_t fd = mq_open(name.c_str(), O_RDWR);
    if (fd == static_cast<mqd_t>(-1)) {
      _exit(ClassifyFs(-1));
    }
    mq_close(fd);
    _exit(kAllowed);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenExclusiveOfExistingQueueReportsEexistNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_exclusive";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  ASSERT_THAT(mq_close(queue), SyscallSucceeds());
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds()); });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(ClassifyErrno(
        mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrExist)
      << "exit status " << status;
}

TEST(LandlockV1Test, MqOpenDescriptorCannotNameRule) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const std::string name = "/landlock_mq_open_rule";
  mqd_t queue = mq_open(name.c_str(), O_RDWR | O_CREAT | O_EXCL, 0600, nullptr);
  SKIP_IF(queue == static_cast<mqd_t>(-1) && errno == ENOSYS);
  ASSERT_THAT(static_cast<int>(queue), SyscallSucceeds());
  auto cleanup = Cleanup([&] {
    EXPECT_THAT(mq_close(queue), SyscallSucceeds());
    EXPECT_THAT(mq_unlink(name.c_str()), SyscallSucceeds());
  });

  landlock_ruleset_attr ruleset_attr = {};
  ruleset_attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  FileDescriptor ruleset(
      landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0));
  ASSERT_GE(ruleset.get(), 0);
  landlock_path_beneath_attr rule = {};
  rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  rule.parent_fd = queue;
  EXPECT_THAT(
      landlock_add_rule(ruleset.get(), LANDLOCK_RULE_PATH_BENEATH, &rule, 0),
      SyscallFailsWithErrno(EBADFD));
}

TEST(LandlockV1Test, TiocgptpeerChecksOpenRightsUnlessOPath) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
  SKIP_IF(master < 0);
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(close(master), SyscallSucceeds()); });
  int unlock = 0;
  ASSERT_THAT(ioctl(master, TIOCSPTLCK, &unlock), SyscallSucceeds());

  auto peer = [&](int flags) {
    return InForkedProcess([&] {
      ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE |
                              LANDLOCK_ACCESS_FS_WRITE_FILE);
      _exit(ClassifyFs(ioctl(master, TIOCGPTPEER, flags)));
    });
  };
  int status = ASSERT_NO_ERRNO_AND_VALUE(peer(O_RDWR | O_NOCTTY));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "O_RDWR: exit status " << status;
  status = ASSERT_NO_ERRNO_AND_VALUE(peer(O_PATH));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "O_PATH: exit status " << status;
}

#ifndef SYS_fsopen
#define SYS_fsopen 430
#define SYS_fsconfig 431
#define SYS_fsmount 432
#endif
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_SET_STRING 0x1
#define FSCONFIG_CMD_CREATE 0x6
#define FSCONFIG_CMD_RECONFIGURE 0x7
#endif

TEST(LandlockV1Test, FsconfigReconfigureDeniedWhenDomainActive) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fs_fd = syscall(SYS_fsopen, "tmpfs", 0);
    if (fs_fd < 0) {
      _exit(kUnsupported);
    }
    if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      _exit(kUnsupported);
    }
    int mount_fd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mount_fd < 0) {
      _exit(kUnsupported);
    }

    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    _exit(ClassifyMount(syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_RECONFIGURE,
                                nullptr, nullptr, 0)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kEperm)
      << "exit status " << status;
}

bool InInitUserNamespace() {
  auto uid_map = GetContents("/proc/self/uid_map");
  return uid_map.ok() &&
         uid_map.ValueOrDie().find("4294967295") != std::string::npos;
}

TEST(LandlockV1Test, FsconfigCreateDevtmpfsIgnoresDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!InInitUserNamespace());
  if (!IsRunningOnGvisor()) {
    auto version = ASSERT_NO_ERRNO_AND_VALUE(GetKernelVersion());
    SKIP_IF(version.major < 6 || (version.major == 6 && version.minor < 15));
  }
  const DisableSave ds;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_CHAR |
                            LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_MAKE_SYM);
    int fs_fd = syscall(SYS_fsopen, "devtmpfs", 0);
    if (fs_fd < 0) {
      _exit(kUnsupported);
    }
    _exit(ClassifyErrno(syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE,
                                nullptr, nullptr, 0)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrOk)
      << "exit status " << status;
}

TEST(LandlockV1Test, DomainEnforcedAfterExecve) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(access("/bin/sh", X_OK) != 0);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath control_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  const TempPath enforced_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string control_cmd;
  control_cmd = "echo x > " + control_file.path();
  static std::string enforced_cmd;
  enforced_cmd = "echo x > " + enforced_file.path();
  static std::string enforced_target;
  enforced_target = enforced_file.path();

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    execl("/bin/sh", "sh", "-c", control_cmd.c_str(),
          static_cast<char*>(nullptr));
    _exit(kSetup);
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == 0));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_WRITE_FILE |
                           LANDLOCK_ACCESS_FS_EXECUTE);
    AddPathRule(fd, "/",
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);
    EnforceOrDie(fd);
    execl("/bin/sh", "sh", "-c", enforced_cmd.c_str(),
          static_cast<char*>(nullptr));
    _exit(kSetup);
  }));
  ASSERT_TRUE(WIFEXITED(status)) << "exit status " << status;
  EXPECT_NE(WEXITSTATUS(status), 0) << "the redirect was not denied";
  EXPECT_NE(WEXITSTATUS(status), kSetup) << "execve itself failed";
  struct stat st;
  ASSERT_THAT(stat(enforced_target.c_str(), &st), SyscallSucceeds());
  EXPECT_EQ(st.st_size, 0);
}

TEST(LandlockV1Test, DomainSurvivesSetuid) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn("/tmp"));
  static std::string target;
  target = file.path();
  constexpr uid_t kNobody = 65534;

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (setuid(kNobody) != 0 || getuid() != kNobody) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  SKIP_IF(!(WIFEXITED(control) && WEXITSTATUS(control) == kAllowed));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    if (setuid(kNobody) != 0 || getuid() != kNobody) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfAppliesOnlyToCallingThread) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    std::atomic<int> thread_result{kOther};
    {
      ScopedThread t([&thread_result] {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
          thread_result = kSetup;
          return;
        }
        int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
        if (landlock_restrict_self(fd, 0) != 0) {
          thread_result = kSetup;
          return;
        }
        close(fd);
        thread_result = TryReadOpen(target);
      });
      t.Join();
    }
    if (thread_result == kSetup) {
      _exit(kSetup);
    }
    if (thread_result != kDenied) {
      _exit(kOther);
    }
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ThreadInheritsDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    std::atomic<int> thread_result{kOther};
    {
      ScopedThread t([&thread_result] { thread_result = TryReadOpen(target); });
      t.Join();
    }
    _exit(thread_result);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ChildRestrictionDoesNotAffectParent) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    pid_t pid = fork();
    if (pid < 0) {
      _exit(kSetup);
    }
    if (pid == 0) {
      ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
      _exit(TryReadOpen(target));
    }
    int st;
    if (waitpid(pid, &st, 0) < 0 ||
        !(WIFEXITED(st) && WEXITSTATUS(st) == kDenied)) {
      _exit(kSetup);
    }
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ProcessVmReadvDeniedForUnsandboxedTarget) {
  SKIP_IF(LandlockAbiVersion() < 1);
  static char remote_buf[8] = "watched";
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int stop_fd;
    pid_t tracee = ForkTracee(false, &stop_fd);
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR));

    char local_buf[sizeof(remote_buf)] = {};
    struct iovec local = {local_buf, sizeof(local_buf)};
    struct iovec remote = {remote_buf, sizeof(remote_buf)};
    ssize_t n = process_vm_readv(tracee, &local, 1, &remote, 1, 0);
    int err = errno;
    ChildResult res =
        n >= 0 ? kAllowed
               : ((err == EPERM || err == EACCES) ? kDenied : kOther);
    close(stop_fd);
    waitpid(tracee, nullptr, 0);
    _exit(res);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MknodDeviceWithoutCapabilityIsEaccesUnderLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn("/tmp"));
  ASSERT_THAT(chmod(dir.path().c_str(), 0777), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  static std::string target;
  target = JoinPath(dir.path(), "null");

  int control = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    _exit(ClassifyErrno(mknod(target.c_str(), S_IFCHR | 0600, makedev(1, 3))));
  }));
  SKIP_IF(!WIFEXITED(control) || WEXITSTATUS(control) != kErrPerm);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_CHAR);
    _exit(ClassifyErrno(mknod(target.c_str(), S_IFCHR | 0600, makedev(1, 3))));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, MknodSocketRequiresMakeSock) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath denied_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string allowed;
  static std::string allowed_sock;
  static std::string denied_sock;
  allowed = allowed_dir.path();
  allowed_sock = JoinPath(allowed_dir.path(), "sock");
  denied_sock = JoinPath(denied_dir.path(), "sock");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_SOCK, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_SOCK);
    if (mknod(allowed_sock.c_str(), S_IFSOCK | 0600, 0) != 0) {
      _exit(kOther);
    }
    _exit(ClassifyFs(mknod(denied_sock.c_str(), S_IFSOCK | 0600, 0)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
  EXPECT_THAT(unlink(allowed_sock.c_str()), SyscallSucceeds());
}

TEST(LandlockV1Test, RuleOnUnlinkedFileStillMatchesThroughProcFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  static std::string target;
  target = NewTempAbsPathInDir(dir.path());
  int fd = open(target.c_str(), O_CREAT | O_WRONLY, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  close(fd);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  target,
                  LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (unlink(target.c_str()) != 0) {
      _exit(kSetup);
    }
    const std::string proc_path = "/proc/self/fd/" + std::to_string(fd);
    _exit(ClassifyFs(open(proc_path.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OpenCreatOfExistingFileNeedsNoMakeReg) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath existing =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  static std::string existing_path;
  static std::string new_path;
  allowed = dir.path();
  existing_path = existing.path();
  new_path = JoinPath(dir.path(), "new");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                      LANDLOCK_ACCESS_FS_MAKE_REG,
                  allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(existing_path.c_str(), O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
      _exit(kOther);
    }
    close(fd);
    _exit(ClassifyFs(open(new_path.c_str(), O_CREAT | O_RDWR, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayOfLandlockedCreatorIsNotCheckedInItsLayers) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.path().c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string lower = JoinPath(root.path(), "lower");
    const std::string upper = JoinPath(root.path(), "upper");
    const std::string work = JoinPath(root.path(), "work");
    TEST_PCHECK(mkdir(lower.c_str(), 0755) == 0);
    TEST_PCHECK(mkdir(JoinPath(lower, "sub").c_str(), 0755) == 0);
    TEST_PCHECK(mkdir(upper.c_str(), 0755) == 0);
    TEST_PCHECK(mkdir(work.c_str(), 0755) == 0);
    for (const std::string& file :
         {JoinPath(lower, "g"), JoinPath(lower, "sub/f")}) {
      int fd = open(file.c_str(), O_CREAT | O_WRONLY, 0644);
      TEST_PCHECK(fd >= 0);
      close(fd);
    }

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR,
                  root.path(),
                  LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR);
    int fs_fd = syscall(SYS_fsopen, "overlay", 0);
    if (fs_fd < 0) {
      _exit(kUnsupported);
    }
    if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "lowerdir",
                lower.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "upperdir",
                upper.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "workdir",
                work.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      perror("fsconfig(overlay)");
      _exit(errno == EACCES ? kDenied : kUnsupported);
    }
    int mfd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mfd < 0) {
      perror("fsmount(overlay)");
      _exit(kSetup);
    }
    for (const char* name : {"g", "sub/f"}) {
      int fd = openat(mfd, name, O_WRONLY);
      if (fd < 0) {
        perror(name);
        _exit(ClassifyFs(fd));
      }
      close(fd);
    }
    int fd = openat(mfd, "sub/new", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecveatOfOpathDescriptorRequiresExecute) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(access("/bin/sh", X_OK) != 0);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int exe = open("/bin/sh", O_PATH | O_CLOEXEC);
    if (exe < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_EXECUTE);
    const char* argv[] = {"sh", "-c", "exit 0", nullptr};
    const char* envp[] = {nullptr};
    syscall(SYS_execveat, exe, "", argv, envp, AT_EMPTY_PATH);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkWithTrailingSlashReportsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath victim_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string target;
  target = victim_dir.path() + "/";

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkOfMountPointWithTrailingSlashReportsEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath mnt_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  static std::string from;
  static std::string target;
  from = src_dir.path();
  target = mnt_dir.path() + "/";

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(from.c_str(), mnt_dir.path().c_str(), nullptr, MS_BIND,
                      nullptr) == 0);
    TEST_PCHECK(unlink(target.c_str()) < 0 && errno == EISDIR);
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkKernfsTrailingSlashReportsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink("/proc/sys/")));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, LinkOfProcDirectoryUnderDomainIsExdevNotEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const int control =
      ClassifyErrno(link("/proc/self/task", "/proc/landlock_test_link"));
  SKIP_IF(control != kErrPerm && control != kErrNoent);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(link("/proc/self/task", "/proc/landlock_test_link")));
  }));
  const int want = control == kErrNoent ? kErrNoent : kErrExdev;
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == want)
      << "exit status " << status << " want " << want;
}

TEST(LandlockV1Test, UnlinkOnReadOnlyMountReportsErofsNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string victim = JoinPath(root, "victim");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    int fd = open(victim.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(close(fd) == 0);
    if (mount(nullptr, root.c_str(), nullptr, MS_REMOUNT | MS_RDONLY,
              nullptr) != 0) {
      _exit(kUnsupported);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyErrno(unlink(victim.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnlinkMissingPathOnReadOnlyProcMountErrnos) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string missing_intermediate = JoinPath(root, "nonexistent/victim");
  const std::string missing_final = JoinPath(root, "nonexistent");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("proc", root.c_str(), "proc", MS_RDONLY, nullptr) != 0) {
      _exit(kUnsupported);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_REMOVE_FILE);
    int intermediate = ClassifyErrno(unlink(missing_intermediate.c_str()));
    if (intermediate != kErrNoent) {
      _exit(intermediate);
    }
    _exit(ClassifyErrno(unlink(missing_final.c_str())));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

TEST(LandlockV1Test, WriteOpenOnReadOnlyMountIsErofsBeforeLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  ASSERT_THAT(
      mount(dir.path().c_str(), dir.path().c_str(), nullptr, MS_BIND, nullptr),
      SyscallSucceeds());
  auto unmount = Cleanup([&] { umount2(dir.path().c_str(), MNT_DETACH); });
  ASSERT_THAT(mount(nullptr, dir.path().c_str(), nullptr,
                    MS_BIND | MS_REMOUNT | MS_RDONLY, nullptr),
              SyscallSucceeds());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_WRITE_FILE);
    _exit(ClassifyErrno(open(target.c_str(), O_WRONLY)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
  status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyErrno(open(target.c_str(), O_RDONLY | O_TRUNC)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrRofs)
      << "exit status " << status;
}

TEST(LandlockV1Test, RenameOntoAncestorIsEnotemptyBeforeLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath a =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(dir.path()));
  const TempPath b = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(a.path()));
  static std::string src;
  static std::string dst;
  src = b.path();
  dst = a.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR |
                            LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyErrno(rename(src.c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNotempty)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExchangeWithOwnAncestorIsEinvalBeforeLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string sub = JoinPath(dir.path(), "sub");
  ASSERT_THAT(mkdir(sub.c_str(), 0755), SyscallSucceeds());
  const std::string file = JoinPath(sub, "file");
  ASSERT_NO_ERRNO(Open(file, O_WRONLY | O_CREAT, 0644));
  auto cleanup = Cleanup([&] {
    unlink(file.c_str());
    rmdir(sub.c_str());
  });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(kFsAccessV1, dir.path(), kFsAccessV1);
    int rc = syscall(SYS_renameat2, AT_FDCWD, file.c_str(), AT_FDCWD,
                     sub.c_str(), RENAME_EXCHANGE);
    if (rc == 0) {
      _exit(kAllowed);
    }
    _exit(errno == EINVAL ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

int RunFailedUnixBindRace(const std::string& root, bool landlocked) {
  TEST_PCHECK(chdir(root.c_str()) == 0);
  TEST_PCHECK(mkdir("scratch", 0755) == 0);
  TEST_PCHECK(mkdir("scratch/allowed", 0755) == 0);
  TEST_PCHECK(mkdir("protected", 0755) == 0);
  int fd = open("protected/victim", O_CREAT | O_WRONLY, 0644);
  TEST_PCHECK(fd >= 0);
  close(fd);
  const std::string protected_dir = JoinPath(root, "protected");
  TEST_PCHECK(symlink("allowed", "scratch/link") == 0);
  TEST_PCHECK(symlink(protected_dir.c_str(), "scratch/other") == 0);

  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  TEST_PCHECK(sock >= 0);
  sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  const std::string abstract =
      absl::StrCat("landlock_bind_rollback_", getpid());
  memcpy(addr.sun_path + 1, abstract.c_str(), abstract.size());
  TEST_PCHECK(bind(sock, reinterpret_cast<sockaddr*>(&addr),
                   offsetof(sockaddr_un, sun_path) + 1 + abstract.size()) == 0);

  struct stat st;
  if (landlocked) {
    ApplyFsPolicy(
        LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_SYM,
        JoinPath(root, "scratch"),
        LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_MAKE_SYM);
    if (unlink("protected/victim") == 0 || errno != EACCES) {
      return kSetup;
    }
  }

  std::atomic<bool> done(false);
  ScopedThread swapper([&] {
    while (!done.load()) {
      syscall(SYS_renameat2, AT_FDCWD, "scratch/link", AT_FDCWD,
              "scratch/other", RENAME_EXCHANGE);
    }
  });
  sockaddr_un path_addr = {};
  path_addr.sun_family = AF_UNIX;
  constexpr char kPath[] = "scratch/link/victim";
  memcpy(path_addr.sun_path, kPath, sizeof(kPath));
  const absl::Time deadline = absl::Now() + absl::Seconds(3);
  int result = kAllowed;
  while (absl::Now() < deadline) {
    int rc =
        bind(sock, reinterpret_cast<sockaddr*>(&path_addr), sizeof(path_addr));
    if (rc == 0 || (errno != EINVAL && errno != EADDRINUSE)) {
      result = kOther;
      break;
    }
    if (lstat("protected/victim", &st) != 0) {
      result = kDenied;
      break;
    }
    if (lstat("scratch/allowed/victim", &st) == 0) {
      result = kDenied;
      break;
    }
  }
  done.store(true);
  swapper.Join();
  return result;
}

TEST(LandlockV1Test, FailedUnixBindRemovesOnlyTheFileItCreated) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess(
      [&] { _exit(RunFailedUnixBindRace(root.path(), true)); }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, TiocgptpeerWithOPathReturnsOPathFile) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
  SKIP_IF(master < 0);
  auto cleanup =
      Cleanup([&] { EXPECT_THAT(close(master), SyscallSucceeds()); });
  int unlock = 0;
  ASSERT_THAT(ioctl(master, TIOCSPTLCK, &unlock), SyscallSucceeds());

  for (int flags : {O_PATH, O_RDWR | O_PATH, O_PATH | O_DIRECTORY}) {
    int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
      ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE |
                              LANDLOCK_ACCESS_FS_WRITE_FILE);
      int peer = ioctl(master, TIOCGPTPEER, flags | O_NOCTTY | O_NONBLOCK);
      if (peer < 0) {
        _exit(kSetup);
      }
      int fl = fcntl(peer, F_GETFL);
      if (fl < 0 || (fl & O_PATH) == 0) {
        _exit(kOther);
      }
      char c = 'x';
      if (write(peer, &c, 1) >= 0 || errno != EBADF) {
        _exit(kOther);
      }
      if (read(peer, &c, 1) >= 0 || errno != EBADF) {
        _exit(kOther);
      }
      _exit(kAllowed);
    }));
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
        << "flags " << flags << ": exit status " << status;
  }
}

TEST(LandlockV1Test, ProcPidFilesGuardedByPtraceAccessAreScoped) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const pid_t target = getpid();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    const std::string proc = absl::StrCat("/proc/", target);
    char buf[256];
    for (const char* ns : {"net", "mnt"}) {
      const std::string link = absl::StrCat(proc, "/ns/", ns);
      TEST_PCHECK(readlink(link.c_str(), buf, sizeof(buf)) > 0);
      int fd = open(link.c_str(), O_RDONLY);
      TEST_PCHECK(fd >= 0);
      close(fd);
    }

    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG));
    const bool kernel_bug = !IsRunningOnGvisor();
    for (const char* ns : {"net", "mnt", "user", "pid"}) {
      const std::string link = absl::StrCat(proc, "/ns/", ns);
      errno = 0;
      ssize_t n = readlink(link.c_str(), buf, sizeof(buf));
      if (!(n < 0 && errno == EACCES) && !(kernel_bug && n == 0)) {
        fprintf(stderr, "readlink(%s): %zd, %s\n", link.c_str(), n,
                strerror(errno));
        _exit(kOther);
      }
      errno = 0;
      int fd = open(link.c_str(), O_RDONLY);
      if (fd >= 0) {
        struct stat st;
        bool ns_dir = kernel_bug && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
        close(fd);
        if (!ns_dir) {
          fprintf(stderr, "open(%s) succeeded\n", link.c_str());
          _exit(kOther);
        }
      } else if (errno != EACCES) {
        fprintf(stderr, "open(%s): %s\n", link.c_str(), strerror(errno));
        _exit(kOther);
      }
    }
    const std::string fdinfo = absl::StrCat(proc, "/fdinfo");
    if (open(fdinfo.c_str(), O_RDONLY | O_DIRECTORY) >= 0 || errno != EACCES) {
      fprintf(stderr, "open(%s): %s\n", fdinfo.c_str(), strerror(errno));
      _exit(kOther);
    }
    const std::string fdinfo0 = absl::StrCat(fdinfo, "/0");
    if (open(fdinfo0.c_str(), O_RDONLY) >= 0 || errno != EACCES) {
      fprintf(stderr, "open(%s): %s\n", fdinfo0.c_str(), strerror(errno));
      _exit(kOther);
    }
    const std::string io = absl::StrCat(proc, "/io");
    int fd = open(io.c_str(), O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "open(%s): %s\n", io.c_str(), strerror(errno));
      _exit(kOther);
    }
    if (read(fd, buf, sizeof(buf)) >= 0 || errno != EACCES) {
      fprintf(stderr, "read(%s): %s\n", io.c_str(), strerror(errno));
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ProcSelfFilesGuardedByPtraceAccessStayAccessible) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG));
    char buf[256];
    TEST_PCHECK(readlink("/proc/self/ns/net", buf, sizeof(buf)) > 0);
    int fd = open("/proc/self/ns/net", O_RDONLY);
    TEST_PCHECK(fd >= 0);
    close(fd);
    fd = open("/proc/self/fdinfo/0", O_RDONLY);
    TEST_PCHECK(fd >= 0);
    close(fd);
    fd = open("/proc/self/io", O_RDONLY);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(read(fd, buf, sizeof(buf)) > 0);
    close(fd);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

enum class OverlayCreator {
  kRestrictedBeforeFsopen,
  kRestrictedBeforeCreate,
};

PosixErrorOr<int> OverlayCopyUpOpens(const std::string& root,
                                     std::vector<std::string> granted,
                                     OverlayCreator creator) {
  return InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string lower = JoinPath(root, "lower");
    const std::string sandbox = JoinPath(root, "sandbox");
    const std::string upper = JoinPath(sandbox, "upper");
    const std::string work = JoinPath(sandbox, "work");
    for (const std::string& dir : {lower, sandbox, upper, work}) {
      TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    int fd = open(JoinPath(lower, "key").c_str(), O_CREAT | O_WRONLY, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(write(fd, "secret", 6) == 6);
    close(fd);
    fd = open(JoinPath(lower, "empty").c_str(), O_CREAT | O_WRONLY, 0644);
    TEST_PCHECK(fd >= 0);
    close(fd);

    int fs_fd = -1;
    if (creator == OverlayCreator::kRestrictedBeforeCreate) {
      fs_fd = syscall(SYS_fsopen, "overlay", 0);
      if (fs_fd < 0) {
        _exit(kUnsupported);
      }
    }
    constexpr uint64_t kRW =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    int ruleset = CreateRuleset(kRW);
    for (const std::string& path : granted) {
      AddPathRule(ruleset, JoinPath(root, path), kRW);
    }
    EnforceOrDie(ruleset);
    if (fs_fd < 0) {
      fs_fd = syscall(SYS_fsopen, "overlay", 0);
      if (fs_fd < 0) {
        _exit(kUnsupported);
      }
    }
    if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "lowerdir",
                lower.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "upperdir",
                upper.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "workdir",
                work.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      perror("fsconfig(overlay)");
      _exit(kUnsupported);
    }
    int mfd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mfd < 0) {
      perror("fsmount(overlay)");
      _exit(kSetup);
    }
    if (fchmodat(mfd, "empty", 0600, 0) != 0) {
      perror("fchmodat(empty)");
      _exit(kOther);
    }
    int rc = fchmodat(mfd, "key", 0600, 0);
    ChildResult res = ClassifyFs(rc);
    struct stat st;
    bool copied = stat(JoinPath(upper, "key").c_str(), &st) == 0;
    if ((res == kAllowed) != copied) {
      fprintf(stderr, "fchmodat(key): %d, upper/key exists: %d\n", rc, copied);
      _exit(kOther);
    }
    _exit(res);
  });
}

TEST(LandlockV1Test, OverlayCopyUpChecksCreatorDomainOnLayerFiles) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;

  struct Case {
    std::vector<std::string> granted;
    OverlayCreator creator;
    ChildResult want;
  };
  const Case cases[] = {
      {{"sandbox"}, OverlayCreator::kRestrictedBeforeFsopen, kDenied},
      {{"sandbox"}, OverlayCreator::kRestrictedBeforeCreate, kDenied},
      {{""}, OverlayCreator::kRestrictedBeforeFsopen, kDenied},
      {{"sandbox", "lower"}, OverlayCreator::kRestrictedBeforeFsopen, kAllowed},
      {{"lower", "sandbox/upper"},
       OverlayCreator::kRestrictedBeforeFsopen,
       kAllowed},
      {{"lower"}, OverlayCreator::kRestrictedBeforeFsopen, kDenied},
  };
  for (const Case& c : cases) {
    const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    int status = ASSERT_NO_ERRNO_AND_VALUE(
        OverlayCopyUpOpens(root.path(), c.granted, c.creator));
    SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == c.want)
        << "granted " << absl::StrJoin(c.granted, ",") << ", creator "
        << static_cast<int>(c.creator) << ": exit status " << status;
  }
}

TEST(LandlockV1Test, OverlayLayerOpensCheckCreatorDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.path().c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string lower1 = JoinPath(root.path(), "lower1");
    const std::string lower2 = JoinPath(root.path(), "lower2");
    const std::string sandbox = JoinPath(root.path(), "sandbox");
    for (const std::string& dir : {lower1, lower2, sandbox}) {
      TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    int fd = open(JoinPath(lower1, "key").c_str(), O_CREAT | O_WRONLY, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(write(fd, "secret", 6) == 6);
    close(fd);

    int sv[2];
    TEST_PCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    pid_t pid = fork();
    TEST_PCHECK(pid >= 0);
    if (pid == 0) {
      ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
                    sandbox,
                    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
      int fs_fd = syscall(SYS_fsopen, "overlay", 0);
      if (fs_fd < 0) {
        _exit(kUnsupported);
      }
      const std::string lowers = absl::StrCat(lower1, ":", lower2);
      if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "lowerdir",
                  lowers.c_str(), 0) != 0 ||
          syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                  0) != 0) {
        _exit(kUnsupported);
      }
      int mfd = syscall(SYS_fsmount, fs_fd, 0, 0);
      if (mfd < 0) {
        _exit(kSetup);
      }
      char c = 0;
      iovec iov = {&c, 1};
      char cbuf[CMSG_SPACE(sizeof(int))] = {};
      msghdr msg = {};
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_control = cbuf;
      msg.msg_controllen = sizeof(cbuf);
      cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_level = SOL_SOCKET;
      cmsg->cmsg_type = SCM_RIGHTS;
      cmsg->cmsg_len = CMSG_LEN(sizeof(int));
      memcpy(CMSG_DATA(cmsg), &mfd, sizeof(int));
      TEST_PCHECK(sendmsg(sv[1], &msg, 0) == 1);
      _exit(0);
    }
    char c;
    iovec iov = {&c, 1};
    char cbuf[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    int creator_status;
    TEST_PCHECK(waitpid(pid, &creator_status, 0) == pid);
    if (!WIFEXITED(creator_status) || WEXITSTATUS(creator_status) != 0) {
      _exit(WIFEXITED(creator_status) ? WEXITSTATUS(creator_status) : kSetup);
    }
    TEST_PCHECK(recvmsg(sv[0], &msg, 0) == 1);
    int mfd;
    memcpy(&mfd, CMSG_DATA(CMSG_FIRSTHDR(&msg)), sizeof(int));

    if (openat(mfd, "key", O_RDONLY) >= 0 || errno != EACCES) {
      perror("openat(key)");
      _exit(kOther);
    }
    if (openat(mfd, ".", O_RDONLY | O_DIRECTORY) >= 0 || errno != EACCES) {
      perror("openat(.)");
      _exit(kOther);
    }
    fd = openat(mfd, "key", O_PATH);
    if (fd < 0) {
      perror("openat(key, O_PATH)");
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, FailedUnixBindByUnrestrictedTaskRemovesOnlyItsFile) {
  const DisableSave ds;
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess(
      [&] { _exit(RunFailedUnixBindRace(root.path(), false)); }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, FailedUnixBindRemovesSocketFileWithoutWritePermission) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn("/tmp"));
  ASSERT_THAT(chmod(dir.path().c_str(), 0777), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;

  for (bool landlocked : {false, true}) {
    const std::string path =
        JoinPath(dir.path(), landlocked ? "landlocked" : "unrestricted");
    ASSERT_LT(path.size(), sizeof(sockaddr_un::sun_path));
    int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
      if (landlocked) {
        ApplyFsPolicy(
            LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_REMOVE_FILE,
            dir.path(), LANDLOCK_ACCESS_FS_MAKE_SOCK);
      }
      if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
        _exit(kUnsupported);
      }
      umask(0222);
      int sock = socket(AF_UNIX, SOCK_STREAM, 0);
      TEST_PCHECK(sock >= 0);
      sockaddr_un addr = {};
      addr.sun_family = AF_UNIX;
      const std::string abstract =
          absl::StrCat("landlock_bind_umask_", getpid());
      memcpy(addr.sun_path + 1, abstract.c_str(), abstract.size());
      TEST_PCHECK(bind(sock, reinterpret_cast<sockaddr*>(&addr),
                       offsetof(sockaddr_un, sun_path) + 1 + abstract.size()) ==
                  0);
      sockaddr_un path_addr = {};
      path_addr.sun_family = AF_UNIX;
      memcpy(path_addr.sun_path, path.c_str(), path.size());
      int rc = bind(sock, reinterpret_cast<sockaddr*>(&path_addr),
                    sizeof(path_addr));
      if (rc == 0 || errno != EINVAL) {
        _exit(kOther);
      }
      struct stat st;
      _exit(lstat(path.c_str(), &st) == 0 ? kDenied : kAllowed);
    }));
    SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
        << (landlocked ? "landlocked" : "unrestricted") << ": exit status "
        << status;
  }
}

TEST(LandlockV1Test, BindMountedNamespaceFileIsCheckedLikeAnyFile) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    if (mount("/proc/self/ns/net", file.path().c_str(), nullptr, MS_BIND,
              nullptr) != 0) {
      _exit(kUnsupported);
    }
    int ruleset = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(ruleset, file.path(), LANDLOCK_ACCESS_FS_READ_FILE);
    close(ruleset);
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(file.path()));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, DeviceMknodIntoUnwritableDirIsEaccesBeforeCapability) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SETUID)));
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn("/tmp"));
  ASSERT_THAT(chmod(dir.path().c_str(), 0755), SyscallSucceeds());
  constexpr uid_t kNobody = 65534;
  const std::string node = JoinPath(dir.path(), "null");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_CHAR, dir.path(),
                  LANDLOCK_ACCESS_FS_MAKE_CHAR);
    if (syscall(SYS_setresuid, kNobody, kNobody, kNobody) != 0) {
      _exit(kUnsupported);
    }
    _exit(ClassifyErrno(mknod(node.c_str(), S_IFCHR | 0600, makedev(1, 3))));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, ScopedFdinfoDirectoryCanStillBeStatted) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const pid_t target = getpid();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    const std::string fdinfo = absl::StrCat("/proc/", target, "/fdinfo");
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG));
    struct stat st;
    if (stat(fdinfo.c_str(), &st) != 0) {
      fprintf(stderr, "stat(%s): %s\n", fdinfo.c_str(), strerror(errno));
      _exit(kOther);
    }
    if (open(fdinfo.c_str(), O_RDONLY | O_DIRECTORY) >= 0 || errno != EACCES) {
      fprintf(stderr, "open(%s): %s\n", fdinfo.c_str(), strerror(errno));
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, DirectoryOpenWithTruncIsEisdirNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_DIR);
    _exit(ClassifyErrno(open(dir.path().c_str(), O_RDONLY | O_TRUNC)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrIsdir)
      << "exit status " << status;
}

TEST(LandlockV1Test, DirectoryOpenWithODirectIsEaccesNotEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_DIR);
    _exit(ClassifyErrno(
        open(dir.path().c_str(), O_RDONLY | O_DIRECTORY | O_DIRECT)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrAcces)
      << "exit status " << status;
}

TEST(LandlockV1Test, OpenCreatInRemovedDirectoryIsEnoentNotEacces) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath parent = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string dir = JoinPath(parent.path(), "gone");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    TEST_PCHECK(chdir(dir.c_str()) == 0);
    TEST_PCHECK(rmdir(dir.c_str()) == 0);
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(open("f", O_CREAT | O_WRONLY, 0644)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrNoent)
      << "exit status " << status;
}

TEST(LandlockV1Test, CrossMountLinkAndRenameAreExdevBeforeLandlock) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath src_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath src =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(src_dir.path()));
  const TempPath mnt = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", mnt.path().c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string dst = JoinPath(mnt.path(), "f");
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG |
                            LANDLOCK_ACCESS_FS_REMOVE_FILE);
    int link_rc = ClassifyErrno(link(src.path().c_str(), dst.c_str()));
    if (link_rc != kErrExdev) {
      _exit(link_rc);
    }
    _exit(ClassifyErrno(rename(src.path().c_str(), dst.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrExdev)
      << "exit status " << status;
}

TEST(LandlockV1Test, PivotRootIgnoresSearchPermissionOnTargetsBeforeEperm) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath new_root =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base.path()));
  const TempPath put_old =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(base.path()));
  ASSERT_THAT(chmod(new_root.path().c_str(), 0), SyscallSucceeds());
  ASSERT_THAT(chmod(put_old.path().c_str(), 0), SyscallSucceeds());
  auto restore = Cleanup([&] {
    EXPECT_THAT(chmod(new_root.path().c_str(), 0755), SyscallSucceeds());
    EXPECT_THAT(chmod(put_old.path().c_str(), 0755), SyscallSucceeds());
  });

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_CHECK_NO_ERRNO(SetCapability(CAP_DAC_OVERRIDE, false));
    TEST_CHECK_NO_ERRNO(SetCapability(CAP_DAC_READ_SEARCH, false));
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_REG);
    _exit(ClassifyErrno(syscall(SYS_pivot_root, new_root.path().c_str(),
                                put_old.path().c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kErrPerm)
      << "exit status " << status;
}

TEST(LandlockV1Test, RulesetReleasedWhileItsProcFdResolvesDoesNotHang) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const DisableSave ds;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    const absl::Time deadline = absl::Now() + absl::Seconds(2);
    while (absl::Now() < deadline) {
      int ruleset = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
      AddPathRule(ruleset, "/proc/self/status", LANDLOCK_ACCESS_FS_READ_FILE);
      const std::string link = absl::StrCat("/proc/self/fd/", ruleset);
      std::atomic<bool> stop(false);
      ScopedThread resolver([&] {
        struct stat st;
        while (!stop.load()) {
          stat(link.c_str(), &st);
        }
      });
      close(ruleset);
      absl::SleepFor(absl::Microseconds(50));
      stop.store(true);
      resolver.Join();
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

int OverlayFromLandlockedCreator(const std::string& lower,
                                 const std::string& upper,
                                 const std::string& work, uint64_t handled,
                                 const std::vector<std::string>& granted,
                                 uint64_t granted_access) {
  int sv[2];
  TEST_PCHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  pid_t pid = fork();
  TEST_PCHECK(pid >= 0);
  if (pid == 0) {
    int ruleset = CreateRuleset(handled);
    for (const std::string& path : granted) {
      AddPathRule(ruleset, path, granted_access);
    }
    EnforceOrDie(ruleset);
    int fs_fd = syscall(SYS_fsopen, "overlay", 0);
    if (fs_fd < 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "lowerdir",
                lower.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "upperdir",
                upper.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "workdir",
                work.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      _exit(kUnsupported);
    }
    int mfd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mfd < 0) {
      _exit(kSetup);
    }
    char c = 0;
    iovec iov = {&c, 1};
    char cbuf[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &mfd, sizeof(int));
    TEST_PCHECK(sendmsg(sv[1], &msg, 0) == 1);
    _exit(0);
  }
  int creator_status;
  TEST_PCHECK(waitpid(pid, &creator_status, 0) == pid);
  if (!WIFEXITED(creator_status) || WEXITSTATUS(creator_status) != 0) {
    _exit(WIFEXITED(creator_status) ? WEXITSTATUS(creator_status) : kSetup);
  }
  char c;
  iovec iov = {&c, 1};
  char cbuf[CMSG_SPACE(sizeof(int))] = {};
  msghdr msg = {};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  TEST_PCHECK(recvmsg(sv[0], &msg, 0) == 1);
  int mfd;
  memcpy(&mfd, CMSG_DATA(CMSG_FIRSTHDR(&msg)), sizeof(int));
  close(sv[0]);
  close(sv[1]);
  return mfd;
}

TEST(LandlockV1Test, OverlayCreatorDomainChecksDirectoryEntriesWhenRead) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.path().c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string lower = JoinPath(root.path(), "lower");
    const std::string upper = JoinPath(root.path(), "upper");
    const std::string work = JoinPath(root.path(), "work");
    for (const std::string& dir :
         {lower, upper, work, JoinPath(lower, "d"), JoinPath(upper, "d")}) {
      TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    for (const std::string& file :
         {JoinPath(lower, "d/a"), JoinPath(upper, "d/b")}) {
      int fd = open(file.c_str(), O_CREAT | O_WRONLY, 0644);
      TEST_PCHECK(fd >= 0);
      close(fd);
    }
    const uint64_t kRead =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    int mfd = OverlayFromLandlockedCreator(lower, upper, work, kRead,
                                           {upper, work}, kRead);
    int dfd = openat(mfd, "d", O_RDONLY | O_DIRECTORY);
    if (dfd < 0) {
      perror("openat(d)");
      _exit(kOther);
    }
    char buf[4096];
    int n = syscall(SYS_getdents64, dfd, buf, sizeof(buf));
    if (n >= 0 || errno != EACCES) {
      fprintf(stderr, "getdents64: %d, %s\n", n, strerror(errno));
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayCreateOpenDeniedByCreatorDomainLeavesFile) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.path().c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string lower = JoinPath(root.path(), "lower");
    const std::string upper = JoinPath(root.path(), "upper");
    const std::string work = JoinPath(root.path(), "work");
    for (const std::string& dir : {lower, upper, work}) {
      TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    int mfd = OverlayFromLandlockedCreator(
        lower, upper, work, LANDLOCK_ACCESS_FS_WRITE_FILE, {}, 0);
    if (openat(mfd, "new", O_CREAT | O_WRONLY, 0644) >= 0 || errno != EACCES) {
      perror("openat(new, O_CREAT)");
      _exit(kOther);
    }
    struct stat st;
    if (fstatat(mfd, "new", &st, 0) != 0) {
      perror("fstatat(new)");
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayRulesAddedBeforeAndAfterCopyUpNameOneFile) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string data = "lowerdir=" + lower + ",upperdir=" + upper +
                           ",workdir=" + work +
                           (IsRunningOnGvisor() ? "" : ",index=off");

  auto check = [&](bool linked) {
    return InForkedProcess([&] {
      TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
      TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                  0);
      TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
      for (const std::string& dir : {lower, upper, work, merged}) {
        TEST_PCHECK(mkdir(dir.c_str(), 0777) == 0);
      }
      const std::string lower_a = JoinPath(lower, "a");
      int fd = open(lower_a.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
      TEST_PCHECK(fd >= 0);
      TEST_PCHECK(close(fd) == 0);
      if (linked) {
        TEST_PCHECK(link(lower_a.c_str(), JoinPath(lower, "b").c_str()) == 0);
      }
      if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
        _exit(kUnsupported);
      }

      const std::string merged_a = JoinPath(merged, "a");
      int ruleset_fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                                     LANDLOCK_ACCESS_FS_WRITE_FILE);
      AddPathRule(ruleset_fd, merged_a, LANDLOCK_ACCESS_FS_READ_FILE);
      TEST_PCHECK(chmod(merged_a.c_str(), 0666) == 0);
      AddPathRule(ruleset_fd, merged_a, LANDLOCK_ACCESS_FS_WRITE_FILE);
      EnforceOrDie(ruleset_fd);
      _exit(ClassifyFs(open(merged_a.c_str(), O_RDWR)));
    });
  };
  for (bool linked : {false, true}) {
    int status = ASSERT_NO_ERRNO_AND_VALUE(check(linked));
    SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
        << (linked ? "linked" : "unlinked") << " lower file: exit status "
        << status;
  }
}

TEST(LandlockV1Test, BindMountsOfOneNamespaceFileAreOneFile) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath first =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  const TempPath second =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    for (const TempPath* file : {&first, &second}) {
      if (mount("/proc/self/ns/net", file->path().c_str(), nullptr, MS_BIND,
                nullptr) != 0) {
        _exit(kUnsupported);
      }
    }
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, first.path(),
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(second.path()));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ConcurrentRenamesNeverCombineGrantsFromDifferentPaths) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!IsRunningOnGvisor());
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string a = JoinPath(root, "A");
    const std::string b = JoinPath(a, "B");
    const std::string c = JoinPath(root, "C");
    const std::string d = JoinPath(root, "D");
    for (const std::string& dir : {a, b, c, d}) {
      TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    std::string deep = b;
    for (int i = 1; i < 64; i++) {
      deep = JoinPath(deep, absl::StrCat("x", i));
      TEST_PCHECK(mkdir(deep.c_str(), 0755) == 0);
    }
    const std::string xl = JoinPath(deep, "xl");
    TEST_PCHECK(mkdir(xl.c_str(), 0755) == 0);
    TEST_PCHECK(mkdir(JoinPath(xl, "d").c_str(), 0755) == 0);
    int fd = open(JoinPath(xl, "d/F").c_str(), O_WRONLY | O_CREAT, 0644);
    TEST_PCHECK(fd >= 0);
    TEST_PCHECK(close(fd) == 0);
    const int dfd = open(JoinPath(xl, "d").c_str(), O_PATH | O_DIRECTORY);
    TEST_PCHECK(dfd >= 0);

    int on_b = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(on_b, b, LANDLOCK_ACCESS_FS_READ_FILE);
    int on_d = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(on_d, d, LANDLOCK_ACCESS_FS_READ_FILE);

    std::atomic<bool> stop(false);
    ScopedThread renamer([&] {
      const std::string xl_in_c = JoinPath(c, "xl");
      const std::string b_in_d = JoinPath(d, "B");
      while (!stop.load(std::memory_order_relaxed)) {
        rename(xl.c_str(), xl_in_c.c_str());
        rename(b.c_str(), b_in_d.c_str());
        rename(b_in_d.c_str(), b.c_str());
        rename(xl_in_c.c_str(), xl.c_str());
      }
    });
    EnforceOrDie(on_b);
    EnforceOrDie(on_d);

    int64_t granted = 0;
    const absl::Time end = absl::Now() + absl::Seconds(5);
    while (absl::Now() < end) {
      int f = openat(dfd, "F", O_RDONLY);
      if (f >= 0) {
        granted++;
        close(f);
      }
    }
    stop.store(true, std::memory_order_relaxed);
    renamer.Join();
    if (granted != 0) {
      fprintf(stderr, "%lld opens granted\n", static_cast<long long>(granted));
      _exit(kAllowed);
    }
    _exit(kDenied);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, FdinfoEntryStaysScopedAfterAnotherTaskLooksItUp) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open("/", O_RDONLY));
  const std::string entry =
      absl::StrCat("/proc/", getpid(), "/fdinfo/", fd.get());
  struct stat st;
  ASSERT_THAT(stat(entry.c_str(), &st), SyscallSucceeds());
  ASSERT_NO_ERRNO(Open(entry, O_RDONLY));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_REG));
    _exit(TryReadOpen(entry));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayCopyUpOfFileOfUnknownSizeChecksCreatorDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(InInitialUserNamespace()));
  const std::string lower = "/sys/devices/system/cpu";
  SKIP_IF(access(JoinPath(lower, "online").c_str(), R_OK) != 0);
  const DisableSave ds;
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.path().c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string upper = JoinPath(root.path(), "upper");
    const std::string work = JoinPath(root.path(), "work");
    for (const std::string& dir : {upper, work}) {
      TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    ApplyFsPolicy(kFsAccessV1, root.path(), kFsAccessV1);
    int fs_fd = syscall(SYS_fsopen, "overlay", 0);
    if (fs_fd < 0) {
      _exit(kUnsupported);
    }
    if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "lowerdir",
                lower.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "upperdir",
                upper.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "workdir",
                work.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      _exit(kUnsupported);
    }
    int mfd = syscall(SYS_fsmount, fs_fd, 0, 0);
    if (mfd < 0) {
      _exit(kSetup);
    }
    _exit(ClassifyFs(fchmodat(mfd, "online", 0644, 0)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayCreatesItsWorkDirectoryWithoutCreatorDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const DisableSave ds;
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", root.path().c_str(), "tmpfs", 0, nullptr) == 0);
    const std::string lower = JoinPath(root.path(), "lower");
    const std::string upper = JoinPath(root.path(), "upper");
    const std::string work = JoinPath(root.path(), "work");
    for (const std::string& dir : {lower, upper, work}) {
      TEST_PCHECK(mkdir(dir.c_str(), 0755) == 0);
    }
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_MAKE_DIR);
    int fs_fd = syscall(SYS_fsopen, "overlay", 0);
    if (fs_fd < 0) {
      _exit(kUnsupported);
    }
    if (syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "lowerdir",
                lower.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "upperdir",
                upper.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_SET_STRING, "workdir",
                work.c_str(), 0) != 0 ||
        syscall(SYS_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, nullptr, nullptr,
                0) != 0) {
      _exit(kUnsupported);
    }
    if (syscall(SYS_fsmount, fs_fd, 0, 0) < 0) {
      _exit(kSetup);
    }
    struct stat st;
    _exit(stat(JoinPath(work, "work").c_str(), &st) == 0 ? kAllowed : kDenied);
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, CreatingOpenOfSyntheticFilesystemRootIsEisdir) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(open("/proc", O_RDONLY | O_CREAT, 0644),
              SyscallFailsWithErrno(EISDIR));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(LANDLOCK_ACCESS_FS_READ_DIR);
    int fd = open("/proc", O_RDONLY | O_CREAT, 0644);
    if (fd >= 0) {
      _exit(kAllowed);
    }
    _exit(errno == EISDIR ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
