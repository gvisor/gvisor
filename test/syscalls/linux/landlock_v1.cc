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

TEST(LandlockV1Test, MakeDirOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(root.path(), "new_dir");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_DIR);
    _exit(ClassifyFs(mkdir(target.c_str(), 0700)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveFileOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
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
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyFs(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveFileInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_FILE);
    _exit(ClassifyFs(unlink(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveDirOutsideAllowedTreeDenied) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside_dir.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyFs(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RemoveDirInsideAllowedTreeAllowed) {
  SKIP_IF(IsRunningOnGvisor());
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath inside_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside_dir.release();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_REMOVE_DIR, allowed,
                  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    _exit(ClassifyFs(rmdir(target.c_str())));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

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
