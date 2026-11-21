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

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
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

namespace gvisor {
namespace testing {

namespace {

void CreateFile(const std::string& path) {
  int fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0644);
  ASSERT_THAT(fd, SyscallSucceeds());
  ASSERT_THAT(close(fd), SyscallSucceeds());
}

TEST(LandlockV1Test, AbiVersionIsSupported) {
  int version = LandlockAbiVersion();
  SKIP_IF(version < 0 && errno == ENOSYS);
  ASSERT_GE(version, 1) << "unexpected Landlock ABI version";
}

TEST(LandlockV1Test, CreateRulesetSizeHandling) {
  SKIP_IF(LandlockAbiVersion() < 1);
  uint64_t fs_only = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(
                  reinterpret_cast<landlock_ruleset_attr*>(&fs_only), 7, 0),
              SyscallFailsWithErrno(EINVAL));
  int fd = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(&fs_only), sizeof(fs_only), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
  const long page_size = sysconf(_SC_PAGESIZE);
  std::vector<char> big(page_size + 8, 0);
  memcpy(big.data(), &fs_only, sizeof(fs_only));
  EXPECT_THAT(
      landlock_create_ruleset(
          reinterpret_cast<landlock_ruleset_attr*>(big.data()), big.size(), 0),
      SyscallFailsWithErrno(E2BIG));
  std::vector<char> tail(sizeof(landlock_ruleset_attr) + 8, 0);
  memcpy(tail.data(), &fs_only, sizeof(fs_only));
  tail[tail.size() - 1] = 1;
  int rc = landlock_create_ruleset(
      reinterpret_cast<landlock_ruleset_attr*>(tail.data()), tail.size(), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
  landlock_ruleset_attr full = {};
  full.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  full.scoped = (1ULL << 63);
  rc = landlock_create_ruleset(&full, sizeof(full), 0);
  EXPECT_LT(rc, 0);
  EXPECT_THAT(errno, ::testing::AnyOf(E2BIG, EINVAL));
  if (IsRunningOnGvisor()) {
    EXPECT_EQ(errno, E2BIG);
  }
}

TEST(LandlockV1Test, CreateRulesetNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(landlock_create_ruleset(nullptr, 7, 0),
              SyscallFailsWithErrno(EFAULT));
  EXPECT_THAT(
      landlock_create_ruleset(nullptr, sizeof(landlock_ruleset_attr), 0),
      SyscallFailsWithErrno(EFAULT));
}

TEST(LandlockV1Test, CreateRulesetEmptyHandledAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(ENOMSG));
}

TEST(LandlockV1Test, CreateRulesetErrataReturnsBitmask) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int rc = landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_ERRATA);
  if (rc < 0) {
    EXPECT_EQ(errno, EINVAL) << "unexpected errno " << errno;
  } else {
    EXPECT_GE(rc, 0);
  }
}

TEST(LandlockV1Test, CreateRulesetErrataRejectsAttr) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_MAKE_REG;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(landlock_create_ruleset(nullptr, sizeof(attr),
                                      LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, CreateRulesetVersionAndErrataRejected) {
  SKIP_IF(LandlockAbiVersion() < 1);
  EXPECT_THAT(landlock_create_ruleset(nullptr, 0,
                                      LANDLOCK_CREATE_RULESET_VERSION |
                                          LANDLOCK_CREATE_RULESET_ERRATA),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, CreateRulesetRejectsUnknownFlags) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0xffff),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, AddRuleRejectsUnknownRuleType) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(fd, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EINVAL));
  close(fd);
}

TEST(LandlockV1Test, AddRuleBadFdWithBadRuleTypeReportsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_path_beneath_attr path_beneath = {};
  EXPECT_THAT(landlock_add_rule(-1, static_cast<landlock_rule_type>(0xffff),
                                &path_beneath, 0),
              SyscallFailsWithErrno(EBADF));

  int file_fd = open("/", O_RDONLY | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(file_fd, static_cast<landlock_rule_type>(0xffff),
                        &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(file_fd);
}

TEST(LandlockV1Test, OPathRulesetFdIsEbadf) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int opath_fd = open(dir.path().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
  ASSERT_THAT(opath_fd, SyscallSucceeds());
  auto close_opath = Cleanup([opath_fd] { close(opath_fd); });
  int parent_fd = open(dir.path().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  auto close_parent = Cleanup([parent_fd] { close(parent_fd); });
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(opath_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADF));
  int plain_fd = open(dir.path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  ASSERT_THAT(plain_fd, SyscallSucceeds());
  auto close_plain = Cleanup([plain_fd] { close(plain_fd); });
  EXPECT_THAT(
      landlock_add_rule(plain_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));

  constexpr int kBadf = 130;
  constexpr int kBadfd = 131;
  static std::string path;
  path = dir.path();
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    int fd = open(path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (landlock_restrict_self(fd, 0) == 0) {
      _exit(kAllowed);
    }
    switch (errno) {
      case EBADF:
        _exit(kBadf);
      case EBADFD:
        _exit(kBadfd);
      default:
        _exit(kOther);
    }
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kBadf)
      << "exit status " << status;
}

TEST(LandlockV1Test, AddRuleNullAttrReturnsEfault) {
  SKIP_IF(LandlockAbiVersion() < 1);

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());
  EXPECT_THAT(
      landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, nullptr, 0),
      SyscallFailsWithErrno(EFAULT));
  close(ruleset_fd);
}

TEST(LandlockV1Test, AddRuleUnknownFlagsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 2),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, RestrictSelfWithoutNoNewPrivsFails) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    TEST_PCHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
    TEST_PCHECK(SetCapability(CAP_SYS_ADMIN, false).ok());
    struct landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 0) < 0 && errno == EPERM ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

TEST(LandlockV1Test, RestrictSelfChecksFlagsThenNoNewPrivsThenFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const bool flags_first = IsRunningOnGvisor() || LandlockAbiVersion() >= 11;
  AutoCapability cap_admin(CAP_SYS_ADMIN, false);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_EXECUTE);
    if (landlock_restrict_self(-1, ~0u) != -1) {
      _exit(kOther);
    }
    if (errno != EINVAL && !(errno == EPERM && !flags_first)) {
      _exit(kOther);
    }
    if (landlock_restrict_self(-1, 0) != -1 || errno != EPERM) {
      _exit(kOther);
    }
    if (landlock_restrict_self(fd, 0) != -1 || errno != EPERM) {
      _exit(kOther);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    if (landlock_restrict_self(-1, ~0u) != -1 || errno != EINVAL) {
      _exit(kOther);
    }
    if (landlock_restrict_self(-1, 0) != -1 || errno != EBADF) {
      _exit(kOther);
    }
    if (landlock_restrict_self(fd, 0) != 0) {
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfUnknownFlagsWithNoNewPrivsReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(fd, 1u << 31) < 0 && errno == EINVAL ? kDenied
                                                                      : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RestrictSelfRejectsBadFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    _exit(landlock_restrict_self(-1, 0) < 0 && errno == EBADF ? kDenied
                                                              : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied);
}

TEST(LandlockV1Test, RestrictSelfWithCapSysAdminWithoutNoNewPrivs) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    landlock_ruleset_attr attr = {};
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (fd < 0) {
      _exit(kSetup);
    }
    if (landlock_restrict_self(fd, 0) != 0) {
      _exit(kSetup);
    }
    close(fd);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RulesetFdRejectsIO) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  char c;
  EXPECT_THAT(read(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(write(fd, &c, 1), SyscallFailsWithErrno(EINVAL));
  EXPECT_THAT(lseek(fd, 0, SEEK_SET), SyscallFailsWithErrno(ESPIPE));
  close(fd);
}

TEST(LandlockV1Test, RulesetFdIsCloseOnExecAndReadWrite) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  FileDescriptor fd(landlock_create_ruleset(&attr, sizeof(attr), 0));
  ASSERT_THAT(fd.get(), SyscallSucceeds());
  // Close-on-exec is a descriptor flag; the file description's status flags
  // hold only the access mode.
  EXPECT_THAT(fcntl(fd.get(), F_GETFD), SyscallSucceedsWithValue(FD_CLOEXEC));
  EXPECT_THAT(fcntl(fd.get(), F_GETFL), SyscallSucceedsWithValue(O_RDWR));
}

TEST(LandlockV1Test, CreateRulesetHandlingAllV1RightsSucceeds) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  EXPECT_THAT(fd, SyscallSucceeds());
  if (fd >= 0) {
    close(fd);
  }
}

TEST(LandlockV1Test, CreateRulesetRejectsUnknownAccessBits) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = (1ULL << 63);
  EXPECT_THAT(landlock_create_ruleset(&attr, sizeof(attr), 0),
              SyscallFailsWithErrno(EINVAL));
}

TEST(LandlockV1Test, AddRuleEmptyAllowedAccessReturnsEnomsg) {
  SKIP_IF(LandlockAbiVersion() < 1);
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.parent_fd = -1;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(ENOMSG));
  close(fd);
}

TEST(LandlockV1Test, AddPathBeneathRejectsUnhandledAccess) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(dir.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, AddRuleDirOnlyRightsOnNonDirectoryReturnsEinval) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  landlock_ruleset_attr attr = {};
  attr.handled_access_fs =
      LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  int parent_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(parent_fd, SyscallSucceeds());
  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_DIR;
  path_beneath.parent_fd = parent_fd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EINVAL));
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallSucceeds());
  close(parent_fd);
  close(fd);
}

TEST(LandlockV1Test, FileRuleAcceptsOnlyFileCompatibleRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  int file_fd = open(file.path().c_str(), O_PATH | O_CLOEXEC);
  ASSERT_THAT(file_fd, SyscallSucceeds());

  landlock_ruleset_attr attr = {};
  attr.handled_access_fs = kFsAccessV1;
  int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(ruleset_fd, SyscallSucceeds());

  constexpr uint64_t kFileCompatible = LANDLOCK_ACCESS_FS_EXECUTE |
                                       LANDLOCK_ACCESS_FS_WRITE_FILE |
                                       LANDLOCK_ACCESS_FS_READ_FILE;
  for (int bit = 0; bit < 13; bit++) {
    const uint64_t access = 1ULL << bit;
    landlock_path_beneath_attr path_beneath = {};
    path_beneath.allowed_access = access;
    path_beneath.parent_fd = file_fd;
    if (access & kFileCompatible) {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallSucceeds())
          << "access bit " << bit;
    } else {
      EXPECT_THAT(landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                                    &path_beneath, 0),
                  SyscallFailsWithErrno(EINVAL))
          << "access bit " << bit;
    }
  }
  close(ruleset_fd);
  close(file_fd);
}

TEST(LandlockV1Test, AddPathBeneathRejectsInternalMountFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  struct landlock_ruleset_attr attr = {};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE;
  int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
  ASSERT_THAT(fd, SyscallSucceeds());
  auto close_ruleset = Cleanup([fd] { close(fd); });

  landlock_path_beneath_attr path_beneath = {};
  path_beneath.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;

  int memfd = syscall(SYS_memfd_create, "landlock_v1_test", 0);
  ASSERT_THAT(memfd, SyscallSucceeds());
  path_beneath.parent_fd = memfd;
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(memfd);

  int ns_fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
  if (ns_fd >= 0) {
    path_beneath.parent_fd = ns_fd;
    EXPECT_THAT(
        landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
        SyscallFailsWithErrno(EBADFD));
    close(ns_fd);
  }

  int sv[2];
  ASSERT_THAT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), SyscallSucceeds());
  path_beneath.parent_fd = sv[0];
  EXPECT_THAT(
      landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0),
      SyscallFailsWithErrno(EBADFD));
  close(sv[0]);
  close(sv[1]);
}

TEST(LandlockV1Test, NamespaceFileIsOpenableUnderDomain) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/ns/net"));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MaxSixteenStackedLayers) {
  SKIP_IF(LandlockAbiVersion() < 1);

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    for (int i = 0; i < 16; i++) {
      int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
      if (landlock_restrict_self(fd, 0) != 0) {
        _exit(kSetup);
      }
      close(fd);
    }
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_MAKE_DIR);
    int rc = landlock_restrict_self(fd, 0);
    close(fd);
    _exit(rc < 0 && errno == E2BIG ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ReadInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ReadOutsideAllowedTreeDenied) {
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
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, WriteFileInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_WRITE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, WriteFileOutsideAllowedTreeDenied) {
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
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_WRITE_FILE, allowed,
                  LANDLOCK_ACCESS_FS_WRITE_FILE);
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ReadDirOutsideAllowedTreeDenied) {
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
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_DIR, allowed,
                  LANDLOCK_ACCESS_FS_READ_DIR);
    int fd = open(target.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, OPathOpenNeedsNoRights) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    int fd = open(target.c_str(), O_PATH | O_CLOEXEC);
    _exit(fd >= 0 ? kAllowed : (errno == EACCES ? kDenied : kOther));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnhandledOpenModesRemainAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string allowed;
  allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    int wo = open(target.c_str(), O_WRONLY);
    if (wo < 0) {
      _exit(ClassifyFs(wo));
    }
    close(wo);
    _exit(ClassifyFs(open(target.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, SameFileRulesInTwoLayersIntersect) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFile());
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    constexpr uint64_t kHandled =
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
    ApplyFsPolicy(kHandled, target, LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen(target) != kAllowed) {
      _exit(kSetup);
    }
    ApplyFsPolicy(kHandled, target, LANDLOCK_ACCESS_FS_WRITE_FILE);
    if (TryReadOpen(target) != kDenied) {
      _exit(kOther);
    }
    int fd = open(target.c_str(), O_WRONLY);
    if (fd >= 0) {
      close(fd);
      _exit(kOther);
    }
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RulesInOneLayerUnionAcrossAncestry) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath parent_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath child_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(parent_dir.path()));
  TempPath child_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(child_dir.path()));
  TempPath parent_file =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(parent_dir.path()));
  static std::string parent;
  parent = parent_dir.path();
  static std::string child;
  child = child_dir.path();
  static std::string in_child;
  in_child = child_file.path();
  static std::string in_parent;
  in_parent = parent_file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                           LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, parent, LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, child, LANDLOCK_ACCESS_FS_WRITE_FILE);
    EnforceOrDie(fd);
    int rw = open(in_child.c_str(), O_RDWR);
    if (rw < 0) {
      _exit(ClassifyFs(rw));
    }
    close(rw);
    int denied = open(in_parent.c_str(), O_RDWR);
    if (denied >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    _exit(TryReadOpen(in_parent));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

constexpr uint64_t kAccessRO = LANDLOCK_ACCESS_FS_EXECUTE |
                               LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_READ_DIR;

constexpr uint64_t kAccessRW = kAccessRO | LANDLOCK_ACCESS_FS_WRITE_FILE;

struct Layout1 {
  std::string dir_s1d1;
  std::string dir_s1d2;
  std::string dir_s1d3;
  std::string file1_s1d1;
  std::string file1_s1d2;
  std::string file1_s1d3;
};

void MakeLayout1(const std::string& root, Layout1* l) {
  l->dir_s1d1 = JoinPath(root, "s1d1");
  l->dir_s1d2 = JoinPath(l->dir_s1d1, "s1d2");
  l->dir_s1d3 = JoinPath(l->dir_s1d2, "s1d3");
  ASSERT_THAT(mkdir(l->dir_s1d1.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(l->dir_s1d2.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(l->dir_s1d3.c_str(), 0755), SyscallSucceeds());
  l->file1_s1d1 = JoinPath(l->dir_s1d1, "f1");
  l->file1_s1d2 = JoinPath(l->dir_s1d2, "f1");
  l->file1_s1d3 = JoinPath(l->dir_s1d3, "f1");
  ASSERT_NO_FATAL_FAILURE(CreateFile(l->file1_s1d1));
  ASSERT_NO_FATAL_FAILURE(CreateFile(l->file1_s1d2));
  ASSERT_NO_FATAL_FAILURE(CreateFile(l->file1_s1d3));
}

TEST(LandlockV1Test, RulesOnSameDirectoryInOneRulesetUnion) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Layout1 l;
  ASSERT_NO_FATAL_FAILURE(MakeLayout1(root.path(), &l));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kAccessRW);
    AddPathRule(fd, l.dir_s1d2,
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
    AddPathRule(fd, l.dir_s1d2,
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
    EnforceOrDie(fd);

    ExpectOpen(l.file1_s1d1, O_RDONLY, EACCES);
    ExpectOpen(l.file1_s1d1, O_WRONLY, EACCES);
    ExpectOpen(l.file1_s1d1, O_RDWR, EACCES);
    ExpectOpen(l.dir_s1d1, O_RDONLY | O_DIRECTORY, EACCES);

    ExpectOpen(l.file1_s1d2, O_RDONLY, 0);
    ExpectOpen(l.file1_s1d2, O_WRONLY, 0);
    ExpectOpen(l.file1_s1d2, O_RDWR, 0);
    ExpectOpen(l.dir_s1d2, O_RDONLY | O_DIRECTORY, 0);

    ExpectOpen(l.file1_s1d3, O_RDONLY, 0);
    ExpectOpen(l.file1_s1d3, O_WRONLY, 0);
    ExpectOpen(l.file1_s1d3, O_RDWR, 0);
    ExpectOpen(l.dir_s1d3, O_RDONLY | O_DIRECTORY, 0);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RulesAddedAfterEnforcementNeverWiden) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Layout1 l;
  ASSERT_NO_FATAL_FAILURE(MakeLayout1(root.path(), &l));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int fd = CreateRuleset(kAccessRW);
    AddPathRule(fd, l.dir_s1d2,
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
    auto enforce = [fd] {
      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
          landlock_restrict_self(fd, 0) != 0) {
        _exit(kSetup);
      }
    };
    auto check = [&l] {
      ExpectOpen(l.file1_s1d1, O_WRONLY, EACCES);
      ExpectOpen(l.dir_s1d1, O_RDONLY | O_DIRECTORY, EACCES);
      ExpectOpen(l.file1_s1d2, O_WRONLY, EACCES);
      ExpectOpen(l.dir_s1d2, O_RDONLY | O_DIRECTORY, 0);
      ExpectOpen(l.file1_s1d3, O_WRONLY, EACCES);
      ExpectOpen(l.dir_s1d3, O_RDONLY | O_DIRECTORY, 0);
    };
    enforce();
    check();

    AddPathRule(fd, l.dir_s1d2, LANDLOCK_ACCESS_FS_WRITE_FILE);
    enforce();
    check();

    AddPathRule(fd, l.dir_s1d1, kAccessRW);
    enforce();
    check();

    AddPathRule(fd, l.dir_s1d3, LANDLOCK_ACCESS_FS_WRITE_FILE);
    enforce();
    close(fd);
    check();
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, LayersIntersectWhileRulesWithinALayerUnion) {
  SKIP_IF(LandlockAbiVersion() < 1);
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Layout1 l;
  ASSERT_NO_FATAL_FAILURE(MakeLayout1(root.path(), &l));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    auto check_first_layers = [&l] {
      ExpectOpen(l.file1_s1d1, O_RDONLY, EACCES);
      ExpectOpen(l.file1_s1d1, O_WRONLY, EACCES);
      ExpectOpen(l.file1_s1d1, O_RDWR, EACCES);
      ExpectOpen(l.dir_s1d1, O_RDONLY | O_DIRECTORY, EACCES);

      ExpectOpen(l.file1_s1d2, O_RDONLY, 0);
      ExpectOpen(l.file1_s1d2, O_WRONLY, EACCES);
      ExpectOpen(l.file1_s1d2, O_RDWR, EACCES);

      ExpectOpen(l.file1_s1d3, O_RDONLY, 0);
      ExpectOpen(l.file1_s1d3, O_WRONLY, 0);
      ExpectOpen(l.file1_s1d3, O_RDWR, 0);
    };

    int fd = CreateRuleset(kAccessRW);
    AddPathRule(fd, l.dir_s1d2, LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, l.dir_s1d3, LANDLOCK_ACCESS_FS_WRITE_FILE);
    EnforceOrDie(fd);
    check_first_layers();

    fd = CreateRuleset(kAccessRW);
    AddPathRule(fd, l.dir_s1d2,
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
    EnforceOrDie(fd);
    check_first_layers();

    fd = CreateRuleset(kAccessRW);
    AddPathRule(fd, l.dir_s1d2, LANDLOCK_ACCESS_FS_WRITE_FILE);
    EnforceOrDie(fd);

    ExpectOpen(l.file1_s1d1, O_RDONLY, EACCES);
    ExpectOpen(l.file1_s1d1, O_WRONLY, EACCES);
    ExpectOpen(l.file1_s1d1, O_RDWR, EACCES);
    ExpectOpen(l.dir_s1d1, O_RDONLY | O_DIRECTORY, EACCES);

    ExpectOpen(l.file1_s1d2, O_RDONLY, EACCES);
    ExpectOpen(l.file1_s1d2, O_WRONLY, EACCES);
    ExpectOpen(l.file1_s1d2, O_RDWR, EACCES);

    ExpectOpen(l.file1_s1d3, O_RDONLY, EACCES);
    ExpectOpen(l.file1_s1d3, O_WRONLY, 0);
    ExpectOpen(l.file1_s1d3, O_RDWR, EACCES);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, UnmountReleasesTheRulesFiles) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));
  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  Layout1 l;
  ASSERT_NO_FATAL_FAILURE(MakeLayout1(root.path(), &l));
  const std::string dir_s3d2 = JoinPath(root.path(), "s3d2");
  const std::string dir_s3d3 = JoinPath(dir_s3d2, "s3d3");
  ASSERT_THAT(mkdir(dir_s3d2.c_str(), 0755), SyscallSucceeds());

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount("tmpfs", dir_s3d2.c_str(), "tmpfs", 0, nullptr) == 0);
    TEST_PCHECK(mkdir(dir_s3d3.c_str(), 0755) == 0);

    int fd = CreateRuleset(kAccessRW);
    AddPathRule(fd, l.dir_s1d1, kAccessRO);
    AddPathRule(fd, dir_s3d2, kAccessRO);
    AddPathRule(fd, dir_s3d3, kAccessRO);

    TEST_PCHECK(umount(dir_s3d2.c_str()) == 0);

    EnforceOrDie(fd);
    ExpectOpen(l.file1_s1d1, O_RDONLY, 0);
    ExpectOpen(dir_s3d2, O_RDONLY, EACCES);
    ExpectOpen(dir_s3d3, O_RDONLY, ENOENT);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, LayeredRulesetsOnlyIntersect) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    EnforceOrDie(fd);
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, SameRulesetEnforcedTwiceStillDenies) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  TempPath inside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(allowed_dir.path()));
  TempPath outside =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(root.path()));
  static std::string allowed;
  allowed = allowed_dir.path();
  static std::string in_allowed;
  in_allowed = inside.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(fd, allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      _exit(kSetup);
    }
    if (landlock_restrict_self(fd, 0) != 0 ||
        landlock_restrict_self(fd, 0) != 0) {
      _exit(kSetup);
    }
    close(fd);
    if (TryReadOpen(in_allowed) != kAllowed) {
      _exit(kOther);
    }
    _exit(TryReadOpen(target));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleReachesFileThroughBindMount) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath covered_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath mount_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string dir = covered_dir.path();
  const std::string mount_point = mount_dir.path();
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));
  const std::string via_mount = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(dir.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, dir,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(via_mount));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleAboveBindMountPointReachesMountContents) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string src = JoinPath(root.path(), "src");
  const std::string covering = JoinPath(root.path(), "covering");
  const std::string mount_point = JoinPath(covering, "mp");
  ASSERT_THAT(mkdir(src.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(covering.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_point.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(src, "f")));
  const std::string via_mount = JoinPath(mount_point, "f");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(src.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, covering,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(TryReadOpen(via_mount));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, RuleOnBindMountRootReachesDisconnectedDirectory) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string src = JoinPath(root.path(), "src");
  const std::string mount_root = JoinPath(src, "a");
  const std::string dir = JoinPath(mount_root, "b");
  const std::string moved_dir = JoinPath(src, "b");
  const std::string mount_point = JoinPath(root.path(), "mp");
  ASSERT_THAT(mkdir(src.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_root.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(dir.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(mount_point.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(dir, "f")));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
    TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                0);
    TEST_PCHECK(mount(mount_root.c_str(), mount_point.c_str(), nullptr, MS_BIND,
                      nullptr) == 0);

    int dirfd = open(JoinPath(mount_point, "b").c_str(),
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    TEST_PCHECK(dirfd >= 0);
    TEST_PCHECK(rename(dir.c_str(), moved_dir.c_str()) == 0);

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, mount_root,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    _exit(ClassifyFs(openat(dirfd, "f", O_RDONLY)));
  }));
  const int want = LandlockErratumFixed(3) ? kAllowed : kDenied;
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == want)
      << "exit status " << status;
}

TEST(LandlockV1Test, RelativePathsAreEnforced) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed_abs = JoinPath(root.path(), "a");
  const std::string outside_abs = JoinPath(root.path(), "b");
  ASSERT_THAT(mkdir(allowed_abs.c_str(), 0755), SyscallSucceeds());
  ASSERT_THAT(mkdir(outside_abs.c_str(), 0755), SyscallSucceeds());
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(allowed_abs, "f")));
  ASSERT_NO_FATAL_FAILURE(CreateFile(JoinPath(outside_abs, "g")));
  static std::string top;
  top = root.path();
  static std::string allowed;
  allowed = allowed_abs;

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    if (chdir(top.c_str()) != 0) {
      _exit(kSetup);
    }
    int outside_dirfd = open("b", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (outside_dirfd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    if (TryReadOpen("a/f") != kAllowed) {
      _exit(kOther);
    }
    int denied = open("b/g", O_RDONLY);
    if (denied >= 0 || errno != EACCES) {
      _exit(kOther);
    }
    _exit(ClassifyFs(openat(outside_dirfd, "g", O_RDONLY)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(root.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE, allowed,
                  LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteOutsideAllowedTreeDeniedWhenOnlyReadFileHandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const TempPath outside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(root.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = outside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, allowed,
                  LANDLOCK_ACCESS_FS_READ_FILE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteInsideAllowedTreeDeniedWithoutReadFile) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                  allowed, LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteInsideAllowedTreeAllowedWhenReadFileUnhandled) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE, allowed,
                  LANDLOCK_ACCESS_FS_EXECUTE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ExecuteInsideAllowedTreeDeniedWithoutExecuteGrant) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath inside = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(allowed_dir.path(), "#!/nonexistent\n", 0755));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = inside.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
                  allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    char* const argv[] = {const_cast<char*>(target.c_str()), nullptr};
    char* const envp[] = {nullptr};
    execve(target.c_str(), argv, envp);
    _exit(errno == EACCES ? kDenied : kOther);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MakeRegOutsideAllowedTreeDenied) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath root = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed_dir =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDirIn(root.path()));
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(root.path(), "new_file");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    int fd = open(target.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, MakeRegInsideAllowedTreeAllowed) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath allowed_dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string allowed = allowed_dir.path();
  static std::string target;
  target = JoinPath(allowed_dir.path(), "new_file");

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_MAKE_REG, allowed,
                  LANDLOCK_ACCESS_FS_MAKE_REG);
    int fd = open(target.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd >= 0) {
      close(fd);
    }
    _exit(ClassifyFs(fd));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, MagicLinkReopenCannotWidenAccess) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  static std::string allowed;
  allowed = dir.path();
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  allowed, LANDLOCK_ACCESS_FS_READ_FILE);
    int fd = open(target.c_str(), O_RDONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    const std::string proc_path = "/proc/self/fd/" + std::to_string(fd);
    int ro = open(proc_path.c_str(), O_RDONLY);
    if (ro < 0) {
      _exit(kOther);
    }
    close(ro);
    _exit(ClassifyFs(open(proc_path.c_str(), O_RDWR)));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kDenied)
      << "exit status " << status;
}

TEST(LandlockV1Test, PipeIsReopenableThroughProcFd) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fds[2];
    if (pipe(fds) != 0) {
      _exit(kSetup);
    }
    EnforceOrDie(CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                               LANDLOCK_ACCESS_FS_WRITE_FILE));
    _exit(TryReadOpen("/proc/self/fd/" + std::to_string(fds[0])));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, ProcFdReopenOfPipeIsExempt) {
  SKIP_IF(LandlockAbiVersion() < 1);
  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fds[2];
    if (pipe(fds) != 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    const std::string path = "/proc/self/fd/" + std::to_string(fds[0]);
    _exit(TryReadOpen(path));
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, TruncateUnrestrictedByV1Domain) {
  SKIP_IF(LandlockAbiVersion() < 1);

  TempPath file = ASSERT_NO_ERRNO_AND_VALUE(
      TempPath::CreateFileWith(GetAbsoluteTestTmpdir(), "content", 0666));
  static std::string target;
  target = file.path();

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([] {
    int fd = open(target.c_str(), O_WRONLY);
    if (fd < 0) {
      _exit(kSetup);
    }
    ApplyFsPolicyDenyingAll(kFsAccessV1);
    if (truncate(target.c_str(), 3) != 0) {
      _exit(errno == EACCES ? kDenied : kOther);
    }
    if (ftruncate(fd, 0) != 0) {
      _exit(kOther);
    }
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayCopyUpAllowedByRuleOnMergedDir) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string source = JoinPath(lower, "victim");
  const std::string target = JoinPath(merged, "victim");
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

    int lower_fd = open(source.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(lower_fd >= 0);
    TEST_PCHECK(close(lower_fd) == 0);

    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kUnsupported);
    }

    ApplyFsPolicy(kFsAccessV1, merged, kFsAccessV1);
    _exit(ClassifyFs(open(target.c_str(), O_WRONLY)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

TEST(LandlockV1Test, OverlayLayerFilesAndMergedFilesAreDifferent) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string data =
      "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work;
  const std::string lower_fl = JoinPath(lower, "fl");
  const std::string merged_fl = JoinPath(merged, "fl");
  const std::string upper_fu = JoinPath(upper, "fu");
  const std::string merged_fu = JoinPath(merged, "fu");

  auto check = [&](const std::string& rule_dir, const std::string& target) {
    return InForkedProcess([&] {
      TEST_PCHECK(unshare(CLONE_NEWNS) == 0);
      TEST_PCHECK(mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) ==
                  0);
      TEST_PCHECK(mount("tmpfs", root.c_str(), "tmpfs", 0, nullptr) == 0);
      TEST_PCHECK(mkdir(lower.c_str(), 0777) == 0);
      TEST_PCHECK(mkdir(upper.c_str(), 0777) == 0);
      TEST_PCHECK(mkdir(work.c_str(), 0777) == 0);
      TEST_PCHECK(mkdir(merged.c_str(), 0777) == 0);
      int fd = open(lower_fl.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
      TEST_PCHECK(fd >= 0);
      TEST_PCHECK(close(fd) == 0);
      if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
        _exit(kUnsupported);
      }
      fd = open(merged_fu.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
      TEST_PCHECK(fd >= 0);
      TEST_PCHECK(close(fd) == 0);
      ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE, rule_dir,
                    LANDLOCK_ACCESS_FS_READ_FILE);
      _exit(TryReadOpen(target));
    });
  };
  struct Leg {
    const std::string& rule_dir;
    const std::string& target;
    ChildResult want;
    const char* what;
  };
  const Leg legs[] = {
      {merged, merged_fl, kAllowed,
       "merged rule reaches the merged lower-backed file"},
      {merged, merged_fu, kAllowed,
       "merged rule reaches the merged upper-backed file"},
      {lower, lower_fl, kAllowed, "lower rule reaches the lower file"},
      {merged, lower_fl, kDenied, "merged rule must not reach the lower file"},
      {merged, upper_fu, kDenied, "merged rule must not reach the upper file"},
      {lower, merged_fl, kDenied, "lower rule must not reach the merged file"},
      {upper, merged_fu, kDenied, "upper rule must not reach the merged file"},
  };
  for (const Leg& leg : legs) {
    int status = ASSERT_NO_ERRNO_AND_VALUE(check(leg.rule_dir, leg.target));
    SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
    EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == leg.want)
        << leg.what << ": exit status " << status;
  }
}

TEST(LandlockV1Test, OverlayRuleOnLowerFileSurvivesCopyUp) {
  SKIP_IF(LandlockAbiVersion() < 1);
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

  const TempPath base = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const std::string root = base.path();
  const std::string lower = JoinPath(root, "lower");
  const std::string upper = JoinPath(root, "upper");
  const std::string work = JoinPath(root, "work");
  const std::string merged = JoinPath(root, "merged");
  const std::string source = JoinPath(lower, "victim");
  const std::string target = JoinPath(merged, "victim");
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

    int lower_fd = open(source.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0644);
    TEST_PCHECK(lower_fd >= 0);
    TEST_PCHECK(close(lower_fd) == 0);

    if (mount("overlay", merged.c_str(), "overlay", 0, data.c_str()) != 0) {
      _exit(kUnsupported);
    }

    ApplyFsPolicy(LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                  target,
                  LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);

    int writable = open(target.c_str(), O_WRONLY);
    if (writable < 0) {
      _exit(ClassifyFs(writable));
    }
    TEST_PCHECK(close(writable) == 0);

    _exit(ClassifyFs(open(target.c_str(), O_RDONLY)));
  }));
  SKIP_IF(WIFEXITED(status) && WEXITSTATUS(status) == kUnsupported);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
