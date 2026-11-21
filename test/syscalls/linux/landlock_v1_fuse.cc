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

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include "gtest/gtest.h"
#include "test/syscalls/linux/landlock_util.h"
#include "test/util/fs_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

TEST(LandlockV1FuseTest, RulesOnFilesSurviveCheckpoint) {
  SKIP_IF(LandlockAbiVersion() < 1);

  const TempPath dir = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
  const TempPath allowed =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));
  const TempPath denied =
      ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateFileIn(dir.path()));

  int status = ASSERT_NO_ERRNO_AND_VALUE(InForkedProcess([&] {
    int ruleset = CreateRuleset(LANDLOCK_ACCESS_FS_READ_FILE |
                                LANDLOCK_ACCESS_FS_READ_DIR);
    AddPathRule(ruleset, allowed.path(), LANDLOCK_ACCESS_FS_READ_FILE);
    AddPathRule(ruleset, dir.path(), LANDLOCK_ACCESS_FS_READ_DIR);
    EnforceOrDie(ruleset);
    MaybeSave();
    if (TryReadOpen(allowed.path()) != kAllowed ||
        TryReadOpen(denied.path()) != kDenied) {
      _exit(kOther);
    }
    int fd = open(dir.path().c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
      _exit(kOther);
    }
    close(fd);
    _exit(kAllowed);
  }));
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == kAllowed)
      << "exit status " << status;
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
