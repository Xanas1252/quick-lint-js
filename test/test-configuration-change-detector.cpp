// Copyright (C) 2020  Matthew "strager" Glazar
// See end of file for extended copyright information.

#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <quick-lint-js/char8.h>
#include <quick-lint-js/configuration-change-detector.h>
#include <quick-lint-js/file-canonical.h>
#include <quick-lint-js/file-matcher.h>
#include <quick-lint-js/file-path.h>
#include <quick-lint-js/file.h>
#include <quick-lint-js/have.h>
#include <quick-lint-js/temporary-directory.h>
#include <quick-lint-js/utf-16.h>
#include <quick-lint-js/warning.h>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if QLJS_HAVE_KQUEUE
#include <sys/event.h>
#endif

#if QLJS_HAVE_POLL
#include <poll.h>
#endif

// NOTE(strager): Many of these tests assume that there is no
// quick-lint-js.config file in /tmp or in /.

using ::testing::ElementsAre;
using ::testing::IsEmpty;
using namespace std::literals::string_view_literals;

namespace quick_lint_js {
// @@@
// [x] add new file
// [x] add shadowing file in same dir
// [x] add shadowing file in child dir
// [x] delete in-use file; fall back to default
// [x] delete in-use file; fall back to other in same dir
// [x] delete in-use file; fall back to other in ancestor dir
// [#] delete not-in-use file
// [x] rename directory
// [x] rename away config file
// [x] rename quick-lint-js.config -> .quick-lint-js.config
// [x] rename .quick-lint-js.config -> quick-lint-js.config
// [x] atomic-move onto config file
// [x] modify config file
// [x] .js file doesn't exist yet
// [_] virtual config files
// [#] delete directory
// [x] no change after multiple writes to .config (content checking)
// [x] no change after .config atomic move (content checking)
// [x] no change after .config move then move back (content checking)
// [_] unwatch .js file

namespace {
void move_file(const std::string& from, const std::string& to);

// @@@ omg...
struct configuration_change_detector {
#if QLJS_HAVE_INOTIFY
  explicit configuration_change_detector() : impl_(&this->fs_) {}
#elif QLJS_HAVE_KQUEUE
  explicit configuration_change_detector()
      : kqueue_fd(::kqueue()), fs_(this->kqueue_fd.ref()), impl_(&this->fs_) {
    QLJS_ASSERT(this->kqueue_fd.valid());
  }
#elif defined(_WIN32)
  explicit configuration_change_detector() : impl_(&this->fs_) {}
#endif

  configuration* get_config_for_file(const std::string& path) {
    return this->impl_.get_config_for_file(path);
  }

  std::vector<configuration_change> poll_and_process_changes() {
#if QLJS_HAVE_INOTIFY
    std::vector<::pollfd> pollfds{this->fs_.get_notify_poll_fd()};
    int poll_rc = ::poll(pollfds.data(), pollfds.size(), 0);
    if (poll_rc == -1) {
      ADD_FAILURE() << "poll failed: " << std::strerror(errno);
      return {};
    }
    bool timed_out = poll_rc == 0;

    std::vector<configuration_change> changes;
    this->fs_.process_changes(this->impl_, &changes);

    if (timed_out) {
      EXPECT_THAT(changes, IsEmpty())
          << "no filesystem notifications happened, but changes were detected";
    } else {
      EXPECT_EQ(pollfds[0].revents & POLLIN, POLLIN);
      // NOTE(strager): We cannot assert that at least one change happened,
      // because filesystem notifications might be spurious.
    }

    return changes;
#elif QLJS_HAVE_KQUEUE
    std::vector<struct kevent> events;
    events.resize(100);
    struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
    int kqueue_rc = ::kevent(
        /*fd=*/this->kqueue_fd.get(),
        /*changelist=*/nullptr,
        /*nchanges=*/0,
        /*eventlist=*/events.data(),
        /*nevents=*/narrow_cast<int>(events.size()),
        /*timeout=*/&timeout);
    if (kqueue_rc == -1) {
      ADD_FAILURE() << "kqueue failed: " << std::strerror(errno);
      return {};
    }
    bool timed_out = kqueue_rc == 0;

    std::vector<configuration_change> config_changes;
    this->fs_.process_changes(events.data(), kqueue_rc, this->impl_,
                              &config_changes);

    if (timed_out) {
      EXPECT_THAT(config_changes, IsEmpty())
          << "no filesystem notifications happened, but changes were detected";
    } else {
      for (int i = 0; i < kqueue_rc; ++i) {
        EXPECT_FALSE(events[i].flags & EV_ERROR)
            << std::strerror(events[i].data);
      }
      // NOTE(strager): We cannot assert that at least one change happened,
      // because filesystem notifications might be spurious.
    }

    return config_changes;
#elif defined(_WIN32)
    // HACK(strager): A non-zero timeout is necessary because
    // configuration_filesystem_win32 is implemented using asynchronous I/O
    // (with an I/O Completion Port pumped by a background thread).
    DWORD timeoutMilliseconds = 100;
    DWORD rc = ::WaitForSingleObject(this->fs_.get_change_event().get(),
                                     timeoutMilliseconds);
    if (rc == WAIT_FAILED) {
      ADD_FAILURE() << "WaitForSingleObject failed: " << ::GetLastError();
      return {};
    }
    bool timed_out = rc == WAIT_TIMEOUT;

    std::vector<configuration_change> changes;
    this->fs_.process_changes(this->impl_, &changes);

    if (timed_out) {
      EXPECT_THAT(changes, IsEmpty())
          << "no filesystem notifications happened, but changes were detected";
    } else {
      EXPECT_EQ(rc, WAIT_OBJECT_0);
      // NOTE(strager): We cannot assert that at least one change happened,
      // because filesystem notifications might be spurious.
    }

    return changes;
#else
#error "Unsupported platform"
#endif
  }

#if QLJS_HAVE_INOTIFY
  configuration_filesystem_inotify fs_;
#elif QLJS_HAVE_KQUEUE
  posix_fd_file kqueue_fd;
  configuration_filesystem_kqueue fs_;
#elif defined(_WIN32)
  configuration_filesystem_win32 fs_;
#endif
  configuration_change_detector_impl impl_;
};

class test_configuration_change_detector : public ::testing::Test {
 private:
  std::vector<std::string> temporary_directories_;

 public:
  std::string make_temporary_directory() {
    std::string temp_dir = quick_lint_js::make_temporary_directory();
    this->temporary_directories_.emplace_back(temp_dir);
    return temp_dir;
  }

 protected:
  void TearDown() override {
    for (const std::string& temp_dir : this->temporary_directories_) {
      delete_directory_recursive(temp_dir);
    }
  }
};

// @@@ inline
std::vector<configuration_change> poll_and_process_changes(
    configuration_change_detector& detector) {
  return detector.poll_and_process_changes();
}

TEST_F(test_configuration_change_detector, no_config_is_not_found_initially) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");

  configuration_change_detector detector;
  configuration* config = detector.get_config_for_file(js_file);
  EXPECT_EQ(config->config_file_path(), std::nullopt);
}

TEST_F(test_configuration_change_detector,
       config_is_found_initially_in_same_dir) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    write_file(js_file, u8"");
    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    configuration_change_detector detector;
    configuration* config = detector.get_config_for_file(js_file);
    EXPECT_SAME_FILE(config->config_file_path(), config_file);
  }
}

TEST_F(test_configuration_change_detector,
       config_is_found_initially_in_same_dir_if_file_doesnt_exist) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    configuration_change_detector detector;
    configuration* config = detector.get_config_for_file(js_file);
    EXPECT_SAME_FILE(config->config_file_path(), config_file);
  }
}

#if 0  // @@@
TEST_F(test_configuration_change_detector,
       fake_config_is_found_initially_in_same_dir) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    write_file(js_file, u8"");
    std::string config_file = project_dir + "/" + config_file_name;

    struct fake_filesystem : public thingy {
      void enter_directory(const canonical_path&);

      // @@@ we should avoid copying for virtual files
      file_read_result read_file(std::string_view);
    };
    configuration_change_detector detector;
    padded_string config_file_content(u8""_sv);
    detector.assume_file(config_file, &config_file_content);

    const configuration_watch& watch = detector.watch_for_file(js_file);
    EXPECT_SAME_FILE(watch.config_file_path, config_file);
  }
}
#endif

TEST_F(test_configuration_change_detector,
       config_found_initially_is_not_a_detected_change) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    write_file(js_file, u8"");
    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    EXPECT_THAT(changes, IsEmpty());
  }
}

TEST_F(test_configuration_change_detector,
       config_is_found_initially_in_parent_dir) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    create_directory(project_dir + "/dir");
    std::string js_file = project_dir + "/dir/hello.js";
    write_file(js_file, u8"");
    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    configuration_change_detector detector;
    configuration* config = detector.get_config_for_file(js_file);
    EXPECT_SAME_FILE(config->config_file_path(), config_file);
  }
}

TEST_F(test_configuration_change_detector,
       config_is_found_initially_in_parent_dir_if_dir_doesnt_exist) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    create_directory(project_dir + "/dir");
    std::string js_file = project_dir + "/dir/subdir/hello.js";
    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    configuration_change_detector detector;
    configuration* config = detector.get_config_for_file(js_file);
    EXPECT_SAME_FILE(config->config_file_path(), config_file);
  }
}

TEST_F(test_configuration_change_detector,
       creating_config_in_same_dir_is_detected) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    write_file(js_file, u8"");

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    ASSERT_THAT(changes, ElementsAre(::testing::_));
    EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
    EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
  }
}

TEST_F(test_configuration_change_detector,
       creating_config_in_same_dir_is_detected_if_file_doesnt_exit) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    ASSERT_THAT(changes, ElementsAre(::testing::_));
    EXPECT_THAT(*changes[0].watched_path, ::testing::HasSubstr("hello.js"));
    EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
  }
}

TEST_F(test_configuration_change_detector,
       creating_config_in_same_dir_as_many_watched_files_is_detected) {
  std::string project_dir = this->make_temporary_directory();

  std::unordered_set<std::string> js_files;
  for (int i = 0; i < 10; ++i) {
    std::string js_file = project_dir + "/hello" + std::to_string(i) + ".js";
    write_file(js_file, u8"");
    auto [_iterator, inserted] = js_files.insert(std::move(js_file));
    ASSERT_TRUE(inserted) << "duplicate js_file: " << js_file;
  }

  configuration_change_detector detector;
  for (const std::string& js_file : js_files) {
    detector.get_config_for_file(js_file);
  }

  std::string config_file = project_dir + "/quick-lint-js.config";
  write_file(config_file, u8"{}");

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  std::unordered_set<std::string> unconfigured_js_files = js_files;
  for (const configuration_change& change : changes) {
    SCOPED_TRACE(*change.watched_path);
    EXPECT_EQ(js_files.count(*change.watched_path), 1)
        << "change should report a watched file";
    EXPECT_EQ(unconfigured_js_files.erase(*change.watched_path), 1)
        << "change should report no duplicate watched files";
    EXPECT_SAME_FILE(change.config->config_file_path(), config_file);
  }
  EXPECT_THAT(unconfigured_js_files, IsEmpty())
      << "all watched files should have a config";
}

TEST_F(test_configuration_change_detector,
       creating_config_in_parent_dir_is_detected) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    create_directory(project_dir + "/dir");
    std::string js_file = project_dir + "/dir/hello.js";
    write_file(js_file, u8"");

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    ASSERT_THAT(changes, ElementsAre(::testing::_));
    EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
    EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
  }
}

TEST_F(test_configuration_change_detector,
       creating_shadowing_config_in_child_dir_is_detected) {
  for (const char* outer_config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    for (const char* inner_config_file_name :
         {"quick-lint-js.config", ".quick-lint-js.config"}) {
      SCOPED_TRACE(outer_config_file_name);
      SCOPED_TRACE(inner_config_file_name);

      std::string project_dir = this->make_temporary_directory();
      create_directory(project_dir + "/dir");
      std::string js_file = project_dir + "/dir/hello.js";
      write_file(js_file, u8"");
      std::string outer_config_file =
          project_dir + "/" + outer_config_file_name;
      write_file(outer_config_file, u8"{}");

      configuration_change_detector detector;
      detector.get_config_for_file(js_file);

      std::string inner_config_file =
          project_dir + "/dir/" + inner_config_file_name;
      write_file(inner_config_file, u8"{}");

      std::vector<configuration_change> changes =
          poll_and_process_changes(detector);
      ASSERT_THAT(changes, ElementsAre(::testing::_));
      EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
      EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                       inner_config_file);
    }
  }
}

TEST_F(test_configuration_change_detector,
       creating_shadowing_config_in_same_dir_is_detected) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string secondary_config_file = project_dir + "/.quick-lint-js.config";
  write_file(secondary_config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  std::string primary_config_file = project_dir + "/quick-lint-js.config";
  write_file(primary_config_file, u8"{}");

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
  EXPECT_SAME_FILE(changes[0].config->config_file_path(), primary_config_file);
}

TEST_F(test_configuration_change_detector,
       deleting_config_in_same_dir_is_detected) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    write_file(js_file, u8"");
    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    EXPECT_EQ(std::remove(config_file.c_str()), 0)
        << "failed to delete " << config_file << ": " << std::strerror(errno);

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    ASSERT_THAT(changes, ElementsAre(::testing::_));
    EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
    EXPECT_EQ(changes[0].config->config_file_path(), std::nullopt);
  }
}

TEST_F(test_configuration_change_detector,
       deleting_shadowing_config_in_same_dir_is_detected) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string primary_config_file = project_dir + "/quick-lint-js.config";
  write_file(primary_config_file, u8"{}");
  std::string secondary_config_file = project_dir + "/.quick-lint-js.config";
  write_file(secondary_config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  EXPECT_EQ(std::remove(primary_config_file.c_str()), 0)
      << "failed to delete " << primary_config_file << ": "
      << std::strerror(errno);

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
  EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                   secondary_config_file);
}

TEST_F(test_configuration_change_detector,
       deleting_shadowing_config_in_child_dir_is_detected) {
  for (const char* outer_config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    for (const char* inner_config_file_name :
         {"quick-lint-js.config", ".quick-lint-js.config"}) {
      SCOPED_TRACE(outer_config_file_name);
      SCOPED_TRACE(inner_config_file_name);

      std::string project_dir = this->make_temporary_directory();
      create_directory(project_dir + "/dir");
      std::string js_file = project_dir + "/dir/hello.js";
      write_file(js_file, u8"");
      std::string outer_config_file =
          project_dir + "/" + outer_config_file_name;
      write_file(outer_config_file, u8"{}");
      std::string inner_config_file =
          project_dir + "/dir/" + inner_config_file_name;
      write_file(inner_config_file, u8"{}");

      configuration_change_detector detector;
      detector.get_config_for_file(js_file);

      EXPECT_EQ(std::remove(inner_config_file.c_str()), 0)
          << "failed to delete " << inner_config_file << ": "
          << std::strerror(errno);

      std::vector<configuration_change> changes =
          poll_and_process_changes(detector);
      ASSERT_THAT(changes, ElementsAre(::testing::_));
      EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
      EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                       outer_config_file);
    }
  }
}

TEST_F(test_configuration_change_detector,
       moving_config_away_in_same_dir_is_detected) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    write_file(js_file, u8"");
    std::string config_file = project_dir + "/" + config_file_name;
    write_file(config_file, u8"{}");

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    move_file(config_file, (project_dir + "/moved.config"));

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    ASSERT_THAT(changes, ElementsAre(::testing::_));
    EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
    EXPECT_EQ(changes[0].config->config_file_path(), std::nullopt);
  }
}

TEST_F(test_configuration_change_detector,
       moving_shadowing_config_away_in_same_dir_is_detected) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string primary_config_file = project_dir + "/quick-lint-js.config";
  write_file(primary_config_file, u8"{}");
  std::string secondary_config_file = project_dir + "/.quick-lint-js.config";
  write_file(secondary_config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file(primary_config_file, (project_dir + "/moved.config"));

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
  EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                   secondary_config_file);
}

TEST_F(test_configuration_change_detector,
       moving_shadowing_config_away_in_child_dir_is_detected) {
  for (const char* outer_config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    for (const char* inner_config_file_name :
         {"quick-lint-js.config", ".quick-lint-js.config"}) {
      SCOPED_TRACE(outer_config_file_name);
      SCOPED_TRACE(inner_config_file_name);

      std::string project_dir = this->make_temporary_directory();
      create_directory(project_dir + "/dir");
      std::string js_file = project_dir + "/dir/hello.js";
      write_file(js_file, u8"");
      std::string outer_config_file =
          project_dir + "/" + outer_config_file_name;
      write_file(outer_config_file, u8"{}");
      std::string inner_config_file =
          project_dir + "/dir/" + inner_config_file_name;
      write_file(inner_config_file, u8"{}");

      configuration_change_detector detector;
      detector.get_config_for_file(js_file);

      move_file(inner_config_file, (project_dir + "/dir/moved.config"));

      std::vector<configuration_change> changes =
          poll_and_process_changes(detector);
      ASSERT_THAT(changes, ElementsAre(::testing::_));
      EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
      EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                       outer_config_file);
    }
  }
}

TEST_F(test_configuration_change_detector,
       moving_config_into_same_dir_is_detected) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    std::string js_file = project_dir + "/hello.js";
    write_file(js_file, u8"");
    std::string temp_config_file = project_dir + "/temp.config";
    write_file(temp_config_file, u8"{}");
    std::string renamed_config_file = project_dir + "/" + config_file_name;

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    move_file(temp_config_file, renamed_config_file);

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    ASSERT_THAT(changes, ElementsAre(::testing::_));
    EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
    EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                     renamed_config_file);
  }
}

TEST_F(test_configuration_change_detector,
       moving_config_into_parent_dir_is_detected) {
  for (const char* config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    SCOPED_TRACE(config_file_name);

    std::string project_dir = this->make_temporary_directory();
    create_directory(project_dir + "/dir");
    std::string js_file = project_dir + "/dir/hello.js";
    write_file(js_file, u8"");
    std::string temp_config_file = project_dir + "/temp.config";
    write_file(temp_config_file, u8"{}");
    std::string renamed_config_file = project_dir + "/" + config_file_name;

    configuration_change_detector detector;
    detector.get_config_for_file(js_file);

    move_file(temp_config_file, renamed_config_file);

    std::vector<configuration_change> changes =
        poll_and_process_changes(detector);
    ASSERT_THAT(changes, ElementsAre(::testing::_));
    EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
    EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                     renamed_config_file);
  }
}

TEST_F(test_configuration_change_detector,
       moving_shadowing_config_into_child_dir_is_detected) {
  for (const char* outer_config_file_name :
       {"quick-lint-js.config", ".quick-lint-js.config"}) {
    for (const char* inner_config_file_name :
         {"quick-lint-js.config", ".quick-lint-js.config"}) {
      SCOPED_TRACE(outer_config_file_name);
      SCOPED_TRACE(inner_config_file_name);

      std::string project_dir = this->make_temporary_directory();
      create_directory(project_dir + "/dir");
      std::string js_file = project_dir + "/dir/hello.js";
      write_file(js_file, u8"");
      std::string outer_config_file =
          project_dir + "/" + outer_config_file_name;
      write_file(outer_config_file, u8"{}");
      std::string temp_config_file = project_dir + "/dir/temp.config";
      write_file(temp_config_file, u8"{}");
      std::string inner_config_file =
          project_dir + "/dir/" + inner_config_file_name;

      configuration_change_detector detector;
      detector.get_config_for_file(js_file);

      move_file(temp_config_file, inner_config_file);

      std::vector<configuration_change> changes =
          poll_and_process_changes(detector);
      ASSERT_THAT(changes, ElementsAre(::testing::_));
      EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
      EXPECT_SAME_FILE(changes[0].config->config_file_path(),
                       inner_config_file);
    }
  }
}

TEST_F(test_configuration_change_detector,
       moving_shadowing_config_into_same_dir_is_detected) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string secondary_config_file = project_dir + "/.quick-lint-js.config";
  write_file(secondary_config_file, u8"{}");
  std::string temp_config_file = project_dir + "/temp.config";
  write_file(temp_config_file, u8"{}");
  std::string primary_config_file = project_dir + "/quick-lint-js.config";

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file(temp_config_file, primary_config_file);

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
  EXPECT_SAME_FILE(changes[0].config->config_file_path(), primary_config_file);
}

TEST_F(test_configuration_change_detector,
       moving_directory_containing_file_and_config_unlinks_config) {
  std::string project_dir = this->make_temporary_directory();
  create_directory(project_dir + "/olddir");
  std::string js_file = project_dir + "/olddir/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/olddir/quick-lint-js.config";
  write_file(config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file((project_dir + "/olddir"), (project_dir + "/newdir"));

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_THAT(*changes[0].watched_path, ::testing::HasSubstr("hello.js"));
  EXPECT_THAT(*changes[0].watched_path, ::testing::HasSubstr("olddir"));
  EXPECT_EQ(changes[0].config->config_file_path(), std::nullopt)
      << "config should be removed";
}

TEST_F(test_configuration_change_detector,
       moving_ancestor_directory_containing_file_and_config_unlinks_config) {
  std::string project_dir = this->make_temporary_directory();
  create_directory(project_dir + "/olddir");
  create_directory(project_dir + "/olddir/subdir");
  std::string js_file = project_dir + "/olddir/subdir/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/olddir/subdir/quick-lint-js.config";
  write_file(config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file((project_dir + "/olddir"), (project_dir + "/newdir"));

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_THAT(*changes[0].watched_path, ::testing::HasSubstr("hello.js"));
  EXPECT_THAT(*changes[0].watched_path, ::testing::HasSubstr("olddir"));
  EXPECT_EQ(changes[0].config->config_file_path(), std::nullopt)
      << "config should be removed";
}

TEST_F(test_configuration_change_detector,
       moving_directory_containing_file_keeps_config) {
  std::string project_dir = this->make_temporary_directory();
  create_directory(project_dir + "/olddir");
  std::string js_file = project_dir + "/olddir/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/quick-lint-js.config";
  write_file(config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file((project_dir + "/olddir"), (project_dir + "/newdir"));

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  EXPECT_THAT(changes, IsEmpty());
}

TEST_F(test_configuration_change_detector, moving_file_keeps_config) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/oldfile.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/quick-lint-js.config";
  write_file(config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file((project_dir + "/oldfile.js"), (project_dir + "/newfile.js"));

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  EXPECT_THAT(changes, IsEmpty());
}

TEST_F(test_configuration_change_detector,
       creating_directory_of_watched_file_and_adding_config_is_detected) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/dir/test.js";

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  create_directory(project_dir + "/dir");
  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  EXPECT_THAT(changes, IsEmpty())
      << "creating dir should not change associated config file";

  std::string config_file = project_dir + "/dir/quick-lint-js.config";
  write_file(config_file, u8"{}");

  changes = poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_))
      << "adding config should change associated config file";
  EXPECT_THAT(*changes[0].watched_path, ::testing::HasSubstr("test.js"));
  EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
}

TEST_F(
    test_configuration_change_detector,
    creating_directory_of_watched_file_and_adding_config_is_detected_batched) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/dir/test.js";

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  create_directory(project_dir + "/dir");
  std::string config_file = project_dir + "/dir/quick-lint-js.config";
  write_file(config_file, u8"{}");

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_THAT(*changes[0].watched_path, ::testing::HasSubstr("test.js"));
  EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
}

TEST_F(test_configuration_change_detector,
       rewriting_config_completely_is_detected_as_change) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/quick-lint-js.config";
  write_file(config_file, u8R"({"globals": {"before": true}})");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  write_file(config_file, u8R"({"globals": {"after": true}})");

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
  EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
}

TEST_F(test_configuration_change_detector,
       rewriting_config_partially_is_detected_as_change) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/quick-lint-js.config";
  write_file(config_file, u8R"({"globals": {"before": true}})");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  {
#if defined(_WIN32)
    std::optional<std::wstring> wide_config_file =
        mbstring_to_wstring(config_file.c_str());
    ASSERT_TRUE(wide_config_file.has_value())
        << windows_error_message(::GetLastError());
    windows_handle_file handle(::CreateFileW(
        wide_config_file->c_str(),
        /*dwDesiredAccess=*/GENERIC_READ | GENERIC_WRITE,
        /*dwShareMode=*/FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        /*lpSecurityAttributes=*/nullptr,
        /*dwCreationDisposition=*/OPEN_EXISTING,
        /*dwFlagsAndAttributes=*/FILE_ATTRIBUTE_NORMAL,
        /*hTemplateFile=*/nullptr));
    ASSERT_TRUE(handle.valid()) << windows_error_message(::GetLastError());
#else
    posix_fd_file handle(::open(config_file.c_str(), O_RDWR | O_EXCL));
    ASSERT_TRUE(handle.valid()) << std::strerror(errno);
#endif
    ASSERT_TRUE(handle.seek_to(strlen(u8R"({"globals": {")")))
        << handle.get_last_error_message();
    ASSERT_EQ(handle.write(u8"after_", 6), 6)
        << handle.get_last_error_message();
  }

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
  EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
}

TEST_F(test_configuration_change_detector,
       rewriting_config_back_to_original_keeps_config) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/quick-lint-js.config";
  write_file(config_file, u8R"({"globals": {"a": true}})");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  write_file(config_file, u8R"({"globals": {"b": true}})");
  write_file(config_file, u8R"({"globals": {"a": true}})");

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  EXPECT_THAT(changes, IsEmpty());
}

TEST_F(test_configuration_change_detector,
       renaming_file_over_config_is_detected_as_change) {
  std::string project_dir = this->make_temporary_directory();
  create_directory(project_dir + "/dir");
  std::string js_file = project_dir + "/dir/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/dir/quick-lint-js.config";
  write_file(config_file, u8R"({"globals": {"before": true}})");
  create_directory(project_dir + "/temp");
  std::string new_config_file = project_dir + "/temp/new-config";
  write_file(new_config_file, u8R"({"globals": {"after": true}})");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file(new_config_file, config_file);

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  ASSERT_THAT(changes, ElementsAre(::testing::_));
  EXPECT_SAME_FILE(*changes[0].watched_path, js_file);
  EXPECT_SAME_FILE(changes[0].config->config_file_path(), config_file);
}

TEST_F(test_configuration_change_detector,
       renaming_file_over_config_with_same_content_keeps_config) {
  std::string project_dir = this->make_temporary_directory();
  create_directory(project_dir + "/dir");
  std::string js_file = project_dir + "/dir/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/dir/quick-lint-js.config";
  write_file(config_file, u8"{}");
  create_directory(project_dir + "/temp");
  std::string new_config_file = project_dir + "/temp/new-config";
  write_file(new_config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  move_file(new_config_file, config_file);

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  EXPECT_THAT(changes, IsEmpty());
}

TEST_F(test_configuration_change_detector,
       moving_config_file_away_and_back_keeps_config) {
  std::string project_dir = this->make_temporary_directory();
  std::string js_file = project_dir + "/hello.js";
  write_file(js_file, u8"");
  std::string config_file = project_dir + "/quick-lint-js.config";
  write_file(config_file, u8"{}");

  configuration_change_detector detector;
  detector.get_config_for_file(js_file);

  std::string temp_config_file = project_dir + "/temp.config";
  move_file(config_file, temp_config_file);
  move_file(temp_config_file, config_file);

  std::vector<configuration_change> changes =
      poll_and_process_changes(detector);
  EXPECT_THAT(changes, IsEmpty());
}

void move_file(const std::string& from, const std::string& to) {
  if (std::rename(from.c_str(), to.c_str()) != 0) {
    int error = errno;
#if defined(_WIN32)
    if (error == EEXIST) {
      BOOL ok = ::ReplaceFileW(
          /*lpReplacedFileName=*/std::filesystem::path(to).wstring().c_str(),
          /*lpReplacementFileName=*/
          std::filesystem::path(from).wstring().c_str(),
          /*lpBackupFileName=*/nullptr,
          /*dwReplacemeFlags=*/0,
          /*lpExclude=*/nullptr,
          /*lpReserved=*/nullptr);
      if (!ok) {
        ADD_FAILURE() << "failed to move " << from << " to " << to << ": "
                      << windows_handle_file::get_last_error_message();
      }
      return;
    }
#endif
    ADD_FAILURE() << "failed to move " << from << " to " << to << ": "
                  << std::strerror(error);
  }
}
}
}

// quick-lint-js finds bugs in JavaScript programs.
// Copyright (C) 2020  Matthew Glazar
//
// This file is part of quick-lint-js.
//
// quick-lint-js is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// quick-lint-js is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with quick-lint-js.  If not, see <https://www.gnu.org/licenses/>.
