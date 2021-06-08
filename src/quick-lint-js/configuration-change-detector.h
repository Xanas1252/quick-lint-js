// Copyright (C) 2020  Matthew "strager" Glazar
// See end of file for extended copyright information.

#ifndef QUICK_LINT_JS_CONFIGURATION_CHANGE_DETECTOR_H
#define QUICK_LINT_JS_CONFIGURATION_CHANGE_DETECTOR_H

#include <memory>
#include <optional>
#include <quick-lint-js/configuration.h>
#include <quick-lint-js/file-canonical.h>
#include <quick-lint-js/file-handle.h>
#include <quick-lint-js/have.h>
#include <quick-lint-js/padded-string.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <list> // @@@

#if QLJS_HAVE_KQUEUE
#include <sys/event.h>
#endif

#if QLJS_HAVE_POLL
#include <poll.h>
#endif

#if defined(_WIN32)
#include <Windows.h>
#endif

namespace quick_lint_js {
class configuration_filesystem;
struct read_file_result;

struct configuration_change {
  const std::string* watched_path;  // Never nullptr.
  configuration* config;            // Never nullptr.
};

class configuration_change_detector_impl {
 public:
  explicit configuration_change_detector_impl(configuration_filesystem* fs);

  configuration* get_config_for_file(const std::string& path);

  void refresh(std::vector<configuration_change>* out_changes);

 private:
  struct watched_file {
    explicit watched_file(const std::string& watched_file_path)
        : watched_file_path(watched_file_path) {}

    std::string watched_file_path;
    std::optional<canonical_path> config_file_path;
  };

  struct loaded_config_file {
    padded_string file_content;
    configuration config;
  };

  loaded_config_file* get_config_file(watched_file&, bool* did_change);

  configuration_filesystem* fs_;
  std::vector<watched_file> watches_;
  configuration default_config_;
  std::unordered_map<canonical_path, loaded_config_file> loaded_config_files_;
};

class configuration_filesystem {
 public:
  virtual ~configuration_filesystem() = default;

  virtual canonical_path_result canonicalize_path(const std::string&) = 0;

  virtual void enter_directory(const canonical_path&) = 0;

  // Read a file in the given directory.
  //
  // 'directory' must be equal to the path most recently given to
  // enter_directory.
  virtual read_file_result read_file(const canonical_path& directory,
                                     std::string_view file_name) = 0;
};

#if QLJS_HAVE_INOTIFY
class configuration_filesystem_inotify : public configuration_filesystem {
 public:
  explicit configuration_filesystem_inotify();
  ~configuration_filesystem_inotify();

  canonical_path_result canonicalize_path(const std::string&) override;
  void enter_directory(const canonical_path&) override;
  read_file_result read_file(const canonical_path& directory,
                             std::string_view file_name) override;

  void process_changes(configuration_change_detector_impl&,
                       std::vector<configuration_change>* out_changes);

  ::pollfd get_notify_poll_fd();

 private:
  void watch_directory(const canonical_path&);

  void read_inotify();

#if QLJS_HAVE_INOTIFY
  std::vector<int> watch_descriptors_;
  posix_fd_file inotify_fd_;
#endif
};
#endif

#if QLJS_HAVE_KQUEUE
class configuration_filesystem_kqueue : public configuration_filesystem {
 public:
  explicit configuration_filesystem_kqueue(posix_fd_file_ref kqueue_fd);

  canonical_path_result canonicalize_path(const std::string&) override;
  void enter_directory(const canonical_path&) override;
  read_file_result read_file(const canonical_path& directory,
                             std::string_view file_name) override;

  void process_changes(const struct kevent* events, int event_count,
                       configuration_change_detector_impl&,
                       std::vector<configuration_change>* out_changes);

 private:
  void watch_directory(const canonical_path&);
  void watch_file(posix_fd_file_ref);

  posix_fd_file_ref kqueue_fd_;
  std::vector<posix_fd_file> watched_directories_;
};
#endif

#if defined(_WIN32)
class configuration_filesystem_win32 : public configuration_filesystem {
 public:
  explicit configuration_filesystem_win32();

  ~configuration_filesystem_win32();

  canonical_path_result canonicalize_path(const std::string&) override;
  void enter_directory(const canonical_path&) override;
  read_file_result read_file(const canonical_path& directory,
                             std::string_view file_name) override;

  void process_changes(configuration_change_detector_impl&,
                       std::vector<configuration_change>* out_changes);

 private:
  struct watched_directory {
    explicit watched_directory(HANDLE directory_handle)
        : directory_handle(directory_handle) {}

    windows_handle_file directory_handle;

    OVERLAPPED read_changes_overlapped;
    struct {
      FILE_NOTIFY_INFORMATION info;
      wchar_t name[1024];  // @@@ needed?
    } buffer;

    OVERLAPPED oplock_overlapped;
    HANDLE oplock_wait_handle;
    REQUEST_OPLOCK_OUTPUT_BUFFER oplock_response;
  };

  void watch_directory(const canonical_path&);

  static void on_read_directory_changes(DWORD dwErrorCode,
                                        DWORD dwNumberOfBytesTransfered,
                                        LPOVERLAPPED lpOverlapped) noexcept;

  // @@@ double check: does deque have stable ptrs?
  std::list<watched_directory> watched_directories_;
};
#endif
}

#endif

// quick-lint-js finds bugs in JavaScript programs.
// Copyright (C) 2020  Matthew "strager" Glazar
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
