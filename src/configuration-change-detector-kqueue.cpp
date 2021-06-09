// Copyright (C) 2020  Matthew "strager" Glazar
// See end of file for extended copyright information.

#include <quick-lint-js/have.h>

#if QLJS_HAVE_KQUEUE

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <optional>
#include <quick-lint-js/assert.h>
#include <quick-lint-js/configuration-change-detector.h>
#include <quick-lint-js/file-canonical.h>
#include <quick-lint-js/file-handle.h>
#include <quick-lint-js/file.h>
#include <quick-lint-js/narrow-cast.h>
#include <quick-lint-js/unreachable.h>
#include <quick-lint-js/utf-16.h>
#include <string>
#include <string_view>
#include <sys/event.h>
#include <sys/time.h>
#include <unordered_map>
#include <utility>
#include <vector>

// @@@ document caveats:
// [_] symlinks
// @@@ add a nuke feature to clear caches and reload all configs. or just have
// the client restart the LSP server...

namespace quick_lint_js {
configuration_filesystem_kqueue::configuration_filesystem_kqueue(
    posix_fd_file_ref kqueue_fd)
    : kqueue_fd_(kqueue_fd) {}

canonical_path_result configuration_filesystem_kqueue::canonicalize_path(
    const std::string& path) {
  return quick_lint_js::canonicalize_path(path);
}

void configuration_filesystem_kqueue::enter_directory(
    const canonical_path& directory) {
  this->watch_directory(directory);
}

read_file_result configuration_filesystem_kqueue::read_file(
    const canonical_path& directory, std::string_view file_name) {
  canonical_path config_path = directory;
  config_path.append_component(file_name);

  // TODO(strager): Use openat. We opened a directory fd in enter_directory.
  int file_fd = ::open(config_path.c_str(), O_RDONLY);
  if (file_fd == -1) {
    int error = errno;
    read_file_result result = read_file_result::failure(
        std::string("failed to open ") + config_path.c_str() + ": " +
        std::strerror(error));
    result.is_not_found_error = error == ENOENT;
    return result;
  }

  posix_fd_file file(file_fd);
  this->watch_file(file.ref());
  read_file_result result =
      quick_lint_js::read_file(config_path.c_str(), file.ref());
  if (!result.ok()) {
    return result;
  }

  this->watched_directories_.emplace_back(
      std::move(file));  // @@@ put this in the watch
  //@@@ watch.watched_file_fd = std::move(file);
  return result;
}

void configuration_filesystem_kqueue::process_changes(
    const struct kevent* events, int event_count,
    configuration_change_detector_impl& detector,
    std::vector<configuration_change>* out_changes) {
  (void)events;
  (void)event_count;
  detector.refresh(out_changes);
}

void configuration_filesystem_kqueue::watch_directory(
    const canonical_path& directory) {
  // @@@ don't duplicate watches
  int directory_fd = ::open(directory.c_str(), O_RDONLY | O_EVTONLY);
  if (directory_fd == -1) {
    QLJS_UNIMPLEMENTED();  // @@@
  }
  posix_fd_file dir(directory_fd);
  struct kevent change;
  EV_SET(
      /*kev=*/&change,
      /*ident=*/dir.get(),
      /*filter=*/EVFILT_VNODE,
      /*flags=*/EV_ADD | EV_ENABLE,
      // @@@ audit
      /*fflags=*/NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB |
          NOTE_LINK | NOTE_RENAME | NOTE_REVOKE | NOTE_FUNLOCK,
      /*data=*/0,
      /*udata=*/0);

  // @@@ should we use receipts?
  struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
  int kqueue_rc = ::kevent(
      /*fd=*/this->kqueue_fd_.get(),
      /*changelist=*/&change,
      /*nchanges=*/1,
      /*eventlist=*/nullptr,
      /*nevents=*/0,
      /*timeout=*/&timeout);
  if (kqueue_rc == -1) {
    QLJS_UNIMPLEMENTED();  // @@@
  }
  this->watched_directories_.emplace_back(std::move(dir));
}

void configuration_filesystem_kqueue::watch_file(posix_fd_file_ref file) {
  struct kevent change;
  EV_SET(
      /*kev=*/&change,
      /*ident=*/file.get(),
      /*filter=*/EVFILT_VNODE,
      /*flags=*/EV_ADD | EV_ENABLE,
      // @@@ audit
      /*fflags=*/NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB |
          NOTE_LINK | NOTE_RENAME | NOTE_REVOKE | NOTE_FUNLOCK,
      /*data=*/0,
      /*udata=*/0);
  // @@@ should we use receipts?
  struct timespec timeout = {.tv_sec = 0, .tv_nsec = 0};
  int kqueue_rc = ::kevent(
      /*fd=*/this->kqueue_fd_.get(),
      /*changelist=*/&change,
      /*nchanges=*/1,
      /*eventlist=*/nullptr,
      /*nevents=*/0,
      /*timeout=*/&timeout);
  if (kqueue_rc == -1) {
    QLJS_UNIMPLEMENTED();  // @@@
  }
}
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
