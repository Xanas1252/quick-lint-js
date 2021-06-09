// Copyright (C) 2020  Matthew "strager" Glazar
// See end of file for extended copyright information.

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <optional>
#include <quick-lint-js/assert.h>
#include <quick-lint-js/configuration-change-detector.h>
#include <quick-lint-js/file-canonical.h>
#include <quick-lint-js/file-handle.h>
#include <quick-lint-js/file.h>
#include <quick-lint-js/have.h>
#include <quick-lint-js/narrow-cast.h>
#include <quick-lint-js/utf-16.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#if QLJS_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if QLJS_HAVE_INOTIFY
#include <sys/inotify.h>
#include <unistd.h>
#endif

#if QLJS_HAVE_KQUEUE
#include <sys/event.h>
#include <sys/time.h>
#endif

#if QLJS_HAVE_POLL
#include <poll.h>
#endif

// @@@ document caveats:
// [_] symlinks
// @@@ add a nuke feature to clear caches and reload all configs. or just have
// the client restart the LSP server...

using namespace std::literals::string_view_literals;

namespace quick_lint_js {
namespace {
#if QLJS_HAVE_INOTIFY
std::vector<posix_fd_file> garbage_inotify_fds;
#endif

#if defined(_WIN32)
#if NDEBUG
#define QLJS_LOG(...) do { } while (false)
#else
#define QLJS_LOG(...) do { ::std::fprintf(stderr, __VA_ARGS__); } while (false)
#endif
#endif
}

configuration_change_detector_impl::configuration_change_detector_impl(
    configuration_filesystem* fs)
    : fs_(fs) {}

configuration* configuration_change_detector_impl::get_config_for_file(
    const std::string& path) {
  watched_file& watch = this->watches_.emplace_back(path);
  [[maybe_unused]] bool did_change;
  loaded_config_file* config_file = this->get_config_file(watch, &did_change);
  return config_file ? &config_file->config : &this->default_config_;
}

configuration_change_detector_impl::loaded_config_file*
configuration_change_detector_impl::get_config_file(watched_file& watch,
                                                    bool* did_change) {
  canonical_path_result canonical_input_path =
      this->fs_->canonicalize_path(watch.watched_file_path);
  if (!canonical_input_path.ok()) {
    fprintf(stderr, "@@@ %s\n",
            std::move(canonical_input_path).error().c_str());
    QLJS_UNIMPLEMENTED();  // @@@
  }

  // @@@ dedupe!
  bool should_drop_file_name = true;
  if (canonical_input_path.have_missing_components()) {
    canonical_input_path.drop_missing_components();
    should_drop_file_name = false;
  }
  canonical_path parent_directory = std::move(canonical_input_path).canonical();
  if (should_drop_file_name) {
    parent_directory.parent();
  }

  loaded_config_file* found_config = nullptr;
  for (;;) {
    this->fs_->enter_directory(parent_directory);

    if (!found_config) {
      for (const std::string_view& file_name : {
               "quick-lint-js.config"sv,
               ".quick-lint-js.config"sv,
           }) {
        read_file_result result =
            this->fs_->read_file(parent_directory, file_name);
        if (result.ok()) {
          canonical_path config_path = parent_directory;
          config_path.append_component(file_name);

          auto [config_file_it, inserted] = this->loaded_config_files_.emplace(
              std::piecewise_construct, std::forward_as_tuple(config_path),
              std::forward_as_tuple());
          loaded_config_file* config_file = &config_file_it->second;

          *did_change = !(config_path == watch.config_file_path &&
                          result.content == config_file->file_content);

          if (*did_change) {
            watch.config_file_path = config_path;
            config_file->file_content = std::move(result.content);

            config_file->config.reset();
            if (inserted) {
              config_file->config.set_config_file_path(std::move(config_path));
            }
            config_file->config.load_from_json(&config_file->file_content);
          }
          found_config = config_file;
          break;  // Continue watching parent directories.
        } else if (result.is_not_found_error) {
          // Loop, looking for a different file.
        } else {
          QLJS_UNIMPLEMENTED();  // @@@
        }
      }
    }

    // Loop, looking in parent directories.
    if (!parent_directory.parent()) {
      // We searched the root directory which has no parent.
      break;
    }
  }

  if (found_config) {
    return found_config;
  } else {
    *did_change = watch.config_file_path.has_value();
    watch.config_file_path = std::nullopt;
    return nullptr;
  }
}

void configuration_change_detector_impl::refresh(
    std::vector<configuration_change>* out_changes) {
  for (watched_file& watch : this->watches_) {
    bool did_change;
    loaded_config_file* config_file = this->get_config_file(watch, &did_change);
    if (did_change) {
      out_changes->emplace_back(configuration_change{
          .watched_path = &watch.watched_file_path,
          .config = config_file ? &config_file->config : &this->default_config_,
      });
    }
  }
  // TODO(strager): Clean up old entries in this->loaded_config_files_.
  // TODO(strager): Clean up old filesystem watches.
}

#if QLJS_HAVE_INOTIFY
configuration_filesystem_inotify::configuration_filesystem_inotify()
    : inotify_fd_(::inotify_init1(IN_CLOEXEC | IN_NONBLOCK)) {
  QLJS_ASSERT(this->inotify_fd_.valid());
}

configuration_filesystem_inotify::~configuration_filesystem_inotify() {
  // HACK(strager): On Linux 5.4.86, close() becomes *very* slow (10
  // milliseconds or more) because it summons RCU synchronization demons.
  // (This performance problem only matters in tests.) More details:
  // https://lore.kernel.org/linux-fsdevel/CAC-ggsFLmFpz5Y=-9MMLwxuO2LOS9rhpewDp_-u2hrT9J79ryg@mail.gmail.com/
  //
  // Work around the slowness by deferring close() but manually clearing the
  // inotify.
  for (int watch_descriptor : this->watch_descriptors_) {
    int rc = ::inotify_rm_watch(this->inotify_fd_.get(), watch_descriptor);
    QLJS_ASSERT(rc == 0);
  }
  constexpr std::size_t closes_to_defer = 10;
  if (garbage_inotify_fds.size() > closes_to_defer) {
    garbage_inotify_fds.clear();  // Closes each fd.
  }
  garbage_inotify_fds.push_back(std::move(this->inotify_fd_));
}

canonical_path_result configuration_filesystem_inotify::canonicalize_path(
    const std::string& path) {
  return quick_lint_js::canonicalize_path(path);
}

void configuration_filesystem_inotify::enter_directory(
    const canonical_path& directory) {
  this->watch_directory(directory);
}

read_file_result configuration_filesystem_inotify::read_file(
    const canonical_path& directory, std::string_view file_name) {
  canonical_path config_path = directory;
  config_path.append_component(file_name);
  return quick_lint_js::read_file(config_path.c_str());
}

void configuration_filesystem_inotify::process_changes(
    configuration_change_detector_impl& detector,
    std::vector<configuration_change>* out_changes) {
  this->read_inotify();
  detector.refresh(out_changes);
}

::pollfd configuration_filesystem_inotify::get_notify_poll_fd() {
  return ::pollfd{
      .fd = this->inotify_fd_.get(),
      .events = POLLIN,
      .revents = 0,
  };
}

void configuration_filesystem_inotify::read_inotify() {
  union inotify_event_buffer {
    ::inotify_event event;
    char buffer[sizeof(::inotify_event) + NAME_MAX + 1];
  };

  // TODO(strager): Optimize syscall usage by calling read once with a big
  // buffer.
  for (;;) {
    inotify_event_buffer buffer;
    ssize_t rc = ::read(this->inotify_fd_.get(), &buffer, sizeof(buffer));
    QLJS_ASSERT(rc <= narrow_cast<ssize_t>(sizeof(buffer)));
    if (rc == -1) {
      int error = errno;
      if (error == EAGAIN) {
        // We read all of the queuedevents.
        break;
      }
      QLJS_UNIMPLEMENTED();
    }
    if (rc == 0) {
      QLJS_UNIMPLEMENTED();
    }
  }
}

void configuration_filesystem_inotify::watch_directory(
    const canonical_path& directory) {
  int watch_descriptor = ::inotify_add_watch(
      this->inotify_fd_.get(), directory.c_str(),
      IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
          IN_DELETE_SELF /*@@@*/ | IN_MODIFY | IN_MOVE_SELF /*@@@*/ |
          IN_EXCL_UNLINK | IN_ONLYDIR | IN_MOVED_FROM /*@@@*/ |
          IN_MOVED_TO /*@@@*/ | 0);
  if (watch_descriptor == -1) {
    std::fprintf(stderr, "fatal: inotify_add_watch failed: %s\n",
                 std::strerror(errno));
    QLJS_UNIMPLEMENTED();
  }
  // TODO(strager): Use a more efficient data structure, such as a sorted
  // interval set, for watch descriptors.
  if (std::find(this->watch_descriptors_.begin(),
                this->watch_descriptors_.end(),
                watch_descriptor) == this->watch_descriptors_.end()) {
    this->watch_descriptors_.emplace_back(watch_descriptor);
  }
}
#endif

#if QLJS_HAVE_KQUEUE
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
#endif

#if defined(_WIN32)
configuration_filesystem_win32::configuration_filesystem_win32()
    : change_event_(::CreateEventW(/*lpEventAttributes=*/nullptr, /*bManualReset=*/false, /*bInitialState=*/false, /*lpName=*/nullptr)),
    io_completion_port_(::CreateIoCompletionPort(/*FileHandle=*/INVALID_HANDLE_VALUE, /*ExistingCompletionPort=*/nullptr, /*CompletionKey=*/0, /*NumberOfConcurrentThreads=*/1)) {
  if (this->io_completion_port_.get() == nullptr) {
    QLJS_UNIMPLEMENTED();
  }
  this->io_thread_ = std::thread([this]() -> void { this->run_io_thread(); });
}

configuration_filesystem_win32::~configuration_filesystem_win32() {
  {
    std::unique_lock guard(this->watched_directories_mutex_);

    for (watched_directory& dir : this->watched_directories_) {
      if (dir.directory_handle.get() == nullptr) {
        continue;  // @@@ hack for now
      }
      [[maybe_unused]] BOOL ok =
          ::CancelIoEx(dir.directory_handle.get(), nullptr);
      if (!ok) {
        DWORD error = ::GetLastError();
        if (error == ERROR_NOT_FOUND) {
          // @@@ probably shouldn't happen, but it does.
        } else {
          QLJS_UNIMPLEMENTED();
        }
      }
    }
    //for (watched_directory& dir : this->watched_directories_) {
    //  [[maybe_unused]] DWORD bytes_transferred;
    //  BOOL ok = ::GetOverlappedResult(dir.directory_handle.get(),
    //                                  &dir.read_changes_overlapped,
    //                                  &bytes_transferred, /*bWait=*/true);
    //  if (!ok) {
    //    DWORD error = ::GetLastError();
    //    if (error == ERROR_OPERATION_ABORTED) {
    //      // Expected: CancelIoEx succeeded.
    //    } else {
    //      QLJS_UNIMPLEMENTED();
    //    }
    //  }
    //}
    for (watched_directory& dir : this->watched_directories_) {
      [[maybe_unused]] DWORD bytes_transferred;
      BOOL ok = ::GetOverlappedResult(dir.directory_handle.get(),
                                      &dir.oplock_overlapped,
                                      &bytes_transferred, /*bWait=*/true);
      if (!ok) {
        DWORD error = ::GetLastError();
        if (error == ERROR_OPERATION_ABORTED) {
          // Expected: CancelIoEx succeeded.
        } else {
          QLJS_UNIMPLEMENTED();
        }
      }
    }
  }

    BOOL ok = ::PostQueuedCompletionStatus(
      /*CompletionPort=*/this->io_completion_port_.get(),
      /*dwNumberOfBytesTransferred=*/0,
      /*dwCompletionKey=*/completion_key::stop_io_thread,
      /*lpOverlapped=*/nullptr);
  if (!ok) {
    QLJS_UNIMPLEMENTED();
  }

  this->io_thread_.join();
}

canonical_path_result configuration_filesystem_win32::canonicalize_path(
    const std::string& path) {
  return quick_lint_js::canonicalize_path(path);
}

void configuration_filesystem_win32::enter_directory(
    const canonical_path& directory) {
  this->watch_directory(directory);
}

read_file_result configuration_filesystem_win32::read_file(
    const canonical_path& directory, std::string_view file_name) {
  canonical_path config_path = directory;
  config_path.append_component(file_name);
  return quick_lint_js::read_file(config_path.c_str());
}

void configuration_filesystem_win32::process_changes(
    configuration_change_detector_impl& detector,
    std::vector<configuration_change>* out_changes) {
  detector.refresh(out_changes);
}

windows_handle_file_ref configuration_filesystem_win32::get_change_event()
    noexcept {
  return this->change_event_.ref();
}

void configuration_filesystem_win32::watch_directory(
    const canonical_path& directory) {
  std::optional<std::wstring> wpath =
      mbstring_to_wstring(directory.c_str());
  if (!wpath.has_value()) {
    QLJS_UNIMPLEMENTED();
  }

  std::unique_lock guard(this->watched_directories_mutex_);
    HANDLE directory_handle = ::CreateFileW(
      wpath->c_str(), /*dwDesiredAccess=*/GENERIC_READ,
      /*dwShareMode=*/FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
      /*lpSecurityAttributes=*/nullptr,
      /*dwCreationDisposition=*/OPEN_EXISTING,
      /*dwFlagsAndAttributes=*/FILE_ATTRIBUTE_NORMAL |
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
      /*hTemplateFile=*/nullptr);
  if (directory_handle == INVALID_HANDLE_VALUE) {
    QLJS_UNIMPLEMENTED();  // @@@
  }
  HANDLE iocp = ::CreateIoCompletionPort(
      /*FileHandle=*/directory_handle,
      /*ExistingCompletionPort=*/this->io_completion_port_.get(),
      /*CompletionKey=*/completion_key::directory, /*NumberOfConcurrentThreads=*/1);
  if (iocp != this->io_completion_port_.get()) {
    QLJS_UNIMPLEMENTED();
  }
  watched_directory& dir =
      this->watched_directories_.emplace_back(directory, directory_handle, this);

  // @@@ create/destroy the event cleanly
  dir.oplock_overlapped.hEvent = ::CreateEvent(/*lpEventAttributes=*/nullptr, /*bManualReset=*/false,
      /*bInitialState=*/false, /*lpName=*/nullptr);
  if (!dir.oplock_overlapped.hEvent) {
    QLJS_UNIMPLEMENTED();
  }

  // https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/3f2438b15c59fdc104c13e2cf6cf46c1b16cf281/winbase/io/Oplocks/Oplocks/Oplocks.cpp
  // "An RH oplock on a directory breaks to R when the directory itself is renamed or deleted." https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock
  REQUEST_OPLOCK_INPUT_BUFFER request;
    request.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
  request.StructureLength = sizeof(REQUEST_OPLOCK_INPUT_BUFFER);
    request.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ |
                                 OPLOCK_LEVEL_CACHE_HANDLE;
  request.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
  BOOL okie =
      ::DeviceIoControl(/*hDevice=*/dir.directory_handle.get(),
                                /*dwIoControlCode=*/FSCTL_REQUEST_OPLOCK,
                        /*lpInBuffer=*/&request,
                        /*nInBufferSize=*/sizeof(request),
                        /*lpOutBuffer=*/&dir.oplock_response,
                        /*nOutBufferSize=*/sizeof(dir.oplock_response),
                        /*lpBytesReturned=*/nullptr, &dir.oplock_overlapped);
  if (okie) {
    QLJS_UNIMPLEMENTED();
  } else {
    DWORD error = ::GetLastError();
    if (error == ERROR_IO_PENDING) {
        // Do nothing. run_io_thread will handle the oplock breaking.
    } else {
      QLJS_UNIMPLEMENTED();  // @@@
    }
  }

  //BOOL ok = ::ReadDirectoryChangesW(
  //    /*hDirectory=*/dir.directory_handle.get(),
  //    /*lpBuffer=*/&dir.buffer,
  //    /*nBufferLength=*/sizeof(dir.buffer),
  //    /*bWatchSubtree=*/false,
  //    /*dwNotifyFilter=*/FILE_NOTIFY_CHANGE_FILE_NAME |
  //        FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES |
  //        FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
  //        FILE_NOTIFY_CHANGE_SECURITY | FILE_NOTIFY_CHANGE_CREATION |
  //        FILE_NOTIFY_CHANGE_LAST_ACCESS,
  //    /*lpBytesReturned=*/nullptr,
  //    /*lpOverlapped=*/&dir.read_changes_overlapped,
  //    /*lpCompletionRoutine=*/nullptr);
  //if (!ok) {
  //  std::fprintf(stderr, "fatal: ReadDirectoryChangesW failed: %d\n",
  //               ::GetLastError());
  //  QLJS_UNIMPLEMENTED();  // @@@
  //}
}

void configuration_filesystem_win32::run_io_thread() {
  for (;;) {
    [[maybe_unused]] DWORD number_of_bytes_transferred;
    ULONG_PTR completion_key;
    OVERLAPPED* overlapped;
    BOOL ok = ::GetQueuedCompletionStatus(
        /*CompletionPort=*/this->io_completion_port_.get(),
        /*lpNumberOfBytesTransferred=*/&number_of_bytes_transferred,
        /*lpCompletionKey=*/&completion_key,
        /*lpOverlapped=*/&overlapped,
        /*dwMilliseconds=*/INFINITE);
    if (!ok) {
      DWORD error = ::GetLastError();
      if (error == ERROR_OPERATION_ABORTED) {
        // @@@
        continue;
      } else {
        QLJS_UNIMPLEMENTED();
      }
    }
    switch (completion_key) {
    case completion_key::directory:
      switch (overlapped->Offset) {
      case watched_directory::oplock_overlapped_offset: {
        watched_directory& dir =
            *watched_directory::from_oplock_overlapped(overlapped);
        std::unique_lock guard(this->watched_directories_mutex_);
        QLJS_ASSERT(dir.oplock_response.Flags &
                    REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED);
        QLJS_LOG(
            "note: Directory handle %#llx: %s: Oplock broke. Somebody probably "
            "moved the directory or an ancestor.\n",
            reinterpret_cast<unsigned long long>(dir.directory_handle.get()),
            dir.directory_path.c_str());
        dir.directory_handle.close();
        // @@@ we should reopen it or something.

                BOOL ok = ::SetEvent(this->change_event_.get());
        if (!ok) {
          QLJS_UNIMPLEMENTED();
        }

        break;
      }
        
      case watched_directory::read_changes_overlapped_offset: {
        watched_directory& dir =
            *watched_directory::from_read_changes_overlapped(overlapped);
        std::unique_lock guard(this->watched_directories_mutex_);
        QLJS_ASSERT(dir.oplock_response.Flags &
                    REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED);
        QLJS_LOG(
            "note: Directory handle %#llx: %s: ReadDirectoryChangesW signalled.\n",
            reinterpret_cast<unsigned long long>(dir.directory_handle.get()),
            dir.directory_path.c_str());
        //BOOL ok = ::SetEvent(this->change_event_.get());
        //if (!ok) {
        //  QLJS_UNIMPLEMENTED();
        //}
        break;
      }

                                                            default:
        QLJS_UNIMPLEMENTED();
                                                              break;
      }
                                                            break;

    case completion_key::stop_io_thread:
      return;
    }
  }
}

configuration_filesystem_win32::watched_directory*
configuration_filesystem_win32::watched_directory::from_read_changes_overlapped(
    OVERLAPPED* overlapped) noexcept {
  return reinterpret_cast<watched_directory*>(
      reinterpret_cast<std::uintptr_t>(overlapped) -
      offsetof(watched_directory, read_changes_overlapped));
}

configuration_filesystem_win32::watched_directory*
configuration_filesystem_win32::watched_directory::from_oplock_overlapped(
    OVERLAPPED* overlapped) noexcept {
  return reinterpret_cast<watched_directory*>(
      reinterpret_cast<std::uintptr_t>(overlapped) -
      offsetof(watched_directory, oplock_overlapped));
}
#endif
}

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
