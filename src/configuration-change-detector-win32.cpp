// Copyright (C) 2020  Matthew "strager" Glazar
// See end of file for extended copyright information.

#if defined(_WIN32)

#include <Windows.h>
#include <cerrno>
#include <cstddef>
#include <cstdio>
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
#include <unordered_map>
#include <utility>
#include <vector>

#if NDEBUG
#define QLJS_LOG(...) \
  do {                \
  } while (false)
#else
#define QLJS_LOG(...)                    \
  do {                                   \
    ::std::fprintf(stderr, __VA_ARGS__); \
  } while (false)
#endif

// @@@ document caveats:
// [_] symlinks
// @@@ add a nuke feature to clear caches and reload all configs. or just have
// the client restart the LSP server...

namespace quick_lint_js {
namespace {
windows_handle_file create_windows_event() noexcept;
windows_handle_file create_io_completion_port() noexcept;
void attach_handle_to_iocp(windows_handle_file_ref handle,
                           windows_handle_file_ref iocp,
                           ULONG_PTR completionKey) noexcept;
bool file_ids_equal(const FILE_ID_INFO&, const FILE_ID_INFO&) noexcept;
}

// configuration_filesystem_win32 implements directory and file change
// notifications using a little-known feature called oplocks.
//
// For each directory we want to watch, we acquire an oplock. When a change
// happens, the oplock is broken and we are notified.
//
// Well-known APIs, such as FindFirstChangeNotificationW and
// ReadDirectoryChangesW, don't work because they hold a directory handle. This
// handle prevents renaming any ancestor directory. Directory handles with an
// oplock don't have this problem.
//
// Documentation on oplocks:
// * https://github.com/pauldotknopf/WindowsSDK7-Samples/blob/3f2438b15c59fdc104c13e2cf6cf46c1b16cf281/winbase/io/Oplocks/Oplocks/Oplocks.cpp
// * https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock
//
// When an oplock is broken, the directory handle is signalled. We could wait
// for the directory handles using WaitForMultipleObjects, but WFMO has a limit
// of 64 handles. This limit is low for our use case. To wait for any number of
// directory handles, we wait for events using an I/O completion port
// (io_completion_port_) pumped on a background thread (io_thread_). The
// background thread signals that a refresh is necessary using an event
// (change_event_).
configuration_filesystem_win32::configuration_filesystem_win32()
    : change_event_(create_windows_event()),
      io_completion_port_(create_io_completion_port()) {
  this->io_thread_ = std::thread([this]() -> void { this->run_io_thread(); });
}

configuration_filesystem_win32::~configuration_filesystem_win32() {
  {
    std::unique_lock lock(this->watched_directories_mutex_);
    for (auto& [directory_path, dir] : this->watched_directories_) {
      dir.begin_cancel();
    }
    this->wait_until_all_watches_cancelled(lock);
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

windows_handle_file_ref
configuration_filesystem_win32::get_change_event() noexcept {
  return this->change_event_.ref();
}

void configuration_filesystem_win32::watch_directory(
    const canonical_path& directory) {
  std::optional<std::wstring> wpath = mbstring_to_wstring(directory.c_str());
  if (!wpath.has_value()) {
    QLJS_UNIMPLEMENTED();
  }

  windows_handle_file directory_handle(::CreateFileW(
      wpath->c_str(), /*dwDesiredAccess=*/GENERIC_READ,
      /*dwShareMode=*/FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
      /*lpSecurityAttributes=*/nullptr,
      /*dwCreationDisposition=*/OPEN_EXISTING,
      /*dwFlagsAndAttributes=*/FILE_ATTRIBUTE_NORMAL |
          FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
      /*hTemplateFile=*/nullptr));
  if (!directory_handle.valid()) {
    QLJS_UNIMPLEMENTED();  // @@@
  }
  FILE_ID_INFO directory_id;
  if (!::GetFileInformationByHandleEx(directory_handle.get(), ::FileIdInfo,
                                      &directory_id, sizeof(directory_id))) {
    QLJS_UNIMPLEMENTED();
  }

  std::unique_lock lock(this->watched_directories_mutex_);

  auto [watched_directory_it, inserted] =
      this->watched_directories_.try_emplace(
          directory, std::move(directory_handle), directory_id);
  watched_directory* dir = &watched_directory_it->second;
  if (!inserted) {
    bool already_watched = file_ids_equal(dir->directory_id, directory_id);
    if (already_watched) {
      return;
    }

    QLJS_LOG("note: Directory handle %#llx: %s: Directory identity changed\n",
             reinterpret_cast<unsigned long long>(dir->directory_handle.get()),
             directory.c_str());
    dir->begin_cancel();
    this->wait_until_watch_cancelled(lock, directory);

    auto [watched_directory_it, inserted] =
        this->watched_directories_.try_emplace(
            directory, std::move(directory_handle), directory_id);
    QLJS_ASSERT(inserted);
    dir = &watched_directory_it->second;
  }

  attach_handle_to_iocp(dir->directory_handle.ref(),
                        this->io_completion_port_.ref(),
                        completion_key::directory);

  REQUEST_OPLOCK_INPUT_BUFFER request = {
      .StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION,
      .StructureLength = sizeof(REQUEST_OPLOCK_INPUT_BUFFER),
      .RequestedOplockLevel =
          OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE,
      .Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST,
  };
  BOOL ok = ::DeviceIoControl(/*hDevice=*/dir->directory_handle.get(),
                              /*dwIoControlCode=*/FSCTL_REQUEST_OPLOCK,
                              /*lpInBuffer=*/&request,
                              /*nInBufferSize=*/sizeof(request),
                              /*lpOutBuffer=*/&dir->oplock_response,
                              /*nOutBufferSize=*/sizeof(dir->oplock_response),
                              /*lpBytesReturned=*/nullptr,
                              /*lpOverlapped=*/&dir->oplock_overlapped);
  if (ok) {
    // TODO(strager): Can this happen? I assume if this happens, the oplock was
    // immediately broken.
    QLJS_UNIMPLEMENTED();
  } else {
    DWORD error = ::GetLastError();
    if (error == ERROR_IO_PENDING) {
      // run_io_thread will handle the oplock breaking.
    } else {
      QLJS_UNIMPLEMENTED();
    }
  }
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
    DWORD error = ok ? 0 : ::GetLastError();
    if (!ok) {
      if (error != ERROR_OPERATION_ABORTED) {
        QLJS_UNIMPLEMENTED();
      }
    }
    switch (completion_key) {
    case completion_key::directory:
      this->handle_directory_event(overlapped, number_of_bytes_transferred,
                                   error);
      break;

    case completion_key::stop_io_thread:
      return;

    default:
      QLJS_UNREACHABLE();
    }
  }
}

void configuration_filesystem_win32::handle_directory_event(
    OVERLAPPED* overlapped, DWORD number_of_bytes_transferred, DWORD error) {
  std::unique_lock lock(watched_directories_mutex_);

  bool aborted = error == ERROR_OPERATION_ABORTED;
  watched_directory& dir =
      *watched_directory::from_oplock_overlapped(overlapped);
  auto directory_it = this->find_watched_directory(lock, &dir);

  if (!aborted) {
    // A directory oplock breaks if any of the following happens:
    //
    // * The directory or any of its ancestors is renamed. The rename blocks
    //   until we release the oplock.
    // * A file in the directory is created, modified, or deleted.
    //
    // https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock
    QLJS_LOG("note: Directory handle %#llx: %s: Oplock broke\n",
             reinterpret_cast<unsigned long long>(dir.directory_handle.get()),
             directory_it->first.c_str());
    QLJS_ASSERT(number_of_bytes_transferred == sizeof(dir.oplock_response));
    QLJS_ASSERT(dir.oplock_response.Flags &
                REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED);
  }

  // Erasing the watched_directory will close dir.directory_handle,
  // releasing the oplock.
  this->watched_directories_.erase(directory_it);
  this->watched_directory_unwatched_.notify_all();

  if (!aborted) {
    BOOL ok = ::SetEvent(this->change_event_.get());
    if (!ok) {
      QLJS_UNIMPLEMENTED();
    }
  }
}

std::unordered_map<canonical_path,
                   configuration_filesystem_win32::watched_directory>::iterator
configuration_filesystem_win32::find_watched_directory(
    std::unique_lock<std::mutex>&, watched_directory* dir) {
  auto directory_it = std::find_if(
      this->watched_directories_.begin(), this->watched_directories_.end(),
      [&](const auto& entry) { return &entry.second == dir; });
  QLJS_ASSERT(directory_it != this->watched_directories_.end());
  return directory_it;
}

void configuration_filesystem_win32::wait_until_all_watches_cancelled(
    std::unique_lock<std::mutex>& lock) {
  this->watched_directory_unwatched_.wait(
      lock, [&] { return this->watched_directories_.empty(); });
}

void configuration_filesystem_win32::wait_until_watch_cancelled(
    std::unique_lock<std::mutex>& lock, const canonical_path& directory) {
  this->watched_directory_unwatched_.wait(
      lock, [&] { return this->watched_directories_.count(directory) == 0; });
}

configuration_filesystem_win32::watched_directory::watched_directory(
    windows_handle_file&& directory_handle, const FILE_ID_INFO& directory_id)
    : directory_handle(std::move(directory_handle)),
      directory_id(directory_id) {
  QLJS_ASSERT(this->directory_handle.valid());

  this->oplock_overlapped.Offset = 0;
  this->oplock_overlapped.OffsetHigh = 0;
  this->oplock_overlapped.hEvent = nullptr;
}

void configuration_filesystem_win32::watched_directory::begin_cancel() {
  BOOL ok = ::CancelIoEx(this->directory_handle.get(), nullptr);
  if (!ok) {
    DWORD error = ::GetLastError();
    if (error == ERROR_NOT_FOUND) {
      // TODO(strager): Figure out why this error happens sometimes.
    } else {
      QLJS_UNIMPLEMENTED();
    }
  }
}

configuration_filesystem_win32::watched_directory*
configuration_filesystem_win32::watched_directory::from_oplock_overlapped(
    OVERLAPPED* overlapped) noexcept {
  return reinterpret_cast<watched_directory*>(
      reinterpret_cast<std::uintptr_t>(overlapped) -
      offsetof(watched_directory, oplock_overlapped));
}

namespace {
windows_handle_file create_windows_event() noexcept {
  windows_handle_file event(
      ::CreateEventW(/*lpEventAttributes=*/nullptr, /*bManualReset=*/false,
                     /*bInitialState=*/false, /*lpName=*/nullptr));
  if (!event.valid()) {
    QLJS_UNIMPLEMENTED();
  }
  return event;
}

windows_handle_file create_io_completion_port() noexcept {
  windows_handle_file iocp(::CreateIoCompletionPort(
      /*FileHandle=*/INVALID_HANDLE_VALUE,
      /*ExistingCompletionPort=*/nullptr, /*CompletionKey=*/0,
      /*NumberOfConcurrentThreads=*/1));
  if (!iocp.valid()) {
    QLJS_UNIMPLEMENTED();
  }
  return iocp;
}

void attach_handle_to_iocp(windows_handle_file_ref handle,
                           windows_handle_file_ref iocp,
                           ULONG_PTR completionKey) noexcept {
  HANDLE iocp2 = CreateIoCompletionPort(
      /*FileHandle=*/handle.get(),
      /*ExistingCompletionPort=*/iocp.get(),
      /*CompletionKey=*/completionKey,
      /*NumberOfConcurrentThreads=*/1);
  if (iocp2 != iocp.get()) {
    QLJS_UNIMPLEMENTED();
  }
}

bool file_ids_equal(const FILE_ID_INFO& a, const FILE_ID_INFO& b) noexcept {
  return b.VolumeSerialNumber == a.VolumeSerialNumber &&
         memcmp(&b.FileId, &a.FileId, sizeof(b.FileId)) == 0;
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
