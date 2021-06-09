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
#include <quick-lint-js/unreachable.h>
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
#define QLJS_LOG(...) \
  do {                \
  } while (false)
#else
#define QLJS_LOG(...)                    \
  do {                                   \
    ::std::fprintf(stderr, __VA_ARGS__); \
  } while (false)
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
namespace {
windows_handle_file create_windows_event() noexcept;
windows_handle_file create_io_completion_port() noexcept;
void attach_handle_to_iocp(
    windows_handle_file_ref handle, windows_handle_file_ref iocp,
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
      this->handle_directory_event(overlapped, number_of_bytes_transferred, error);
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
    QLJS_LOG(
        "note: Directory handle %#llx: %s: Oplock broke\n",
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
configuration_filesystem_win32::find_watched_directory(std::unique_lock<std::mutex>&, watched_directory* dir) {
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
      directory_id(directory_id)
{
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

void attach_handle_to_iocp(
    windows_handle_file_ref handle, windows_handle_file_ref iocp,
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
  return b.VolumeSerialNumber ==
         a.VolumeSerialNumber &&
         memcmp(&b.FileId, &a.FileId,
                sizeof(b.FileId)) == 0;
}
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
