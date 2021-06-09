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

// @@@ document caveats:
// [_] symlinks
// @@@ add a nuke feature to clear caches and reload all configs. or just have
// the client restart the LSP server...

using namespace std::literals::string_view_literals;

namespace quick_lint_js {
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
