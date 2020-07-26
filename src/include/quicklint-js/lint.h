// quicklint-js finds bugs in JavaScript programs.
// Copyright (C) 2020  Matthew Glazar
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#ifndef QUICKLINT_JS_LINT_H
#define QUICKLINT_JS_LINT_H

#include <algorithm>
#include <cassert>
#include <quicklint-js/error.h>
#include <quicklint-js/lex.h>
#include <quicklint-js/parse.h>
#include <string>
#include <vector>

namespace quicklint_js {
class linter {
 public:
  explicit linter(error_reporter *error_reporter) noexcept
      : error_reporter_(error_reporter) {}

  void visit_enter_class_scope() {}

  void visit_enter_function_scope() { this->scopes_.emplace_back(); }

  void visit_exit_class_scope() {}

  void visit_exit_function_scope() {
    assert(this->scopes_.size() >= 2);
    scope &current_scope = this->scopes_[this->scopes_.size() - 1];
    scope &parent_scope = this->scopes_[this->scopes_.size() - 2];

    for (identifier &name :
         this->scopes_.back().variables_used_before_declaration) {
      const declared_variable *var = this->find_declared_variable(name);
      if (var && (var->kind == variable_kind::_const ||
                  var->kind == variable_kind::_let)) {
        this->error_reporter_->report_error_variable_used_before_declaration(
            name);
      } else {
        parent_scope.variables_used_in_descendant_scope.emplace_back(
            std::move(name));
      }
    }

    parent_scope.variables_used_in_descendant_scope.insert(
        parent_scope.variables_used_in_descendant_scope.end(),
        current_scope.variables_used_in_descendant_scope.begin(),
        current_scope.variables_used_in_descendant_scope.end());

    this->scopes_.pop_back();
  }

  void visit_property_declaration(identifier) {}

  void visit_variable_declaration(identifier name, variable_kind kind) {
    this->scopes_.back().declared_variables.emplace_back(
        declared_variable{std::string(name.string_view()), kind});
  }

  void visit_variable_use(identifier name) {
    bool variable_is_declared = this->find_declared_variable(name);
    if (!variable_is_declared) {
      this->scopes_.back().variables_used_before_declaration.emplace_back(name);
    }
  }

  void visit_end_of_module() {
    for (const identifier &name :
         this->scopes_.back().variables_used_before_declaration) {
      const declared_variable *var = this->find_declared_variable(name);
      if (!var || var->kind == variable_kind::_const ||
          var->kind == variable_kind::_let) {
        this->error_reporter_->report_error_variable_used_before_declaration(
            name);
      }
    }
    for (const identifier &name :
         this->scopes_.back().variables_used_in_descendant_scope) {
      const declared_variable *var = this->find_declared_variable(name);
      if (!var) {
        this->error_reporter_->report_error_variable_used_before_declaration(
            name);
      }
    }
  }

 private:
  struct declared_variable {
    std::string name;
    variable_kind kind;
  };

  struct scope {
    std::vector<declared_variable> declared_variables;
    std::vector<identifier> variables_used_before_declaration;
    std::vector<identifier> variables_used_in_descendant_scope;
  };

  const declared_variable *find_declared_variable(
      identifier name) const noexcept {
    for (const scope &s : this->scopes_) {
      for (const declared_variable &var : s.declared_variables) {
        if (var.name == name.string_view()) {
          return &var;
        }
      }
    }
    return nullptr;
  }

  std::vector<scope> scopes_{1};
  error_reporter *error_reporter_;
};
}  // namespace quicklint_js

#endif