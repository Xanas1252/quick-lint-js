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

#ifndef QUICKLINT_JS_ERROR_COLLECTOR_H
#define QUICKLINT_JS_ERROR_COLLECTOR_H

#include <quicklint-js/error.h>
#include <quicklint-js/lex.h>
#include <quicklint-js/location.h>
#include <vector>

namespace quicklint_js {
struct error_collector : public error_reporter {
  void report_error_invalid_binding_in_let_statement(
      source_code_span where) override {
    this->errors.emplace_back(
        error{error_invalid_binding_in_let_statement, where});
  }

  void report_error_let_with_no_bindings(source_code_span where) override {
    this->errors.emplace_back(error{error_let_with_no_bindings, where});
  }

  void report_error_missing_oprand_for_operator(
      source_code_span where) override {
    this->errors.emplace_back(error{error_missing_oprand_for_operator, where});
  }

  void report_error_stray_comma_in_let_statement(
      source_code_span where) override {
    this->errors.emplace_back(error{error_stray_comma_in_let_statement, where});
  }

  void report_error_unclosed_block_comment(
      source_code_span comment_open) override {
    this->errors.emplace_back(
        error{error_unclosed_block_comment, comment_open});
  }

  void report_error_unclosed_string_literal(
      source_code_span string_literal) override {
    this->errors.emplace_back(
        error{error_unclosed_string_literal, string_literal});
  }

  void report_error_unclosed_template(
      source_code_span incomplete_template) override {
    this->errors.emplace_back(
        error{error_unclosed_template, incomplete_template});
  }

  void report_error_unexpected_identifier(source_code_span where) override {
    this->errors.emplace_back(error{error_unexpected_identifier, where});
  }

  void report_error_unmatched_parenthesis(source_code_span where) override {
    this->errors.emplace_back(error{error_unmatched_parenthesis, where});
  }

  void report_error_variable_used_before_declaration(identifier name) override {
    this->errors.emplace_back(
        error{error_variable_used_before_declaration, name.span()});
  }

  enum error_kind {
    error_invalid_binding_in_let_statement,
    error_let_with_no_bindings,
    error_missing_oprand_for_operator,
    error_stray_comma_in_let_statement,
    error_unclosed_block_comment,
    error_unclosed_string_literal,
    error_unclosed_template,
    error_unexpected_identifier,
    error_unmatched_parenthesis,
    error_variable_used_before_declaration,
  };
  struct error {
    error_kind kind;
    source_code_span where;
  };
  std::vector<error> errors;
};
}  // namespace quicklint_js

#endif
