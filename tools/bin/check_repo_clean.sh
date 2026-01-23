#!/usr/bin/env bash
set -euo pipefail

# Script to run repository hygiene commands and fail if they modify the repo.
# Runs: just tidy, just mock, just generate
# Exits non-zero and prints modified files if any step changes the working tree.

# Ensure we are inside a git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: not inside a git repository" >&2
  exit 2
fi

# Ensure `just` is available
if ! command -v just >/dev/null 2>&1; then
  echo "ERROR: 'just' not found in PATH" >&2
  exit 2
fi

run_and_check() {
  local name="$1"; shift
  local before
  local after

  echo "--- Running: just $* (${name}) ---"
  before=$(git status --porcelain)

  if ! just "$@"; then
    echo "ERROR: 'just $*' failed" >&2
    exit 1
  fi

  after=$(git status --porcelain)

  if [ "${before}" != "${after}" ]; then
    echo "\nERROR: Repository changed after 'just $*' (${name})." >&2
    echo "Changed files (git status --porcelain):" >&2
    git --no-pager status --porcelain >&2
    echo "\nYou should inspect and commit or revert these changes." >&2
    exit 1
  fi

  echo "OK: no repo changes after 'just $*' (${name}).\n"
}

# Run tasks in order
run_and_check "mod-tidy" tidy
run_and_check "mock" mock
run_and_check "generate" generate

echo "All checks passed: repository unchanged by tidy, mock, and generate."
exit 0

