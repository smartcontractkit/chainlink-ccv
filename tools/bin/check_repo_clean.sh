#!/usr/bin/env bash
set -euo pipefail

# Script to run repository hygiene commands and fail if they modify the repo.
# Exits non-zero and prints modified files if any step fails or changes the working tree.

# List of just targets to run for checks.
just_targets_to_run=(tidy mock generate shellcheck)

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
  local before
  local after

  echo "--- Running: just $* ---"
  before=$(git status --porcelain)

  if ! just "$@"; then
    echo "ERROR: 'just $*' failed" >&2
    exit 1
  fi

  after=$(git status --porcelain)

  if [ "${before}" != "${after}" ]; then
    echo ""
    echo "ERROR: Repository changed after 'just $*'." >&2
    echo "Changed files (git status --porcelain):" >&2
    git --no-pager status --porcelain >&2
    echo ""
    echo "You should inspect and commit or revert these changes." >&2
    exit 1
  fi

  echo "OK: no repo changes after 'just $*'."
  echo ""
}

for c in "${just_targets_to_run[@]}"; do
  run_and_check "$c"
done

# Print a multiline bulleted list showing which just targets ran
echo "All checks passed:"
for t in "${just_targets_to_run[@]}"; do
  echo "    * just $t"
done

exit 0
