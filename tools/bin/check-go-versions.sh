#!/usr/bin/env bash
# Enforce that all go.mod files declare the expected Go version.
# This script reads the expected Go version from the tool-versions.env file
# located at the root of the git repository (VERSION_GO=<version>).

set -euo pipefail

# Determine the git repository root
repo_root=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$repo_root" ]; then
  echo "Error: not inside a git repository (cannot locate repo root)."
  exit 1
fi

pushd "$repo_root" > /dev/null

tool_versions_file="tool-versions.env"
if [ ! -f "$tool_versions_file" ]; then
  echo "Error: $tool_versions_file not found."
  exit 1
fi

EXPECTED_GO_FULL=$(grep -E '^VERSION_GO=' "$tool_versions_file" | cut -d= -f2 || true)
if [ -z "$EXPECTED_GO_FULL" ]; then
  echo "Error: VERSION_GO= not found or empty in $tool_versions_file"
  exit 1
fi

# Collect go.mod files under the repository root using find (handles nested modules)
# Use a null-separated list to be safe with spaces in filenames, then read into an array
mapfile -d '' -t files < <(find . -type f -name 'go.mod' -print0)

if [ ${#files[@]} -eq 0 ]; then
  echo "No go.mod files found."
  exit 1
fi

failed=0
for gomod in "${files[@]}"; do
  declared=$(grep -E '^go [0-9]+\.[0-9]+' "$gomod" | awk '{print $2}' | head -n1 || true)
  if [ -z "$declared" ]; then
    echo "❌ Missing 'go' directive in $gomod"
    failed=1
    continue
  fi
  if [ "$declared" != "$EXPECTED_GO_FULL" ]; then
    echo "❌ $gomod: go $declared != expected go $EXPECTED_GO_FULL (from $tool_versions_file)"
    failed=1
  else
    echo "✅ $gomod"
  fi
done

if [ "$failed" -ne 0 ]; then
  echo
  echo "Please update 'go' directives to 'go $EXPECTED_GO_FULL' in all go.mod files."
  exit 1
fi

echo "All go.mod files use go $EXPECTED_GO_FULL."
