#!/usr/bin/env bash
# Compare coverage between two Go coverprofiles by top-level package.
# Usage:
#   ./cov_compare.sh [--no-header] OLD.cov NEW.cov
#
# Example:
#   ./cov_compare.sh coverage.out coverage_new.out
#   ./cov_compare.sh --no-header coverage.out coverage_new.out

NO_HEADER=0

# Collect non-flag arguments in an array so they remain separate when
# resetting positional parameters with `set --`.
ARGS=()

# Parse optional flags
for arg in "$@"; do
  case "$arg" in
    --no-header)
      NO_HEADER=1
      ;;
    *)
      ARGS+=("$arg")
      ;;
  esac
done

# Reset positional parameters
set -- "${ARGS[@]}"

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 [--no-header] coverage1.out coverage2.out" >&2
  exit 1
fi

COV1="$1"
COV2="$2"

# Locate the module root and import path so coverage import paths can be
# resolved to filesystem paths for existence checks.
MODULE_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
MODULE_PATH=$(grep '^module ' "$MODULE_ROOT/go.mod" 2>/dev/null | awk '{print $2}' | head -1)

# List all unique source-file import paths referenced in a coverage profile.
list_profile_files() {
  grep -v '^mode:' "$1" | sed 's/\(.*\.go\):.*/\1/' | sort -u
}

# Write a filtered copy of a coverage profile to stdout, omitting lines for
# source files that do not exist on the current filesystem.
# go tool cover aborts on the first missing file, so pre-filtering is required
# for correct output when comparing profiles from different commits.
filter_missing_files() {
  local profile="$1"

  # Build a grep -E alternation pattern for import paths absent on disk.
  local pattern=""
  while IFS= read -r pkg_file; do
    local rel="${pkg_file#${MODULE_PATH}/}"
    if [ ! -f "$MODULE_ROOT/$rel" ]; then
      # Escape regex metacharacters that appear in import paths (primarily '.').
      local escaped
      escaped=$(printf '%s' "$pkg_file" | sed 's/\./\\./g')
      pattern="${pattern:+${pattern}|}^${escaped}:"
    fi
  done < <(list_profile_files "$profile")

  if [ -z "$pattern" ]; then
    cat "$profile"
  else
    grep -v -E "$pattern" "$profile"
  fi
}

tmp1=$(mktemp)
tmp2=$(mktemp)
f1=$(mktemp)
f2=$(mktemp)
err1=$(mktemp)
err2=$(mktemp)
files1=$(mktemp)
files2=$(mktemp)

cleanup() {
  rm -f "$tmp1" "$tmp2" "$f1" "$f2" "$err1" "$err2" "$files1" "$files2"
}
trap cleanup EXIT

# Snapshot file lists before filtering (used for the added/removed report).
list_profile_files "$COV1" > "$files1"
list_profile_files "$COV2" > "$files2"

# Build filtered profiles so go tool cover won't abort on missing files.
filter_missing_files "$COV1" > "$f1"
filter_missing_files "$COV2" > "$f2"

# Extract top-level package coverage (simple average)
extract_top_pkg_coverage() {
  go tool cover -func="$1" 2> "$2" | awk '
    $1 != "total:" {
      gsub(":", "", $1)
      split($1, parts, "/")

      # Top-level package = module + first directory
      pkg = parts[1] "/" parts[2] "/" parts[3] "/" parts[4]

      cov = $NF
      gsub("%", "", cov)

      sum[pkg] += cov
      count[pkg]++
    }
    END {
      for (p in count) {
        printf "%s %.2f\n", p, sum[p] / count[p]
      }
    }
  '
}

ok1=1
ok2=1

if ! extract_top_pkg_coverage "$f1" "$err1" | sort > "$tmp1"; then
  ok1=0
fi

if ! extract_top_pkg_coverage "$f2" "$err2" | sort > "$tmp2"; then
  ok2=0
fi

# If both failed, abort early (still print errors)
if [ "$ok1" -eq 0 ] && [ "$ok2" -eq 0 ]; then
  echo "ERROR: coverage extraction failed for both inputs" >&2
  cat "$err1" "$err2" >&2
  exit 1
fi

# Markdown header
if [ "$NO_HEADER" -eq 0 ]; then
  echo "| Top Package | Coverage 1 | Coverage 2 | Diff |"
fi

# Results
echo "|------------|------------|------------|------|"
join -a1 -a2 -e "0.00" -o 0,1.2,2.2 "$tmp1" "$tmp2" \
  | awk '{
      diff = $3 - $2
      printf "| %s | %.2f%% | %.2f%% | %+0.2f%% |\n", $1, $2, $3, diff
    }'

# Report files that appear in one profile but not the other.
# comm requires sorted input; list_profile_files guarantees that via sort -u.
only_in_1=$(comm -23 "$files1" "$files2")
only_in_2=$(comm -13 "$files1" "$files2")

if [ -n "$only_in_1" ] || [ -n "$only_in_2" ]; then
  echo
  if [ -n "$only_in_1" ]; then
    echo "Files removed (only in \`$(basename "$COV1")\`):"
    echo "$only_in_1" | sed 's/^/- /'
  fi
  if [ -n "$only_in_1" ] && [ -n "$only_in_2" ]; then
    echo
  fi
  if [ -n "$only_in_2" ]; then
    echo "Files added (only in \`$(basename "$COV2")\`):"
    echo "$only_in_2" | sed 's/^/- /'
  fi
fi

# Emit any unexpected stderr from go tool cover after the results.
# Missing-file errors are handled above and should not appear here.
if [ -s "$err1" ] || [ -s "$err2" ]; then
  echo
  if [ -s "$err1" ]; then
    echo "WARNING: go tool cover failed for $COV1"
    cat "$err1"
  fi
  if [ -s "$err2" ]; then
    echo "WARNING: go tool cover failed for $COV2"
    cat "$err2"
  fi
fi
