#!/usr/bin/env bash
# Compare coverage between two Go coverprofiles by top-level package.
# Usage:
#   ./cov_compare.sh [--no-header] [--label1=NAME] [--label2=NAME] OLD.cov NEW.cov
#
# Example:
#   ./cov_compare.sh --label1=main --label2=my-branch coverage.out coverage_new.out

NO_HEADER=0
LABEL1=""
LABEL2=""

# Collect non-flag arguments in an array so they remain separate when
# resetting positional parameters with `set --`.
ARGS=()

# Parse optional flags
for arg in "$@"; do
  case "$arg" in
    --no-header)
      NO_HEADER=1
      ;;
    --label1=*)
      LABEL1="${arg#--label1=}"
      ;;
    --label2=*)
      LABEL2="${arg#--label2=}"
      ;;
    *)
      ARGS+=("$arg")
      ;;
  esac
done

# Reset positional parameters
set -- "${ARGS[@]}"

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 [--no-header] [--label1=NAME] [--label2=NAME] coverage1.out coverage2.out" >&2
  exit 1
fi

COV1="$1"
COV2="$2"

# Default labels to the filename if not provided.
LABEL1="${LABEL1:-$(basename "$COV1")}"
LABEL2="${LABEL2:-$(basename "$COV2")}"

# Locate the module root and import path so coverage import paths can be
# resolved to filesystem paths for existence checks.
MODULE_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
MODULE_PATH=$(grep '^module ' "$MODULE_ROOT/go.mod" 2>/dev/null | awk '{print $2}' | head -1)

# List all unique source-file import paths referenced in a coverage profile.
list_profile_files() {
  grep -v '^mode:' "$1" | cut -d: -f1 | sort | uniq
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
    local rel="${pkg_file#"${MODULE_PATH}"/}"
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
raw1=$(mktemp)
raw2=$(mktemp)
err1=$(mktemp)
err2=$(mktemp)
files1=$(mktemp)
files2=$(mktemp)

cleanup() {
  rm -f "$tmp1" "$tmp2" "$f1" "$f2" "$raw1" "$raw2" "$err1" "$err2" "$files1" "$files2"
}
trap cleanup EXIT

# Snapshot file lists before filtering (used for the added/removed report).
list_profile_files "$COV1" > "$files1"
list_profile_files "$COV2" > "$files2"

# Build filtered profiles so go tool cover won't abort on missing files.
filter_missing_files "$COV1" > "$f1"
filter_missing_files "$COV2" > "$f2"

ok1=1
ok2=1

# Run go tool cover once per profile; reuse the output for both per-package
# breakdown and the overall total line.
go tool cover -func="$f1" > "$raw1" 2>"$err1" || ok1=0
go tool cover -func="$f2" > "$raw2" 2>"$err2" || ok2=0

# If both failed, abort early (still print errors)
if [ "$ok1" -eq 0 ] && [ "$ok2" -eq 0 ]; then
  echo "ERROR: coverage extraction failed for both inputs" >&2
  cat "$err1" "$err2" >&2
  exit 1
fi

# Extract top-level package coverage (simple average) from captured output.
extract_top_pkg_coverage() {
  awk '
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
  ' "$1"
}

extract_top_pkg_coverage "$raw1" | sort > "$tmp1"
extract_top_pkg_coverage "$raw2" | sort > "$tmp2"

# Extract the overall total coverage percentage from the "total:" line.
total1=$(awk '$1 == "total:" { gsub("%", "", $NF); print $NF }' "$raw1")
total2=$(awk '$1 == "total:" { gsub("%", "", $NF); print $NF }' "$raw2")

# Markdown header
if [ "$NO_HEADER" -eq 0 ]; then
  echo "| Package | \`${LABEL1}\` | \`${LABEL2}\` | Diff |"
fi

# Results
echo "|------------|------------|------------|------|"
join -a1 -a2 -e "0.00" -o 0,1.2,2.2 "$tmp1" "$tmp2" \
  | awk '{
      diff = $3 - $2
      emoji = (diff <= -10) ? " ⚠️" : (diff >= 10) ? " 🎉" : ""
      printf "| %s | %.2f%% | %.2f%% | %+0.2f%%%s |\n", $1, $2, $3, diff, emoji
    }'

# Overall total row (covers only files present on the current filesystem).
if [ -n "$total1" ] || [ -n "$total2" ]; then
  t1="${total1:-0.00}"
  t2="${total2:-0.00}"
  awk -v t1="$t1" -v t2="$t2" 'BEGIN {
    diff = t2 - t1
    emoji = (diff <= -10) ? " ⚠️" : (diff >= 10) ? " 🎉" : ""
    printf "| **Total** | %.2f%% | %.2f%% | %+.2f%%%s |\n", t1, t2, diff, emoji
  }'
fi

# Report files that appear in one profile but not the other.
# comm requires sorted input; list_profile_files guarantees that via sort | uniq.
only_in_1=$(comm -23 "$files1" "$files2")
only_in_2=$(comm -13 "$files1" "$files2")

if [ -n "$only_in_1" ] || [ -n "$only_in_2" ]; then
  echo
  if [ -n "$only_in_1" ]; then
    echo "Files removed (from \`${LABEL1}\`):"
    echo "- ${only_in_1//$'\n'/$'\n- '}"
  fi
  if [ -n "$only_in_1" ] && [ -n "$only_in_2" ]; then
    echo
  fi
  if [ -n "$only_in_2" ]; then
    echo "Files added (in \`${LABEL2}\`):"
    echo "- ${only_in_2//$'\n'/$'\n- '}"
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
