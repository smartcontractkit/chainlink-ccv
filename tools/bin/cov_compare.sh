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

tmp1=$(mktemp)
tmp2=$(mktemp)
err1=$(mktemp)
err2=$(mktemp)

cleanup() {
  rm -f "$tmp1" "$tmp2" "$err1" "$err2"
}
trap cleanup EXIT

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

if ! extract_top_pkg_coverage "$COV1" "$err1" | sort > "$tmp1"; then
  ok1=0
fi

if ! extract_top_pkg_coverage "$COV2" "$err2" | sort > "$tmp2"; then
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

# Emit errors AFTER results, separated by a blank line
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
