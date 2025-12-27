#!/usr/bin/env bash
# Compare coverage between two Go coverprofiles by top-level package.
# Usage:
#   ./cov_compare.sh [--no-header] OLD.cov NEW.cov
#
# Example:
#   ./cov_compare.sh coverage.out coverage_new.out
#   ./cov_compare.sh --no-header coverage.out coverage_new.out

set -euo pipefail

NO_HEADER=0
ARGS=""

# Parse optional flags
for arg in "$@"; do
  case "$arg" in
    --no-header)
      NO_HEADER=1
      ;;
    *)
      ARGS="$ARGS $arg"
      ;;
  esac
done

# Reset positional parameters
set -- $ARGS

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 [--no-header] coverage1.out coverage2.out"
  exit 1
fi

COV1="$1"
COV2="$2"

tmp1=$(mktemp)
tmp2=$(mktemp)

cleanup() {
  rm -f "$tmp1" "$tmp2"
}
trap cleanup EXIT

# Extract top-level package coverage (simple average)
extract_top_pkg_coverage() {
  go tool cover -func="$1" | awk '
    $1 != "total:" {
      # Remove trailing colon from file path
      gsub(":", "", $1)

      # Split path
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

extract_top_pkg_coverage "$COV1" | sort > "$tmp1"
extract_top_pkg_coverage "$COV2" | sort > "$tmp2"

if [ "$NO_HEADER" -eq 0 ]; then
  echo "| Top Package | Coverage 1 | Coverage 2 | Diff |"
fi

echo "|------------|------------|------------|-------|"

join -a1 -a2 -e "0.00" -o 0,1.2,2.2 "$tmp1" "$tmp2" \
  | awk '{
      diff = $3 - $2
      printf "| %s | %.2f%% | %.2f%% | %+0.2f%% |\n", $1, $2, $3, diff
    }'
