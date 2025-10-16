#!/usr/bin/env bash
# Compare coverage between two Go coverprofiles by top-level package.
# Usage:
#   ./cov_compare.sh [--no-header] OLD.cov NEW.cov
#
# Example:
#   ./cov_compare.sh coverage.out coverage_new.out
#   ./cov_compare.sh --no-header coverage.out coverage_new.out

set -euo pipefail

SHOW_HEADER=1

# Parse optional flag
if [[ "${1:-}" == "--no-header" ]]; then
  SHOW_HEADER=0
  shift
fi

OLD=${1:?usage: $0 [--no-header] OLD.cov NEW.cov}
NEW=${2:?usage: $0 [--no-header] OLD.cov NEW.cov}

# You can override this manually:
#   MODULE_PATH="github.com/org/repo" ./cov_compare.sh old.cov new.cov
MODULE_PATH="${MODULE_PATH:-$(go list -m -f '{{.Path}}' 2>/dev/null || echo "")}"

calc_pct_by_top_level_pkg() {
  local file=$1 mod=$2
  awk -v mod="$mod" '
    BEGIN { FS="[: ]+" }
    /^mode:/ { next }

    {
      path = $1

      # Prefer exact module stripping if known.
      if (mod != "" && index(path, mod"/") == 1) {
        sub("^"mod"/", "", path)
      } else {
        # Heuristic for github.com/org/repo/pkg/foo.go → pkg/foo.go
        split(path, a, "/")
        if (index(a[1], ".") > 0 && length(a) >= 4) {
          path = ""
          for (i=4; i<=length(a); i++) path = path (i==4 ? "" : "/") a[i]
        }
      }

      split(path, parts, "/")
      top = parts[1]

      stmts = $3 + 0
      cnt   = $4 + 0
      total[top]   += stmts
      covered[top] += (cnt > 0 ? stmts : 0)
      seen[top] = 1
    }

    END {
      for (p in seen) {
        pct = total[p] > 0 ? (covered[p] / total[p]) * 100 : 0
        printf "%s\t%.2f\n", p, pct
      }
    }
  ' "$file"
}

# Join OLD and NEW results
REPORT=$(
  join -a1 -a2 -e "0.00" -o '0,1.2,2.2' -t $'\t' \
    <(calc_pct_by_top_level_pkg "$OLD" "$MODULE_PATH" | sort -k1,1) \
    <(calc_pct_by_top_level_pkg "$NEW" "$MODULE_PATH" | sort -k1,1)
)

# Print
if (( SHOW_HEADER )); then
  printf "| %-32s | %10s | %10s |\n" "PACKAGE" "OLD" "NEW"
fi

printf "| ---- | ---- | ---- |\n"

awk '{ printf "| %-32s | %9.2f%% | %9.2f%% |\n", $1, $2, $3 }' <<<"$REPORT"
