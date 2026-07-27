#!/usr/bin/env bash

set -euo pipefail

readonly policy_dir=".github/licenses"
readonly allowed_licenses_file="${policy_dir}/allowed-licenses.txt"
readonly ignored_packages_file="${policy_dir}/ignored-packages.txt"
readonly exception_modules_file="${policy_dir}/exception-modules.txt"

usage() {
  echo "Usage: $0 [--update-exception-versions]" >&2
}

update_exception_versions() {
  local actual_version
  local actual_replacement
  local expected_version
  local expected_replacement
  local module
  local replacement_module
  local temporary_file

  temporary_file="$(mktemp)"
  trap 'rm -f "${temporary_file}"' EXIT

  {
    echo "# Module versions covered by the matching entries in ignored-packages.txt. An optional"
    echo "# replacement module path and version pins the source selected by a Go replace directive."
    echo "# Update only with Legal approval after reviewing the new version."
    while IFS=' ' read -r module expected_version replacement_module expected_replacement; do
      [[ -z "${module}" || "${module}" == \#* ]] && continue
      actual_version="$(go list -m -f '{{.Version}}' "${module}")"
      if [[ -n "${replacement_module}" ]]; then
        actual_replacement="$(go list -m -f '{{if .Replace}}{{.Replace.Path}} {{.Replace.Version}}{{end}}' "${module}")"
        echo "${module} ${actual_version} ${actual_replacement}"
      else
        echo "${module} ${actual_version}"
      fi
    done < "${exception_modules_file}"
  } > "${temporary_file}"

  mv "${temporary_file}" "${exception_modules_file}"
  trap - EXIT
  echo "Updated ${exception_modules_file}; obtain Legal approval before committing the changes."
}

case "${1:-}" in
  "")
    ;;
  --update-exception-versions)
    update_exception_versions
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

for policy_file in "${allowed_licenses_file}" "${ignored_packages_file}" "${exception_modules_file}"; do
  if [[ ! -f "${policy_file}" ]]; then
    echo "::error title=Dependency license policy is missing::Expected ${policy_file}."
    exit 1
  fi
done

mapfile -t allowed_licenses < <(grep -Ev '^[[:space:]]*(#|$)' "${allowed_licenses_file}")
mapfile -t ignored_packages < <(grep -Ev '^[[:space:]]*(#|$)' "${ignored_packages_file}")

if [[ ${#allowed_licenses[@]} -eq 0 ]]; then
  echo "::error title=Dependency license policy is empty::Add an approved SPDX identifier."
  exit 1
fi

while IFS=' ' read -r module expected_version replacement_module expected_replacement; do
  [[ -z "${module}" || "${module}" == \#* ]] && continue
  actual_version="$(go list -m -f '{{.Version}}' "${module}")"
  if [[ "${actual_version}" != "${expected_version}" ]]; then
    echo "::error title=Dependency license exception expired::${module} changed from ${expected_version} to ${actual_version}. Legal review is required."
    exit 1
  fi
  if [[ -n "${replacement_module}" ]]; then
    actual_replacement="$(go list -m -f '{{if .Replace}}{{.Replace.Path}} {{.Replace.Version}}{{end}}' "${module}")"
    if [[ "${actual_replacement}" != "${replacement_module} ${expected_replacement}" ]]; then
      echo "::error title=Dependency license exception expired::${module} replacement changed from ${replacement_module} ${expected_replacement} to ${actual_replacement}. Legal review is required."
      exit 1
    fi
  fi
done < "${exception_modules_file}"

args=(check ./... "--allowed_licenses=$(IFS=,; echo "${allowed_licenses[*]}")" --ignore github.com/smartcontractkit/chainlink-ccv)
for package in "${ignored_packages[@]}"; do
  args+=(--ignore "${package}")
done

echo "Checking root Go module dependencies against the approved license allowlist."
license_output="$(mktemp)"
if ! go-licenses "${args[@]}" > "${license_output}" 2>&1; then
  while IFS= read -r line; do
    echo "${line}"
  done < "${license_output}"
  rm -f "${license_output}"
  echo "::error title=Unapproved dependency license::Review the rejected dependency above. GPL, unknown, and unlisted licenses are blocked."
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## Dependency license check failed"
      echo
      echo "A dependency has an unapproved, unknown, or unclassified license."
      echo "Review the error above and the policy at \`.github/licenses/README.md\`."
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
  exit 1
fi
rm -f "${license_output}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Dependency license check passed"
    echo
    echo "All scanned root-module dependencies use an approved license."
  } >> "${GITHUB_STEP_SUMMARY}"
fi

echo "Dependency license check passed."
