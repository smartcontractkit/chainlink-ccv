#!/usr/bin/env bash
set -euo pipefail

# Renders the published policy hook contract as browsable markdown.
#
# The YAML is the source of truth an operator builds against, but it is not the thing to hand
# someone who is reading the contract for the first time. This produces the reading surface:
# one page per schema, with the field tables and the descriptions already written in the spec.
#
# Output is committed. `just generate` runs this, and the repo-hygiene job fails if the result
# differs from what is checked in, so the docs cannot drift from the spec.
#
# Paths are anchored to this script rather than to the caller's working directory. go generate
# always runs it from the package directory, so the two agree there, but the script is executable
# and someone will eventually run it from the repo root; mounting the wrong directory there would
# fail to find the spec rather than do anything useful.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

docker run --rm \
  -v "${script_dir}:/local" \
  openapitools/openapi-generator-cli:v7.19.0 generate \
  -i /local/policy_hook_openapi_v1.yaml \
  -g markdown \
  -o /local/docs/policy_hook_api
