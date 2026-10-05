#!/usr/bin/env bash
set -euo pipefail

# Renders the indexer API spec as browsable markdown.
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
  -i /local/indexer_opanapi_v1.yaml \
  -g markdown \
  -o /local/docs
