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
docker run --rm \
  -v "${PWD}:/local" \
  openapitools/openapi-generator-cli:v7.19.0 generate \
  -i /local/policy_hook_openapi_v1.yaml \
  -g markdown \
  -o /local/docs/policy_hook_api
