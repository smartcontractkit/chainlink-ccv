#!/usr/bin/env bash
docker run --rm \
  -v "${PWD}:/local" \
  openapitools/openapi-generator-cli generate \
  -i /local/indexer_opanapi_v1.yaml \
  -g markdown \
  -o /local/docs
