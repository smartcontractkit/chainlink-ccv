#!/usr/bin/env bash
set -euo pipefail

go get github.com/googleapis/googleapis
 
protoc -Iproto -I"$(go list -m -f '{{.Dir}}' github.com/googleapis/googleapis)" \
  --go_out=paths=source_relative:./pb/aggregator \
  --go-grpc_out=paths=source_relative:./pb/aggregator \
  proto/aggregator.proto