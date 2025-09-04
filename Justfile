# Default: show available recipes
default:
    just --list

install-protoc:
    sudo ./tools/bin/install-protoc.sh 32.0

install-go-tools:
    go install github.com/jmank88/gomods@v0.1.6
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.8
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
    go install github.com/bufbuild/buf/cmd/buf@v1.57.0
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0
    go install github.com/vektra/mockery/v2@v2.53.5

lint-all:
    @just ./verifier/lint
    @just ./executor/lint
    @just ./aggregator/lint
    @just ./indexer/lint
    @just ./build/devenv/lint

mod-tidy-all:
    gomods tidy