import './tools/lib/utils.justfile'

# Default: show available recipes
default:
    just --list

install-protoc:
    sudo ./tools/bin/install-protoc.sh $VERSION_PROTOC

install-go-tools:
    go install github.com/jmank88/gomods@v$VERSION_GOMODS
    go install github.com/jmank88/modgraph@v$VERSION_MODGRAPH
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v$VERSION_PROTOC_GEN_GO
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$VERSION_PROTOC_GEN_GO_GRPC
    go install github.com/bufbuild/buf/cmd/buf@v$VERSION_BUF
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$VERSION_GOLANGCI_LINT
    go install github.com/vektra/mockery/v2@v$VERSION_MOCKERY

install-pre-commit:
    brew install pre-commit
    pre-commit install

mod-tidy: ensure-go
    go mod tidy

# Run go test on all modules.
test-all: mod-tidy
    @echo "Testing verifier"
    @just ./verifier/test
    @echo "Testing executor"
    @just ./executor/test

lint fix="": ensure-golangci-lint
    golangci-lint run --output.text.path stdout {{ if fix != "" { "--fix" } else { "" } }}

lint-all fix="": lint
    @echo "Linting protocol"
    @just ./protocol/lint {{fix}}
    @echo "Linting verifier"
    @just ./verifier/lint {{fix}}
    @echo "Linting executor"
    @just ./executor/lint {{fix}}
    @echo "Linting devenv"
    @just ./build/devenv/lint {{fix}}

fmt: ensure-golangci-lint
    golangci-lint fmt

mod-tidy-all: ensure-gomods
    gomods tidy
    ./tools/bin/modgraph.sh > go.md

test: ensure-go
    go test -v -race ./...

test-coverage:
    go test -v -race -coverprofile=coverage.out ./...
