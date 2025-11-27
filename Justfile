import './tools/lib/utils.justfile'

# Default: show available recipes
default:
    just --list

# Coverage exclusion regex for mockery-generated files
# - mock_*.go files
# - *_mocks directories
# - mocks directories
COVERAGE_EXCLUDE_REGEX := '(/mock_.*\.go:|/_mocks/.*:|/mocks/.*:)'

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

mock: ensure-mockery
    @echo "Cleaning existing mocks..."
    find . -path "*/*_mocks/*.go"
    @echo "Generating mocks with mockery..."
    find . -type f -name .mockery.yaml -execdir mockery \;

tidy: ensure-go
    gomods tidy

# Format all go files
fmt: ensure-golangci-lint
    find . -type f -name go.mod -execdir golangci-lint fmt \;

# Run golangci-lint
lint fix="": ensure-golangci-lint
    find . -type f -name go.mod -execdir golangci-lint run {{ if fix != "" { "--fix" } else { "" } }} \;


mod-download: ensure-go
    go mod download

test: ensure-go
    gomods -w go test -fullpath -shuffle on -v -race ./...

test-coverage coverage_file="coverage.out":
    # coverage_file := env_var_or_default('COVERAGE_FILE', 'coverage.out')
    go test -shuffle on -v -coverprofile={{coverage_file}} ./...
    # Filter mockery-generated files (mock_*.go) from coverage profile
    { head -n1 {{coverage_file}}; tail -n +2 {{coverage_file}} | grep -v -E '{{COVERAGE_EXCLUDE_REGEX}}' || true; } > {{coverage_file}}.filtered
    mv {{coverage_file}}.filtered {{coverage_file}}

bump-chainlink-ccip sha:
    @echo "Bumping chainlink-ccip dependencies in root..."
    go get github.com/smartcontractkit/chainlink-ccip@{{sha}}
    go get github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment@{{sha}}
    go get github.com/smartcontractkit/chainlink-ccip/deployment@{{sha}}
    go get github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment@{{sha}}
    go get github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm@{{sha}}

    @echo "Bumping chainlink-ccip dependencies in build/devenv..."
    (cd build/devenv && go get github.com/smartcontractkit/chainlink-ccip@{{sha}} && go get github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment@{{sha}} && go get github.com/smartcontractkit/chainlink-ccip/deployment@{{sha}} && go get github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm/deployment@{{sha}} && go get github.com/smartcontractkit/chainlink-ccip/ccv/chains/evm@{{sha}})

    @just tidy
    
sh:
    @just ccv sh

ccv args="sh":
    cd ./build/devenv && go run ./cmd/ccv {{args}}
