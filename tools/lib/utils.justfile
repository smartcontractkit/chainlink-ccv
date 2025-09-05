set dotenv-filename := "tool-versions.env"
set dotenv-required

ensure-go:
    @go version | grep -q "go$VERSION_GO" || (echo "Please use go$VERSION_GO (just install-go-tools)" && exit 1)

ensure-golangci-lint:
	@golangci-lint --version | grep -q '2.4.0' || (echo "Please use golangci-lint 2.4.0 (just install-go-tools)" && exit 1)

ensure-protoc:
	@protoc --version | grep -q "libprotoc $VERSION_PROTOC" || (echo "Please use protoc $VERSION_PROTOC (just install-go-tools)" && exit 1)
	@protoc-gen-go --version | grep -q "protoc-gen-go v$VERSION_PROTOC_GEN_GO" || (echo "Please use protoc-gen-go v$VERSION_PROTOC_GEN_GO (just install-go-tools)" && exit 1)
	@protoc-gen-go-grpc --version | grep -q "protoc-gen-go-grpc $VERSION_PROTOC_GEN_GO_GRPC" || (echo "Please use protoc-gen-go-grpc v$VERSION_PROTOC_GEN_GO_GRPC (just install-go-tools)" && exit 1)

ensure-buf:
	@buf --version | grep -q "$VERSION_BUF" || (echo "Please use buf v$VERSION_BUF (just install-go-tools)" && exit 1)

ensure-mockery:
	@mockery --version | grep -q "v$VERSION_MOCKERY" || (echo "Please use mockery v$VERSION_MOCKERY (just install-go-tools)" && exit 1)