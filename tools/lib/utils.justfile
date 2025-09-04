ensure-go:
    @go version | grep -q 'go1.24.6' || (echo "Please use go1.24.6 (just install-go-tools)" && exit 1)

ensure-golangci-lint:
	@golangci-lint --version | grep -q '2.4.0' || (echo "Please use golangci-lint 2.4.0 (just install-go-tools)" && exit 1)

ensure-protoc:
	@protoc --version | grep -q 'libprotoc 32.0' || (echo "Please use protoc 32.0 (just install-go-tools)" && exit 1)
	@protoc-gen-go --version | grep -q 'protoc-gen-go v1.36.8' || (echo "Please use protoc-gen-go v1.36.8 (just install-go-tools)" && exit 1)
	@protoc-gen-go-grpc --version | grep -q 'protoc-gen-go-grpc 1.5.1' || (echo "Please use protoc-gen-go v1.36.8 (just install-go-tools)" && exit 1)

ensure-buf:
	@buf --version | grep -q '1.57.0' || (echo "Please use buf 1.57.0 (just install-go-tools)" && exit 1)

ensure-mockery:
	@mockery --version | grep -q 'v2.53.5' || (echo "Please use mockery v2.53.5 (just install-go-tools)" && exit 1)