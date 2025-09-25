module github.com/smartcontractkit/chainlink-ccv/aggregator

go 1.24.6

replace (
	github.com/smartcontractkit/chainlink-ccv/common => ../common
	github.com/smartcontractkit/chainlink-ccv/protocol => ../protocol
)

require (
	github.com/BurntSushi/toml v1.5.0
	github.com/ethereum/go-ethereum v1.16.3
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0
	github.com/google/uuid v1.6.0
	github.com/grafana/pyroscope-go v1.2.7
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.1.0
	github.com/oklog/run v1.0.0
	github.com/smartcontractkit/chainlink-ccv/common v0.0.0-00010101000000-000000000000
	github.com/smartcontractkit/chainlink-ccv/protocol v0.0.0-00010101000000-000000000000
	github.com/smartcontractkit/chainlink-common v0.9.4
	github.com/stretchr/testify v1.11.1
	go.opentelemetry.io/otel/metric v1.37.0
	go.opentelemetry.io/otel/sdk/metric v1.37.0
	go.uber.org/zap v1.27.0
	google.golang.org/grpc v1.75.0
)

require (
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cloudevents/sdk-go/binding/format/protobuf/v2 v2.16.1 // indirect
	github.com/cloudevents/sdk-go/v2 v2.16.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.25.0 // indirect
	github.com/grafana/pyroscope-go/godeltaprof v0.1.9 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.1 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/smartcontractkit/chainlink-common/pkg/chipingress v0.0.1 // indirect
	github.com/smartcontractkit/libocr v0.0.0-20250408131511-c90716988ee0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.10.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.10.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdoutlog v0.13.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdoutmetric v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.34.0 // indirect
	go.opentelemetry.io/otel/log v0.13.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk/log v0.13.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.opentelemetry.io/proto/otlp v1.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
