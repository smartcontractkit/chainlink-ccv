# syntax=docker/dockerfile:1.7
FROM golang:1.24.6-alpine AS builder
WORKDIR /app
COPY common/go.mod common/go.sum ./
WORKDIR /
# Copy dependencies in order of stability for optimal cache efficiency
# Protocol module - rarely changes, copied first for best cache hits
COPY protocol/ ./protocol/
# Common module - depends on protocol, executor, and verifier via replace directives
COPY common/ ./common/
# Executor module - required by common/go.mod replace directive: ../executor
COPY executor/ ./executor/
# Verifier module - required by common/go.mod replace directive: ../verifier
COPY verifier/ ./verifier/
WORKDIR /app
ENV GOWORK=off
# Download dependencies for each module in dependency order
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /protocol && go mod download
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /common && go mod download
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go mod download
# Copy executor source code last (changes most frequently)
COPY executor/ ./executor/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd executor && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/executor cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/executor /bin/
CMD ["/bin/executor"]
