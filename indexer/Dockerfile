# syntax=docker/dockerfile:1.7
FROM golang:1.24.6-alpine AS builder
WORKDIR /app
COPY indexer/go.mod indexer/go.sum ./
WORKDIR /
COPY protocol/ ./protocol/
COPY common/ ./common/
WORKDIR /app
ENV GOWORK=off
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /protocol && go mod download
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /common && go mod download
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd indexer && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/indexer cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/indexer /bin/
CMD ["/bin/indexer"]
