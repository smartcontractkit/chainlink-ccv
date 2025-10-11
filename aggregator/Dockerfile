# syntax=docker/dockerfile:1.7
FROM golang:1.24.6-alpine AS builder
WORKDIR /app
COPY aggregator/go.mod aggregator/go.sum ./
WORKDIR /
COPY protocol/ ./protocol/
COPY common/ ./common/
WORKDIR /app
ENV GOWORK=off
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /protocol && go mod download
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /app && go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd aggregator && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/aggregator cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/aggregator /bin/
CMD ["/bin/aggregator"]
