# syntax=docker/dockerfile:1.7
FROM golang:1.24.6-alpine AS builder
WORKDIR /app

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    cd aggregator && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/aggregator cmd/main.go

FROM alpine:latest
WORKDIR /app
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/aggregator bin/
COPY --from=builder /app/aggregator/migrations /migrations
RUN ln -s /migrations /app/migrations || true
CMD ["/app/bin/aggregator"]
