# syntax=docker/dockerfile:1.7
FROM golang:1.26.2-alpine AS builder
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

FROM alpine:3.23
RUN apk --no-cache add ca-certificates

# Create a non-root user and group for running the application
RUN addgroup -S aggregator && adduser -S aggregator -G aggregator

COPY --chown=aggregator:aggregator --from=builder /bin/aggregator /bin/
COPY --chown=aggregator:aggregator --from=builder /app/aggregator/migrations /migrations
WORKDIR /app
RUN chown aggregator:aggregator /app && ln -s /migrations /app/migrations || true
USER aggregator:aggregator
CMD ["/bin/aggregator"]
