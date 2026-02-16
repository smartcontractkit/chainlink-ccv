# syntax=docker/dockerfile:1.7
# Base image: jdwatcher only. Intended for use as FROM in other repositories.
#
# Consumer repos (that import chainlink-ccv and have their own main.go) should:
#   1. Use this image as base: FROM <registry>/chainlink-ccv-jdwatcher:<tag>
#   2. Build their worker binary in a builder stage and COPY it into the image
#      at a path of their choice (e.g. /bin/worker).
#   3. Set process_binary_path in config to that path at runtime.
#
# See Dockerfile.consumer-example for a copy-paste Dockerfile for consumer repos.
# For building jdwatcher + a child binary inside this repo, use Dockerfile.watcher-app.
FROM golang:1.25.5-alpine AS builder
WORKDIR /

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .
WORKDIR /cmd/jdwatcher
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/jdwatcher main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/jdwatcher /bin/
CMD ["/bin/jdwatcher"]
