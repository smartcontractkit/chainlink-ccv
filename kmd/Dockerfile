# syntax=docker/dockerfile:1.7
FROM golang:1.25.5-alpine AS builder
WORKDIR /

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .
WORKDIR /cmd/kmd
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/kmd main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/kmd /bin/
CMD ["/bin/kmd"]
