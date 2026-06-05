# syntax=docker/dockerfile:1.7
FROM golang:1.26.2 AS builder

ENV GOPRIVATE=github.com/smartcontractkit/*

WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download
WORKDIR /app/build/devenv/fakes
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    CGO_ENABLED=0 GOOS=linux go build -o /fake cmd/main.go

FROM alpine:3.23
RUN apk --no-cache add ca-certificates

# Create a non-root user and group for running the application
RUN addgroup -S fakes && adduser -S fakes -G fakes

COPY --chown=fakes:fakes --from=builder /fake /fake
USER fakes:fakes
EXPOSE 9111
CMD ["/fake"]
