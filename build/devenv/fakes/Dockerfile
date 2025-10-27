# syntax=docker/dockerfile:1.7
FROM golang:1.25.3 AS builder

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

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /fake /fake
EXPOSE 9111
CMD ["/fake"]
