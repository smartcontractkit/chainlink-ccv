# syntax=docker/dockerfile:1.7
FROM golang:1.24.6-alpine AS builder
WORKDIR /
COPY protocol/ ./protocol/
COPY common/ ./common/
COPY executor/ ./executor/
WORKDIR /app
COPY common/go.mod common/go.sum ./
ENV GOWORK=off
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /protocol && go mod download
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd /app && go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build cd common && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/executor cmd/executor/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/executor /bin/
CMD ["/bin/executor"]
