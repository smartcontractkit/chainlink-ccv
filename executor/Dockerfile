# syntax=docker/dockerfile:1.7
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
WORKDIR /

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .
WORKDIR /cmd/executor/standalone
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/executor main.go

# 65532 is the nonroot user provided by the distroless base image.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --chown=65532:65532 --from=builder /bin/executor /bin/
USER 65532:65532
CMD ["/bin/executor"]
