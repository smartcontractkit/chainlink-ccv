# syntax=docker/dockerfile:1.7
# Builder base is digest-pinned so image builds are reproducible and the base
# is supply-chain verifiable; dependabot bumps the digest in its grouped weekly PR.
FROM golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS builder

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

# 65532 is the nonroot user provided by the distroless base image.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --chown=65532:65532 --from=builder /fake /fake
USER 65532:65532
EXPOSE 9111
CMD ["/fake"]
