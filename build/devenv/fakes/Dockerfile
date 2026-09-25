# syntax=docker/dockerfile:1.7
FROM golang:1.26.6@sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6 AS builder

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
