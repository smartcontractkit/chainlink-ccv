# syntax=docker/dockerfile:1.7
# Builder base is digest-pinned so image builds are reproducible and the base
# is supply-chain verifiable; dependabot bumps the digest in its grouped weekly PR.
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder
WORKDIR /

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .
WORKDIR /pricer/cmd
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o /bin/pricer main.go

# The final base is digest-pinned so the shipped image is supply-chain verifiable
# (dependabot bumps it weekly); 65532 is the nonroot user it provides.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --chown=65532:65532 --from=builder /bin/pricer /bin/
USER 65532:65532
ENTRYPOINT ["/bin/pricer"]
