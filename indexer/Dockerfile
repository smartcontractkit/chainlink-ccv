# syntax=docker/dockerfile:1.7
# Builder base is digest-pinned so image builds are reproducible and the base
# is supply-chain verifiable; dependabot bumps the digest in its grouped weekly PR.
FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
WORKDIR /app

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .
# Build identity for the version/commit metrics; see tools/buildargs.
ARG VERSION=unset
ARG COMMIT_SHA=unset
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    cd indexer && CGO_ENABLED=0 go build \
    -ldflags="-s -w -X github.com/smartcontractkit/chainlink-ccv/common/static.Version=${VERSION} -X github.com/smartcontractkit/chainlink-ccv/common/static.Sha=${COMMIT_SHA}" \
    -o /bin/indexer cmd/main.go && \
    CGO_ENABLED=0 go build \
    -ldflags="-s -w -X github.com/smartcontractkit/chainlink-ccv/common/static.Version=${VERSION} -X github.com/smartcontractkit/chainlink-ccv/common/static.Sha=${COMMIT_SHA}" \
    -o /bin/indexer-replay cmd/replay/main.go

# The final base is digest-pinned so the shipped image is supply-chain verifiable
# (dependabot bumps it weekly); 65532 is the nonroot user it provides.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --chown=65532:65532 --from=builder /bin/indexer /bin/
COPY --chown=65532:65532 --from=builder /bin/indexer-replay /bin/
COPY --chown=65532:65532 --from=builder /app/indexer/migrations ./migrations
USER 65532:65532
CMD ["/bin/indexer"]
