# syntax=docker/dockerfile:1.7
# Builder base is digest-pinned so image builds are reproducible and the base
# is supply-chain verifiable; dependabot bumps the digest in its grouped weekly PR.
FROM golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS builder
WORKDIR /

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .

ARG VERIFIER_TYPE=committee
# Build identity for the version/commit metrics; see tools/buildargs.
ARG VERSION=unset
ARG COMMIT_SHA=unset
WORKDIR /cmd/verifier/${VERIFIER_TYPE}

RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    CGO_ENABLED=0 go build \
    -ldflags="-s -w -X github.com/smartcontractkit/chainlink-ccv/common/static.Version=${VERSION} -X github.com/smartcontractkit/chainlink-ccv/common/static.Sha=${COMMIT_SHA}" \
    -o /bin/verifier main.go

# Static tini for the final image, which has no package manager
RUN apk --no-cache add tini-static

# The final base is digest-pinned so the shipped image is supply-chain verifiable
# (dependabot bumps it weekly); 65532 is the nonroot user it provides.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /sbin/tini-static /sbin/tini
COPY --chown=65532:65532 --from=builder /bin/verifier /bin/
COPY --from=builder /verifier/LICENSE /licenses/chainlink-ccv/LICENSE
USER 65532:65532

# tini stays PID 1 because namespace init ignores SIGSTOP; quiescing the
# verifier (`/bin/verifier ccv quiesce pause`) only works on a child process.
ENTRYPOINT ["/sbin/tini", "--", "/bin/verifier"]
