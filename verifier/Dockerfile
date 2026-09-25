# syntax=docker/dockerfile:1.7
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
WORKDIR /

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .

ARG VERIFIER_TYPE=committee
WORKDIR /cmd/verifier/${VERIFIER_TYPE}

RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/verifier main.go

# Static tini for the final image, which has no package manager
RUN apk --no-cache add tini-static

# 65532 is the nonroot user provided by the distroless base image.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --from=builder /sbin/tini-static /sbin/tini
COPY --chown=65532:65532 --from=builder /bin/verifier /bin/
COPY --from=builder /verifier/LICENSE /licenses/chainlink-ccv/LICENSE
USER 65532:65532

# tini stays PID 1 because namespace init ignores SIGSTOP; quiescing the
# verifier (`/bin/verifier ccv quiesce pause`) only works on a child process.
ENTRYPOINT ["/sbin/tini", "--", "/bin/verifier"]
