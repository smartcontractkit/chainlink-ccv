# syntax=docker/dockerfile:1.7
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder
WORKDIR /app

# Copy module files first to maximize cache reuse across apps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    go mod download

# Then copy the rest of the source and build
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build,id=ccv-go-build \
    --mount=type=cache,target=/go/pkg/mod,id=ccv-go-mod \
    cd aggregator && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/aggregator cmd/main.go

# Stage the /app/migrations symlink for the final image, which has no shell to create it
RUN mkdir -p /staging/app && ln -s /migrations /staging/app/migrations

# 65532 is the nonroot user provided by the distroless base image.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

COPY --chown=65532:65532 --from=builder /bin/aggregator /bin/
COPY --chown=65532:65532 --from=builder /app/aggregator/migrations /migrations
COPY --from=builder /app/aggregator/LICENSE /licenses/chainlink-ccv/LICENSE
# Staged in the builder: /app/migrations as a symlink to /migrations (no shell here).
COPY --from=builder /staging/app /app
WORKDIR /app
USER 65532:65532
CMD ["/bin/aggregator"]
