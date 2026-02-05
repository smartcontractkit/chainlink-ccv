# syntax=docker/dockerfile:1.7
FROM golang:1.25.6-alpine AS builder
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

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/verifier /bin/
CMD ["/bin/verifier"]
