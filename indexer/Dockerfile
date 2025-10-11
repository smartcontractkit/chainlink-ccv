FROM golang:1.24.6-alpine AS builder
WORKDIR /app
COPY indexer/go.mod indexer/go.sum ./
WORKDIR /
COPY protocol/ ./protocol/
COPY common/ ./common/
WORKDIR /app
RUN go mod download
COPY . .
RUN cd indexer && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/indexer cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/indexer /bin/
CMD ["/bin/indexer"]
