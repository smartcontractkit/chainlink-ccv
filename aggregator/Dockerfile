FROM golang:1.24.6-alpine AS builder
WORKDIR /app
COPY . .
WORKDIR /
COPY protocol/ ./protocol/
COPY common/ ./common/
WORKDIR /app
RUN go mod download
RUN cd aggregator && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/aggregator cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/aggregator /bin/
CMD ["/bin/aggregator"]
