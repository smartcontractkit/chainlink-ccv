FROM golang:1.24.6-alpine AS builder
WORKDIR /app
COPY . .
COPY executor/go.mod executor/go.sum ./
WORKDIR /
COPY protocol/ ./protocol/
WORKDIR /app
RUN go mod download
RUN cd executor && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/executor cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/executor /bin/
CMD ["/bin/executor"]