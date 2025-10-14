FROM golang:1.24.6-alpine AS builder
WORKDIR /
COPY . .
WORKDIR /common/cmd/executor
RUN go mod download
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/executor main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/executor /bin/
CMD ["/bin/executor"]
