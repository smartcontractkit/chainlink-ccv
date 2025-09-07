FROM golang:1.24.6-alpine AS builder
WORKDIR /app
COPY . .
COPY verifier/go.mod verifier/go.sum ./
WORKDIR /
COPY protocol/ ./protocol/
COPY common/ ./common/
WORKDIR /app
RUN go mod download
RUN cd verifier && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/verifier cmd/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/verifier /bin/
CMD ["/bin/verifier"]