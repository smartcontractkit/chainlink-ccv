FROM golang:1.24.6-alpine AS builder
WORKDIR /
COPY . .
WORKDIR /common
RUN go mod download
RUN CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/verifier cmd/verifier/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/verifier /bin/
CMD ["/bin/verifier"]
