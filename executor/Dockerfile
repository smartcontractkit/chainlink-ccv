FROM golang:1.24.6-alpine AS builder
WORKDIR /
COPY . .
WORKDIR /app
COPY . .
COPY ../common/go.mod ../common/go.sum ./
RUN go mod download
RUN cd common && CGO_ENABLED=0 go build -ldflags='-s -w' -o /bin/executor cmd/executor/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /bin/executor /bin/
CMD ["/bin/executor"]
