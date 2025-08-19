FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=linux go build -a -installsuffix cgo -o kubesnoop ./cmd/kubesnoop

# Build from scratch https://hub.docker.com/_/scratch
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /app/kubesnoop /app/kubesnoop

USER 65534:65534

ENTRYPOINT ["/app/kubesnoop"]
