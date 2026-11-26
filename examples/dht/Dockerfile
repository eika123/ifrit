# Stage 1: Build ifrit-ca and dht-node binaries
FROM docker.io/library/golang:1.27-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/bin/ifrit-ca ./cmd/ca
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/bin/dht-node ./examples/dht

# Stage 2: Minimal runtime image
FROM docker.io/library/alpine:3.20

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /build/bin/ifrit-ca /usr/local/bin/ifrit-ca
COPY --from=builder /build/bin/dht-node /usr/local/bin/dht-node

EXPOSE 8080

CMD ["dht-node"]
