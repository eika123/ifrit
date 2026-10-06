# Stage 1: Build binaries
FROM docker.io/library/golang:1.24-alpine AS builder

WORKDIR /build

# Copy dependency files and source code
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the CA daemon
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/bin/ifrit-ca ./cmd/ca

# Build the gossip content example node
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/bin/gossip-node ./_examples/gossipContentExample.go

# Stage 2: Minimal runtime image
FROM docker.io/library/alpine:3.20

# iproute2 is for traffic control and network utilities (tc)
# to simulate packet loss, jitter, corruption etc.
RUN apk --no-cache add ca-certificates bash iproute2

WORKDIR /app

COPY --from=builder /build/bin/ifrit-ca /usr/local/bin/ifrit-ca
COPY --from=builder /build/bin/gossip-node /usr/local/bin/gossip-node

# Copy default config template
COPY ifrit_config.yaml /app/ifrit_config.yaml

# Entrypoint default
CMD ["gossip-node"]
