# Build stage
FROM golang:1.25.5-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev linux-headers

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the CLI binary
RUN make build-cli

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 warp && \
    adduser -u 1000 -G warp -s /bin/sh -D warp

# Copy binary from builder
COPY --from=builder /build/build/warp-cli /usr/local/bin/warp

# Set ownership
RUN chown -R warp:warp /usr/local/bin/warp

# Switch to non-root user
USER warp

# Set entrypoint
ENTRYPOINT ["warp"]

# Default command shows help
CMD ["--help"]