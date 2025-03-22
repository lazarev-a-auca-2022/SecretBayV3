FROM golang:1.21-alpine AS builder

# Install git and CA certificates
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod .
COPY go.sum .

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o /app/secretbay ./cmd/secretbay

# Use a minimal alpine image for the final stage
FROM alpine:3.18

# Add necessary runtime packages
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN adduser -D -H -h /app appuser

# Create data directory with proper permissions
RUN mkdir -p /app/data/temp/public && \
    chown -R appuser:appuser /app

# Set working directory
WORKDIR /app

# Copy binary from builder stage with explicit paths
COPY --from=builder /app/secretbay /app/

# Run a test to ensure the binary exists
RUN ls -la /app && test -f /app/secretbay

# Set proper permissions
RUN chmod +x /app/secretbay

# Handle config file using shell command
RUN echo "Checking for config file..." && \
    mkdir -p /tmp && \
    if [ -f /app/config.json ]; then \
        echo "Config file found, copying..."; \
        cp /app/config.json /app/; \
    else \
        echo "No config file found."; \
    fi

# Set user to non-root
USER appuser

# Expose port
EXPOSE 8080

# Set entry point
CMD ["/app/secretbay"] 