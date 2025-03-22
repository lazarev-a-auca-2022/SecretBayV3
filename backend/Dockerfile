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
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o secretbay ./cmd/secretbay

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

# Copy binary from builder stage
COPY --from=builder /app/secretbay .

# Optionally copy config file - no direct COPY that might fail
RUN mkdir -p /tmp/config && \
    test -f /builder/app/config.json && cp /builder/app/config.json . || echo "No config file found."

# Set user to non-root
USER appuser

# Expose port
EXPOSE 8080

# Set entry point
CMD ["./secretbay"] 