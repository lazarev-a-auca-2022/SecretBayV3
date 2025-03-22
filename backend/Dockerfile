FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /build

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application with explicit output name
RUN go build -o main ./cmd/secretbay/main.go

# Create a minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

# Create app directory
RUN mkdir /app

# Copy the binary from builder stage
COPY --from=builder /build/main /app/main

# Check that the binary exists and is executable
RUN ls -la /app/main && chmod +x /app/main

# Set working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/data/temp/public

# Expose the port
EXPOSE 8080

# Run the binary
CMD ["/app/main"] 