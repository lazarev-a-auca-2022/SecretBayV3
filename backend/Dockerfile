FROM golang:1.21 as builder

WORKDIR /app

COPY . .

RUN go build -o secretbay ./cmd/secretbay/main.go

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/secretbay /app/

# Create data directories
RUN mkdir -p /app/data/temp/public

EXPOSE 8080

CMD ["/app/secretbay"] 