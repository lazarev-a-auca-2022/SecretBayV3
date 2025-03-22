#!/bin/bash
set -e

# SecretBay deployment script

# Display welcome message
echo "SecretBay VPN Configuration Tool - Deployment Script"
echo "==================================================="
echo

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker first."
    echo "Visit https://docs.docker.com/get-docker/ for installation instructions."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed. Please install Docker Compose first."
    echo "Visit https://docs.docker.com/compose/install/ for installation instructions."
    exit 1
fi

# Create .env file for sensitive data
if [ ! -f .env ]; then
    echo "Creating .env file for configuration..."
    cat > .env << EOL
# SecretBay Configuration
# ---------------------
# These values will be used by Docker Compose

# Security settings
JWT_SECRET=$(openssl rand -hex 32)
EOL
    echo "Created .env file with secure random values."
else
    echo "Using existing .env file."
fi

# Ensure the current user has permissions to run Docker
if ! docker info &> /dev/null; then
    echo "Error: Cannot connect to the Docker daemon. If using Linux, make sure your user is in the 'docker' group."
    exit 1
fi

# Build and start the services
echo "Building and starting SecretBay services..."
docker-compose up -d --build

# Display success message
echo
echo "SecretBay has been successfully deployed!"
echo
echo "The backend API is available at: http://localhost:8080"
echo "The frontend UI is available at: http://localhost"
echo
echo "To view logs, run: docker-compose logs -f"
echo "To stop the services, run: docker-compose down"
echo 