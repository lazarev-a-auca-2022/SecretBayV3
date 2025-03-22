# SecretBay VPN Configuration Tool

SecretBay is a cross-platform VPN configuration tool that automates the setup and configuration of VPN servers. It simplifies the process of setting up OpenVPN and IKEv2 (StrongSwan) VPN servers on remote Ubuntu machines.

## Features

- **IKEv2 (StrongSwan) Support**: Configure iOS-compatible VPN servers
- **OpenVPN Support**: Set up OpenVPN servers with secure configurations
- **Automated Security**: Installs and configures fail2ban, firewall rules, and security best practices
- **Zero Data Retention**: Cleans up all sensitive data after configuration
- **Password Management**: Automatically changes server passwords for enhanced security
- **Docker Support**: Easy deployment with Docker and Docker Compose

## Architecture

SecretBay consists of the following components:

1. **Backend API Server**: A Go-based server that handles VPN configuration requests
2. **Flutter-based UI**: A cross-platform user interface for configuring VPN servers

## Prerequisites

- Docker
- Docker Compose
- Ubuntu 18.04+ on target servers
- Root access to the target servers

## Quick Start

1. Clone the repository:
   ```
   git clone https://github.com/username/secretbay.git
   cd secretbay
   ```

2. Run the deployment script:
   ```
   chmod +x deploy.sh
   ./deploy.sh
   ```

3. Access the UI at http://localhost

## API Usage

The API accepts POST requests to `/api/vpn/configure` with the following JSON payload:

```json
{
  "server_ip": "1.2.3.4",
  "username": "root",
  "auth_method": "password",
  "auth_credential": "your-password",
  "vpn_type": "ikev2"
}
```

Response:

```json
{
  "status": "success",
  "message": "VPN configured successfully",
  "new_password": "generated-secure-password",
  "config_url": "/download/vpn.mobileconfig"
}
```

## VPN Types

- `ikev2` or `strongswan` - IKEv2 VPN (compatible with iOS devices)
- `openvpn` - OpenVPN

## Security Considerations

- All passwords are transferred securely over HTTPS
- SSH connections use strong encryption
- Server passwords are changed after configuration
- All sensitive data is removed from the server after configuration

## Development

### Backend

The backend is written in Go and uses the following dependencies:

- Gorilla Mux for routing
- Logrus for logging
- Golang SSH library for server communication

Build the backend:

```
cd backend
go build ./cmd/secretbay
```

### Docker Setup

The project includes Docker and Docker Compose configurations for easy development and deployment:

```
docker-compose up -d
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 