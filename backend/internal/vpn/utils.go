package vpn

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"

	"github.com/secretbay/backend/internal/ssh"
	"github.com/sirupsen/logrus"
)

// Initialize random number generator
func init() {
	rand.Seed(time.Now().UnixNano())
}

// EncodeBase64 encodes data to base64
func EncodeBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// GenerateRandomUUID generates a random UUID
func GenerateRandomUUID() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)

	// Set version (4) and variant (2)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

// ChangeServerPassword changes the server password using SSH client
func ChangeServerPassword(client interface{}, conn interface{}, username, newPassword string) error {
	// Type assertion for client
	sshClient, ok := client.(*ssh.Client)
	if !ok {
		return fmt.Errorf("invalid SSH client type")
	}

	// Type assertion for connection
	sshConn, ok := conn.(*ssh.Client)
	if !ok {
		return fmt.Errorf("invalid SSH connection type")
	}

	// Check if we're working with root or a regular user
	if username == "root" {
		// Change root password directly
		cmd := fmt.Sprintf("echo 'root:%s' | chpasswd", newPassword)
		_, stderr, err := sshClient.RunCommand(sshConn, cmd)
		if err != nil {
			return fmt.Errorf("failed to change root password: %w, stderr: %s", err, stderr)
		}
	} else {
		// Change regular user password
		cmd := fmt.Sprintf("echo '%s:%s' | chpasswd", username, newPassword)
		_, stderr, err := sshClient.RunCommand(sshConn, cmd)
		if err != nil {
			return fmt.Errorf("failed to change user password: %w, stderr: %s", err, stderr)
		}
	}

	return nil
}

// CleanupServerData cleans up sensitive data on the server after VPN configuration
func CleanupServerData(client interface{}, conn interface{}, log *logrus.Logger) error {
	// Type assertion for client
	sshClient, ok := client.(*ssh.Client)
	if !ok {
		return fmt.Errorf("invalid SSH client type")
	}

	// Type assertion for connection
	sshConn, ok := conn.(*ssh.Client)
	if !ok {
		return fmt.Errorf("invalid SSH connection type")
	}

	log.Info("Cleaning up sensitive data on the server")

	// List of commands to clean up sensitive data
	cleanupCommands := []string{
		// Clear command history
		"history -c",
		"rm -f ~/.bash_history",

		// Wipe temporary files
		"rm -rf /tmp/*",

		// Clear logs that might contain sensitive information
		"find /var/log -type f -exec truncate --size=0 {} \\;",

		// Remove any temporary SSH keys
		"rm -f /root/.ssh/authorized_keys.*",

		// Secure SSH config
		"chmod 600 /etc/ssh/sshd_config",

		// Clean apt cache
		"apt-get clean",

		// Restart SSH service to apply changes
		"systemctl restart ssh",
	}

	// Execute each cleanup command
	for _, cmd := range cleanupCommands {
		_, stderr, err := sshClient.RunCommand(sshConn, cmd)
		if err != nil {
			log.Warnf("Cleanup command failed: %s, error: %v, stderr: %s", cmd, err, stderr)
			// Continue with other commands even if one fails
		}
	}

	log.Info("Server cleanup completed")
	return nil
}

// SetupHTTPS installs and configures certbot for HTTPS support
func SetupHTTPS(sshConn interface{}, domain string) error {
	sshClient, ok := sshConn.(*ssh.Client)
	if !ok {
		return fmt.Errorf("invalid SSH connection type")
	}

	// Install certbot and nginx
	if _, stderr, err := sshClient.RunCommand(sshConn, "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-nginx nginx"); err != nil {
		return fmt.Errorf("failed to install certbot and nginx: %w, stderr: %s", err, stderr)
	}

	// Configure basic nginx site for domain
	nginxConfig := fmt.Sprintf(`server {
    listen 80;
    server_name %s;
    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}`, domain)

	// Write nginx config
	cmd := fmt.Sprintf("cat > /etc/nginx/sites-available/%s << 'EOL'\n%s\nEOL", domain, nginxConfig)
	if _, stderr, err := sshClient.RunCommand(sshConn, cmd); err != nil {
		return fmt.Errorf("failed to write nginx config: %w, stderr: %s", err, stderr)
	}

	// Enable the site
	if _, stderr, err := sshClient.RunCommand(sshConn, fmt.Sprintf("ln -sf /etc/nginx/sites-available/%s /etc/nginx/sites-enabled/%s", domain, domain)); err != nil {
		return fmt.Errorf("failed to enable nginx site: %w, stderr: %s", err, stderr)
	}

	// Remove default nginx site
	if _, stderr, err := sshClient.RunCommand(sshConn, "rm -f /etc/nginx/sites-enabled/default"); err != nil {
		return fmt.Errorf("failed to remove default nginx site: %w, stderr: %s", err, stderr)
	}

	// Test nginx config
	if _, stderr, err := sshClient.RunCommand(sshConn, "nginx -t"); err != nil {
		return fmt.Errorf("nginx configuration test failed: %w, stderr: %s", err, stderr)
	}

	// Restart nginx
	if _, stderr, err := sshClient.RunCommand(sshConn, "systemctl restart nginx"); err != nil {
		return fmt.Errorf("failed to restart nginx: %w, stderr: %s", err, stderr)
	}

	// Get SSL certificate
	certbotCmd := fmt.Sprintf("certbot --nginx --non-interactive --agree-tos --email admin@%s -d %s", domain, domain)
	if _, stderr, err := sshClient.RunCommand(sshConn, certbotCmd); err != nil {
		return fmt.Errorf("failed to obtain SSL certificate: %w, stderr: %s", err, stderr)
	}

	// Set up auto-renewal
	if _, stderr, err := sshClient.RunCommand(sshConn, "systemctl enable certbot.timer && systemctl start certbot.timer"); err != nil {
		return fmt.Errorf("failed to enable certificate auto-renewal: %w, stderr: %s", err, stderr)
	}

	return nil
}
