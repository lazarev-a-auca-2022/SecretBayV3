package vpn

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/secretbay/backend/internal/ssh"
	"github.com/sirupsen/logrus"
)

// OpenVPNConfigurator handles the configuration of OpenVPN servers
type OpenVPNConfigurator struct {
	client  *ssh.Client
	log     *logrus.Logger
	tempDir string
}

// NewOpenVPNConfigurator creates a new OpenVPN configurator
func NewOpenVPNConfigurator(client *ssh.Client, log *logrus.Logger, tempDir string) *OpenVPNConfigurator {
	return &OpenVPNConfigurator{
		client:  client,
		log:     log,
		tempDir: tempDir,
	}
}

// Configure configures OpenVPN on the remote server
func (c *OpenVPNConfigurator) Configure(conn interface{}, serverIP string) (string, error) {
	c.log.Info("Configuring OpenVPN server")

	// Type assertion for SSH client
	sshConn, ok := conn.(*ssh.Client)
	if !ok {
		return "", fmt.Errorf("invalid SSH connection type")
	}

	// Install necessary packages
	if err := c.installPackages(sshConn); err != nil {
		return "", fmt.Errorf("failed to install packages: %w", err)
	}

	// Configure OpenVPN
	if err := c.setupOpenVPN(sshConn, serverIP); err != nil {
		return "", fmt.Errorf("failed to configure OpenVPN: %w", err)
	}

	// Generate client configuration
	configPath, err := c.generateClientConfig(sshConn, serverIP)
	if err != nil {
		return "", fmt.Errorf("failed to generate client configuration: %w", err)
	}

	// Enable IP forwarding and configure firewall
	if err := c.configureNetworking(sshConn); err != nil {
		return "", fmt.Errorf("failed to configure networking: %w", err)
	}

	// Set up security
	if err := c.configureSecurity(sshConn); err != nil {
		return "", fmt.Errorf("failed to configure security: %w", err)
	}

	return configPath, nil
}

// installPackages installs necessary packages on the remote server
func (c *OpenVPNConfigurator) installPackages(conn *ssh.Client) error {
	c.log.Info("Installing OpenVPN packages")

	// Update package list
	if _, stderr, err := c.client.RunCommand(conn, "apt-get update"); err != nil {
		return fmt.Errorf("failed to update package list: %w, stderr: %s", err, stderr)
	}

	// Install OpenVPN and Easy-RSA
	if _, stderr, err := c.client.RunCommand(conn, "DEBIAN_FRONTEND=noninteractive apt-get install -y openvpn easy-rsa fail2ban"); err != nil {
		return fmt.Errorf("failed to install packages: %w, stderr: %s", err, stderr)
	}

	return nil
}

// setupOpenVPN configures OpenVPN on the remote server
func (c *OpenVPNConfigurator) setupOpenVPN(conn *ssh.Client, serverIP string) error {
	c.log.Info("Setting up OpenVPN")

	// Create directory structure
	if _, stderr, err := c.client.RunCommand(conn, "mkdir -p /etc/openvpn/easy-rsa"); err != nil {
		return fmt.Errorf("failed to create directory: %w, stderr: %s", err, stderr)
	}

	// Copy Easy-RSA files
	if _, stderr, err := c.client.RunCommand(conn, "cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/"); err != nil {
		return fmt.Errorf("failed to copy Easy-RSA files: %w, stderr: %s", err, stderr)
	}

	// Generate server configuration
	if err := c.generateServerConfig(conn, serverIP); err != nil {
		return fmt.Errorf("failed to generate server configuration: %w", err)
	}

	// Initialize PKI
	if _, stderr, err := c.client.RunCommand(conn, "cd /etc/openvpn/easy-rsa && ./easyrsa init-pki"); err != nil {
		return fmt.Errorf("failed to initialize PKI: %w, stderr: %s", err, stderr)
	}

	// Build CA
	if _, stderr, err := c.client.RunCommand(conn, "cd /etc/openvpn/easy-rsa && echo 'yes' | ./easyrsa build-ca nopass"); err != nil {
		return fmt.Errorf("failed to build CA: %w, stderr: %s", err, stderr)
	}

	// Generate server key pair
	if _, stderr, err := c.client.RunCommand(conn, "cd /etc/openvpn/easy-rsa && echo 'yes' | ./easyrsa gen-req server nopass"); err != nil {
		return fmt.Errorf("failed to generate server key: %w, stderr: %s", err, stderr)
	}

	// Sign server key
	if _, stderr, err := c.client.RunCommand(conn, "cd /etc/openvpn/easy-rsa && echo 'yes' | ./easyrsa sign-req server server"); err != nil {
		return fmt.Errorf("failed to sign server key: %w, stderr: %s", err, stderr)
	}

	// Generate Diffie-Hellman parameters
	if _, stderr, err := c.client.RunCommand(conn, "cd /etc/openvpn/easy-rsa && ./easyrsa gen-dh"); err != nil {
		return fmt.Errorf("failed to generate DH params: %w, stderr: %s", err, stderr)
	}

	// Generate HMAC key
	if _, stderr, err := c.client.RunCommand(conn, "openvpn --genkey --secret /etc/openvpn/ta.key"); err != nil {
		return fmt.Errorf("failed to generate HMAC key: %w, stderr: %s", err, stderr)
	}

	// Copy keys to OpenVPN directory
	commands := []string{
		"cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/",
		"cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/",
		"cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/",
		"cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/",
	}

	for _, cmd := range commands {
		if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
			return fmt.Errorf("failed to copy keys: %w, stderr: %s", err, stderr)
		}
	}

	// Generate client key pair
	if _, stderr, err := c.client.RunCommand(conn, "cd /etc/openvpn/easy-rsa && echo 'yes' | ./easyrsa gen-req client nopass"); err != nil {
		return fmt.Errorf("failed to generate client key: %w, stderr: %s", err, stderr)
	}

	// Sign client key
	if _, stderr, err := c.client.RunCommand(conn, "cd /etc/openvpn/easy-rsa && echo 'yes' | ./easyrsa sign-req client client"); err != nil {
		return fmt.Errorf("failed to sign client key: %w, stderr: %s", err, stderr)
	}

	// Start OpenVPN service
	if _, stderr, err := c.client.RunCommand(conn, "systemctl enable openvpn@server && systemctl start openvpn@server"); err != nil {
		return fmt.Errorf("failed to start OpenVPN service: %w, stderr: %s", err, stderr)
	}

	return nil
}

// generateServerConfig generates the OpenVPN server configuration
func (c *OpenVPNConfigurator) generateServerConfig(conn *ssh.Client, serverIP string) error {
	c.log.Info("Generating server configuration")

	config := `port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
verb 3
explicit-exit-notify 1
`

	// Create directory for logs
	if _, stderr, err := c.client.RunCommand(conn, "mkdir -p /var/log/openvpn"); err != nil {
		return fmt.Errorf("failed to create log directory: %w, stderr: %s", err, stderr)
	}

	// Write configuration to file
	cmd := fmt.Sprintf("cat > /etc/openvpn/server.conf << 'EOL'\n%s\nEOL", config)
	if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
		return fmt.Errorf("failed to write server configuration: %w, stderr: %s", err, stderr)
	}

	// Create vars file for EasyRSA
	vars := `set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_CA_EXPIRE 3650
set_var EASYRSA_CERT_EXPIRE 3650
set_var EASYRSA_REQ_COUNTRY "US"
set_var EASYRSA_REQ_PROVINCE "California"
set_var EASYRSA_REQ_CITY "San Francisco"
set_var EASYRSA_REQ_ORG "SecretBay VPN"
set_var EASYRSA_REQ_EMAIL "admin@example.com"
set_var EASYRSA_REQ_OU "SecretBay"
set_var EASYRSA_BATCH "yes"
`

	cmd = fmt.Sprintf("cat > /etc/openvpn/easy-rsa/vars << 'EOL'\n%s\nEOL", vars)
	if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
		return fmt.Errorf("failed to write vars file: %w, stderr: %s", err, stderr)
	}

	return nil
}

// generateClientConfig generates the OpenVPN client configuration
func (c *OpenVPNConfigurator) generateClientConfig(conn *ssh.Client, serverIP string) (string, error) {
	c.log.Info("Generating client configuration")

	// Template for client configuration
	clientTemplate := `client
dev tun
proto udp
remote {{.ServerIP}} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
verb 3
<ca>
{{.CA}}
</ca>
<cert>
{{.Cert}}
</cert>
<key>
{{.Key}}
</key>
<tls-auth>
{{.TLSAuth}}
</tls-auth>
key-direction 1
`

	// Create temporary directory for client config
	localTempDir := filepath.Join(c.tempDir, "client")
	if err := c.createLocalTempDir(localTempDir); err != nil {
		return "", fmt.Errorf("failed to create local temp directory: %w", err)
	}

	// Download necessary files from the server
	files := map[string]string{
		"/etc/openvpn/ca.crt":                          filepath.Join(localTempDir, "ca.crt"),
		"/etc/openvpn/easy-rsa/pki/issued/client.crt":  filepath.Join(localTempDir, "client.crt"),
		"/etc/openvpn/easy-rsa/pki/private/client.key": filepath.Join(localTempDir, "client.key"),
		"/etc/openvpn/ta.key":                          filepath.Join(localTempDir, "ta.key"),
	}

	for remote, local := range files {
		if err := c.client.DownloadFile(conn, remote, local); err != nil {
			return "", fmt.Errorf("failed to download file %s: %w", remote, err)
		}
	}

	// Read certificate files
	ca, err := c.readFile(filepath.Join(localTempDir, "ca.crt"))
	if err != nil {
		return "", fmt.Errorf("failed to read CA certificate: %w", err)
	}

	cert, err := c.readFile(filepath.Join(localTempDir, "client.crt"))
	if err != nil {
		return "", fmt.Errorf("failed to read client certificate: %w", err)
	}

	key, err := c.readFile(filepath.Join(localTempDir, "client.key"))
	if err != nil {
		return "", fmt.Errorf("failed to read client key: %w", err)
	}

	tlsAuth, err := c.readFile(filepath.Join(localTempDir, "ta.key"))
	if err != nil {
		return "", fmt.Errorf("failed to read TLS auth key: %w", err)
	}

	// Extract certificate content only
	cert = extractCertificate(cert)

	// Prepare template data
	templateData := struct {
		ServerIP string
		CA       string
		Cert     string
		Key      string
		TLSAuth  string
	}{
		ServerIP: serverIP,
		CA:       strings.TrimSpace(ca),
		Cert:     strings.TrimSpace(cert),
		Key:      strings.TrimSpace(key),
		TLSAuth:  strings.TrimSpace(tlsAuth),
	}

	// Execute template
	t := template.Must(template.New("client").Parse(clientTemplate))
	clientConfigPath := filepath.Join(localTempDir, "client.ovpn")
	clientConfigFile, err := c.createFile(clientConfigPath)
	if err != nil {
		return "", fmt.Errorf("failed to create client config file: %w", err)
	}
	defer clientConfigFile.Close()

	if err := t.Execute(clientConfigFile, templateData); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return clientConfigPath, nil
}

// configureNetworking configures the networking for OpenVPN
func (c *OpenVPNConfigurator) configureNetworking(conn *ssh.Client) error {
	c.log.Info("Configuring networking")

	// Enable IP forwarding
	if _, stderr, err := c.client.RunCommand(conn, "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn.conf"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w, stderr: %s", err, stderr)
	}

	if _, stderr, err := c.client.RunCommand(conn, "sysctl --system"); err != nil {
		return fmt.Errorf("failed to apply sysctl settings: %w, stderr: %s", err, stderr)
	}

	// Configure firewall
	commands := []string{
		"ufw allow 1194/udp",
		"ufw allow OpenSSH",
		"ufw disable",
		"ufw --force enable",
	}

	for _, cmd := range commands {
		if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
			c.log.Warnf("Failed to configure firewall: %v, stderr: %s", err, stderr)
			// Continue even if some commands fail
		}
	}

	// Configure NAT
	commands = []string{
		"iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
		"iptables-save > /etc/iptables/rules.v4",
	}

	// Ensure iptables-persistent is installed
	if _, stderr, err := c.client.RunCommand(conn, "DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent"); err != nil {
		return fmt.Errorf("failed to install iptables-persistent: %w, stderr: %s", err, stderr)
	}

	for _, cmd := range commands {
		if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
			c.log.Warnf("Failed to configure NAT: %v, stderr: %s", err, stderr)
			// Continue even if some commands fail
		}
	}

	return nil
}

// configureSecurity configures security settings on the remote server
func (c *OpenVPNConfigurator) configureSecurity(conn *ssh.Client) error {
	c.log.Info("Configuring security")

	// Configure fail2ban
	if _, stderr, err := c.client.RunCommand(conn, "systemctl enable fail2ban && systemctl start fail2ban"); err != nil {
		return fmt.Errorf("failed to enable fail2ban: %w, stderr: %s", err, stderr)
	}

	// Disable unnecessary services
	services := []string{
		"cups", "avahi-daemon", "bluetooth",
	}

	for _, service := range services {
		if _, stderr, err := c.client.RunCommand(conn, fmt.Sprintf("systemctl stop %s && systemctl disable %s", service, service)); err != nil {
			c.log.Warnf("Failed to disable service %s: %v, stderr: %s", service, err, stderr)
			// Continue even if some services cannot be disabled
		}
	}

	return nil
}

// Utility functions
func (c *OpenVPNConfigurator) createLocalTempDir(path string) error {
	if err := c.removeDir(path); err != nil {
		return fmt.Errorf("failed to remove existing temp directory: %w", err)
	}

	if err := c.createDir(path); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	return nil
}

func (c *OpenVPNConfigurator) removeDir(path string) error {
	c.log.Debugf("Removing directory: %s", path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to do
	}
	return os.RemoveAll(path)
}

func (c *OpenVPNConfigurator) createDir(path string) error {
	c.log.Debugf("Creating directory: %s", path)
	return os.MkdirAll(path, 0750)
}

func (c *OpenVPNConfigurator) readFile(path string) (string, error) {
	c.log.Debugf("Reading file: %s", path)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return string(content), nil
}

func (c *OpenVPNConfigurator) createFile(path string) (*os.File, error) {
	c.log.Debugf("Creating file: %s", path)
	return os.Create(path)
}

// extractCertificate extracts the certificate content from a cert file
func extractCertificate(certContent string) string {
	// Find start and end markers
	start := strings.Index(certContent, "-----BEGIN CERTIFICATE-----")
	end := strings.Index(certContent, "-----END CERTIFICATE-----")

	if start >= 0 && end >= 0 {
		// Include end marker length
		end += len("-----END CERTIFICATE-----")
		return certContent[start:end]
	}

	return certContent
}
