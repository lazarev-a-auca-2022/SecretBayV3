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

// StrongSwanConfigurator handles the configuration of StrongSwan (IKEv2) VPN servers
type StrongSwanConfigurator struct {
	client  *ssh.Client
	log     *logrus.Logger
	tempDir string
}

// NewStrongSwanConfigurator creates a new StrongSwan configurator
func NewStrongSwanConfigurator(client *ssh.Client, log *logrus.Logger, tempDir string) *StrongSwanConfigurator {
	return &StrongSwanConfigurator{
		client:  client,
		log:     log,
		tempDir: tempDir,
	}
}

// Configure configures StrongSwan on the remote server
func (c *StrongSwanConfigurator) Configure(conn interface{}, serverIP string) (string, error) {
	c.log.Info("Configuring StrongSwan (IKEv2) server")

	// Type assertion for SSH client
	sshConn, ok := conn.(*ssh.Client)
	if !ok {
		return "", fmt.Errorf("invalid SSH connection type")
	}

	// Set up HTTPS with Let's Encrypt
	if err := SetupHTTPS(sshConn, "secretbay.me"); err != nil {
		return "", fmt.Errorf("failed to set up HTTPS: %w", err)
	}

	// Install necessary packages
	if err := c.installPackages(sshConn); err != nil {
		return "", fmt.Errorf("failed to install packages: %w", err)
	}

	// Configure StrongSwan
	if err := c.setupStrongSwan(sshConn, serverIP); err != nil {
		return "", fmt.Errorf("failed to configure StrongSwan: %w", err)
	}

	// Generate certificates
	if err := c.generateCertificates(sshConn, serverIP); err != nil {
		return "", fmt.Errorf("failed to generate certificates: %w", err)
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
func (c *StrongSwanConfigurator) installPackages(conn *ssh.Client) error {
	c.log.Info("Installing StrongSwan packages")

	// Update package list
	if _, stderr, err := c.client.RunCommand(conn, "apt-get update"); err != nil {
		return fmt.Errorf("failed to update package list: %w, stderr: %s", err, stderr)
	}

	// Install StrongSwan and related packages
	packages := []string{
		"strongswan",
		"libstrongswan-standard-plugins",
		"libcharon-extra-plugins",
		"strongswan-libcharon",
		"libcharon-standard-plugins",
		"fail2ban",
	}

	installCmd := fmt.Sprintf("DEBIAN_FRONTEND=noninteractive apt-get install -y %s", strings.Join(packages, " "))
	if _, stderr, err := c.client.RunCommand(conn, installCmd); err != nil {
		return fmt.Errorf("failed to install packages: %w, stderr: %s", err, stderr)
	}

	return nil
}

// setupStrongSwan configures StrongSwan on the remote server
func (c *StrongSwanConfigurator) setupStrongSwan(conn *ssh.Client, serverIP string) error {
	c.log.Info("Setting up StrongSwan")

	// Configure strongswan.conf
	strongswanConf := `charon {
    load_modular = yes
    duplicheck.enable = no
    compress = yes
    plugins {
        include strongswan.d/charon/*.conf
    }
    dns1 = 8.8.8.8
    dns2 = 8.8.4.4
}

include strongswan.d/*.conf
`

	cmd := fmt.Sprintf("cat > /etc/strongswan/strongswan.conf << 'EOL'\n%s\nEOL", strongswanConf)
	if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
		return fmt.Errorf("failed to write strongswan.conf: %w, stderr: %s", err, stderr)
	}

	// Configure ipsec.conf
	ipsecConf := fmt.Sprintf(`config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%%any
    leftid=%s
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%%any
    rightid=%%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes128gcm16-sha256-prfsha256-ecp256,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes128gcm16-ecp256,aes256-sha256,aes256-sha1,3des-sha1!
`, serverIP)

	cmd = fmt.Sprintf("cat > /etc/ipsec.conf << 'EOL'\n%s\nEOL", ipsecConf)
	if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
		return fmt.Errorf("failed to write ipsec.conf: %w, stderr: %s", err, stderr)
	}

	// Generate VPN user credentials
	vpnUsername := "vpnuser"
	vpnPassword, err := ssh.GenerateRandomPassword(16)
	if err != nil {
		return fmt.Errorf("failed to generate VPN password: %w", err)
	}

	// Configure ipsec.secrets
	ipsecSecrets := fmt.Sprintf(`: RSA "server-key.pem"
%s : EAP "%s"
`, vpnUsername, vpnPassword)

	cmd = fmt.Sprintf("cat > /etc/ipsec.secrets << 'EOL'\n%s\nEOL", ipsecSecrets)
	if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
		return fmt.Errorf("failed to write ipsec.secrets: %w, stderr: %s", err, stderr)
	}

	// Set secure permissions for the secrets file
	if _, stderr, err := c.client.RunCommand(conn, "chmod 600 /etc/ipsec.secrets"); err != nil {
		return fmt.Errorf("failed to set permissions on ipsec.secrets: %w, stderr: %s", err, stderr)
	}

	return nil
}

// generateCertificates generates certificates for StrongSwan
func (c *StrongSwanConfigurator) generateCertificates(conn *ssh.Client, serverIP string) error {
	c.log.Info("Generating certificates")

	// Create directory structure
	if _, stderr, err := c.client.RunCommand(conn, "mkdir -p /etc/ipsec.d/private /etc/ipsec.d/certs"); err != nil {
		return fmt.Errorf("failed to create certificate directories: %w, stderr: %s", err, stderr)
	}

	// Generate CA private key
	if _, stderr, err := c.client.RunCommand(conn, "ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem"); err != nil {
		return fmt.Errorf("failed to generate CA private key: %w, stderr: %s", err, stderr)
	}

	// Generate CA certificate
	caCommand := fmt.Sprintf(`ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem --type rsa --dn "CN=SecretBay VPN CA" --outform pem > /etc/ipsec.d/certs/ca-cert.pem`)
	if _, stderr, err := c.client.RunCommand(conn, caCommand); err != nil {
		return fmt.Errorf("failed to generate CA certificate: %w, stderr: %s", err, stderr)
	}

	// Generate server private key
	if _, stderr, err := c.client.RunCommand(conn, "ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem"); err != nil {
		return fmt.Errorf("failed to generate server private key: %w, stderr: %s", err, stderr)
	}

	// Generate server certificate
	serverCommand := fmt.Sprintf(`ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa | ipsec pki --issue --lifetime 3650 --cacert /etc/ipsec.d/certs/ca-cert.pem --cakey /etc/ipsec.d/private/ca-key.pem --dn "CN=%s" --san "%s" --flag serverAuth --flag ikeIntermediate --outform pem > /etc/ipsec.d/certs/server-cert.pem`, serverIP, serverIP)
	if _, stderr, err := c.client.RunCommand(conn, serverCommand); err != nil {
		return fmt.Errorf("failed to generate server certificate: %w, stderr: %s", err, stderr)
	}

	// Copy certificates to working directory
	commands := []string{
		"cp /etc/ipsec.d/certs/ca-cert.pem /etc/strongswan/ipsec.d/cacerts/",
		"cp /etc/ipsec.d/certs/server-cert.pem /etc/strongswan/ipsec.d/certs/",
		"cp /etc/ipsec.d/private/server-key.pem /etc/strongswan/ipsec.d/private/",
		"cp /etc/ipsec.d/private/ca-key.pem /etc/strongswan/ipsec.d/private/",
		"ln -s /etc/ipsec.d/certs/server-cert.pem /etc/ipsec.d/certs/server-cert.pem",
		"ln -s /etc/ipsec.d/private/server-key.pem /etc/ipsec.d/private/server-key.pem",
	}

	for _, cmd := range commands {
		if _, stderr, err := c.client.RunCommand(conn, cmd); err != nil {
			c.log.Warnf("Failed to copy certificate: %v, stderr: %s", err, stderr)
			// Continue even if some commands fail
		}
	}

	return nil
}

// generateClientConfig generates the StrongSwan client configuration
func (c *StrongSwanConfigurator) generateClientConfig(conn *ssh.Client, serverIP string) (string, error) {
	c.log.Info("Generating client configuration")

	// Create temporary directory for client config
	localTempDir := filepath.Join(c.tempDir, "client")
	if err := c.createLocalTempDir(localTempDir); err != nil {
		return "", fmt.Errorf("failed to create local temp directory: %w", err)
	}

	// Download CA certificate from the server
	if err := c.client.DownloadFile(conn, "/etc/ipsec.d/certs/ca-cert.pem", filepath.Join(localTempDir, "ca-cert.pem")); err != nil {
		return "", fmt.Errorf("failed to download CA certificate: %w", err)
	}

	// Read CA certificate
	caCert, err := c.readFile(filepath.Join(localTempDir, "ca-cert.pem"))
	if err != nil {
		return "", fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Get VPN username and password from ipsec.secrets
	stdout, stderr, err := c.client.RunCommand(conn, "grep EAP /etc/ipsec.secrets")
	if err != nil {
		return "", fmt.Errorf("failed to get VPN credentials: %w, stderr: %s", err, stderr)
	}

	parts := strings.Split(stdout, ":")
	if len(parts) < 2 {
		return "", fmt.Errorf("failed to parse VPN credentials")
	}

	vpnUsername := strings.TrimSpace(parts[0])
	vpnPassword := strings.Trim(strings.TrimSpace(parts[1]), " \"EAP")
	vpnPassword = strings.TrimSpace(vpnPassword)

	// Create mobileconfig template
	mobileConfigTemplate := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>IKEv2</key>
			<dict>
				<key>AuthenticationMethod</key>
				<string>None</string>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>DiffieHellmanGroup</key>
					<integer>20</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<integer>0</integer>
				<key>EnableCertificateRevocationCheck</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<integer>1</integer>
				<key>ExtendedAuthEnabled</key>
				<true/>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>DiffieHellmanGroup</key>
					<integer>20</integer>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>OnDemandEnabled</key>
				<integer>1</integer>
				<key>OnDemandRules</key>
				<array>
					<dict>
						<key>Action</key>
						<string>Connect</string>
					</dict>
				</array>
				<key>RemoteAddress</key>
				<string>{{.ServerIP}}</string>
				<key>RemoteIdentifier</key>
				<string>{{.ServerIP}}</string>
				<key>UseConfigurationAttributeInternalIPSubnet</key>
				<integer>0</integer>
				<key>AuthName</key>
				<string>{{.Username}}</string>
				<key>AuthPassword</key>
				<string>{{.Password}}</string>
				<key>PayloadCertificateUUID</key>
				<string>{{.UUID}}</string>
			</dict>
			<key>IPv4</key>
			<dict>
				<key>OverridePrimary</key>
				<integer>1</integer>
			</dict>
			<key>PayloadDescription</key>
			<string>Configures VPN settings</string>
			<key>PayloadDisplayName</key>
			<string>SecretBay VPN</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.vpn.managed.{{.UUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>{{.UUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>Proxies</key>
			<dict>
				<key>HTTPEnable</key>
				<integer>0</integer>
				<key>HTTPSEnable</key>
				<integer>0</integer>
			</dict>
			<key>UserDefinedName</key>
			<string>SecretBay VPN</string>
			<key>VPNType</key>
			<string>IKEv2</string>
		</dict>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>ca.pem</string>
			<key>PayloadContent</key>
			<data>
{{.CACertBase64}}
			</data>
			<key>PayloadDescription</key>
			<string>Adds a CA root certificate</string>
			<key>PayloadDisplayName</key>
			<string>SecretBay VPN CA</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.security.root.{{.UUID2}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{{.UUID2}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>SecretBay VPN</string>
	<key>PayloadIdentifier</key>
	<string>com.secretbay.vpn.{{.UUID3}}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{.UUID3}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>`

	// Generate UUIDs
	uuid1 := GenerateRandomUUID()
	uuid2 := GenerateRandomUUID()
	uuid3 := GenerateRandomUUID()

	// Encode CA certificate to base64
	caCertBase64 := EncodeBase64(caCert)

	// Prepare template data
	templateData := struct {
		ServerIP     string
		Username     string
		Password     string
		UUID         string
		UUID2        string
		UUID3        string
		CACertBase64 string
	}{
		ServerIP:     serverIP,
		Username:     vpnUsername,
		Password:     vpnPassword,
		UUID:         uuid1,
		UUID2:        uuid2,
		UUID3:        uuid3,
		CACertBase64: caCertBase64,
	}

	// Execute template
	t := template.Must(template.New("mobileconfig").Parse(mobileConfigTemplate))
	mobileConfigPath := filepath.Join(localTempDir, "vpn.mobileconfig")
	mobileConfigFile, err := c.createFile(mobileConfigPath)
	if err != nil {
		return "", fmt.Errorf("failed to create mobileconfig file: %w", err)
	}
	defer mobileConfigFile.Close()

	if err := t.Execute(mobileConfigFile, templateData); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return mobileConfigPath, nil
}

// configureNetworking configures the networking for StrongSwan
func (c *StrongSwanConfigurator) configureNetworking(conn *ssh.Client) error {
	c.log.Info("Configuring networking")

	// Enable IP forwarding
	if _, stderr, err := c.client.RunCommand(conn, "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-strongswan.conf"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w, stderr: %s", err, stderr)
	}

	if _, stderr, err := c.client.RunCommand(conn, "sysctl --system"); err != nil {
		return fmt.Errorf("failed to apply sysctl settings: %w, stderr: %s", err, stderr)
	}

	// Configure firewall
	commands := []string{
		"ufw allow 500/udp",  // IKEv2
		"ufw allow 4500/udp", // IKEv2 NAT traversal
		"ufw allow 80/tcp",   // HTTP
		"ufw allow 443/tcp",  // HTTPS
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
		"iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE",
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

	// Start StrongSwan service
	if _, stderr, err := c.client.RunCommand(conn, "systemctl enable strongswan && systemctl restart strongswan"); err != nil {
		return fmt.Errorf("failed to start StrongSwan service: %w, stderr: %s", err, stderr)
	}

	return nil
}

// configureSecurity configures security settings on the remote server
func (c *StrongSwanConfigurator) configureSecurity(conn *ssh.Client) error {
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
func (c *StrongSwanConfigurator) createLocalTempDir(path string) error {
	if err := c.removeDir(path); err != nil {
		return fmt.Errorf("failed to remove existing temp directory: %w", err)
	}

	if err := c.createDir(path); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	return nil
}

func (c *StrongSwanConfigurator) removeDir(path string) error {
	c.log.Debugf("Removing directory: %s", path)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to do
	}
	return os.RemoveAll(path)
}

func (c *StrongSwanConfigurator) createDir(path string) error {
	c.log.Debugf("Creating directory: %s", path)
	return os.MkdirAll(path, 0750)
}

func (c *StrongSwanConfigurator) readFile(path string) (string, error) {
	c.log.Debugf("Reading file: %s", path)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return string(content), nil
}

func (c *StrongSwanConfigurator) createFile(path string) (*os.File, error) {
	c.log.Debugf("Creating file: %s", path)
	return os.Create(path)
}
