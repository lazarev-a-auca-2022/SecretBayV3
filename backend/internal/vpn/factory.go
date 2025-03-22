package vpn

import (
	"fmt"

	"github.com/secretbay/backend/internal/ssh"
	"github.com/sirupsen/logrus"
)

// VPNType represents the type of VPN configurator
type VPNType string

const (
	// OpenVPNType represents OpenVPN type
	OpenVPNType VPNType = "openvpn"

	// StrongSwanType represents StrongSwan (IKEv2) type
	StrongSwanType VPNType = "ikev2"
)

// ConfiguratorFactory creates VPN configurators
type ConfiguratorFactory struct {
	client  *ssh.Client
	log     *logrus.Logger
	tempDir string
}

// NewConfiguratorFactory creates a new VPN configurator factory
func NewConfiguratorFactory(client *ssh.Client, log *logrus.Logger, tempDir string) *ConfiguratorFactory {
	return &ConfiguratorFactory{
		client:  client,
		log:     log,
		tempDir: tempDir,
	}
}

// CreateConfigurator creates a configurator based on the VPN type
func (f *ConfiguratorFactory) CreateConfigurator(vpnType VPNType) (VPNConfigurator, error) {
	switch vpnType {
	case OpenVPNType:
		f.log.Info("Creating OpenVPN configurator")
		return NewOpenVPNConfigurator(f.client, f.log, f.tempDir), nil
	case StrongSwanType:
		f.log.Info("Creating StrongSwan configurator")
		return NewStrongSwanConfigurator(f.client, f.log, f.tempDir), nil
	default:
		return nil, fmt.Errorf("unsupported VPN type: %s", vpnType)
	}
}

// VPNConfigurator interface defines methods that all VPN configurators must implement
type VPNConfigurator interface {
	// Configure configures the VPN server and returns the path to the client configuration file
	Configure(conn interface{}, serverIP string) (string, error)
}
