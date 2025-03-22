package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/secretbay/backend/internal/config"
	"github.com/secretbay/backend/internal/ssh"
	"github.com/secretbay/backend/internal/vpn"
	"github.com/sirupsen/logrus"
)

// VPNConfigRequest represents the request to configure a VPN
type VPNConfigRequest struct {
	ServerIP   string `json:"server_ip"`
	Username   string `json:"username"`
	AuthMethod string `json:"auth_method"`
	AuthCred   string `json:"auth_credential"`
	VPNType    string `json:"vpn_type"`
}

// VPNConfigResponse represents the response from a VPN configuration
type VPNConfigResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	NewPassword string `json:"new_password,omitempty"`
	ConfigURL   string `json:"config_url,omitempty"`
}

// ConfigureVPNHandler handles VPN configuration requests
func ConfigureVPNHandler(log *logrus.Logger, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse request
		var req VPNConfigRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			log.Errorf("Failed to parse request: %v", err)
			http.Error(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		// Validate request
		if req.ServerIP == "" {
			http.Error(w, "Missing server IP", http.StatusBadRequest)
			return
		}

		if req.AuthMethod == "" {
			req.AuthMethod = "password" // Default to password authentication
		}

		if req.Username == "" {
			req.Username = "root" // Default to root user
		}

		if req.AuthCred == "" {
			http.Error(w, "Missing authentication credential", http.StatusBadRequest)
			return
		}

		// Default VPN type
		if req.VPNType == "" {
			req.VPNType = "ikev2" // Default to StrongSwan
		}

		// Map VPN type string to enum
		var vpnType vpn.VPNType
		switch req.VPNType {
		case "openvpn":
			vpnType = vpn.OpenVPNType
		case "ikev2", "strongswan":
			vpnType = vpn.StrongSwanType
		default:
			http.Error(w, "Unsupported VPN type", http.StatusBadRequest)
			return
		}

		// Create SSH client
		sshClient, err := createSSHClient(req, log)
		if err != nil {
			log.Errorf("Failed to create SSH client: %v", err)
			http.Error(w, fmt.Sprintf("SSH client error: %v", err), http.StatusInternalServerError)
			return
		}

		// Connect to the server
		conn, err := sshClient.Connect()
		if err != nil {
			log.Errorf("Failed to connect to server: %v", err)
			http.Error(w, fmt.Sprintf("Connection error: %v", err), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Create session directory
		sessionDir := filepath.Join(cfg.TempDir, "vpn_"+vpn.GenerateRandomUUID())
		if err := os.MkdirAll(sessionDir, 0750); err != nil {
			log.Errorf("Failed to create session directory: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer os.RemoveAll(sessionDir)

		// Create VPN configurator
		factory := vpn.NewConfiguratorFactory(sshClient, log, sessionDir)
		configurator, err := factory.CreateConfigurator(vpnType)
		if err != nil {
			log.Errorf("Failed to create VPN configurator: %v", err)
			http.Error(w, fmt.Sprintf("Configuration error: %v", err), http.StatusInternalServerError)
			return
		}

		// Configure VPN - pass the connection as interface{}
		configPath, err := configurator.Configure(conn, req.ServerIP)
		if err != nil {
			log.Errorf("Failed to configure VPN: %v", err)
			http.Error(w, fmt.Sprintf("VPN configuration error: %v", err), http.StatusInternalServerError)
			return
		}

		// Generate new password for the server
		newPassword, err := ssh.GenerateRandomPassword(16)
		if err != nil {
			log.Errorf("Failed to generate new password: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Change server password - pass client and connection as interface{}
		if err := vpn.ChangeServerPassword(sshClient, conn, req.Username, newPassword); err != nil {
			log.Errorf("Failed to change server password: %v", err)
			http.Error(w, fmt.Sprintf("Password change error: %v", err), http.StatusInternalServerError)
			return
		}

		// Copy config file to public directory
		configFileName := filepath.Base(configPath)
		publicConfigPath := filepath.Join(cfg.TempDir, "public", configFileName)

		// Ensure public directory exists
		if err := os.MkdirAll(filepath.Dir(publicConfigPath), 0750); err != nil {
			log.Errorf("Failed to create public directory: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Copy the config file
		if err := copyFile(configPath, publicConfigPath); err != nil {
			log.Errorf("Failed to copy config file: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Clean up server data - pass client and connection as interface{}
		if err := vpn.CleanupServerData(sshClient, conn, log); err != nil {
			log.Warnf("Server cleanup warning: %v", err)
			// Continue even if cleanup has issues
		}

		// Create response
		configURL := fmt.Sprintf("/download/%s", configFileName)
		resp := VPNConfigResponse{
			Status:      "success",
			Message:     "VPN configured successfully",
			NewPassword: newPassword,
			ConfigURL:   configURL,
		}

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}
}

// Helper functions
func createSSHClient(req VPNConfigRequest, log *logrus.Logger) (*ssh.Client, error) {
	opts := ssh.ClientOptions{
		Host:       req.ServerIP,
		Port:       22,
		Username:   req.Username,
		AuthMethod: req.AuthMethod,
		AuthCred:   req.AuthCred,
		Logger:     log,
	}

	return ssh.NewClient(opts)
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}
