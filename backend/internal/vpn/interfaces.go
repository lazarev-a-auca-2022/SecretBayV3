package vpn

import (
	"github.com/secretbay/backend/internal/ssh"
)

// SSHConnection defines common interface that both our custom SSH client
// and the standard golang.org/x/crypto/ssh client will implement
type SSHConnection interface {
	// RunCommand executes a command over SSH and returns stdout, stderr, and error
	RunCommand(conn interface{}, cmd string) (string, string, error)
	// DownloadFile downloads a file from the remote server
	DownloadFile(conn interface{}, remotePath, localPath string) error
	// CopyFile copies a local file to the remote server
	CopyFile(conn interface{}, localPath, remotePath string) error
}

// GetSSHConnection converts any SSH connection to our SSHConnection interface
func GetSSHConnection(conn interface{}) SSHConnection {
	// Type assertion for our custom SSH client
	if client, ok := conn.(*ssh.Client); ok {
		return client
	}
	// Add other type assertions here if needed
	return nil
}
