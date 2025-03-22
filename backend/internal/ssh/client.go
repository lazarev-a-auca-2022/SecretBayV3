package ssh

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// Client represents an SSH client connection
type Client struct {
	config *ssh.ClientConfig
	addr   string
	log    *logrus.Logger
}

// ClientOptions contains the options for creating a new SSH client
type ClientOptions struct {
	Host       string
	Port       int
	Username   string
	AuthMethod string // "password" or "key"
	AuthCred   string // password or private key content
	KeyPath    string // path to private key file (alternative to AuthCred)
	Timeout    time.Duration
	Logger     *logrus.Logger
}

// NewClient creates a new SSH client
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Logger == nil {
		opts.Logger = logrus.New()
		opts.Logger.SetOutput(io.Discard) // Silent by default
	}

	if opts.Port == 0 {
		opts.Port = 22
	}

	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}

	// Create authentication method
	var authMethod ssh.AuthMethod
	switch opts.AuthMethod {
	case "password":
		authMethod = ssh.Password(opts.AuthCred)
	case "key":
		var keyData []byte
		var err error

		if opts.AuthCred != "" {
			keyData = []byte(opts.AuthCred)
		} else if opts.KeyPath != "" {
			keyData, err = os.ReadFile(opts.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read private key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("either AuthCred or KeyPath must be specified for key authentication")
		}

		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethod = ssh.PublicKeys(signer)
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", opts.AuthMethod)
	}

	// Create client config
	config := &ssh.ClientConfig{
		User: opts.Username,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // WARNING: this is insecure
		Timeout:         opts.Timeout,
	}

	return &Client{
		config: config,
		addr:   fmt.Sprintf("%s:%d", opts.Host, opts.Port),
		log:    opts.Logger,
	}, nil
}

// Connect establishes a connection to the SSH server
func (c *Client) Connect() (*ssh.Client, error) {
	c.log.Infof("Connecting to SSH server at %s", c.addr)
	return ssh.Dial("tcp", c.addr, c.config)
}

// RunCommand runs a command on the remote server
func (c *Client) RunCommand(conn interface{}, command string) (string, string, error) {
	// Type assertion for standard SSH client
	client, ok := conn.(*ssh.Client)
	if !ok {
		return "", "", fmt.Errorf("invalid SSH client type")
	}

	session, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	c.log.Debugf("Running command: %s", command)
	err = session.Run(command)
	return stdout.String(), stderr.String(), err
}

// CopyFile copies a local file to the remote server
func (c *Client) CopyFile(conn interface{}, localPath, remotePath string) error {
	// Type assertion for standard SSH client
	client, ok := conn.(*ssh.Client)
	if !ok {
		return fmt.Errorf("invalid SSH client type")
	}

	c.log.Debugf("Copying file from %s to %s", localPath, remotePath)

	// Open local file
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	// Get file info
	fileInfo, err := localFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}

	// Create SCP session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up pipes
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	var stderr bytes.Buffer
	session.Stderr = &stderr

	// Start SCP command
	err = session.Start(fmt.Sprintf("scp -t %s", remotePath))
	if err != nil {
		return fmt.Errorf("failed to start scp session: %w", err)
	}

	// Send file header
	fileHeader := fmt.Sprintf("C%04o %d %s\n", fileInfo.Mode().Perm(), fileInfo.Size(), filepath.Base(remotePath))
	_, err = stdin.Write([]byte(fileHeader))
	if err != nil {
		return fmt.Errorf("failed to send file header: %w", err)
	}

	// Copy file content
	_, err = io.Copy(stdin, localFile)
	if err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Signal end of transfer
	_, err = stdin.Write([]byte{0})
	if err != nil {
		return fmt.Errorf("failed to signal end of transfer: %w", err)
	}

	// Close stdin and wait for session to finish
	stdin.Close()
	err = session.Wait()
	if err != nil {
		return fmt.Errorf("scp transfer failed: %w, stderr: %s", err, stderr.String())
	}

	return nil
}

// DownloadFile downloads a file from the remote server
func (c *Client) DownloadFile(conn interface{}, remotePath, localPath string) error {
	// Type assertion for standard SSH client
	client, ok := conn.(*ssh.Client)
	if !ok {
		return fmt.Errorf("invalid SSH client type")
	}

	c.log.Debugf("Downloading file from %s to %s", remotePath, localPath)

	// Create SCP session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Set up pipes
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %w", err)
	}

	var stderr bytes.Buffer
	session.Stderr = &stderr

	// Start SCP command
	err = session.Start(fmt.Sprintf("scp -f %s", remotePath))
	if err != nil {
		return fmt.Errorf("failed to start scp session: %w", err)
	}

	// Create local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer localFile.Close()

	// Signal ready to receive
	_, err = stdin.Write([]byte{0})
	if err != nil {
		return fmt.Errorf("failed to signal ready: %w", err)
	}

	// Read file header
	headerBuf := make([]byte, 1024)
	_, err = stdout.Read(headerBuf)
	if err != nil {
		return fmt.Errorf("failed to read file header: %w", err)
	}

	// Parse header to get file size
	header := string(headerBuf)
	parts := strings.SplitN(header, " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[0], "C") {
		return fmt.Errorf("invalid file header: %s", header)
	}

	// Extract file size
	var fileSize int64
	_, err = fmt.Sscanf(parts[1], "%d", &fileSize)
	if err != nil {
		return fmt.Errorf("failed to parse file size: %w", err)
	}

	// Signal ready to receive file content
	_, err = stdin.Write([]byte{0})
	if err != nil {
		return fmt.Errorf("failed to signal ready for content: %w", err)
	}

	// Copy file content
	_, err = io.CopyN(localFile, stdout, fileSize)
	if err != nil {
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Read and discard the final status byte
	_, err = stdout.Read(make([]byte, 1))
	if err != nil {
		return fmt.Errorf("failed to read status byte: %w", err)
	}

	// Signal completion
	_, err = stdin.Write([]byte{0})
	if err != nil {
		return fmt.Errorf("failed to signal completion: %w", err)
	}

	// Wait for session to finish
	err = session.Wait()
	if err != nil {
		return fmt.Errorf("scp transfer failed: %w, stderr: %s", err, stderr.String())
	}

	return nil
}

// GenerateRandomPassword generates a random password
func GenerateRandomPassword(length int) (string, error) {
	if length < 8 {
		length = 16
	}

	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	bytes := make([]byte, length)

	// Use crypto/rand for secure password generation
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}

	// Map random bytes to the character set
	for i := 0; i < length; i++ {
		bytes[i] = chars[int(bytes[i])%len(chars)]
	}

	return string(bytes), nil
}
