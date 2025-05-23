package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Rhyanz46/tunneling/os_service"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall" // Needed for ProcessExists

	"golang.org/x/crypto/ssh"
)

type TunnelConfig struct {
	Name        string `json:"name"`
	LocalPort   int    `json:"local_port"`
	RemotePort  int    `json:"remote_port"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type Config struct {
	VPSHost    string         `json:"vps_host"`
	VPSUser    string         `json:"vps_user"`
	VPSPort    int            `json:"vps_port"`
	KeyFile    string         `json:"key_file"`
	Tunnels    []TunnelConfig `json:"tunnels"`
	Retries    int            `json:"retries"`
	RetryDelay int            `json:"retry_delay"`
}

type TunnelManager struct {
	config    Config
	client    *ssh.Client
	listeners map[string]net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
}

func NewTunnelManager(configPath string) (*TunnelManager, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TunnelManager{
		config:    config,
		listeners: make(map[string]net.Listener),
		ctx:       ctx,
		cancel:    cancel,
	}, nil
}

func LoadConfig(configPath string) (Config, error) {
	var config Config

	// Default config
	config = Config{
		VPSHost:    "your-vps-ip",
		VPSUser:    "your-user",
		VPSPort:    22,
		KeyFile:    "~/.ssh/id_rsa",
		Retries:    5,
		RetryDelay: 5,
		Tunnels: []TunnelConfig{
			{
				Name:        "docker",
				LocalPort:   2376,
				RemotePort:  2376,
				Description: "Docker Engine",
				Enabled:     true,
			},
		},
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config file
		return config, SaveConfig(configPath, config)
	}

	file, err := os.Open(configPath)
	if err != nil {
		return config, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	return config, err
}

func SaveConfig(configPath string, config Config) error {
	// Create directory if not exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

func (tm *TunnelManager) Connect() error {
	keyFile := tm.config.KeyFile
	if strings.HasPrefix(keyFile, "~/") {
		home, _ := os.UserHomeDir()
		keyFile = filepath.Join(home, keyFile[2:])
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: tm.config.VPSUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", tm.config.VPSHost, tm.config.VPSPort)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("failed to connect to VPS: %v", err)
	}

	tm.client = client
	log.Printf("✅ Connected to VPS: %s", addr)
	return nil
}

func (tm *TunnelManager) StartTunnels() error {
	for _, tunnel := range tm.config.Tunnels {
		if !tunnel.Enabled {
			log.Printf("⏭️  Skipping disabled tunnel: %s", tunnel.Name)
			continue
		}

		if err := tm.startTunnel(tunnel); err != nil {
			log.Printf("❌ Failed to start tunnel %s: %v", tunnel.Name, err)
			continue
		}
		log.Printf("✅ Started tunnel: %s (%s:%d -> %s:%d)",
			tunnel.Name,
			"localhost", tunnel.LocalPort,
			tm.config.VPSHost, tunnel.RemotePort)
	}
	return nil
}

func (tm *TunnelManager) startTunnel(tunnel TunnelConfig) error {
	localAddr := fmt.Sprintf("localhost:%d", tunnel.LocalPort)
	remoteAddr := fmt.Sprintf("localhost:%d", tunnel.RemotePort)

	// Create reverse tunnel
	listener, err := tm.client.Listen("tcp", remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on remote port %d: %v", tunnel.RemotePort, err)
	}

	tm.mu.Lock()
	tm.listeners[tunnel.Name] = listener
	tm.mu.Unlock()

	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		defer listener.Close()

		for {
			select {
			case <-tm.ctx.Done():
				return
			default:
			}

			conn, err := listener.Accept()
			if err != nil {
				if tm.ctx.Err() == nil {
					log.Printf("❌ Error accepting connection for tunnel %s: %v", tunnel.Name, err)
				}
				return
			}

			go tm.handleConnection(conn, localAddr, tunnel.Name)
		}
	}()

	return nil
}

func (tm *TunnelManager) handleConnection(remoteConn net.Conn, localAddr, tunnelName string) {
	defer remoteConn.Close()

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		log.Printf("❌ Failed to connect to local service %s for tunnel %s: %v", localAddr, tunnelName, err)
		return
	}
	defer localConn.Close()

	// Copy data between connections
	go func() {
		io.Copy(localConn, remoteConn)
		localConn.Close()
	}()

	io.Copy(remoteConn, localConn)
}

func (tm *TunnelManager) AddTunnel(name string, localPort, remotePort int, description string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Check if tunnel already exists
	for _, tunnel := range tm.config.Tunnels {
		if tunnel.Name == name {
			return fmt.Errorf("tunnel with name '%s' already exists", name)
		}
	}

	newTunnel := TunnelConfig{
		Name:        name,
		LocalPort:   localPort,
		RemotePort:  remotePort,
		Description: description,
		Enabled:     true,
	}

	tm.config.Tunnels = append(tm.config.Tunnels, newTunnel)

	// Save config
	configPath := GetConfigPath()
	if err := SaveConfig(configPath, tm.config); err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}

	// Start tunnel if connected
	if tm.client != nil {
		if err := tm.startTunnel(newTunnel); err != nil {
			return fmt.Errorf("failed to start tunnel: %v", err)
		}
		log.Printf("✅ Added and started tunnel: %s", name)
	}

	return nil
}

func (tm *TunnelManager) RemoveTunnel(name string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Stop tunnel if running
	if listener, exists := tm.listeners[name]; exists {
		listener.Close()
		delete(tm.listeners, name)
	}

	// Remove from config
	for i, tunnel := range tm.config.Tunnels {
		if tunnel.Name == name {
			tm.config.Tunnels = append(tm.config.Tunnels[:i], tm.config.Tunnels[i+1:]...)

			// Save config
			configPath := GetConfigPath()
			if err := SaveConfig(configPath, tm.config); err != nil {
				return fmt.Errorf("failed to save config: %v", err)
			}

			log.Printf("✅ Removed tunnel: %s", name)
			return nil
		}
	}

	return fmt.Errorf("tunnel '%s' not found", name)
}

func (tm *TunnelManager) ListTunnels() {
	fmt.Println("\n📋 Configured Tunnels:")
	fmt.Println("Name\t\tLocal\tRemote\tStatus\t\tDescription")
	fmt.Println("----\t\t-----\t------\t------\t\t-----------")

	for _, tunnel := range tm.config.Tunnels {
		status := "❌ Disabled"
		if tunnel.Enabled {
			tm.mu.RLock()
			if _, exists := tm.listeners[tunnel.Name]; exists {
				status = "✅ Running"
			} else {
				status = "⏸️  Stopped"
			}
			tm.mu.RUnlock()
		}

		fmt.Printf("%s\t\t%d\t%d\t%s\t%s\n",
			tunnel.Name, tunnel.LocalPort, tunnel.RemotePort, status, tunnel.Description)
	}
}

func (tm *TunnelManager) Stop() {
	log.Println("🛑 Stopping all tunnels...")
	tm.cancel()

	tm.mu.Lock()
	for name, listener := range tm.listeners {
		listener.Close()
		log.Printf("⏹️  Stopped tunnel: %s", name)
	}
	tm.mu.Unlock()

	tm.wg.Wait()

	if tm.client != nil {
		tm.client.Close()
	}

	log.Println("✅ All tunnels stopped")
}

func GetConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "."+os_service.ServiceName, "config.json")
}

func GetPidFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "."+os_service.ServiceName, "tunnel-manager.pid")
}

func WritePidFile(pid int) error {
	pidFile := GetPidFilePath()
	dir := filepath.Dir(pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0644)
}

func ReadPidFile() (int, error) {
	pidFile := GetPidFilePath()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func RemovePidFile() {
	pidFile := GetPidFilePath()
	os.Remove(pidFile)
}

func InstallSystemService() error {
	switch {
	case isLinux():
		return os_service.InstallSystemdService()
	case isDarwin():
		return os_service.InstallLaunchdPlist()
	case isWindows():
		return os_service.InstallWindowsService()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

func UninstallSystemService() error {
	switch {
	case isLinux():
		return os_service.UninstallSystemdService()
	case isDarwin():
		return os_service.UninstallLaunchdPlist()
	case isWindows():
		return os_service.UninstallWindowsService()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

func isLinux() bool {
	return runtime.GOOS == "linux"
}

func isDarwin() bool {
	return runtime.GOOS == "darwin"
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  tunnel-manager start              - Start all tunnels")
		fmt.Println("  tunnel-manager start -d           - Start all tunnels in background (daemon)")
		fmt.Println("  tunnel-manager stop               - Stop background tunnel-manager")
		fmt.Println("  tunnel-manager add <name> <local_port> <remote_port> [description]")
		fmt.Println("  tunnel-manager remove <name>      - Remove a tunnel")
		fmt.Println("  tunnel-manager list               - List all tunnels")
		fmt.Println("  tunnel-manager status             - Show connection status")
		fmt.Println("  tunnel-manager login              - Login and setup SSH key authentication")
		fmt.Println("  tunnel-manager install-service    - Install systemd service")
		fmt.Println("  tunnel-manager uninstall-service  - Uninstall systemd service")
		return
	}

	configPath := GetConfigPath()
	tm, err := NewTunnelManager(configPath)
	if err != nil {
		log.Fatal("Failed to create tunnel manager:", err)
	}

	command := os.Args[1]

	switch command {
	case "start":
		handleStartCommand(tm, os.Args)
	case "stop":
		handleStopCommand(tm, os.Args)
	case "add":
		handleAddCommand(tm, os.Args)
	case "remove":
		handleRemoveCommand(tm, os.Args)
	case "list":
		handleListCommand(tm, os.Args)
	case "status":
		handleStatusCommand(tm, os.Args)
	case "login":
		handleLoginCommand(tm, os.Args)
	case "install-service":
		handleInstallServiceCommand(tm, os.Args)
	case "uninstall-service":
		handleUninstallServiceCommand(tm, os.Args)
	default:
		log.Fatal("Unknown command:", command)
	}
}

// GenerateRSAKeyPair generates a new RSA private and public key pair.
func GenerateRSAKeyPair() ([]byte, []byte, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}
	privPEM := pem.EncodeToMemory(&privBlock)
	pub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	return privPEM, pubBytes, nil
}

// ProcessExists returns true if a process with the given pid exists
func ProcessExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false // Process not found means it doesn't exist
	}
	// Sending signal 0 to a process on Unix-like systems checks if the process exists without affecting it.
	// On Windows, os.FindProcess alone doesn't guarantee the process is still running,
	// but process.Signal(syscall.Signal(0)) is a common way to check.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
