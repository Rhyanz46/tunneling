package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

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
	config, err := loadConfig(configPath)
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

func loadConfig(configPath string) (Config, error) {
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
		return config, saveConfig(configPath, config)
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

func saveConfig(configPath string, config Config) error {
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
	configPath := getConfigPath()
	if err := saveConfig(configPath, tm.config); err != nil {
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
			configPath := getConfigPath()
			if err := saveConfig(configPath, tm.config); err != nil {
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

func getConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".tunnel-manager", "config.json")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  tunnel-manager start              - Start all tunnels")
		fmt.Println("  tunnel-manager add <name> <local_port> <remote_port> [description]")
		fmt.Println("  tunnel-manager remove <name>      - Remove a tunnel")
		fmt.Println("  tunnel-manager list               - List all tunnels")
		fmt.Println("  tunnel-manager status             - Show connection status")
		return
	}

	configPath := getConfigPath()
	tm, err := NewTunnelManager(configPath)
	if err != nil {
		log.Fatal("Failed to create tunnel manager:", err)
	}

	command := os.Args[1]

	switch command {
	case "start":
		if err := tm.Connect(); err != nil {
			log.Fatal("Failed to connect:", err)
		}

		if err := tm.StartTunnels(); err != nil {
			log.Fatal("Failed to start tunnels:", err)
		}

		// Handle graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		log.Println("🚀 Tunnel manager started. Press Ctrl+C to stop.")
		<-sigChan
		tm.Stop()

	case "add":
		if len(os.Args) < 5 {
			log.Fatal("Usage: tunnel-manager add <name> <local_port> <remote_port> [description]")
		}

		name := os.Args[2]
		localPort, err := strconv.Atoi(os.Args[3])
		if err != nil {
			log.Fatal("Invalid local port:", err)
		}

		remotePort, err := strconv.Atoi(os.Args[4])
		if err != nil {
			log.Fatal("Invalid remote port:", err)
		}

		description := ""
		if len(os.Args) > 5 {
			description = strings.Join(os.Args[5:], " ")
		}

		if err := tm.AddTunnel(name, localPort, remotePort, description); err != nil {
			log.Fatal("Failed to add tunnel:", err)
		}

	case "remove":
		if len(os.Args) < 3 {
			log.Fatal("Usage: tunnel-manager remove <name>")
		}

		if err := tm.RemoveTunnel(os.Args[2]); err != nil {
			log.Fatal("Failed to remove tunnel:", err)
		}

	case "list":
		tm.ListTunnels()

	case "status":
		if err := tm.Connect(); err != nil {
			fmt.Printf("❌ Connection status: Failed (%v)\n", err)
		} else {
			fmt.Printf("✅ Connection status: Connected to %s\n", tm.config.VPSHost)
			tm.client.Close()
		}

	default:
		log.Fatal("Unknown command:", command)
	}
}
