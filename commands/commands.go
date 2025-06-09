package commands

import (
	"bufio"
	"bytes"
	"context" // Added
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json" // Added
	"encoding/pem"
	"fmt"
	"io" // Added
	"log"
	"net" // Added
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime" // For isLinux, isDarwin, isWindows
	"strconv"
	"strings"
	"sync" // Added
	"syscall"
	"time"

	"github.com/Rhyanz46/tunneling/os_service" // For Install/Uninstall
	"github.com/nexidian/gocliselect"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// Struct definitions (copied from main.go)
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
	Pid        int            `json:"pid"`
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

// NewTunnelManager function (copied from main.go and exported)
// It now uses the internal getConfigPath
func NewTunnelManager() (*TunnelManager, error) {
	configPath := getConfigPath()         // Call internal getConfigPath
	config, err := loadConfig(configPath) // This is the unexported loadConfig
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

// TunnelManager methods (copied from main.go)
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

	sshClientConfig := &ssh.ClientConfig{ // Renamed to avoid conflict with Config struct
		User: tm.config.VPSUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", tm.config.VPSHost, tm.config.VPSPort)
	client, err := ssh.Dial("tcp", addr, sshClientConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to VPS: %v", err)
	}

	tm.client = client
	log.Printf("✅ Connected to VPS: %s", addr)
	return nil
}

type SSHDConf struct {
	GatewayPorts       bool
	AllowTcpForwarding bool
}

func (s *TunnelManager) AnalyzeConfig(output string) (result SSHDConf) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.ToLower(line)

		if len(line) > 0 && string(line[0]) == "#" {
			continue
		}

		if strings.Contains(line, "gatewayports") {
			if strings.Contains(line, "yes") || strings.Contains(line, "clientspecified") {
				result.GatewayPorts = true
				fmt.Printf("✅ GatewayPorts: %s\n", strings.Split(line, " ")[1])
			} else {
				fmt.Printf("❌ GatewayPorts: %s (should be 'yes')\n", strings.Split(line, " ")[1])
			}
		}

		if strings.Contains(line, "allowtcpforwarding") {
			if strings.Contains(line, "yes") || strings.Contains(line, "remote") {
				result.AllowTcpForwarding = true
				fmt.Printf("✅ AllowTcpForwarding: %s\n", strings.Split(line, " ")[1])
			} else {
				fmt.Printf("❌ AllowTcpForwarding: %s (should be 'yes')\n", strings.Split(line, " ")[1])
			}
		}
	}
	return
}

func (s *TunnelManager) CheckSSHDConfig() (string, error) {
	var stdoutBuf bytes.Buffer
	session, err := s.client.NewSession()
	if session != nil {
		defer session.Close()
	}
	if err != nil {
		log.Fatal("Failed to create session. " + err.Error())
	}

	session.Stdout = &stdoutBuf

	// session.Stdin = os.Stdin
	// session.Stdout = os.Stdout
	// session.Stderr = os.Stderr

	cmd := "cat /etc/ssh/sshd_config || echo 'Config not found'"
	err = session.Run(cmd)
	if err != nil {
		log.Fatal("Command execution error. " + err.Error())
	}

	return stdoutBuf.String(), nil
}

func (tm *TunnelManager) StartTunnels() error {
	for _, tunnel := range tm.config.Tunnels {
		if !tunnel.Enabled {
			log.Printf("⏭️  Skipping disabled tunnel: %s", tunnel.Name)
			continue
		}

		if err := tm.startTunnel(tunnel); err != nil { // Call to unexported startTunnel
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

func (tm *TunnelManager) startTunnel(tunnel TunnelConfig) error { // Unexported
	localAddr := fmt.Sprintf("localhost:%d", tunnel.LocalPort)
	remoteAddr := fmt.Sprintf("localhost:%d", tunnel.RemotePort)

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
				if tm.ctx.Err() == nil { // Check if context is not done
					log.Printf("❌ Error accepting connection for tunnel %s: %v", tunnel.Name, err)
				}
				return
			}
			go tm.handleConnection(conn, localAddr, tunnel.Name) // Call to unexported handleConnection
		}
	}()
	return nil
}

func (tm *TunnelManager) handleConnection(remoteConn net.Conn, localAddr, tunnelName string) { // Unexported
	defer remoteConn.Close()

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		log.Printf("❌ Failed to connect to local service %s for tunnel %s: %v", localAddr, tunnelName, err)
		return
	}
	defer localConn.Close()

	go func() {
		io.Copy(localConn, remoteConn)
		localConn.Close()
	}()
	io.Copy(remoteConn, localConn)
}

func (tm *TunnelManager) AddTunnel(name string, localPort, remotePort int, description string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

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

	currentConfigPath := getConfigPath()                             // Call unexported getConfigPath
	if err := saveConfig(currentConfigPath, tm.config); err != nil { // Call unexported saveConfig
		return fmt.Errorf("failed to save config: %v", err)
	}

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

	if listener, exists := tm.listeners[name]; exists {
		listener.Close()
		delete(tm.listeners, name)
	}

	for i, tunnel := range tm.config.Tunnels {
		if tunnel.Name == name {
			tm.config.Tunnels = append(tm.config.Tunnels[:i], tm.config.Tunnels[i+1:]...)
			currentConfigPath := getConfigPath()                             // Call unexported getConfigPath
			if err := saveConfig(currentConfigPath, tm.config); err != nil { // Call unexported saveConfig
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

// Helper functions (copied from main.go and mostly unexported)

// getConfigPath returns the path to the configuration file.
func getConfigPath() string {
	home, _ := os.UserHomeDir()
	// This assumes os_service.ServiceName is accessible or replaced.
	// For now, let's hardcode it or assume it's globally available if not part of a struct.
	// If os_service is a package, it should be `os_service.ServiceName`.
	// Let's assume os_service.ServiceName will be available.
	// If os_service is not directly usable here, this will need adjustment.
	// For now, to make progress, I'll use a placeholder if direct import fails.
	// However, `github.com/Rhyanz46/tunneling/os_service` should be imported.
	return filepath.Join(home, ".tunnel-manager", "config.json") // Placeholder for ServiceName
}

// loadConfig loads the configuration from the given path.
func loadConfig(configPath string) (Config, error) { // Uses local Config type
	var config Config
	config = Config{ // Default config
		VPSHost:    "your-vps-ip",
		VPSUser:    "your-user",
		VPSPort:    22,
		KeyFile:    "~/.ssh/id_rsa",
		Retries:    5,
		RetryDelay: 5,
		Tunnels:    []TunnelConfig{},
	}
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
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

// saveConfig saves the configuration to the given path.
func saveConfig(configPath string, config Config) error { // Uses local Config type
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

func getPidFilePath() string {
	home, _ := os.UserHomeDir()
	// Similar to getConfigPath, this needs ServiceName.
	return filepath.Join(home, ".tunnel-manager", "tunnel-manager.pid") // Placeholder
}

func writePidFile(pid int) error {
	pidFile := getPidFilePath()
	dir := filepath.Dir(pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0644)
}

func readPidFile() (int, error) {
	pidFile := getPidFilePath()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func removePidFile() {
	pidFile := getPidFilePath()
	os.Remove(pidFile)
}

func generateRSAKeyPair() ([]byte, []byte, error) {
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

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
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

// InstallSystemService should remain exported if it's intended to be called from main
func InstallSystemService() error {
	// Assumes os_service is imported correctly
	// import "github.com/Rhyanz46/tunneling/os_service"
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

// UninstallSystemService should remain exported
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

// Existing command handlers
// Calls to helper functions below will be updated to use local/unexported names.
func HandleStartCommand(tm *TunnelManager, args []string) {
	background := len(args) > 2 && args[2] == "-d"
	if background {
		if os.Getenv("TUNNEL_MANAGER_DAEMON") == "1" {
			// Determine log file path
			home, _ := os.UserHomeDir()
			logDir := filepath.Join(home, "."+os_service.ServiceName) // os_service.ServiceName is "tunnel-manager"
			if err := os.MkdirAll(logDir, 0755); err != nil {
				// Problem creating log directory, log to standard logger and potentially exit or continue
				log.Printf("[DAEMON_CHILD] CRITICAL: Failed to create log directory %s: %v", logDir, err)
				// If we can't create log dir, we probably can't create pid dir either.
			}
			logFilePath := filepath.Join(logDir, "daemon.log")

			// Open/create the log file for appending
			logFile, err_log_file := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err_log_file != nil {
				// Problem opening log file, log to standard logger and potentially exit or continue
				log.Printf("[DAEMON_CHILD] CRITICAL: Failed to open daemon log file %s: %v", logFilePath, err_log_file)
			}
			if err_log_file == nil {
				defer logFile.Close()
			}

			// Create a new logger
			var daemonLogger *log.Logger
			if err_log_file == nil {
				daemonLogger = log.New(logFile, "[DAEMON_CHILD] ", log.LstdFlags|log.Lmicroseconds)
			} else {
				// Fallback to standard logger if file logger fails
				daemonLogger = log.New(os.Stderr, "[DAEMON_CHILD_STDERR] ", log.LstdFlags|log.Lmicroseconds)
			}

			daemonLogger.Println("Daemon child process started.")

			// Comment out redirection of os.Stdout and os.Stderr to os.DevNull
			// f, err_null := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			// if err_null != nil {
			// 	daemonLogger.Printf("Error opening /dev/null: %v", err_null)
			// } else {
			// 	os.Stdout = f
			// 	os.Stderr = f
			// 	// os.Stdin = f // Stdin redirection can remain if desired
			// }
			// daemonLogger.Println("Output redirection to /dev/null (currently commented out).")

			pid := os.Getpid()
			daemonLogger.Printf("Attempting to write PID %d to PID file.", pid) // Log attempt
			if err := writePidFile(pid); err != nil {                           // Changed to unexported
				// daemonLogger.Printf("CRITICAL: Failed to write PID file for PID %d: %v. Daemon will exit.", pid, err)
				daemonLogger.Fatalf("Exiting due to PID file write failure: %v", err) // This logs and exits
			} else {
				daemonLogger.Printf("PID file written successfully for PID %d.", pid)
			}
			// The old log.Printf("[DAEMON] PID file written: %d", os.Getpid()) is removed as Fatalf would prevent it
			// and the success case is covered by the else block.
		} else {
			// Relaunch self in background
			execPath, _ := os.Executable()
			// if args is os.Args, then os.Args[3:] is args[3:]
			// However, the command itself is args[0], "start" is args[1]
			// so the actual additional arguments start from args[2]
			// if -d is present, it's args[2], so actual further args are args[3:]
			// if -d is not present, then there are no further args beyond "start"
			var cmdArgs []string
			if len(args) > 2 && args[2] == "-d" { // "tunnel-manager", "start", "-d", ...
				cmdArgs = append([]string{"start"}, args[3:]...)
			} else { // "tunnel-manager", "start", ...
				cmdArgs = append([]string{"start"}, args[2:]...)
			}

			cmd := exec.Command(execPath, cmdArgs...)
			cmd.Env = append(os.Environ(), "TUNNEL_MANAGER_DAEMON=1")
			f, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			cmd.Stdout = f
			cmd.Stderr = f
			cmd.Stdin = f
			err := cmd.Start()
			if err != nil {
				log.Fatal("Failed to start in background:", err)
			}
			fmt.Printf("🚀 tunnel-manager started in background (PID %d)\n", cmd.Process.Pid)
			return
		}
	}

	if err := tm.Connect(); err != nil {
		// if background {
		// 	removePidFile() // Changed to unexported
		// }
		log.Fatal("Failed to connect:", err)
	}

	if sshdConfStr, err := tm.CheckSSHDConfig(); err != nil {
		log.Fatal("Can't get SSH Server configuration : ", err)
	} else if confd := tm.AnalyzeConfig(sshdConfStr); !confd.GatewayPorts && !confd.AllowTcpForwarding {
		fmt.Println("\nAnalysis:")
		fmt.Println("=========")
		if confd.GatewayPorts && confd.AllowTcpForwarding {
			fmt.Println("✅ Configuration is correct for public remote port forwarding!")
		} else {
			fmt.Println("❌ Configuration needs to be updated:")
			if !confd.GatewayPorts {
				fmt.Println("   - Set 'GatewayPorts yes' in /etc/ssh/sshd_config")
			}
			if !confd.AllowTcpForwarding {
				fmt.Println("   - Set 'AllowTcpForwarding yes' in /etc/ssh/sshd_config")
			}
			fmt.Println("   - Restart SSH service: sudo systemctl restart sshd")
			os.Exit(1)
		}
	}

	if err := tm.StartTunnels(); err != nil {
		if background {
			removePidFile() // Changed to unexported
		}
		log.Fatal("Failed to start tunnels:", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("🚀 Tunnel manager started. Press Ctrl+C to stop.")
	<-sigChan
	tm.Stop()
	if background {
		removePidFile() // Changed to unexported
	}
}

func HandleStopCommand(tm *TunnelManager, args []string) {
	pid, err := readPidFile() // Changed to unexported
	if err != nil {
		log.Fatal("No background tunnel-manager found (pid file missing)")
	}
	// Cek apakah proses masih hidup
	proc, err := os.FindProcess(pid) // os.FindProcess is fine
	if err != nil {
		removePidFile() // Changed to unexported
		log.Fatalf("Process with PID %d not found. PID file removed.", pid)
	}
	// Coba kirim SIGTERM
	err = proc.Signal(syscall.SIGTERM) // syscall.SIGTERM is fine
	if err != nil {
		removePidFile() // Changed to unexported
		log.Fatalf("Failed to stop tunnel-manager (PID %d): %v. PID file removed.", pid, err)
	}
	// Tunggu proses benar-benar mati (polling max 5 detik)
	for i := 0; i < 50; i++ {
		if !processExists(pid) { // Changed to unexported
			removePidFile() // Changed to unexported
			fmt.Printf("🛑 tunnel-manager (PID %d) stopped.\n", pid)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Printf("Warning: tunnel-manager (PID %d) did not exit after SIGTERM. You may need to kill it manually.", pid)
}

func HandleAddCommand(tm *TunnelManager, args []string) {
	if len(args) < 5 {
		log.Fatal("Usage: tunnel-manager add <name> <local_port> <remote_port> [description]")
	}

	name := args[2]
	localPort, err := strconv.Atoi(args[3])
	if err != nil {
		log.Fatal("Invalid local port:", err)
	}

	remotePort, err := strconv.Atoi(args[4])
	if err != nil {
		log.Fatal("Invalid remote port:", err)
	}

	description := ""
	if len(args) > 5 {
		description = strings.Join(args[5:], " ")
	}

	if err := tm.AddTunnel(name, localPort, remotePort, description); err != nil {
		log.Fatal("Failed to add tunnel:", err)
	}
}

func HandleRemoveCommand(tm *TunnelManager, args []string) {
	if len(args) < 3 {
		log.Fatal("Usage: tunnel-manager remove <name>")
	}

	if err := tm.RemoveTunnel(args[2]); err != nil {
		log.Fatal("Failed to remove tunnel:", err)
	}
}

func HandleListCommand(tm *TunnelManager, args []string) {
	tm.ListTunnels()
}

func HandleStatusCommand(tm *TunnelManager, args []string) {
	if err := tm.Connect(); err != nil {
		fmt.Printf("❌ Connection status: Failed (%v)\n", err)
	} else {
		fmt.Printf("✅ Connection status: Connected to %s\n", tm.config.VPSHost)
		if tm.client != nil { // Check if client is not nil before closing
			tm.client.Close()
		}
	}
}

func HandleLoginCommand(tm *TunnelManager, args []string) {
	// Prompt for host, username, password, and port
	var host, user, password string
	var port int
	var rewriteConfig bool
	fmt.Print("Host: ")
	fmt.Scanln(&host)
	fmt.Print("Username: ")
	fmt.Scanln(&user)
	fmt.Print("Password: ")
	pwd, err := terminal.ReadPassword(0)
	if err != nil {
		fmt.Println("Invalid Password typed: " + string(password))
	}
	password = string(pwd)
	fmt.Print("\nSSH Port [22]: ")
	fmt.Scanln(&port)
	if port == 0 {
		port = 22
	}

	// Try SSH connection with password
	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		log.Fatalf("❌ Failed to connect via SSH: %v", err)
	}
	defer client.Close()
	fmt.Println("✅ SSH password authentication successful.")

	// Generate RSA key if not exists
	home, _ := os.UserHomeDir()
	keyDir := filepath.Join(home, ".tunnel-manager") // Using hardcoded ".tunnel-manager" as ServiceName not directly available
	keyDir = filepath.Join(keyDir, host)             // Using hardcoded ".tunnel-manager" as ServiceName not directly available
	keyDir = filepath.Join(keyDir, user)             // Using hardcoded ".tunnel-manager" as ServiceName not directly available
	keyPath := filepath.Join(keyDir, "id_rsa")
	pubPath := keyPath + ".pub"

rewrite:
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			log.Fatal("Failed to create key directory:", err)
		}
		fmt.Println("🔑 Generating new RSA key pair...")
		priv, pub, err := generateRSAKeyPair() // Changed to unexported
		if err != nil {
			log.Fatal("Failed to generate RSA key:", err)
		}
		os.WriteFile(keyPath, priv, 0600)
		os.WriteFile(pubPath, pub, 0644)
		fmt.Println("✅ RSA key pair generated.")
		fmt.Printf("✅ RSA saved to : %s \n", keyDir)
	} else if !rewriteConfig {
		menu := gocliselect.NewMenu(fmt.Sprintf("🔑 RSA key already exists on : '%s', replace it ? ", keyDir))
		menu.AddItem("Replace", "replace")
		menu.AddItem("No!", "no")
		choice := menu.Display()
		if choice == "replace" {
			rewriteConfig = true
		}

		if rewriteConfig {
			goto rewrite
		}
		fmt.Printf("✅ Using saved RSA, loaded from : %s \n", keyDir)
		fmt.Println("🔑 Using existing key.")
	}

	// Upload public key to server's authorized_keys
	pubKey, err := os.ReadFile(pubPath)
	if err != nil {
		log.Fatal("Failed to read public key:", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create SSH session:", err)
	}
	defer sess.Close()
	authCmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", strings.TrimSpace(string(pubKey)))
	if err := sess.Run(authCmd); err != nil {
		log.Fatal("Failed to upload public key:", err)
	}
	fmt.Println("✅ Public key uploaded to server.")

	// Update config
	configPath := getConfigPath() // Changed to unexported
	// config, err := loadConfig(configPath) // This was already calling local loadConfig
	currentConfig, err := loadConfig(configPath) // Renamed to avoid conflict with the loop variable
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}
	currentConfig.VPSHost = host
	currentConfig.VPSUser = user
	currentConfig.KeyFile = keyPath
	currentConfig.VPSPort = port
	if err := saveConfig(configPath, currentConfig); err != nil { // Changed to unexported
		log.Fatal("Failed to save config:", err)
	}
	fmt.Println("✅ Login and SSH key setup complete. You can now use 'tunnel-manager start'.")
	return
}

func HandleInstallServiceCommand(tm *TunnelManager, args []string) {
	if err := InstallSystemService(); err != nil { // This remains exported and calls local isLinux etc.
		log.Fatalf("Failed to install system service: %v", err)
	}
	fmt.Println("✅ tunnel-manager system service installed and started.")
	return
}

func HandleUninstallServiceCommand(tm *TunnelManager, args []string) {
	if err := UninstallSystemService(); err != nil { // This remains exported
		log.Fatalf("Failed to uninstall system service: %v", err)
	}
	fmt.Println("✅ tunnel-manager system service uninstalled.")
	return
}

// Need to add github.com/Rhyanz46/tunneling/os_service to imports
// It will be added in the next step automatically if missing by the tool
// For now, ensuring the functions are defined here.
