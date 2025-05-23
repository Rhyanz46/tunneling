package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

func handleStartCommand(tm *TunnelManager, args []string) {
	background := len(args) > 2 && args[2] == "-d"
	if background {
		if os.Getenv("TUNNEL_MANAGER_DAEMON") == "1" {
			// Already in daemon mode, setup output to /dev/null
			f, _ := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			os.Stdout = f
			os.Stderr = f
			os.Stdin = f
			if err := WritePidFile(os.Getpid()); err != nil {
				log.Fatalf("Failed to write PID file: %v", err)
			}
			log.Printf("[DAEMON] PID file written: %d", os.Getpid())
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
		if background {
			RemovePidFile()
		}
		log.Fatal("Failed to connect:", err)
	}

	if err := tm.StartTunnels(); err != nil {
		if background {
			RemovePidFile()
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
		RemovePidFile()
	}
}

func handleStopCommand(tm *TunnelManager, args []string) {
	pid, err := ReadPidFile()
	if err != nil {
		log.Fatal("No background tunnel-manager found (pid file missing)")
	}
	// Cek apakah proses masih hidup
	proc, err := os.FindProcess(pid)
	if err != nil {
		RemovePidFile()
		log.Fatalf("Process with PID %d not found. PID file removed.", pid)
	}
	// Coba kirim SIGTERM
	err = proc.Signal(syscall.SIGTERM)
	if err != nil {
		RemovePidFile()
		log.Fatalf("Failed to stop tunnel-manager (PID %d): %v. PID file removed.", pid, err)
	}
	// Tunggu proses benar-benar mati (polling max 5 detik)
	for i := 0; i < 50; i++ {
		if !ProcessExists(pid) {
			RemovePidFile()
			fmt.Printf("🛑 tunnel-manager (PID %d) stopped.\n", pid)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	log.Printf("Warning: tunnel-manager (PID %d) did not exit after SIGTERM. You may need to kill it manually.", pid)
}

func handleAddCommand(tm *TunnelManager, args []string) {
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

func handleRemoveCommand(tm *TunnelManager, args []string) {
	if len(args) < 3 {
		log.Fatal("Usage: tunnel-manager remove <name>")
	}

	if err := tm.RemoveTunnel(args[2]); err != nil {
		log.Fatal("Failed to remove tunnel:", err)
	}
}

func handleListCommand(tm *TunnelManager, args []string) {
	tm.ListTunnels()
}

func handleStatusCommand(tm *TunnelManager, args []string) {
	if err := tm.Connect(); err != nil {
		fmt.Printf("❌ Connection status: Failed (%v)\n", err)
	} else {
		fmt.Printf("✅ Connection status: Connected to %s\n", tm.config.VPSHost)
		tm.client.Close()
	}
}

func handleLoginCommand(tm *TunnelManager, args []string) {
	// Prompt for host, username, password, and port
	var host, user, password string
	var port int
	fmt.Print("Host: ")
	fmt.Scanln(&host)
	fmt.Print("Username: ")
	fmt.Scanln(&user)
	fmt.Print("Password: ")
	fmt.Scanln(&password)
	fmt.Print("SSH Port [22]: ")
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
	keyDir := filepath.Join(home, ".tunnel-manager")
	keyPath := filepath.Join(keyDir, "id_rsa")
	pubPath := keyPath + ".pub"
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			log.Fatal("Failed to create key directory:", err)
		}
		fmt.Println("🔑 Generating new RSA key pair...")
		priv, pub, err := GenerateRSAKeyPair()
		if err != nil {
			log.Fatal("Failed to generate RSA key:", err)
		}
		os.WriteFile(keyPath, priv, 0600)
		os.WriteFile(pubPath, pub, 0644)
		fmt.Println("✅ RSA key pair generated.")
	} else {
		fmt.Println("🔑 RSA key already exists, using existing key.")
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
	configPath := GetConfigPath()
	config, err := LoadConfig(configPath) // This uses the local Config type, not tm.config
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}
	config.VPSHost = host
	config.VPSUser = user
	config.KeyFile = keyPath
	config.VPSPort = port
	if err := SaveConfig(configPath, config); err != nil {
		log.Fatal("Failed to save config:", err)
	}
	fmt.Println("✅ Login and SSH key setup complete. You can now use 'tunnel-manager start'.")
	return
}

func handleInstallServiceCommand(tm *TunnelManager, args []string) {
	if err := InstallSystemService(); err != nil {
		log.Fatalf("Failed to install system service: %v", err)
	}
	fmt.Println("✅ tunnel-manager system service installed and started.")
	return
}

func handleUninstallServiceCommand(tm *TunnelManager, args []string) {
	if err := UninstallSystemService(); err != nil {
		log.Fatalf("Failed to uninstall system service: %v", err)
	}
	fmt.Println("✅ tunnel-manager system service uninstalled.")
	return
}
