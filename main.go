package main

import (
	"fmt"
	"log"
	"os"
	"github.com/Rhyanz46/tunneling/commands" // Corrected import path
)

// All helper functions, struct definitions, and TunnelManager methods are now in the commands package.
// main.go will only contain the main function and basic CLI argument parsing.

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

	// NewTunnelManager in commands package now handles its own config path internally.
	tm, err := commands.NewTunnelManager() // Call without arguments
	if err != nil {
		log.Fatal("Failed to create tunnel manager:", err)
	}

	command := os.Args[1]

	switch command {
	case "start":
		commands.HandleStartCommand(tm, os.Args)
	case "stop":
		commands.HandleStopCommand(tm, os.Args)
	case "add":
		commands.HandleAddCommand(tm, os.Args)
	case "remove":
		commands.HandleRemoveCommand(tm, os.Args)
	case "list":
		commands.HandleListCommand(tm, os.Args)
	case "status":
		commands.HandleStatusCommand(tm, os.Args)
	case "login":
		commands.HandleLoginCommand(tm, os.Args)
	case "install-service":
		commands.HandleInstallServiceCommand(tm, os.Args)
	case "uninstall-service":
		commands.HandleUninstallServiceCommand(tm, os.Args)
	default:
		log.Fatal("Unknown command:", command)
	}
}
