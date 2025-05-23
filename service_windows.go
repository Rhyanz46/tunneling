// +build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// InstallWindowsService creates a basic Windows service using nssm (Non-Sucking Service Manager)
func InstallWindowsService() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	usr, _ := user.Current()
	serviceName := "TunnelManager"
	cmd := exec.Command("nssm", "install", serviceName, execPath, "start")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nssm not found or failed: %v", err)
	}
	cmd = exec.Command("nssm", "start", serviceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// UninstallWindowsService removes the Windows service
func UninstallWindowsService() error {
	serviceName := "TunnelManager"
	exec.Command("nssm", "stop", serviceName).Run()
	exec.Command("nssm", "remove", serviceName, "confirm").Run()
	return nil
}
