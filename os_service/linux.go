package os_service

import (
	"fmt"
	"os"
	"os/exec"
)

func InstallSystemdService() error {
	service := `[Unit]
Description=Tunnel Manager Service
After=network.target

[Service]
Type=simple
ExecStart=%s start
Restart=on-failure
User=%s
WorkingDirectory=%s

[Install]
WantedBy=multi-user.target
`

	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	user := os.Getenv("USER")
	workDir, _ := os.Getwd()
	serviceContent := fmt.Sprintf(service, execPath, user, workDir)
	servicePath := fmt.Sprintf("/etc/systemd/system/tunnel-manager.service")

	f, err := os.Create(servicePath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(serviceContent)
	if err != nil {
		return err
	}

	// Reload systemd and enable service
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", ServiceName},
		{"systemctl", "start", ServiceName},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

// UninstallSystemdService disables and removes the systemd service
func UninstallSystemdService() error {
	cmds := [][]string{
		{"systemctl", "stop", ServiceName},
		{"systemctl", "disable", ServiceName},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
	os.Remove("/etc/systemd/system/tunnel-manager.service")
	cmd := exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
	return nil
}
