package os_service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
)

// InstallLaunchdPlist creates a launchd plist for tunnel-manager and loads it
func InstallLaunchdPlist() error {
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.tunnelmanager</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>%s</string>
    <key>StandardOutPath</key>
    <string>%s/tunnel-manager.log</string>
    <key>StandardErrorPath</key>
    <string>%s/tunnel-manager.log</string>
</dict>
</plist>
`
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	workDir, _ := os.Getwd()
	usr, _ := user.Current()
	logPath := usr.HomeDir
	plistContent := fmt.Sprintf(plist, execPath, workDir, logPath, logPath)
	plistPath := fmt.Sprintf("%s/Library/LaunchAgents/com.tunnelmanager.plist", usr.HomeDir)
	f, err := os.Create(plistPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(plistContent)
	if err != nil {
		return err
	}
	cmd := exec.Command("launchctl", "load", plistPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// UninstallLaunchdPlist unloads and removes the launchd plist
func UninstallLaunchdPlist() error {
	usr, _ := user.Current()
	plistPath := fmt.Sprintf("%s/Library/LaunchAgents/com.tunnelmanager.plist", usr.HomeDir)
	exec.Command("launchctl", "unload", plistPath).Run()
	os.Remove(plistPath)
	return nil
}
