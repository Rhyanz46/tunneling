## installation

```
git clone https://github.com/Rhyanz46/tunneling.git
cd tunneling
go mod download
go build -o tunnel-manager main.go
```

you can link this to your bin folder
### linux
```shell
sudo ln -s $(pwd)/tunnel-manager /usr/local/bin/tunnel-manager
```

### mac
```shell
sudo ln -s $(pwd)/tunnel-manager /usr/local/bin/tunnel-manager
```

### windows
```powershell
# Build the executable (from PowerShell or CMD)
go build -o tunnel-manager.exe main.go
# Copy to a directory in your PATH, e.g. C:\Windows or C:\Program Files (requires admin)
copy tunnel-manager.exe "C:\Windows\tunnel-manager.exe"
# Or add the project directory to your PATH environment variable
# setx PATH "%PATH%;C:\path\to\your\project"
```

## usage
### show help
```
tunnel-manager
```
example output
```
$ tunnel-manager     
Usage:
  tunnel-manager start              - Start all tunnels
  tunnel-manager add <name> <local_port> <remote_port> [description]
  tunnel-manager remove <name>      - Remove a tunnel
  tunnel-manager list               - List all tunnels
  tunnel-manager status             - Show connection status
  tunnel-manager set-config --host <VPS_IP> --user <USER> --rsa <KEY_PATH> --ssh-port <PORT>
```

### add tunnel
```
$ tunnel-manager add docker-daemon 2375 2375 "docker daemon"
```

### set config
```
$ tunnel-manager set-config --host 1.2.3.4 --user myuser --rsa ~/.ssh/id_rsa --ssh-port 22
```
