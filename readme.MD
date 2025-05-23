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
mklink /d "C:\Program Files\tunnel-manager" "C:\Users\rhyan\go\src\github.com\Rhyanz46\tunneling"
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
```

### add tunnel
```
$ tunnel-manager add docker-daemon 2375 2375 "docker daemon"
```
