## installation

```
git clone https://github.com/Rhyanz46/tunneling.git
cd tunneling
make install
```

- Pastikan Go sudah terinstall di sistem Anda.
- Perintah di atas akan otomatis membangun dan menginstall tunnel-manager ke /usr/local/bin (Linux/macOS).
- Untuk Windows, jalankan `make install` lalu salin tunnel-manager.exe ke folder PATH Anda secara manual.

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
