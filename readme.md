# tunnel-manager
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Tunnel Manager adalah CLI tool berbasis Go untuk mengelola SSH tunnel ke VPS secara mudah dan aman. Fitur utama:
- Setup otomatis SSH key ke server (tanpa perlu copy manual)
- Manajemen multi tunnel (add, remove, list)
- Koneksi aman ke VPS tanpa password setelah login pertama
- Instalasi dan penggunaan mudah di Linux, macOS, dan Windows

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
  tunnel-manager start -d           - Start all tunnels in background (daemon)
  tunnel-manager stop               - Stop background tunnel-manager
  tunnel-manager add <name> <local_port> <remote_port> [description]
  tunnel-manager remove <name>      - Remove a tunnel
  tunnel-manager list               - List all tunnels
  tunnel-manager status             - Show connection status
  tunnel-manager login              - Login and setup SSH key authentication
```

### login dan setup SSH key
```
$ tunnel-manager login
# Masukkan host, username, password, dan port saat diminta.
# Jika berhasil, SSH key akan otomatis dibuat dan diupload ke server.
```

### start di background (daemon)
```
$ tunnel-manager start -d
# Tunnel manager akan berjalan di background.
```

### stop background tunnel-manager
```
$ tunnel-manager stop
# Menghentikan tunnel-manager yang berjalan di background.
```

### add tunnel
```
$ tunnel-manager add docker-daemon 2375 2375 "docker daemon"
```
