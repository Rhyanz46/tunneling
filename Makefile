OS := $(shell uname -s)
BINARY := tunnel-manager
ifeq ($(OS),Linux)
	BIN_PATH := /usr/local/bin/$(BINARY)
	EXT :=
else ifeq ($(OS),Darwin)
	BIN_PATH := /usr/local/bin/$(BINARY)
	EXT :=
else
	BIN_PATH := $(BINARY).exe
	EXT := .exe
endif

.PHONY: all build install clean

all: build

build:
	@echo "[INFO] Building for $(OS)..."
	go build -o $(BINARY)$(EXT) main.go

install: build
ifeq ($(OS),Linux)
	@echo "[INFO] Installing to /usr/local/bin (requires sudo)"
	sudo cp $(BINARY) /usr/local/bin/$(BINARY)
else ifeq ($(OS),Darwin)
	@echo "[INFO] Installing to /usr/local/bin (requires sudo)"
	sudo cp $(BINARY) /usr/local/bin/$(BINARY)
else
	@echo "[INFO] Detected Windows. Please copy '$(BINARY).exe' to a directory in your PATH manually."
endif

clean:
	rm -f $(BINARY) $(BINARY).exe

check-go:
	@command -v go >/dev/null 2>&1 || { echo >&2 "Go is not installed. Please install Go first."; exit 1; }
