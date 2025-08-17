# Warp CLI Integration Guide

This document explains how to integrate Warp V2 with the Lux CLI and use it as a standalone tool.

## Standalone CLI Usage

### Installation

```bash
# Build from source
make build-cli
sudo make install

# Or download pre-built binary
curl -L https://github.com/luxfi/warp/releases/latest/download/warp-linux-amd64.tar.gz | tar xz
sudo mv warp /usr/local/bin/
```

### Basic Commands

```bash
# Create a cross-chain message
warp create --source 0xAA --dest 0xBB --payload "Hello from chain A"

# Sign a message
warp sign --message <hex> --key ~/.lux/staking/signer.key

# Verify a signature
warp verify --message <hex> --signature <hex>

# Encode data
warp encode --data "Hello World" --format hex

# Decode data
warp decode --data 48656c6c6f20576f726c64

# Run relay server
warp serve --port 9650 --dev
```

## Lux CLI Plugin Integration

### Installation as Plugin

```bash
# Install Warp as a plugin for Lux CLI
make install-plugin

# Or manually copy the plugin
cp -r cmd/plugin/* ~/work/lux/cli/pkg/warp/
```

### Usage with Lux CLI

Once installed as a plugin, Warp commands are available through the Lux CLI:

```bash
# Create a message between Lux networks
lux warp create --source 96369 --dest 200200 --payload "Bridge LUX to ZOO"

# Sign with validator key
lux warp sign --message <hex> --key ~/.lux/staking/signer.key

# Verify cross-chain message
lux warp verify --message <hex> --signature <hex>

# Start message relayer
lux warp relay
```

## Docker Usage

```bash
# Build Docker image
make docker-build

# Run with Docker
docker run --rm luxfi/warp:latest create --source 0xAA --dest 0xBB --payload "Hello"

# Run relay server
docker run -d -p 9650:9650 luxfi/warp:latest serve
```

## Library Usage

Warp can also be used as a Go library:

```go
import "github.com/luxfi/warp"

// Create a message
msg := warp.NewMessage(sourceChain, destChain, payload)

// Sign the message
sig, err := warp.Sign(msg, privateKey)

// Verify signatures
valid := warp.Verify(msg, sig, validatorSet)
```

## Configuration

### Environment Variables

- `WARP_RPC_URL` - RPC endpoint for blockchain connection
- `WARP_KEY_PATH` - Path to signing key
- `WARP_LOG_LEVEL` - Logging level (debug, info, warn, error)

### Config File

Create `~/.warp/config.yaml`:

```yaml
rpc:
  url: http://localhost:9650/ext/bc/C/rpc
  timeout: 30s

signing:
  key_path: ~/.lux/staking/signer.key

relay:
  port: 9650
  chains:
    - id: 96369
      name: lux-mainnet
    - id: 200200
      name: zoo-mainnet
```

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/luxfi/warp
cd warp

# Install dependencies
go mod download

# Build everything
make all

# Run tests
make test

# Run linter
make lint
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run `make ci` to ensure all checks pass
6. Submit a pull request

## Binary Releases

Pre-built binaries are available for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

Download from: https://github.com/luxfi/warp/releases

## Support

- Documentation: https://docs.lux.network/warp
- Issues: https://github.com/luxfi/warp/issues
- Discord: https://discord.gg/lux