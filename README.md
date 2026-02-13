<p align="center">
  <img src="https://raw.githubusercontent.com/pegasusheavy/corevpn/main/.github/assets/logo.svg" alt="CoreVPN" width="400">
</p>

<h1 align="center">CoreVPN</h1>

<p align="center">
  <strong>Secure OpenVPN-compatible VPN server with OAuth2/SAML support and ghost mode</strong>
</p>

<p align="center">
  <a href="https://github.com/pegasusheavy/corevpn/actions/workflows/ci.yml"><img src="https://github.com/pegasusheavy/corevpn/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/pegasusheavy/corevpn/actions/workflows/security.yml"><img src="https://github.com/pegasusheavy/corevpn/actions/workflows/security.yml/badge.svg" alt="Security"></a>
  <a href="https://github.com/pegasusheavy/corevpn/releases"><img src="https://img.shields.io/github/v/release/pegasusheavy/corevpn" alt="Release"></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/pegasusheavy/corevpn/stargazers"><img src="https://img.shields.io/github/stars/pegasusheavy/corevpn" alt="Stars"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#ghost-mode-">Ghost Mode</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#documentation">Documentation</a>
</p>

---

## Features

| Feature | CoreVPN | OpenVPN |
|---------|:-------:|:-------:|
| OpenVPN Protocol Compatible | ✅ | ✅ |
| TLS 1.3 | ✅ | ❌ |
| ChaCha20-Poly1305 | ✅ | ✅ |
| OAuth2/OIDC Authentication | ✅ | ❌ |
| SAML Authentication | ✅ | ❌ |
| Ghost Mode (Zero Logging) | ✅ | ❌ |
| IP Anonymization | ✅ | ❌ |
| Web Admin UI | ✅ | ❌ |
| Desktop GUI Client | ✅ | ❌ |
| Kubernetes/Helm | ✅ | ⚠️ |
| Written in Rust | ✅ | ❌ |
| Memory Safe | ✅ | ❌ |

### Highlights

- 🔐 **OpenVPN Protocol Compatibility** — Works with existing OpenVPN clients
- 🔑 **Modern Authentication** — OAuth2, OIDC, SAML with Google, Microsoft, Okta support
- 👻 **Ghost Mode** — Zero connection logging for privacy-focused deployments
- 🔒 **Modern Security** — TLS 1.3, ChaCha20-Poly1305, Ed25519, AES-256-GCM
- 🌐 **Web Admin Interface** — Manage clients, monitor connections, generate configs
- 🖥️ **Desktop Client** — Native GUI built with OpenKit
- 🐳 **Container Ready** — Docker, Kubernetes, Helm charts included
- 📦 **Easy Deployment** — DEB, RPM, systemd, OpenRC packages

## Quick Start

### Docker (Fastest)

```bash
# Pull and run
docker run -d \
  --name corevpn \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -p 1194:1194/udp \
  -p 8080:8080 \
  -e COREVPN_ADMIN_PASSWORD=changeme \
  ghcr.io/pegasusheavy/corevpn:latest

# Access web UI at http://localhost:8080
```

### One-Line Install (Linux)

```bash
curl -sSL https://get.corevpn.io | sudo bash
```

### Helm (Kubernetes)

```bash
helm repo add corevpn https://charts.corevpn.io
helm install corevpn corevpn/corevpn \
  --namespace corevpn --create-namespace \
  --set server.publicHost=vpn.example.com
```

## Ghost Mode 👻

For deployments requiring **absolute privacy**, CoreVPN offers ghost mode — complete elimination of all connection logging:

```bash
# Enable via CLI
corevpn-server run --ghost

# Or via config
echo '[logging]
connection_mode = "none"' >> /etc/corevpn/config.toml
```

**What Ghost Mode disables:**
- ❌ No connection timestamps
- ❌ No client IP addresses
- ❌ No usernames or identifiers
- ❌ No session durations
- ❌ No transfer statistics
- ❌ No authentication logs
- ✅ Complete ephemeral operation

## Installation

### Package Managers

```bash
# Debian/Ubuntu
curl -fsSL https://pkg.corevpn.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/corevpn.gpg
echo "deb [signed-by=/usr/share/keyrings/corevpn.gpg] https://pkg.corevpn.io/apt stable main" | sudo tee /etc/apt/sources.list.d/corevpn.list
sudo apt update && sudo apt install corevpn-server

# RHEL/Fedora/CentOS
sudo dnf config-manager --add-repo https://pkg.corevpn.io/rpm/corevpn.repo
sudo dnf install corevpn-server

# Alpine
sudo apk add --repository https://pkg.corevpn.io/alpine corevpn-server
```

### From Source

```bash
# Prerequisites: Rust 1.85+
git clone https://github.com/pegasusheavy/corevpn.git
cd corevpn

# Build
cargo build --release

# Install
sudo make install        # systemd
sudo make install-openrc # OpenRC
```

### Docker Compose

```bash
git clone https://github.com/pegasusheavy/corevpn.git
cd corevpn/deploy

# Standard deployment
docker-compose up -d

# Ghost mode
docker-compose -f docker-compose.ghost.yaml up -d
```

## Configuration

### Minimal Configuration

```toml
# /etc/corevpn/config.toml
[server]
public_host = "vpn.example.com"

[network]
subnet = "10.8.0.0/24"
```

### Full Configuration Example

```toml
[server]
listen_addr = "0.0.0.0:1194"
public_host = "vpn.example.com"
protocol = "udp"
max_clients = 100
data_dir = "/var/lib/corevpn"

[network]
subnet = "10.8.0.0/24"
dns = ["1.1.1.1", "1.0.0.1"]
redirect_gateway = true
mtu = 1420

[security]
cipher = "chacha20-poly1305"
tls_min_version = "1.3"
tls_auth = true
client_cert_lifetime_days = 90

[logging]
level = "info"
connection_mode = "memory"  # none | memory | file | database

[logging.anonymization]
hash_client_ips = true
round_timestamps = true

# OAuth2/SSO (optional)
[oauth]
enabled = true
provider = "google"
client_id = "your-client-id"
client_secret = "your-client-secret"
allowed_domains = ["yourcompany.com"]

# OAuth callback port (default: 9000)
oauth_port = 9000

# External URL for OAuth callbacks (optional).
# Use when behind a reverse proxy or when the public URL
# differs from the server's listen address.
# If not set, defaults to https://<public_host>:<oauth_port>
# external_url = "https://vpn.example.com"
```

## Authentication

### OAuth2/OIDC Providers

| Provider | Configuration |
|----------|--------------|
| Google | `provider = "google"` |
| Microsoft/Azure AD | `provider = "microsoft"`, `tenant_id = "..."` |
| Okta | `provider = "okta"`, `domain = "your-org.okta.com"` |
| Generic OIDC | `provider = "generic"`, `issuer_url = "..."` |

OAuth uses HTTPS redirect URIs by default, which is required by providers like Google.
Set `external_url` in the `[oauth]` config section if your server is behind a reverse proxy
or load balancer.

### Certificate-Based

Standard OpenVPN certificate authentication works out of the box:

```bash
# Generate client config
corevpn-server client --user alice@example.com --output alice.ovpn
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Applications                      │
│    ┌──────────┐    ┌──────────┐    ┌──────────────────┐    │
│    │ OpenVPN  │    │ CoreVPN  │    │ CoreVPN Desktop  │    │
│    │ Clients  │    │   CLI    │    │   (OpenKit UI)   │    │
│    └──────────┘    └──────────┘    └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      CoreVPN Server                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Protocol   │  │    Auth     │  │      Logging        │  │
│  │  (OpenVPN)  │  │ OAuth/SAML  │  │ Ghost/File/Database │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Crypto    │  │   Config    │  │      Web UI         │  │
│  │  TLS 1.3    │  │  Generator  │  │   (Admin Panel)     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      Network Layer                           │
│              TUN/TAP • IP Routing • NAT/Masquerade          │
└─────────────────────────────────────────────────────────────┘
```

## Crate Structure

| Crate | Description |
|-------|-------------|
| `corevpn-server` | Main server binary with web UI |
| `corevpn-cli` | Command-line VPN client |
| `corevpn-ui` | Desktop GUI client (OpenKit) |
| `corevpn-core` | Core VPN session and network logic |
| `corevpn-protocol` | OpenVPN protocol implementation |
| `corevpn-crypto` | Cryptographic primitives (TLS, ciphers, keys) |
| `corevpn-auth` | OAuth2/OIDC/SAML authentication |
| `corevpn-config` | Configuration and .ovpn generation |

## Privacy & Anonymization

| Feature | Description |
|---------|-------------|
| **Ghost Mode** | Complete disable of all connection logging |
| **IP Hashing** | HMAC-SHA256 with daily rotating salt |
| **IP Truncation** | Reduce precision to /24 (IPv4) or /48 (IPv6) |
| **Username Hashing** | Store only irreversible hashed identifiers |
| **Timestamp Rounding** | Round to nearest hour |
| **Transfer Bucketing** | Aggregate stats into size buckets |
| **Secure Deletion** | 3-pass overwrite before file deletion |

## Building

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test --workspace

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Build packages
make deb    # Debian/Ubuntu .deb
make rpm    # RHEL/Fedora .rpm
```

## Documentation

- 📖 [Configuration Reference](https://github.com/pegasusheavy/corevpn/wiki/Configuration)
- 🚀 [Deployment Guide](https://github.com/pegasusheavy/corevpn/wiki/Deployment)
- 🔐 [Security Best Practices](SECURITY.md)
- 🤝 [Contributing Guidelines](CONTRIBUTING.md)
- 📋 [Changelog](https://github.com/pegasusheavy/corevpn/releases)

## Support

- 💬 [GitHub Discussions](https://github.com/pegasusheavy/corevpn/discussions)
- 🐛 [Issue Tracker](https://github.com/pegasusheavy/corevpn/issues)
- 📧 Email: support@pegasusheavyindustries.com

## Sponsors

<a href="https://www.patreon.com/c/PegasusHeavyIndustries">
  <img src="https://img.shields.io/badge/Patreon-Support%20Us-orange?logo=patreon" alt="Patreon">
</a>

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) or email security@pegasusheavyindustries.com.

---

<p align="center">
  Made with ❤️ by <a href="https://pegasusheavyindustries.com">Pegasus Heavy Industries</a>
</p>
