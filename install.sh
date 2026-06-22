#!/bin/bash
#
# SMTP Tunnel Proxy (Go) - Server Installation Script
#
# One-liner installation:
#   curl -sSL https://raw.githubusercontent.com/sodas-cheddar/smtp-tunnel-go/main/install.sh | sudo bash
#
# Version: 2.0.0-go
#
# This installs the Go-based smtp-tunnel. The Go version is a drop-in
# replacement for the Python version: same config.yaml / users.yaml
# format, same protocol, but dramatically faster and with zero runtime
# dependencies (single static binary).

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# GitHub raw URL base
GITHUB_RAW="https://raw.githubusercontent.com/sodas-cheddar/smtp-tunnel-go/main"

# Installation directories
INSTALL_DIR="/opt/smtp-tunnel"
CONFIG_DIR="/etc/smtp-tunnel"
BIN_DIR="/usr/local/bin"

# Print functions
print_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }
print_ask()   { echo -e "${CYAN}[?]${NC} $1"; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Please run as root (use sudo)"
        echo ""
        echo "Usage: curl -sSL $GITHUB_RAW/install.sh | sudo bash"
        exit 1
    fi
}

# Detect OS and architecture
detect_arch() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        i386|i686) ARCH="386" ;;
        *)
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    case "$OS" in
        linux) OS="linux" ;;
        darwin) OS="darwin" ;;
        *)
            print_error "Unsupported OS: $OS (this installer supports Linux and macOS only)"
            exit 1
            ;;
    esac
    print_info "Detected: $OS/$ARCH"
}

# Download the prebuilt binary (or build from source if unavailable)
fetch_binary() {
    local bin_name="$1"
    local dest="$2"
    local url="$GITHUB_RAW/releases/latest/download/${bin_name}-${OS}-${ARCH}"
    if curl -sSL -f "$url" -o "$dest" 2>/dev/null; then
        chmod +x "$dest"
        return 0
    fi
    return 1
}

# Install the smtp-tunnel-go binary
install_binary() {
    print_step "Installing smtp-tunnel-go binary..."

    # Try prebuilt first
    if fetch_binary smtp-tunnel-go "$INSTALL_DIR/smtp-tunnel-go"; then
        print_info "  Downloaded prebuilt binary"
    else
        print_warn "  Prebuilt binary unavailable; building from source"
        # Build from source — requires Go to be installed.
        if ! command -v go &> /dev/null; then
            print_error "  Go is required to build from source"
            print_error "  Install Go from https://go.dev/doc/install and re-run"
            exit 1
        fi
        mkdir -p /tmp/smtp-tunnel-go-build
        curl -sSL "$GITHUB_RAW/archive/main.tar.gz" | \
            tar -xz -C /tmp/smtp-tunnel-go-build
        cd /tmp/smtp-tunnel-go-build/smtp-tunnel-go-main
        CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' \
            -o "$INSTALL_DIR/smtp-tunnel-go" ./cmd/smtp-tunnel-go
        cd -
        rm -rf /tmp/smtp-tunnel-go-build
        print_info "  Built from source"
    fi
    chmod +x "$INSTALL_DIR/smtp-tunnel-go"
}

# Create directories
create_directories() {
    print_step "Creating directories..."
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$CONFIG_DIR"
    print_info "  $INSTALL_DIR"
    print_info "  $CONFIG_DIR"
}

# Install management command symlinks
install_symlinks() {
    print_step "Creating management command symlinks..."
    ln -sf "$INSTALL_DIR/smtp-tunnel-go" "$BIN_DIR/smtp-tunnel-adduser"
    ln -sf "$INSTALL_DIR/smtp-tunnel-go" "$BIN_DIR/smtp-tunnel-deluser"
    ln -sf "$INSTALL_DIR/smtp-tunnel-go" "$BIN_DIR/smtp-tunnel-listusers"
    ln -sf "$INSTALL_DIR/smtp-tunnel-go" "$BIN_DIR/smtp-tunnel-update"
    ln -sf "$INSTALL_DIR/smtp-tunnel-go" "$BIN_DIR/smtp-tunnel-gencerts"
    print_info "  adduser / deluser / listusers / update / gencerts -> $BIN_DIR"
}

# Install systemd service
install_systemd_service() {
    print_step "Installing systemd service..."
    cat > /etc/systemd/system/smtp-tunnel.service << EOF
[Unit]
Description=SMTP Tunnel Proxy Server (Go)
Documentation=https://github.com/sodas-cheddar/smtp-tunnel-go
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/smtp-tunnel-go server -c $CONFIG_DIR/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CONFIG_DIR
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    print_info "  Service installed"
}

# Create uninstall script
create_uninstall_script() {
    cat > "$INSTALL_DIR/uninstall.sh" << 'EOF'
#!/bin/bash
echo "Stopping service..."
systemctl stop smtp-tunnel 2>/dev/null || true
systemctl disable smtp-tunnel 2>/dev/null || true

echo "Removing files..."
rm -f /etc/systemd/system/smtp-tunnel.service
rm -f /usr/local/bin/smtp-tunnel-adduser
rm -f /usr/local/bin/smtp-tunnel-deluser
rm -f /usr/local/bin/smtp-tunnel-listusers
rm -f /usr/local/bin/smtp-tunnel-update
rm -f /usr/local/bin/smtp-tunnel-gencerts
rm -rf /opt/smtp-tunnel

echo ""
echo "Note: Configuration in /etc/smtp-tunnel was NOT removed."
echo "Remove manually if needed: rm -rf /etc/smtp-tunnel"

systemctl daemon-reload
echo "SMTP Tunnel Proxy uninstalled."
EOF
    chmod +x "$INSTALL_DIR/uninstall.sh"
    print_info "  Created: $INSTALL_DIR/uninstall.sh"
}

# Interactive setup
interactive_setup() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Interactive Setup${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    print_ask "Enter your domain name (e.g., myserver.duckdns.org):"
    echo -e "    ${YELLOW}Tip: free domains at duckdns.org, noip.com, freedns.afraid.org${NC}"
    read -p "    Domain: " DOMAIN_NAME < /dev/tty

    if [ -z "$DOMAIN_NAME" ]; then
        print_error "Domain name is required!"
        exit 1
    fi
    print_info "Using domain: $DOMAIN_NAME"
    echo ""

    print_step "Creating configuration..."
    cat > "$CONFIG_DIR/config.yaml" << EOF
# SMTP Tunnel Proxy Configuration (Go version)
# Generated by install.sh

server:
  host: "0.0.0.0"
  port: 587
  hostname: "$DOMAIN_NAME"
  cert_file: "$CONFIG_DIR/server.crt"
  key_file: "$CONFIG_DIR/server.key"
  users_file: "$CONFIG_DIR/users.yaml"
  log_users: true

client:
  server_host: "$DOMAIN_NAME"
  server_port: 587
  socks_port: 1080
  socks_host: "127.0.0.1"
  ca_cert: "ca.crt"
EOF
    chmod 600 "$CONFIG_DIR/config.yaml"
    print_info "  $CONFIG_DIR/config.yaml"

    cat > "$CONFIG_DIR/users.yaml" << 'EOF'
# SMTP Tunnel Users
# Managed by smtp-tunnel-adduser

users: {}
EOF
    chmod 600 "$CONFIG_DIR/users.yaml"
    print_info "  $CONFIG_DIR/users.yaml"

    echo ""
    print_step "Generating TLS certificates for $DOMAIN_NAME..."
    if "$INSTALL_DIR/smtp-tunnel-go" gencerts \
        --hostname "$DOMAIN_NAME" \
        --output-dir "$CONFIG_DIR"; then
        print_info "  Certificates generated (ECDSA P-256, 3-year validity)"
        ln -sf "$CONFIG_DIR/ca.crt" "$INSTALL_DIR/ca.crt"
    else
        print_error "  Certificate generation failed. Try manually:"
        echo "    $INSTALL_DIR/smtp-tunnel-go gencerts --hostname $DOMAIN_NAME --output-dir $CONFIG_DIR"
    fi

    echo ""
    print_ask "Create your first user now? [Y/n]: "
    read -p "    " CREATE_USER < /dev/tty

    if [ -z "$CREATE_USER" ] || [ "$CREATE_USER" = "y" ] || [ "$CREATE_USER" = "Y" ]; then
        print_ask "Enter username: "
        read -p "    " FIRST_USER < /dev/tty
        if [ -n "$FIRST_USER" ]; then
            print_step "Creating user '$FIRST_USER'..."
            if "$INSTALL_DIR/smtp-tunnel-go" adduser "$FIRST_USER" \
                -c "$CONFIG_DIR/config.yaml" \
                -u "$CONFIG_DIR/users.yaml" \
                -o "$INSTALL_DIR/"; then
                print_info "User '$FIRST_USER' created"
                print_info "Client package: $INSTALL_DIR/${FIRST_USER}.zip"
                echo -e "    ${YELLOW}Send this ZIP to the user${NC}"
            else
                print_warn "Failed to create user. Run:"
                echo "    smtp-tunnel-adduser $FIRST_USER"
            fi
        fi
    fi

    echo ""
    print_step "Configuring firewall..."
    if command -v ufw &> /dev/null; then
        ufw allow 587/tcp >/dev/null 2>&1 && \
            print_info "  Opened 587/tcp (ufw)" || \
            print_warn "  Could not configure ufw"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=587/tcp >/dev/null 2>&1 && \
            firewall-cmd --reload >/dev/null 2>&1 && \
            print_info "  Opened 587/tcp (firewalld)" || \
            print_warn "  Could not configure firewalld"
    else
        print_warn "  No firewall detected. Make sure 587/tcp is open!"
    fi

    echo ""
    print_step "Starting service..."
    systemctl enable smtp-tunnel >/dev/null 2>&1 || true
    systemctl start smtp-tunnel 2>&1 || true
    sleep 2
    if systemctl is-active --quiet smtp-tunnel; then
        print_info "  Service started"
    else
        print_warn "  Service may not have started. Check:"
        echo "    systemctl status smtp-tunnel"
        echo "    journalctl -u smtp-tunnel -n 50"
    fi
}

# Update script (overlays new binary, preserves config/certs/users)
install_update_script() {
    cat > "$INSTALL_DIR/smtp-tunnel-update-script.sh" << 'EOF'
#!/bin/bash
# Update script for smtp-tunnel-go
set -e
INSTALL_DIR=/opt/smtp-tunnel
GITHUB_RAW="https://raw.githubusercontent.com/sodas-cheddar/smtp-tunnel-go/main"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
esac

echo "Downloading latest smtp-tunnel-go ${OS}-${ARCH}..."
URL="$GITHUB_RAW/releases/latest/download/smtp-tunnel-go-${OS}-${ARCH}"
if curl -sSL -f "$URL" -o "$INSTALL_DIR/smtp-tunnel-go.new"; then
    chmod +x "$INSTALL_DIR/smtp-tunnel-go.new"
    mv "$INSTALL_DIR/smtp-tunnel-go.new" "$INSTALL_DIR/smtp-tunnel-go"
else
    echo "Prebuilt binary unavailable. Build from source with:"
    echo "  git clone https://github.com/sodas-cheddar/smtp-tunnel-go"
    echo "  cd smtp-tunnel-go && go build -o $INSTALL_DIR/smtp-tunnel-go ./cmd/smtp-tunnel-go"
    exit 1
fi

echo "Restarting service..."
systemctl restart smtp-tunnel 2>/dev/null || true

if systemctl is-active --quiet smtp-tunnel; then
    echo "Update complete. Service running."
else
    echo "Service may not have restarted. Check: systemctl status smtp-tunnel"
fi
EOF
    chmod +x "$INSTALL_DIR/smtp-tunnel-update-script.sh"
}

# Final summary
print_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Installation Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Your SMTP Tunnel Proxy (Go) is running."
    echo ""
    echo -e "${BLUE}Service:${NC}"
    echo "   systemctl status smtp-tunnel"
    echo "   journalctl -u smtp-tunnel -f"
    echo ""
    echo -e "${BLUE}User management:${NC}"
    echo "   smtp-tunnel-adduser <username>    Add user + generate client ZIP"
    echo "   smtp-tunnel-deluser <username>    Remove a user"
    echo "   smtp-tunnel-listusers             List all users"
    echo ""
    echo -e "${BLUE}Update:${NC}"
    echo "   smtp-tunnel-update                Update to latest version"
    echo ""
    echo -e "${BLUE}Config files:${NC}"
    echo "   $CONFIG_DIR/config.yaml"
    echo "   $CONFIG_DIR/users.yaml"
    echo "   $CONFIG_DIR/server.crt + server.key"
    echo ""
    echo -e "${BLUE}Uninstall:${NC}"
    echo "   $INSTALL_DIR/uninstall.sh"
    echo ""
}

# Main
main() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  SMTP Tunnel Proxy Installer (Go)${NC}"
    echo -e "${GREEN}  Version 2.0.0-go${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    check_root
    detect_arch
    create_directories
    install_binary
    install_symlinks
    install_systemd_service
    create_uninstall_script
    install_update_script
    interactive_setup
    print_summary
}

main "$@"
