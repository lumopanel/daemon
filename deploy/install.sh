#!/bin/bash
# Lumo Daemon Installation Script
# Run as root on Ubuntu/Debian

set -euo pipefail

REPO="lumopanel/daemon"
GITHUB_API="https://api.github.com/repos/${REPO}/releases/latest"

echo "Installing Lumo Daemon..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Check for required tools
for cmd in curl jq tar sha256sum; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is required but not installed."
        exit 1
    fi
done

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        ARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [[ "$OS" != "linux" ]]; then
    echo "Error: This installer only supports Linux. Detected: $OS"
    exit 1
fi

# Create temporary directory
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Fetch latest release info
echo "Fetching latest release from GitHub..."
RELEASE_JSON=$(curl -sL "$GITHUB_API")

if echo "$RELEASE_JSON" | jq -e '.message' &>/dev/null; then
    echo "Error: Failed to fetch release info: $(echo "$RELEASE_JSON" | jq -r '.message')"
    exit 1
fi

VERSION=$(echo "$RELEASE_JSON" | jq -r '.tag_name')
echo "Latest version: $VERSION"

# Find the appropriate asset
ASSET_NAME="lumo-daemon-${ARCH}-unknown-linux-gnu.tar.gz"
DOWNLOAD_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name == \"$ASSET_NAME\") | .browser_download_url")

if [[ -z "$DOWNLOAD_URL" || "$DOWNLOAD_URL" == "null" ]]; then
    echo "Error: Could not find release asset for $ASSET_NAME"
    echo "Available assets:"
    echo "$RELEASE_JSON" | jq -r '.assets[].name'
    exit 1
fi

# Download release and checksum
echo "Downloading $ASSET_NAME..."
curl -sL "$DOWNLOAD_URL" -o "$TMPDIR/release.tar.gz"

CHECKSUM_NAME="${ASSET_NAME}.sha256"
CHECKSUM_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name == \"$CHECKSUM_NAME\") | .browser_download_url")

if [[ -n "$CHECKSUM_URL" && "$CHECKSUM_URL" != "null" ]]; then
    echo "Downloading checksum..."
    curl -sL "$CHECKSUM_URL" -o "$TMPDIR/release.tar.gz.sha256"

    echo "Verifying checksum..."
    cd "$TMPDIR"
    # The checksum file contains the original filename, so we need to adjust it
    sed -i "s/$ASSET_NAME/release.tar.gz/" release.tar.gz.sha256
    if ! sha256sum -c release.tar.gz.sha256; then
        echo "Error: Checksum verification failed!"
        exit 1
    fi
    cd - > /dev/null
    echo "Checksum verified."
else
    echo "Warning: No checksum file found. Proceeding without verification."
fi

echo "Extracting..."
tar -xzf "$TMPDIR/release.tar.gz" -C "$TMPDIR"

# Create directories
echo "Creating directories..."
mkdir -p /etc/lumo/templates
mkdir -p /etc/lumo/custom_templates
mkdir -p /var/run/lumo
mkdir -p /var/log/lumo
mkdir -p /var/lib/lumo

# Install binary
echo "Installing binary..."
if [[ -f "$TMPDIR/lumo-daemon" ]]; then
    cp "$TMPDIR/lumo-daemon" /usr/bin/lumo-daemon
    chmod 755 /usr/bin/lumo-daemon
else
    echo "Error: Binary not found in release archive."
    exit 1
fi

# Copy config (don't overwrite if exists)
if [[ ! -f /etc/lumo/daemon.toml ]]; then
    echo "Installing configuration..."
    if [[ -f "$TMPDIR/daemon.toml.example" ]]; then
        cp "$TMPDIR/daemon.toml.example" /etc/lumo/daemon.toml
    elif [[ -f "$TMPDIR/daemon.toml" ]]; then
        cp "$TMPDIR/daemon.toml" /etc/lumo/daemon.toml
    else
        echo "Warning: No configuration file found in release. Creating minimal config."
        cat > /etc/lumo/daemon.toml << 'EOFCONFIG'
# Lumo Daemon Configuration
# See documentation for full options
EOFCONFIG
    fi
    chmod 600 /etc/lumo/daemon.toml
fi

# Generate HMAC secret if it doesn't exist
if [[ ! -f /etc/lumo/hmac.key ]]; then
    echo "Generating HMAC secret..."
    head -c 32 /dev/urandom > /etc/lumo/hmac.key
    chmod 600 /etc/lumo/hmac.key
fi

# Copy templates if directory exists in release
if [[ -d "$TMPDIR/templates" ]]; then
    echo "Installing templates..."
    cp -r "$TMPDIR/templates/"* /etc/lumo/templates/ 2>/dev/null || true
fi

# Install systemd service
echo "Installing systemd service..."
if [[ -f "$TMPDIR/lumo-daemon.service" ]]; then
    cp "$TMPDIR/lumo-daemon.service" /etc/systemd/system/lumo-daemon.service
else
    # Create default service file if not in release
    cat > /etc/systemd/system/lumo-daemon.service << 'EOFSERVICE'
[Unit]
Description=Lumo Privilege Daemon
Documentation=https://github.com/lumopanel/daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/lumo-daemon --config /etc/lumo/daemon.toml
Restart=on-failure
RestartSec=5
User=root
Group=root

# Working directory
WorkingDirectory=/var/lib/lumo

# Environment
Environment=RUST_LOG=info

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/run/lumo /var/log/lumo /tmp/lumo /etc/nginx /etc/php /var/www
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true

# Capabilities - daemon needs root for privilege operations
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID CAP_NET_BIND_SERVICE CAP_SYS_ADMIN
AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID CAP_NET_BIND_SERVICE CAP_SYS_ADMIN

# Timeout settings
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOFSERVICE
fi
chmod 644 /etc/systemd/system/lumo-daemon.service

# Reload systemd
systemctl daemon-reload

# Set permissions
echo "Setting permissions..."
chown -R root:root /etc/lumo

# Detect web server group (www-data for Debian/Ubuntu, nginx for RHEL/CentOS, apache for some systems)
WEB_GROUP=""
for group in www-data nginx apache http; do
    if getent group "$group" > /dev/null 2>&1; then
        WEB_GROUP="$group"
        break
    fi
done

if [[ -n "$WEB_GROUP" ]]; then
    chown "root:$WEB_GROUP" /var/run/lumo
    echo "Using web server group: $WEB_GROUP"
else
    echo "Warning: No web server group found (www-data, nginx, apache, http)."
    echo "Setting /var/run/lumo to root:root. You may need to adjust this manually."
    chown root:root /var/run/lumo
fi
chmod 770 /var/run/lumo
chown root:root /var/log/lumo
chmod 750 /var/log/lumo

echo ""
echo "Installation complete! (version: $VERSION)"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/lumo/daemon.toml to configure allowed_peer_uids"
echo "  2. Start the daemon: systemctl start lumo-daemon"
echo "  3. Enable on boot: systemctl enable lumo-daemon"
echo "  4. Check status: systemctl status lumo-daemon"
echo ""
echo "The HMAC secret is stored in /etc/lumo/hmac.key"
echo "Share this secret with clients that need to connect."
