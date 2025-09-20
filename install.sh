#!/bin/bash
# Installation script for Honeypot Interceptor

echo "Installing Honeypot Interceptor..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update package list
echo "Updating package list..."
apt-get update

# Install Python dependencies
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Install system dependencies
echo "Installing system dependencies..."
apt-get install -y python3-pip python3-dev libpcap-dev iptables-persistent

# Create necessary directories
echo "Creating directories..."
mkdir -p /var/log/honeypot-interceptor
mkdir -p /etc/honeypot-interceptor
mkdir -p /var/lib/honeypot-interceptor

# Copy configuration files
echo "Copying configuration files..."
cp config.yaml /etc/honeypot-interceptor/
cp -r decoy_files /var/lib/honeypot-interceptor/

# Set permissions
echo "Setting permissions..."
chown -R root:root /etc/honeypot-interceptor
chown -R root:root /var/lib/honeypot-interceptor
chmod 755 /var/lib/honeypot-interceptor/decoy_files

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/honeypot-interceptor.service << EOF
[Unit]
Description=Honeypot Interceptor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/python3 $(pwd)/main.py --config /etc/honeypot-interceptor/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo "Installation complete!"
echo ""
echo "To start the service:"
echo "  sudo systemctl start honeypot-interceptor"
echo ""
echo "To enable auto-start:"
echo "  sudo systemctl enable honeypot-interceptor"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u honeypot-interceptor -f"
echo ""
echo "To run manually:"
echo "  sudo python3 main.py --config config.yaml"
