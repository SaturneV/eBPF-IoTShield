#!/bin/bash

# Default installation directory used by DDoS-Deflate
INSTALL_DIR="./ddos-deflate"

# Check if installed
if [ -d "$INSTALL_DIR" ]; then
    echo "DDoS-Deflate is already installed at: $INSTALL_DIR"
    exit 0
fi

echo "DDoS-Deflate not found. Installing..."

# Install dependencies if missing
command -v unzip >/dev/null 2>&1 || {
    echo "Installing unzip..."
    sudo apt-get update && sudo apt-get install -y unzip
}

# Download latest master
wget -O master.zip https://github.com/jgmdev/ddos-deflate/archive/refs/heads/master.zip

# Unzip
unzip master.zip

# Enter folder
cd ddos-deflate-master || {
    echo "Error: directory ddos-deflate-master not found."
    exit 1
}

# Run installer
sudo ./install.sh

echo "DDoS-Deflate installation completed."
