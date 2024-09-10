#!/bin/bash

# Script to set up the environment for Neptune Scan
# This script should be run as root or with sudo

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or use sudo"
  exit
fi

echo "Updating the system packages..."
sudo apt update && sudo apt upgrade -y

echo "Installing Python 3 and pip..."
sudo apt install python3 python3-pip -y

echo "Installing necessary system libraries..."
sudo apt install libpcap-dev -y  # Required for packet capturing (Scapy)

echo "Installing Scapy and other Python dependencies..."
pip3 install scapy

# Optional: install other useful networking tools (e.g., nmap)
echo "Installing additional networking tools (optional)..."
sudo apt install nmap -y

# Verifying installations
echo "Verifying installations..."
python3 --version
pip3 --version
scapy --version

# Print completion message
echo "Setup completed! You can now run the Neptune Scan script."
