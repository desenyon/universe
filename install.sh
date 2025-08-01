#!/bin/bash
# Universe Network Scanner - Quick Installation Script
# Developed by Desenyon - https://github.com/desenyon/universe

set -e

echo "🌌 Universe Network Scanner - Installation"
echo "Developed by Desenyon"
echo "=========================================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1-2)
required_version="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
    echo "❌ Error: Python 3.8+ required. Found: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version"

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo "⚠️  Warning: nmap not found. Installing..."
    
    if command -v brew &> /dev/null; then
        echo "📦 Installing nmap via Homebrew..."
        brew install nmap
    elif command -v apt-get &> /dev/null; then
        echo "📦 Installing nmap via apt..."
        sudo apt-get update && sudo apt-get install -y nmap
    elif command -v yum &> /dev/null; then
        echo "📦 Installing nmap via yum..."
        sudo yum install -y nmap
    else
        echo "❌ Please install nmap manually: https://nmap.org/download.html"
        exit 1
    fi
else
    echo "✅ nmap found: $(nmap --version | head -1)"
fi

# Install Universe
echo "📦 Installing Universe and dependencies..."
pip3 install -e . --quiet

# Test installation
echo "🧪 Testing installation..."
if universe --version > /dev/null 2>&1; then
    echo "✅ Installation successful!"
    echo ""
    echo "🚀 Quick start:"
    echo "   universe scan      # Discover your network"
    echo "   universe map       # Interactive visualization" 
    echo "   universe --help    # See all commands"
    echo ""
    echo "💡 Tip: Use 'sudo universe scan' for best results"
else
    echo "❌ Installation test failed"
    exit 1
fi
