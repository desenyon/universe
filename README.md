# Universe 🌌

### Real-time Network Analyzer & Visualizer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/desenyon/universe)

App that makes etwork scanning into an interactive, visual experience where each device becomes a celestial body in your network galaxy. Universe combines powerful network discovery, security auditing, and beautiful visualization in a single elegant CLI tool.

```
    ██╗   ██╗███╗   ██╗██╗██╗   ██╗███████╗██████╗ ███████╗███████╗
    ██║   ██║████╗  ██║██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝
    ██║   ██║██╔██╗ ██║██║██║   ██║█████╗  ██████╔╝███████╗█████╗  
    ██║   ██║██║╚██╗██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  
    ╚██████╔╝██║ ╚████║██║ ╚████╔╝ ███████╗██║  ██║███████║███████╗
     ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
```

## ✨ Features

### 🔍 **Network Discovery**

- **Smart Scanning**: Auto-detects your network range or specify custom subnets
- **Device Identification**: IP/MAC addresses, hostnames, OS fingerprinting
- **Service Detection**: Open ports, running services, Bluetooth & IoT devices
- **Multiple Scan Modes**: Quick scan, deep scan, or custom port ranges

## 🚀 Quick Start

### Prerequisites

```bash
# Install nmap (required for advanced network scanning)
# macOS
brew install nmap

# Ubuntu/Debian  
sudo apt-get install nmap

# Windows
# Download from https://nmap.org/download.html
```

**Important**: Make sure nmap is in your PATH after installation. You can verify by running:

```bash
nmap --version
```

### Installation

#### Option 1: Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/desenyon/universe.git
cd universe

# Run the automated installer
./install.sh
```

#### Option 2: Manual Installation

```bash
# Clone and install manually
git clone https://github.com/desenyon/universe.git
cd universe

# Install dependencies
pip3 install -e .

# Quick test
universe --version
```

### Basic Usage

```bash
# Discover your network
universe scan

# For best results with advanced features (recommended)
sudo universe scan

# Interactive visualization
universe map --mode orbital

# Real-time monitoring  
universe monitor --alert-new

# Security audit
universe audit --deep

# Export network map
universe export --format png --output network.png
```

> **💡 Pro Tip**: Many network scanning features require elevated privileges. Use `sudo` for complete device discovery and advanced scanning capabilities.

### Why sudo is needed?

- **Raw socket access**: Required for ARP scanning and OS fingerprinting
- **Low-level network operations**: Needed for comprehensive port scanning
- **Bluetooth detection**: Requires system-level hardware access
- **Advanced features**: Full service detection and vulnerability scanning

**Without sudo**: Basic ping-based discovery (limited but functional)
**With sudo**: Complete network analysis with all features enabled

## 🎯 Command Reference

### `universe scan` - Network Discovery

```bash
universe scan [OPTIONS]

Options:
  -n, --network TEXT         Network range (e.g., 192.168.1.0/24)
  -p, --ports TEXT          Port range: quick|common|extended|1-65535
  -t, --timeout INTEGER     Scan timeout in seconds (default: 30)
  -o, --output TEXT         Save results to file
  --format [json|csv|md]    Output format (default: json)
  -v, --verbose             Enable verbose output
  -q, --quick               Quick scan (common ports only)
  -i, --interactive         Interactive scan configuration

Examples:
  universe scan --quick                    # Fast scan of current network
  universe scan -n 10.0.0.0/8 -p 1-1000  # Custom network and ports
  universe scan -i                        # Interactive configuration
```

### `universe map` - Interactive Visualization

```bash
universe map [OPTIONS]

Options:
  --mode [orbital|grid|stargate]    Visualization mode (default: orbital)
  --refresh INTEGER                 Refresh interval in seconds (default: 10)
  --theme [dark|light|cosmic]       Color theme (default: cosmic)
  --network TEXT                    Network range to visualize

Examples:
  universe map                             # Default orbital view
  universe map --mode grid --theme dark   # Grid layout, dark theme
  universe map --refresh 5                # Fast refresh rate
```

### `universe monitor` - Real-time Monitoring

```bash
universe monitor [OPTIONS]

Options:
  --interval INTEGER        Scan interval in seconds (default: 60)
  --alert-new              Alert on new devices
  --alert-suspicious       Alert on security threats  
  --webhook URL            Webhook URL for alerts
  --log-file TEXT          Log file path
  --network TEXT           Network range to monitor

Examples:
  universe monitor --interval 30 --alert-new    # Monitor with new device alerts
  universe monitor --webhook https://hook.url   # Send alerts to webhook
```

### `universe audit` - Security Analysis

```bash
universe audit [OPTIONS]

Options:
  --deep                          Perform deep security scan
  --export-report TEXT           Export audit report to file
  --check-vulns                  Check for known vulnerabilities
  --compliance [basic|strict]    Security compliance level
  --network TEXT                 Network range to audit

Examples:
  universe audit --deep --export-report security.md    # Full audit with report
  universe audit --compliance strict                   # Enterprise security check
```

### `universe export` - Data Export

```bash
universe export [OPTIONS]

Options:
  --format [json|png|svg|md|csv]    Export format
  -o, --output TEXT                 Output file path (required)
  --template TEXT                   Report template
  --include-history                 Include scan history
  --network TEXT                    Network range to export

Examples:
  universe export --format png -o network.png          # Visual network map
  universe export --format md -o report.md             # Markdown report
  universe export --format json -o data.json           # Raw scan data
```

## 🔧 Configuration

Create `~/.universe/config.yml` for persistent settings:

```yaml
# Scan settings
scan:
  default_network: "auto"          # Auto-detect or specify default network
  default_ports: "common"          # quick|common|extended|custom
  timeout: 30                      # Scan timeout in seconds
  
# UI settings  
ui:
  theme: "cosmic"                  # dark|light|cosmic
  default_mode: "orbital"          # orbital|grid|stargate
  refresh_interval: 10             # Refresh rate in seconds
  
# Security settings
security:
  alert_unknown_devices: true     # Alert on new devices
  alert_suspicious_ports: true    # Alert on security threats
  compliance_level: "basic"       # basic|strict
  
# Export settings
export:
  default_format: "json"          # Default export format
  include_timestamps: true        # Add timestamps to exports
  compress_large_files: true     # Compress large output files
```

## 🎨 Visualization Modes

| Mode               | Description                                           | Best For                                             |
| ------------------ | ----------------------------------------------------- | ---------------------------------------------------- |
| **Orbital**  | Devices orbit around network hubs like a solar system | General network overview, relationship visualization |
| **Grid**     | Spatial Cartesian layout with subnet boundaries       | Network topology, IP address organization            |
| **Stargate** | Focused detailed view of individual devices           | Device inspection, troubleshooting                   |

## 🔒 Security Features

### Threat Detection

- ✅ **Rogue Devices**: Unknown MAC addresses and unauthorized devices
- ✅ **Port Scanning**: Detection of scanning activities and suspicious ports
- ✅ **Service Vulnerabilities**: Known security issues in detected services
- ✅ **Network Anomalies**: Unusual traffic patterns and configurations

### 🛠️ Development

### Setup Development Environment

```bash
# Clone and install in development mode
git clone https://github.com/desenyon/universe.git
cd universe
pip install -e ".[dev]"

# Run tests
pytest tests/

# Code formatting
black universe/
```

## 🔧 Troubleshooting

### Common Issues

**"nmap program was not found in path"**

```bash
# Install nmap and verify installation
brew install nmap  # macOS
nmap --version      # Should show version info
```

**"Permission denied" or "could not open /dev/bpf0"**

```bash
# Run with elevated privileges for full functionality
sudo universe scan
```

**"No devices found on the network"**

- Try with sudo: `sudo universe scan`
- Check network connectivity: `ping 8.8.8.8`
- Verify network range: `universe scan -n 192.168.1.0/24`
- Use verbose mode: `universe scan -v`

**Installation issues**

```bash
# Update pip and try again
pip3 install --upgrade pip
pip3 install -e . --force-reinstall
```

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security Notice

Universe requires elevated privileges for certain scanning operations. Always ensure you have proper authorization before scanning networks you don't own. Use responsibly and in compliance with your local laws and regulations.
