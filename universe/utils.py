"""
Utility functions for Universe network scanner.
Developed by Desenyon - https://github.com/desenyon/universe
"""

import re
import socket
import subprocess
import ipaddress
import platform
import sys
from typing import List, Optional, Tuple
import netifaces
import psutil


def get_default_network() -> str:
    """
    Automatically detect the default network range to scan.
    
    Returns:
        Network range in CIDR notation (e.g., "192.168.1.0/24")
    """
    try:
        # Get default gateway interface
        gateways = netifaces.gateways()
        default_info = gateways.get('default', {})
        
        # Handle different gateway structure formats across platforms
        if isinstance(default_info, dict):
            default_gateway = default_info.get(netifaces.AF_INET)
        else:
            default_gateway = None
        
        if not default_gateway:
            return "192.168.1.0/24"  # fallback
        
        # Extract interface name (handle tuple or list format)
        if isinstance(default_gateway, (tuple, list)) and len(default_gateway) > 1:
            interface = default_gateway[1]
        else:
            return "192.168.1.0/24"  # fallback
        
        # Get network info for the interface
        addrs = netifaces.ifaddresses(interface)
        inet_info = addrs.get(netifaces.AF_INET, [])
        
        if not inet_info:
            return "192.168.1.0/24"  # fallback
        
        ip = inet_info[0]['addr']
        netmask = inet_info[0]['netmask']
        
        # Calculate network range
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
        
    except Exception:
        # Fallback to common network ranges
        return "192.168.1.0/24"


def validate_network(network: str) -> bool:
    """
    Validate network range format.
    
    Args:
        network: Network range in CIDR notation
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.IPv4Network(network, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_ip(ip: str) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def parse_port_range(port_spec: str) -> List[int]:
    """
    Parse port specification into list of ports.
    
    Args:
        port_spec: Port specification (e.g., "80", "80,443", "1-1000", "common")
        
    Returns:
        List of port numbers
    """
    if port_spec.lower() == "common":
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
    elif port_spec.lower() == "quick":
        return [22, 80, 443]
    elif port_spec.lower() == "all":
        return list(range(1, 65536))
    
    ports = []
    
    for part in port_spec.split(','):
        part = part.strip()
        
        if '-' in part:
            # Range specification
            try:
                start, end = map(int, part.split('-', 1))
                ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            # Single port
            try:
                ports.append(int(part))
            except ValueError:
                continue
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


def get_local_ip() -> str:
    """
    Get the local IP address of this machine.
    
    Returns:
        Local IP address
    """
    try:
        # Try multiple methods for cross-platform compatibility
        
        # Method 1: Connect to a remote server to determine local IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)  # Add timeout for better reliability
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except Exception:
        try:
            # Method 2: Use hostname resolution
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip != "127.0.0.1":
                return local_ip
        except Exception:
            pass
        
        try:
            # Method 3: Use netifaces to get interface addresses
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr', '')
                        if ip and not ip.startswith('127.') and validate_ip(ip):
                            return ip
        except Exception:
            pass
        
        return "127.0.0.1"  # Final fallback


def get_mac_vendor(mac: str) -> str:
    """
    Get vendor information from MAC address.
    
    Args:
        mac: MAC address string
        
    Returns:
        Vendor name or "Unknown"
    """
    # Simple OUI lookup - in a real implementation, you'd use a proper OUI database
    oui_db = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU",
        "00:16:3E": "Xen",
        "00:15:5D": "Microsoft Hyper-V",
        "00:1B:21": "Intel",
        "00:23:24": "Apple",
        "00:26:BB": "Apple",
        "3C:07:54": "Apple",
        "DC:A6:32": "Raspberry Pi",
        "B8:27:EB": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
    }
    
    if len(mac) >= 8:
        oui = mac[:8].upper()
        return oui_db.get(oui, "Unknown")
    
    return "Unknown"


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private range.
    
    Args:
        ip: IP address string
        
    Returns:
        True if private, False otherwise
    """
    try:
        addr = ipaddress.IPv4Address(ip)
        return addr.is_private
    except ipaddress.AddressValueError:
        return False


def reverse_dns_lookup(ip: str, timeout: float = 1.0) -> str:
    """
    Perform reverse DNS lookup for IP address.
    
    Args:
        ip: IP address string
        timeout: Lookup timeout in seconds
        
    Returns:
        Hostname or IP if lookup fails
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.timeout, OSError):
        return ip


def check_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open on a host.
    
    Args:
        ip: IP address string
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_network_interfaces() -> List[dict]:
    """
    Get information about network interfaces.
    
    Returns:
        List of interface information dictionaries
    """
    interfaces = []
    
    try:
        for interface_name in netifaces.interfaces():
            # Skip loopback and virtual interfaces
            if interface_name.startswith(('lo', 'vir', 'vmnet', 'vbox')):
                continue
                
            interface_info = {
                'name': interface_name,
                'addresses': {}
            }
            
            try:
                addrs = netifaces.ifaddresses(interface_name)
                
                # IPv4 addresses
                if netifaces.AF_INET in addrs:
                    interface_info['addresses']['ipv4'] = addrs[netifaces.AF_INET]
                
                # MAC addresses - handle different platforms
                # On Windows: AF_LINK, on Linux/Mac: also AF_LINK
                if netifaces.AF_LINK in addrs:
                    interface_info['addresses']['mac'] = addrs[netifaces.AF_LINK]
                
                # Only add interfaces that have at least an IP address
                if 'ipv4' in interface_info['addresses']:
                    interfaces.append(interface_info)
                    
            except Exception:
                # Skip interfaces that can't be queried
                continue
            
    except Exception:
        pass
    
    return interfaces


def format_mac_address(mac: str) -> str:
    """
    Format MAC address to standard format.
    
    Args:
        mac: MAC address string
        
    Returns:
        Formatted MAC address (XX:XX:XX:XX:XX:XX)
    """
    # Remove all non-alphanumeric characters
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac)
    
    # Insert colons every 2 characters
    if len(clean_mac) == 12:
        return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2)).upper()
    
    return mac


def get_system_info() -> dict:
    """
    Get system information.
    
    Returns:
        Dictionary with system information
    """
    try:
        return {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'boot_time': psutil.boot_time(),
        }
    except Exception:
        return {}


def check_root_privileges() -> bool:
    """
    Check if running with root/administrator privileges.
    
    Returns:
        True if running as root/admin, False otherwise
    """
    current_platform = platform.system().lower()
    
    if current_platform in ('linux', 'darwin'):
        # Unix-like systems (Linux, macOS)
        try:
            import os
            return os.geteuid() == 0
        except (AttributeError, OSError):
            return False
    elif current_platform == 'windows':
        # Windows
        try:
            import ctypes
            # Type: ignore is needed because windll is not available on non-Windows systems
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
        except (AttributeError, OSError):
            return False
    else:
        # Unknown platform, assume no privileges
        return False


def request_root_privileges() -> bool:
    """
    Request root/administrator privileges if not already running with them.
    
    Returns:
        True if privileges obtained successfully, False otherwise
    """
    if check_root_privileges():
        return True
    
    current_platform = platform.system().lower()
    
    try:
        if current_platform in ('linux', 'darwin'):
            # Unix-like systems - use sudo to re-execute with privileges
            import os
            import sys
            
            # Check if sudo is available
            if subprocess.run(['which', 'sudo'], capture_output=True).returncode != 0:
                print("❌ sudo is not available on this system")
                return False
            
            print("🔐 Root privileges required for network scanning")
            print("📡 Requesting administrator access...")
            
            # Re-execute the current script with sudo
            cmd = ['sudo', sys.executable] + sys.argv
            try:
                # Use os.execvp to replace current process with sudo version
                os.execvp('sudo', cmd)
            except (OSError, PermissionError):
                print("❌ Failed to obtain root privileges")
                return False
                
        elif current_platform == 'windows':
            # Windows - use ShellExecuteEx to request admin privileges
            import ctypes
            import sys
            
            print("🔐 Administrator privileges required for network scanning")
            print("📡 Requesting administrator access...")
            
            try:
                # Re-execute with admin privileges
                # Type: ignore is needed because windll is not available on non-Windows systems
                ctypes.windll.shell32.ShellExecuteW(  # type: ignore
                    None, 
                    "runas", 
                    sys.executable, 
                    " ".join(sys.argv), 
                    None, 
                    1
                )
                # Exit current process since new elevated process will take over
                sys.exit(0)
            except Exception:
                print("❌ Failed to obtain administrator privileges")
                return False
        else:
            print("❌ Privilege escalation not supported on this platform")
            return False
            
    except Exception as e:
        print(f"❌ Error requesting privileges: {e}")
        return False
    
    return False


def ensure_root_privileges(auto_escalate: bool = True) -> bool:
    """
    Ensure the application is running with root/administrator privileges.
    
    Args:
        auto_escalate: Whether to automatically request privileges if not present
        
    Returns:
        True if running with privileges, False otherwise
    """
    if check_root_privileges():
        return True
    
    if auto_escalate:
        print("⚠️  Network scanning requires elevated privileges")
        
        # Ask user for confirmation
        try:
            response = input("🤔 Request administrator access? (y/N): ").lower().strip()
            if response in ('y', 'yes'):
                return request_root_privileges()
            else:
                print("📋 Continuing without elevated privileges (limited functionality)")
                return False
        except (KeyboardInterrupt, EOFError):
            print("\n📋 Continuing without elevated privileges (limited functionality)")
            return False
    
    return False


def run_with_privileges(func, *args, **kwargs):
    """
    Run a function with elevated privileges, requesting them if necessary.
    
    Args:
        func: Function to run
        *args: Positional arguments for the function
        **kwargs: Keyword arguments for the function
        
    Returns:
        Function result if successful, None if privileges couldn't be obtained
    """
    if not check_root_privileges():
        if not ensure_root_privileges():
            print("⚠️  Running with limited privileges - some features may not work")
            # Continue anyway and let the function handle the limitations
    
    try:
        return func(*args, **kwargs)
    except PermissionError as e:
        print(f"❌ Permission denied: {e}")
        print("💡 Try running with administrator/root privileges")
        return None
    except Exception as e:
        print(f"❌ Error running function: {e}")
        return None


def estimate_scan_duration(network: str, ports: List[int], timeout: float = 1.0) -> float:
    """
    Estimate scan duration based on network size and port count.
    
    Args:
        network: Network range in CIDR notation
        ports: List of ports to scan
        timeout: Per-port timeout
        
    Returns:
        Estimated duration in seconds
    """
    try:
        net = ipaddress.IPv4Network(network, strict=False)
        host_count = net.num_addresses - 2  # Exclude network and broadcast
        
        # Rough estimation: ping + port scan time
        ping_time = host_count * 0.1  # 100ms per host for ping
        port_scan_time = host_count * len(ports) * (timeout / 10)  # Parallel scanning
        
        return ping_time + port_scan_time
        
    except Exception:
        return 60.0  # Default estimate


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human-readable string.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    value = float(bytes_value)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if value < 1024.0:
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} PB"


def format_duration(seconds: float) -> str:
    """
    Format duration into human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"
