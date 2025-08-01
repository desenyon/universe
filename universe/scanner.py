"""
Network scanning and device discovery module.
"""

import asyncio
import os
import socket
import subprocess
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
import ipaddress
import json
import logging

try:
    import nmap
except ImportError:
    nmap = None

try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp
except ImportError:
    scapy = None

from .utils import (
    reverse_dns_lookup, 
    check_port_open, 
    get_mac_vendor,
    parse_port_range,
    validate_ip,
    format_mac_address,
    check_root_privileges,
    ensure_root_privileges,
    run_with_privileges
)
from .config import Config

logger = logging.getLogger(__name__)


@dataclass
class Device:
    """Represents a discovered network device."""
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    os: str = ""
    status: str = "unknown"  # up, down, unknown
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    last_seen: float = 0.0
    response_time: float = 0.0
    device_type: str = "unknown"  # router, computer, mobile, iot, etc.
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary."""
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'os': self.os,
            'status': self.status,
            'open_ports': self.open_ports,
            'services': self.services,
            'last_seen': self.last_seen,
            'response_time': self.response_time,
            'device_type': self.device_type,
        }


@dataclass
class ScanResult:
    """Represents the results of a network scan."""
    network: str
    devices: List[Device] = field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: float = field(default_factory=time.time)
    scan_type: str = "basic"
    total_hosts: int = 0
    active_hosts: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to dictionary."""
        return {
            'network': self.network,
            'devices': [device.to_dict() for device in self.devices],
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp,
            'scan_type': self.scan_type,
            'total_hosts': self.total_hosts,
            'active_hosts': self.active_hosts,
        }


class NetworkScanner:
    """Main network scanning class."""
    
    def __init__(self, timeout: int = 30, verbose: bool = False, config: Optional[Config] = None):
        """
        Initialize network scanner.
        
        Args:
            timeout: Scan timeout in seconds
            verbose: Enable verbose logging
            config: Configuration object
        """
        self.timeout = timeout
        self.verbose = verbose
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        
        # Set up logging
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
        
        # Check for required tools
        self.has_nmap = nmap is not None
        self.has_scapy = scapy is not None
        
        if not self.has_nmap and not self.has_scapy:
            self.logger.warning("Neither nmap nor scapy available. Limited functionality.")
    
    def _get_port_list(self, ports: str) -> List[int]:
        """
        Get list of ports to scan based on specification.
        
        Args:
            ports: Port specification ('quick', 'common', 'extended', or range)
            
        Returns:
            List of port numbers
        """
        if ports == "quick":
            return [22, 80, 443]  # SSH, HTTP, HTTPS
        elif ports == "common":
            return list(range(1, 1001))  # Ports 1-1000
        elif ports == "extended":
            return list(range(1, 10001))  # Ports 1-10000
        else:
            # Try to parse as custom range
            try:
                return parse_port_range(ports)
            except Exception:
                self.logger.warning(f"Invalid port specification: {ports}, using common ports")
                return list(range(1, 1001))
    
    async def scan_network(self, network: str, ports: str = "common", 
                          include_bluetooth: bool = False, auto_escalate: bool = True) -> dict:
        """
        Perform comprehensive network scan.
        
        Args:
            network: Network range (e.g., "192.168.1.0/24")
            ports: Port specification ("quick", "common", "extended", or range)
            include_bluetooth: Whether to include Bluetooth scanning
            auto_escalate: Whether to automatically request elevated privileges
            
        Returns:
            Dictionary containing scan results
        """
        scan_start = time.time()
        self.logger.info(f"Starting network scan of {network}")
        
        # Check and request elevated privileges if needed
        has_root = check_root_privileges()
        if not has_root and auto_escalate:
            self.logger.info("🔐 Enhanced scanning requires elevated privileges")
            has_root = ensure_root_privileges(auto_escalate=True)
        
        if not has_root:
            self.logger.warning(
                "⚠️  Running without elevated privileges - some features may be limited.\n"
                "💡 For comprehensive scanning, run with administrator/sudo privileges."
            )
        else:
            self.logger.info("✅ Running with elevated privileges - full functionality available")
        
        results = {
            "network": network,
            "timestamp": datetime.now().isoformat(),
            "scan_type": ports,
            "devices": [],
            "scan_duration": 0.0,
            "elevated_privileges": has_root,
            "scan_method": "comprehensive" if has_root else "basic"
        }
        
        try:
            # Discover active hosts
            active_hosts = await self._discover_hosts(network, has_root)
            self.logger.info(f"Found {len(active_hosts)} active hosts")
            
            # Get port list
            port_list = self._get_port_list(ports)
            self.logger.info(f"Scanning {len(port_list)} ports per host")
            
            # Scan each host
            for host_ip in active_hosts:
                device = self._scan_host(host_ip, port_list, has_root)
                if device:
                    results["devices"].append(device)
            
            # Bluetooth scanning (if requested and available)
            if include_bluetooth:
                if has_root:
                    bluetooth_devices = await self._scan_bluetooth()
                    results["devices"].extend(bluetooth_devices)
                else:
                    self.logger.info("Bluetooth scanning requires sudo privileges - skipped")
        
        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
            results["error"] = str(e)
        
        results["scan_duration"] = time.time() - scan_start
        self.logger.info(f"Scan completed in {results['scan_duration']:.2f} seconds")
        
        return results
    
    async def _discover_hosts(self, network: str, has_root: bool = False) -> List[str]:
        """
        Discover active hosts in the network.
        
        Args:
            network: Network range in CIDR notation
            has_root: Whether running with elevated privileges
            
        Returns:
            List of active IP addresses
        """
        if self.has_scapy and has_root:
            return await self._discover_hosts_scapy(network)
        elif self.has_nmap:
            return await self._discover_hosts_nmap(network)
        else:
            return await self._discover_hosts_ping(network)
    
    async def _discover_hosts_scapy(self, network: str) -> List[str]:
        """Discover hosts using Scapy ARP scan."""
        try:
            active_hosts = []
            
            # Create ARP request packet
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and receive response
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                client_dict = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc
                }
                active_hosts.append(client_dict["ip"])
            
            return active_hosts
            
        except Exception as e:
            error_msg = str(e)
            if "Permission denied" in error_msg and "sudo" in error_msg:
                self.logger.warning(
                    "ARP scanning requires elevated privileges. "
                    "Run with 'sudo universe scan' for complete network discovery. "
                    "Falling back to ping-based detection."
                )
            else:
                self.logger.error(f"Scapy ARP scan failed: {e}")
            return []
    
    async def _discover_hosts_nmap(self, network: str) -> List[str]:
        """Discover hosts using nmap."""
        if not self.has_nmap or nmap is None:
            return []
            
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=network, arguments='-sn')  # Ping scan only
            
            active_hosts = []
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    active_hosts.append(host)
            
            return active_hosts
            
        except Exception as e:
            logger.error(f"Nmap host discovery failed: {e}")
            return []
    
    async def _discover_hosts_ping(self, network: str) -> List[str]:
        """Discover hosts using ping (fallback method)."""
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            active_hosts = []
            
            # Limit to reasonable subnet sizes
            if net.num_addresses > 1024:
                logger.warning("Large network detected, limiting scan scope")
                # Scan only first 254 addresses
                hosts_to_scan = list(net.hosts())[:254]
            else:
                hosts_to_scan = list(net.hosts())
            
            # Ping each host
            with ThreadPoolExecutor(max_workers=50) as executor:
                tasks = []
                for ip in hosts_to_scan:
                    task = asyncio.get_event_loop().run_in_executor(
                        executor, self._ping_host, str(ip)
                    )
                    tasks.append((str(ip), task))
                
                # Wait for all pings
                for ip, task in tasks:
                    try:
                        if await task:
                            active_hosts.append(ip)
                    except Exception:
                        pass
            
            return active_hosts
            
        except Exception as e:
            logger.error(f"Ping discovery failed: {e}")
            return []
    
    def _ping_host(self, ip: str) -> bool:
        """Ping a single host."""
        try:
            # Use platform-specific ping command
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=3
            )
            
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False
    
    def _scan_host(self, ip: str, ports: List[int], has_root: bool = False) -> Device:
        """
        Scan a single host for open ports and services.
        
        Args:
            ip: IP address to scan
            ports: List of ports to scan
            has_root: Whether running with elevated privileges
            
        Returns:
            Device object with scan results
        """
        device = Device(ip=ip, last_seen=time.time())
        
        # Check if host is responding
        if not self._ping_host(ip):
            device.status = "down"
            return device
        
        device.status = "up"
        
        # Get hostname
        device.hostname = reverse_dns_lookup(ip, timeout=1.0)
        
        # Scan ports
        if self.has_nmap:
            self._scan_ports_nmap(device, ports)
        else:
            self._scan_ports_socket(device, ports)
        
        # Try to determine device type and OS
        self._identify_device(device)
        
        return device
    
    def _scan_ports_nmap(self, device: Device, ports: List[int]) -> None:
        """Scan ports using nmap."""
        if not self.has_nmap or nmap is None:
            self._scan_ports_socket(device, ports)
            return
            
        try:
            nm = nmap.PortScanner()
            port_range = ','.join(map(str, ports))
            
            # Scan with service detection
            nm.scan(
                device.ip, 
                port_range, 
                arguments='-sV --version-light'
            )
            
            if device.ip in nm.all_hosts():
                host_info = nm[device.ip]
                
                # Get OS information if available
                if 'osclass' in host_info:
                    os_classes = host_info['osclass']
                    if os_classes:
                        device.os = os_classes[0].get('osfamily', 'Unknown')
                
                # Get port information
                for protocol in host_info.all_protocols():
                    ports_info = host_info[protocol]
                    
                    for port in ports_info:
                        port_info = ports_info[port]
                        state = port_info['state']
                        
                        if state == 'open':
                            device.open_ports.append(port)
                            
                            # Get service information
                            service = port_info.get('name', 'unknown')
                            version = port_info.get('version', '')
                            if version:
                                service += f" ({version})"
                            
                            device.services[port] = service
            
        except Exception as e:
            logger.error(f"Nmap port scan failed for {device.ip}: {e}")
            # Fallback to socket scan
            self._scan_ports_socket(device, ports)
    
    def _scan_ports_socket(self, device: Device, ports: List[int]) -> None:
        """Scan ports using raw sockets (fallback method)."""
        for port in ports:
            if check_port_open(device.ip, port, timeout=1.0):
                device.open_ports.append(port)
                device.services[port] = self._identify_service(port)
    
    def _identify_service(self, port: int) -> str:
        """Identify service based on port number."""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            1433: "MSSQL",
            5984: "CouchDB",
            6379: "Redis",
            27017: "MongoDB",
        }
        
        return common_services.get(port, "Unknown")
    
    def _identify_device(self, device: Device) -> None:
        """Attempt to identify device type based on open ports and services."""
        open_ports = set(device.open_ports)
        
        # Router/Gateway indicators
        if {80, 443, 23} & open_ports:
            device.device_type = "router"
        # Server indicators
        elif {22, 3389} & open_ports:
            device.device_type = "server"
        # Database server
        elif {3306, 5432, 1433, 27017} & open_ports:
            device.device_type = "database"
        # Web server
        elif {80, 443} & open_ports:
            device.device_type = "web_server"
        # IoT device indicators
        elif len(open_ports) == 1 and list(open_ports)[0] in [80, 443, 8080]:
            device.device_type = "iot"
        # Mobile device (limited ports)
        elif len(open_ports) <= 2:
            device.device_type = "mobile"
        else:
            device.device_type = "computer"
    
    async def _scan_bluetooth(self) -> List[Device]:
        """
        Scan for Bluetooth devices.
        
        Returns:
            List of discovered Bluetooth devices
        """
        bluetooth_devices = []
        
        try:
            # This is a placeholder - actual Bluetooth scanning requires
            # platform-specific implementations and may need additional permissions
            logger.info("Bluetooth scanning not yet implemented")
            
            # On Linux, you could use:
            # - bluetoothctl
            # - hcitool
            # - pybluez library
            
            # On macOS:
            # - system_profiler SPBluetoothDataType
            
            # On Windows:
            # - Windows Bluetooth API
            
        except Exception as e:
            logger.error(f"Bluetooth scan failed: {e}")
        
        return bluetooth_devices
    
    async def quick_scan(self, network: str) -> Dict[str, Any]:
        """
        Perform a quick network scan (ping + basic ports only).
        
        Args:
            network: Network range in CIDR notation
            
        Returns:
            Dictionary containing scan results
        """
        return await self.scan_network(network, ports="quick")
    
    async def port_scan_heatmap(self, network: str, ports: List[int]) -> Dict[str, Any]:
        """
        Generate data for port scan rate visualization heatmap.
        
        Args:
            network: Network range in CIDR notation
            ports: List of ports to scan
            
        Returns:
            Dictionary containing heatmap data
        """
        start_time = time.time()
        
        # Discover active hosts
        active_hosts = await self._discover_hosts(network)
        
        # Create heatmap data structure
        heatmap_data = {
            'network': network,
            'timestamp': start_time,
            'scan_rates': {},  # port -> {ip -> scan_rate}
            'total_scans': 0,
            'duration': 0.0
        }
        
        # Scan each port across all hosts and measure response times
        for port in ports:
            port_data = {}
            
            for ip in active_hosts:
                scan_start = time.perf_counter()
                is_open = check_port_open(ip, port, timeout=0.5)
                scan_duration = time.perf_counter() - scan_start
                
                # Calculate scan rate (scans per second)
                scan_rate = 1.0 / scan_duration if scan_duration > 0 else 1000.0
                
                port_data[ip] = {
                    'scan_rate': scan_rate,
                    'is_open': is_open,
                    'response_time': scan_duration * 1000  # ms
                }
                
                heatmap_data['total_scans'] += 1
            
            heatmap_data['scan_rates'][port] = port_data
        
        heatmap_data['duration'] = time.time() - start_time
        
        return heatmap_data
