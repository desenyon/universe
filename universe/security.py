"""
Security auditing and vulnerability detection module.
"""

import asyncio
import json
import re
import socket
import ssl
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field

from .config import Config
from .scanner import NetworkScanner
from .utils import check_port_open, reverse_dns_lookup


@dataclass
class SecurityThreat:
    """Represents a security threat or vulnerability."""
    threat_id: str
    severity: str  # critical, high, medium, low
    category: str  # network, service, configuration, etc.
    title: str
    description: str
    device_ip: str
    port: Optional[int] = None
    service: Optional[str] = None
    cve_id: Optional[str] = None
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat to dictionary."""
        return {
            'threat_id': self.threat_id,
            'severity': self.severity,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'device_ip': self.device_ip,
            'port': self.port,
            'service': self.service,
            'cve_id': self.cve_id,
            'recommendation': self.recommendation,
            'timestamp': self.timestamp,
        }


@dataclass
class SecurityWarning:
    """Represents a security warning or best practice violation."""
    warning_id: str
    severity: str  # medium, low, info
    title: str
    description: str
    device_ip: str
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert warning to dictionary."""
        return {
            'warning_id': self.warning_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'device_ip': self.device_ip,
            'recommendation': self.recommendation,
            'timestamp': self.timestamp,
        }


@dataclass
class AuditResult:
    """Represents the results of a security audit."""
    network: str
    threats: List[SecurityThreat] = field(default_factory=list)
    warnings: List[SecurityWarning] = field(default_factory=list)
    compliance_score: float = 0.0
    scan_duration: float = 0.0
    timestamp: float = field(default_factory=time.time)
    devices_scanned: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit result to dictionary."""
        return {
            'network': self.network,
            'threats': [threat.to_dict() for threat in self.threats],
            'warnings': [warning.to_dict() for warning in self.warnings],
            'compliance_score': self.compliance_score,
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp,
            'devices_scanned': self.devices_scanned,
        }


class SecurityAuditor:
    """Main security auditing class."""
    
    def __init__(self, compliance_level: str = "basic", 
                 check_vulnerabilities: bool = True,
                 config: Optional[Config] = None):
        """
        Initialize security auditor.
        
        Args:
            compliance_level: Security compliance level (basic, strict)
            check_vulnerabilities: Whether to check for known vulnerabilities
            config: Configuration object
        """
        self.compliance_level = compliance_level
        self.check_vulnerabilities = check_vulnerabilities
        self.config = config or Config()
        
        # Known vulnerable services and ports
        self.vulnerable_services = {
            21: {"service": "FTP", "issues": ["Unencrypted", "Anonymous login"]},
            23: {"service": "Telnet", "issues": ["Unencrypted", "Weak authentication"]},
            25: {"service": "SMTP", "issues": ["Open relay", "No encryption"]},
            53: {"service": "DNS", "issues": ["Zone transfer", "Cache poisoning"]},
            135: {"service": "RPC", "issues": ["Remote code execution"]},
            139: {"service": "NetBIOS", "issues": ["Information disclosure"]},
            445: {"service": "SMB", "issues": ["EternalBlue", "Null sessions"]},
            1433: {"service": "MSSQL", "issues": ["Default credentials", "Injection"]},
            3306: {"service": "MySQL", "issues": ["Default credentials", "Injection"]},
            3389: {"service": "RDP", "issues": ["Brute force", "BlueKeep"]},
            5432: {"service": "PostgreSQL", "issues": ["Default credentials"]},
            5984: {"service": "CouchDB", "issues": ["Default admin", "No auth"]},
            6379: {"service": "Redis", "issues": ["No authentication", "Code exec"]},
            27017: {"service": "MongoDB", "issues": ["No authentication"]},
        }
        
        # Suspicious port combinations
        self.suspicious_combinations = [
            ([22, 23], "SSH and Telnet both open"),
            ([80, 8080, 8000], "Multiple web servers"),
            ([21, 22, 23, 25], "Multiple admin services"),
        ]
        
        # Known malicious MAC prefixes (simplified list)
        self.suspicious_mac_prefixes = {
            "00:00:00": "Invalid MAC",
            "FF:FF:FF": "Broadcast MAC",
        }
    
    async def audit_network(self, network: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive security audit of network.
        
        Args:
            network: Network range in CIDR notation
            deep_scan: Whether to perform deep vulnerability scanning
            
        Returns:
            Dictionary containing audit results
        """
        start_time = time.time()
        
        # Initialize result
        result = AuditResult(network=network)
        
        # First, scan the network to get device information
        scanner = NetworkScanner(config=self.config)
        scan_data = await scanner.scan_network(
            network=network, 
            ports="common" if not deep_scan else "1-10000"
        )
        
        devices = scan_data.get('devices', [])
        result.devices_scanned = len(devices)
        
        # Analyze each device for security issues
        for device in devices:
            await self._audit_device(device, result, deep_scan)
        
        # Perform network-level checks
        await self._audit_network_level(devices, result)
        
        # Calculate compliance score
        result.compliance_score = self._calculate_compliance_score(result)
        result.scan_duration = time.time() - start_time
        
        return result.to_dict()
    
    async def _audit_device(self, device: Dict[str, Any], result: AuditResult, 
                           deep_scan: bool) -> None:
        """Audit a single device for security issues."""
        
        ip = device.get('ip', '')
        open_ports = device.get('open_ports', [])
        services = device.get('services', {})
        
        # Check for vulnerable services
        for port in open_ports:
            if port in self.vulnerable_services:
                service_info = self.vulnerable_services[port]
                
                threat = SecurityThreat(
                    threat_id=f"VULN_{ip}_{port}",
                    severity="high" if port in [21, 23, 445] else "medium",
                    category="service",
                    title=f"Vulnerable {service_info['service']} Service",
                    description=f"Port {port} ({service_info['service']}) is open with known vulnerabilities: {', '.join(service_info['issues'])}",
                    device_ip=ip,
                    port=port,
                    service=service_info['service'],
                    recommendation=f"Consider disabling {service_info['service']} or upgrading to secure alternatives"
                )
                result.threats.append(threat)
        
        # Check for suspicious port combinations
        for ports, description in self.suspicious_combinations:
            if all(port in open_ports for port in ports):
                warning = SecurityWarning(
                    warning_id=f"COMBO_{ip}_{'_'.join(map(str, ports))}",
                    severity="medium",
                    title="Suspicious Port Combination",
                    description=f"{description} on {ip}",
                    device_ip=ip,
                    recommendation="Review service configuration and disable unnecessary services"
                )
                result.warnings.append(warning)
        
        # Check for unencrypted admin services
        admin_ports = [21, 23, 80, 8080]  # FTP, Telnet, HTTP
        for port in open_ports:
            if port in admin_ports:
                warning = SecurityWarning(
                    warning_id=f"UNENC_{ip}_{port}",
                    severity="medium",
                    title="Unencrypted Administrative Service",
                    description=f"Port {port} may provide unencrypted access on {ip}",
                    device_ip=ip,
                    recommendation="Use encrypted alternatives (SFTP, SSH, HTTPS)"
                )
                result.warnings.append(warning)
        
        # Check for default credentials (if deep scan)
        if deep_scan:
            await self._check_default_credentials(device, result)
        
        # Check SSL/TLS configuration for HTTPS services
        if 443 in open_ports or 8443 in open_ports:
            await self._check_ssl_configuration(device, result)
        
        # Check for unknown MAC vendor
        mac = device.get('mac', '')
        vendor = device.get('vendor', 'Unknown')
        if vendor == 'Unknown' and mac:
            warning = SecurityWarning(
                warning_id=f"MAC_{ip}_{mac}",
                severity="low",
                title="Unknown MAC Vendor",
                description=f"Device {ip} has MAC {mac} from unknown vendor",
                device_ip=ip,
                recommendation="Investigate device identity and purpose"
            )
            result.warnings.append(warning)
    
    async def _audit_network_level(self, devices: List[Dict[str, Any]], 
                                  result: AuditResult) -> None:
        """Perform network-level security checks."""
        
        # Check for duplicate IP addresses
        ip_counts = {}
        for device in devices:
            ip = device.get('ip', '')
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        for ip, count in ip_counts.items():
            if count > 1:
                threat = SecurityThreat(
                    threat_id=f"DUP_IP_{ip}",
                    severity="critical",
                    category="network",
                    title="Duplicate IP Address",
                    description=f"IP address {ip} is assigned to {count} devices",
                    device_ip=ip,
                    recommendation="Investigate IP conflict and implement proper DHCP management"
                )
                result.threats.append(threat)
        
        # Check for rogue access points (devices with multiple network interfaces)
        # This is a simplified check - in practice, you'd need more sophisticated detection
        
        # Check for devices with excessive open ports
        for device in devices:
            open_ports = device.get('open_ports', [])
            if len(open_ports) > 20:
                warning = SecurityWarning(
                    warning_id=f"MANY_PORTS_{device.get('ip')}",
                    severity="medium",
                    title="Many Open Ports",
                    description=f"Device {device.get('ip')} has {len(open_ports)} open ports",
                    device_ip=device.get('ip', ''),
                    recommendation="Review services and close unnecessary ports"
                )
                result.warnings.append(warning)
        
        # Check for devices without reverse DNS
        for device in devices:
            hostname = device.get('hostname', '')
            ip = device.get('ip', '')
            if hostname == ip:  # No reverse DNS
                warning = SecurityWarning(
                    warning_id=f"NO_RDNS_{ip}",
                    severity="low",
                    title="No Reverse DNS",
                    description=f"Device {ip} has no reverse DNS entry",
                    device_ip=ip,
                    recommendation="Consider setting up reverse DNS for better network management"
                )
                result.warnings.append(warning)
    
    async def _check_default_credentials(self, device: Dict[str, Any], 
                                       result: AuditResult) -> None:
        """Check for services with default credentials."""
        
        ip = device.get('ip', '')
        open_ports = device.get('open_ports', [])
        
        # Common default credential checks
        default_creds = {
            21: [("admin", "admin"), ("ftp", "ftp"), ("anonymous", "")],
            22: [("admin", "admin"), ("root", "root"), ("pi", "raspberry")],
            23: [("admin", "admin"), ("root", "root")],
            80: [("admin", "admin"), ("admin", "password")],
            3306: [("root", ""), ("root", "root")],
            5432: [("postgres", "postgres"), ("postgres", "")],
        }
        
        for port in open_ports:
            if port in default_creds:
                # This is a placeholder - actual credential testing would require
                # careful implementation to avoid triggering security systems
                warning = SecurityWarning(
                    warning_id=f"DEFAULT_CREDS_{ip}_{port}",
                    severity="high",
                    title="Potential Default Credentials",
                    description=f"Service on port {port} may use default credentials",
                    device_ip=ip,
                    recommendation="Change default passwords and implement strong authentication"
                )
                result.warnings.append(warning)
    
    async def _check_ssl_configuration(self, device: Dict[str, Any], 
                                     result: AuditResult) -> None:
        """Check SSL/TLS configuration for HTTPS services."""
        
        ip = device.get('ip', '')
        
        try:
            # Check SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiry
                    if cert:
                        not_after = cert.get('notAfter')
                        if not_after:
                            # Parse certificate date and check if expiring soon
                            # This is simplified - would need proper date parsing
                            warning = SecurityWarning(
                                warning_id=f"SSL_CERT_{ip}",
                                severity="medium",
                                title="SSL Certificate Check",
                                description=f"SSL certificate should be verified for {ip}",
                                device_ip=ip,
                                recommendation="Verify SSL certificate validity and expiration"
                            )
                            result.warnings.append(warning)
        
        except Exception:
            # SSL connection failed
            warning = SecurityWarning(
                warning_id=f"SSL_FAIL_{ip}",
                severity="low",
                title="SSL Connection Failed",
                description=f"Could not establish SSL connection to {ip}:443",
                device_ip=ip,
                recommendation="Verify SSL service configuration"
            )
            result.warnings.append(warning)
    
    def _calculate_compliance_score(self, result: AuditResult) -> float:
        """Calculate compliance score based on threats and warnings."""
        
        if result.devices_scanned == 0:
            return 100.0
        
        # Base score
        score = 100.0
        
        # Deduct points for threats
        for threat in result.threats:
            if threat.severity == "critical":
                score -= 20
            elif threat.severity == "high":
                score -= 10
            elif threat.severity == "medium":
                score -= 5
            elif threat.severity == "low":
                score -= 2
        
        # Deduct points for warnings
        for warning in result.warnings:
            if warning.severity == "medium":
                score -= 3
            elif warning.severity == "low":
                score -= 1
        
        # Apply compliance level modifiers
        if self.compliance_level == "strict":
            # Stricter deductions for strict compliance
            score *= 0.8
        
        return max(0.0, min(100.0, score))
    
    def export_report(self, audit_results: Dict[str, Any], 
                     output_file: str) -> None:
        """Export audit report to file."""
        
        try:
            if output_file.endswith('.json'):
                with open(output_file, 'w') as f:
                    json.dump(audit_results, f, indent=2)
            
            elif output_file.endswith('.md'):
                self._export_markdown_report(audit_results, output_file)
            
            else:
                # Default to JSON
                with open(output_file, 'w') as f:
                    json.dump(audit_results, f, indent=2)
        
        except Exception as e:
            raise Exception(f"Failed to export report: {e}")
    
    def _export_markdown_report(self, audit_results: Dict[str, Any], 
                               output_file: str) -> None:
        """Export audit report as Markdown."""
        
        with open(output_file, 'w') as f:
            # Header
            f.write("# Network Security Audit Report\n\n")
            f.write(f"**Network:** {audit_results.get('network', 'Unknown')}\n")
            f.write(f"**Scan Date:** {datetime.fromtimestamp(audit_results.get('timestamp', 0))}\n")
            f.write(f"**Devices Scanned:** {audit_results.get('devices_scanned', 0)}\n")
            f.write(f"**Compliance Score:** {audit_results.get('compliance_score', 0):.1f}/100\n\n")
            
            # Executive Summary
            threats = audit_results.get('threats', [])
            warnings = audit_results.get('warnings', [])
            
            f.write("## Executive Summary\n\n")
            f.write(f"This security audit identified **{len(threats)} threats** and **{len(warnings)} warnings** ")
            f.write(f"across {audit_results.get('devices_scanned', 0)} network devices.\n\n")
            
            # Threats
            if threats:
                f.write("## Security Threats\n\n")
                for threat in threats:
                    f.write(f"### {threat.get('title', 'Unknown Threat')}\n")
                    f.write(f"**Severity:** {threat.get('severity', 'Unknown')}\n")
                    f.write(f"**Device:** {threat.get('device_ip', 'Unknown')}\n")
                    f.write(f"**Description:** {threat.get('description', 'No description')}\n")
                    if threat.get('recommendation'):
                        f.write(f"**Recommendation:** {threat.get('recommendation')}\n")
                    f.write("\n")
            
            # Warnings
            if warnings:
                f.write("## Security Warnings\n\n")
                for warning in warnings:
                    f.write(f"### {warning.get('title', 'Unknown Warning')}\n")
                    f.write(f"**Severity:** {warning.get('severity', 'Unknown')}\n")
                    f.write(f"**Device:** {warning.get('device_ip', 'Unknown')}\n")
                    f.write(f"**Description:** {warning.get('description', 'No description')}\n")
                    if warning.get('recommendation'):
                        f.write(f"**Recommendation:** {warning.get('recommendation')}\n")
                    f.write("\n")
            
            # Recommendations
            f.write("## General Recommendations\n\n")
            f.write("1. Regularly update all network devices and services\n")
            f.write("2. Implement strong authentication and access controls\n")
            f.write("3. Use encrypted protocols for administrative access\n")
            f.write("4. Monitor network traffic for anomalies\n")
            f.write("5. Conduct regular security audits\n\n")
            
            f.write("---\n")
            f.write("Report generated by Universe Network Scanner\n")
            f.write("Developed by Desenyon - https://github.com/desenyon/universe\n")
