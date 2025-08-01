"""
Real-time network monitoring and alerting module.
"""

import asyncio
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
import aiohttp

from .scanner import NetworkScanner
from .security import SecurityAuditor
from .config import Config
from .utils import format_duration

logger = logging.getLogger(__name__)


@dataclass
class DeviceHistory:
    """Track device presence history."""
    ip: str
    first_seen: float
    last_seen: float
    total_appearances: int = 1
    status_changes: List[Dict[str, Any]] = field(default_factory=list)
    
    def update_seen(self, status: str) -> None:
        """Update when device was last seen."""
        current_time = time.time()
        
        # Record status change if different from last known status
        if not self.status_changes or self.status_changes[-1]['status'] != status:
            self.status_changes.append({
                'status': status,
                'timestamp': current_time
            })
        
        self.last_seen = current_time
        if status == 'up':
            self.total_appearances += 1


@dataclass
class NetworkChange:
    """Represents a change in the network state."""
    change_type: str  # new_device, device_down, device_up, service_change
    device_ip: str
    timestamp: float
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'change_type': self.change_type,
            'device_ip': self.device_ip,
            'timestamp': self.timestamp,
            'details': self.details
        }


@dataclass
class Alert:
    """Represents a monitoring alert."""
    alert_id: str
    alert_type: str  # new_device, security_threat, device_down, etc.
    severity: str  # critical, high, medium, low, info
    title: str
    message: str
    device_ip: str
    timestamp: float = field(default_factory=time.time)
    acknowledged: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'device_ip': self.device_ip,
            'timestamp': self.timestamp,
            'acknowledged': self.acknowledged
        }


class NetworkMonitor:
    """Real-time network monitoring with change detection and alerting."""
    
    def __init__(self, network: str, interval: int = 60,
                 alert_new_devices: bool = True,
                 alert_suspicious: bool = True,
                 webhook_url: Optional[str] = None,
                 log_file: Optional[str] = None,
                 config: Optional[Config] = None):
        """
        Initialize network monitor.
        
        Args:
            network: Network range to monitor
            interval: Monitoring interval in seconds
            alert_new_devices: Whether to alert on new devices
            alert_suspicious: Whether to alert on security issues
            webhook_url: Webhook URL for alerts
            log_file: Log file path
            config: Configuration object
        """
        self.network = network
        self.interval = interval
        self.alert_new_devices = alert_new_devices
        self.alert_suspicious = alert_suspicious
        self.webhook_url = webhook_url
        self.log_file = log_file
        self.config = config or Config()
        
        # Initialize components
        self.scanner = NetworkScanner(config=self.config)
        self.security_auditor = SecurityAuditor(config=self.config)
        
        # State tracking
        self.device_history: Dict[str, DeviceHistory] = {}
        self.previous_scan: Optional[Dict[str, Any]] = None
        self.current_scan: Optional[Dict[str, Any]] = None
        self.changes: List[NetworkChange] = []
        self.alerts: List[Alert] = []
        
        # Control flags
        self.monitoring = False
        self.scan_count = 0
        
        # Set up logging
        self._setup_logging()
        
        # Load historical data if available
        self._load_history()
    
    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        if self.log_file:
            logging.basicConfig(
                level=logging.INFO,
                format=log_format,
                handlers=[
                    logging.FileHandler(self.log_file),
                    logging.StreamHandler()
                ]
            )
        else:
            logging.basicConfig(level=logging.INFO, format=log_format)
    
    def _load_history(self) -> None:
        """Load device history from cache."""
        try:
            cache_dir = self.config.get_cache_dir()
            history_file = cache_dir / "device_history.json"
            
            if history_file.exists():
                with open(history_file, 'r') as f:
                    data = json.load(f)
                
                for ip, hist_data in data.items():
                    self.device_history[ip] = DeviceHistory(
                        ip=ip,
                        first_seen=hist_data['first_seen'],
                        last_seen=hist_data['last_seen'],
                        total_appearances=hist_data.get('total_appearances', 1),
                        status_changes=hist_data.get('status_changes', [])
                    )
                
                logger.info(f"Loaded history for {len(self.device_history)} devices")
        
        except Exception as e:
            logger.warning(f"Failed to load device history: {e}")
    
    def _save_history(self) -> None:
        """Save device history to cache."""
        try:
            cache_dir = self.config.get_cache_dir()
            history_file = cache_dir / "device_history.json"
            
            data = {}
            for ip, history in self.device_history.items():
                data[ip] = {
                    'first_seen': history.first_seen,
                    'last_seen': history.last_seen,
                    'total_appearances': history.total_appearances,
                    'status_changes': history.status_changes
                }
            
            with open(history_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        except Exception as e:
            logger.error(f"Failed to save device history: {e}")
    
    async def start_monitoring(self) -> None:
        """Start the monitoring loop."""
        self.monitoring = True
        logger.info(f"Starting network monitoring of {self.network}")
        logger.info(f"Scan interval: {self.interval} seconds")
        
        try:
            while self.monitoring:
                await self._perform_monitoring_scan()
                
                # Wait for next interval
                await asyncio.sleep(self.interval)
        
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        finally:
            self.monitoring = False
            self._save_history()
    
    def stop_monitoring(self) -> None:
        """Stop the monitoring loop."""
        self.monitoring = False
        logger.info("Monitoring stopped")
    
    async def _perform_monitoring_scan(self) -> None:
        """Perform a single monitoring scan cycle."""
        scan_start = time.time()
        self.scan_count += 1
        
        logger.info(f"Starting monitoring scan #{self.scan_count}")
        
        try:
            # Perform network scan
            self.current_scan = await self.scanner.scan_network(
                network=self.network,
                ports="common"
            )
            
            # Analyze changes if we have previous data
            if self.previous_scan:
                await self._analyze_changes()
            
            # Update device history
            self._update_device_history()
            
            # Check for security issues
            if self.alert_suspicious:
                await self._check_security_issues()
            
            # Clean up old alerts and changes
            self._cleanup_old_data()
            
            # Save current scan as previous for next iteration
            self.previous_scan = self.current_scan.copy()
            
            scan_duration = time.time() - scan_start
            logger.info(f"Monitoring scan #{self.scan_count} completed in {scan_duration:.2f}s")
            
            # Save history periodically
            if self.scan_count % 10 == 0:
                self._save_history()
        
        except Exception as e:
            logger.error(f"Error during monitoring scan: {e}")
    
    async def _analyze_changes(self) -> None:
        """Analyze changes between current and previous scans."""
        if not self.previous_scan or not self.current_scan:
            return
        
        # Get device lists
        prev_devices = {d['ip']: d for d in self.previous_scan.get('devices', [])}
        curr_devices = {d['ip']: d for d in self.current_scan.get('devices', [])}
        
        prev_ips = set(prev_devices.keys())
        curr_ips = set(curr_devices.keys())
        
        # New devices
        new_ips = curr_ips - prev_ips
        for ip in new_ips:
            device = curr_devices[ip]
            change = NetworkChange(
                change_type="new_device",
                device_ip=ip,
                timestamp=time.time(),
                details=device
            )
            self.changes.append(change)
            
            logger.info(f"New device detected: {ip}")
            
            if self.alert_new_devices:
                await self._create_alert(
                    alert_type="new_device",
                    severity="medium",
                    title="New Device Detected",
                    message=f"New device {ip} appeared on the network",
                    device_ip=ip
                )
        
        # Devices that went down
        down_ips = prev_ips - curr_ips
        for ip in down_ips:
            change = NetworkChange(
                change_type="device_down",
                device_ip=ip,
                timestamp=time.time(),
                details=prev_devices[ip]
            )
            self.changes.append(change)
            
            logger.info(f"Device went down: {ip}")
            
            # Only alert if device was consistently present
            if ip in self.device_history and self.device_history[ip].total_appearances > 3:
                await self._create_alert(
                    alert_type="device_down",
                    severity="low",
                    title="Device Went Offline",
                    message=f"Device {ip} is no longer responding",
                    device_ip=ip
                )
        
        # Devices that came back up
        up_ips = curr_ips & prev_ips
        for ip in up_ips:
            prev_status = prev_devices[ip].get('status', 'unknown')
            curr_status = curr_devices[ip].get('status', 'unknown')
            
            if prev_status != 'up' and curr_status == 'up':
                change = NetworkChange(
                    change_type="device_up",
                    device_ip=ip,
                    timestamp=time.time(),
                    details=curr_devices[ip]
                )
                self.changes.append(change)
                
                logger.info(f"Device came back up: {ip}")
        
        # Service changes
        for ip in curr_ips & prev_ips:
            prev_ports = set(prev_devices[ip].get('open_ports', []))
            curr_ports = set(curr_devices[ip].get('open_ports', []))
            
            if prev_ports != curr_ports:
                new_ports = curr_ports - prev_ports
                closed_ports = prev_ports - curr_ports
                
                change = NetworkChange(
                    change_type="service_change",
                    device_ip=ip,
                    timestamp=time.time(),
                    details={
                        'new_ports': list(new_ports),
                        'closed_ports': list(closed_ports)
                    }
                )
                self.changes.append(change)
                
                logger.info(f"Service changes on {ip}: +{new_ports}, -{closed_ports}")
                
                # Alert on new services
                if new_ports:
                    await self._create_alert(
                        alert_type="service_change",
                        severity="low",
                        title="New Services Detected",
                        message=f"Device {ip} opened new ports: {', '.join(map(str, new_ports))}",
                        device_ip=ip
                    )
    
    def _update_device_history(self) -> None:
        """Update device history with current scan data."""
        if not self.current_scan:
            return
        
        current_time = time.time()
        
        for device in self.current_scan.get('devices', []):
            ip = device.get('ip', '')
            status = device.get('status', 'unknown')
            
            if ip not in self.device_history:
                self.device_history[ip] = DeviceHistory(
                    ip=ip,
                    first_seen=current_time,
                    last_seen=current_time
                )
            
            self.device_history[ip].update_seen(status)
    
    async def _check_security_issues(self) -> None:
        """Check for security issues in current scan."""
        if not self.current_scan:
            return
        
        try:
            # Perform security audit on current scan data
            audit_result = await self.security_auditor.audit_network(
                network=self.network,
                deep_scan=False
            )
            
            # Create alerts for new threats
            for threat in audit_result.get('threats', []):
                await self._create_alert(
                    alert_type="security_threat",
                    severity=threat.get('severity', 'medium'),
                    title=f"Security Threat: {threat.get('title', 'Unknown')}",
                    message=threat.get('description', 'No description'),
                    device_ip=threat.get('device_ip', 'Unknown')
                )
            
            # Create alerts for critical warnings
            for warning in audit_result.get('warnings', []):
                if warning.get('severity') == 'high':
                    await self._create_alert(
                        alert_type="security_warning",
                        severity="medium",
                        title=f"Security Warning: {warning.get('title', 'Unknown')}",
                        message=warning.get('description', 'No description'),
                        device_ip=warning.get('device_ip', 'Unknown')
                    )
        
        except Exception as e:
            logger.error(f"Error during security check: {e}")
    
    async def _create_alert(self, alert_type: str, severity: str,
                           title: str, message: str, device_ip: str) -> None:
        """Create and process a new alert."""
        
        alert_id = f"{alert_type}_{device_ip}_{int(time.time())}"
        
        alert = Alert(
            alert_id=alert_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            device_ip=device_ip
        )
        
        self.alerts.append(alert)
        
        # Log the alert
        logger.warning(f"ALERT [{severity.upper()}]: {title} - {message}")
        
        # Send webhook notification if configured
        if self.webhook_url:
            await self._send_webhook_alert(alert)
        
        # Trigger any registered alert handlers
        await self._handle_alert(alert)
    
    async def _send_webhook_alert(self, alert: Alert) -> None:
        """Send alert to webhook URL."""
        if not self.webhook_url:
            return
            
        try:
            payload = {
                'alert': alert.to_dict(),
                'network': self.network,
                'timestamp': datetime.fromtimestamp(alert.timestamp).isoformat()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        logger.info(f"Webhook alert sent successfully for {alert.alert_id}")
                    else:
                        logger.warning(f"Webhook alert failed with status {response.status}")
        
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
    
    async def _handle_alert(self, alert: Alert) -> None:
        """Handle alert processing (can be extended for custom handlers)."""
        # This method can be overridden or extended for custom alert handling
        pass
    
    def _cleanup_old_data(self) -> None:
        """Clean up old changes and alerts."""
        current_time = time.time()
        retention_period = 24 * 60 * 60  # 24 hours
        
        # Clean up old changes
        self.changes = [
            change for change in self.changes
            if current_time - change.timestamp < retention_period
        ]
        
        # Clean up old alerts
        self.alerts = [
            alert for alert in self.alerts
            if current_time - alert.timestamp < retention_period
        ]
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status summary."""
        if not self.current_scan:
            return {'status': 'no_data'}
        
        devices = self.current_scan.get('devices', [])
        active_devices = [d for d in devices if d.get('status') == 'up']
        
        # Recent changes (last hour)
        recent_time = time.time() - 3600
        recent_changes = [
            change for change in self.changes
            if change.timestamp > recent_time
        ]
        
        # Active alerts
        active_alerts = [
            alert for alert in self.alerts
            if not alert.acknowledged
        ]
        
        return {
            'status': 'monitoring',
            'network': self.network,
            'scan_count': self.scan_count,
            'last_scan': self.current_scan.get('timestamp', 0),
            'total_devices': len(devices),
            'active_devices': len(active_devices),
            'device_history_count': len(self.device_history),
            'recent_changes': len(recent_changes),
            'active_alerts': len(active_alerts),
            'changes': [change.to_dict() for change in recent_changes],
            'alerts': [alert.to_dict() for alert in active_alerts]
        }
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                logger.info(f"Alert {alert_id} acknowledged")
                return True
        return False
    
    def get_device_history(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get history for a specific device."""
        if ip in self.device_history:
            history = self.device_history[ip]
            return {
                'ip': ip,
                'first_seen': history.first_seen,
                'last_seen': history.last_seen,
                'total_appearances': history.total_appearances,
                'status_changes': history.status_changes,
                'uptime_percentage': self._calculate_uptime(history)
            }
        return None
    
    def _calculate_uptime(self, history: DeviceHistory) -> float:
        """Calculate device uptime percentage."""
        if not history.status_changes:
            return 0.0
        
        total_time = history.last_seen - history.first_seen
        if total_time <= 0:
            return 100.0
        
        up_time = 0.0
        last_timestamp = history.first_seen
        last_status = 'unknown'
        
        for change in history.status_changes:
            if last_status == 'up':
                up_time += change['timestamp'] - last_timestamp
            
            last_timestamp = change['timestamp']
            last_status = change['status']
        
        # Add time from last status change to now
        if last_status == 'up':
            up_time += history.last_seen - last_timestamp
        
        return (up_time / total_time) * 100.0 if total_time > 0 else 0.0
