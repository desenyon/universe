"""
Configuration management for Universe network scanner.
Developed by Desenyon - https://github.com/desenyon/universe
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    """Scan-related configuration."""
    default_network: str = "auto"
    default_ports: str = "1-1000"
    timeout: int = 30
    max_threads: int = 100
    rate_limit: int = 1000  # packets per second


@dataclass
class UIConfig:
    """User interface configuration."""
    theme: str = "cosmic"
    default_mode: str = "orbital"
    refresh_interval: int = 10
    show_animations: bool = True
    sound_alerts: bool = False


@dataclass
class SecurityConfig:
    """Security audit configuration."""
    alert_unknown_devices: bool = True
    alert_suspicious_ports: bool = True
    compliance_level: str = "basic"
    vulnerability_db_update: bool = True
    check_ssl_certs: bool = True


@dataclass
class ExportConfig:
    """Export and reporting configuration."""
    default_format: str = "json"
    include_timestamps: bool = True
    compress_large_files: bool = True
    template_dir: str = "templates"


@dataclass
class MonitorConfig:
    """Monitoring configuration."""
    default_interval: int = 60
    alert_webhook: Optional[str] = None
    log_level: str = "INFO"
    max_log_size: int = 10  # MB
    retain_history_days: int = 30


class Config:
    """Main configuration class for Universe."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_file: Path to configuration file. If None, uses default locations.
        """
        self.config_file = config_file or self._find_config_file()
        
        # Initialize with defaults
        self.scan = ScanConfig()
        self.ui = UIConfig()
        self.security = SecurityConfig()
        self.export = ExportConfig()
        self.monitor = MonitorConfig()
        
        # Load configuration if file exists
        if self.config_file and Path(self.config_file).exists():
            self.load_config()
    
    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in default locations."""
        possible_locations = [
            Path.home() / ".universe" / "config.yml",
            Path.home() / ".universe" / "config.yaml",
            Path.cwd() / "universe.yml",
            Path.cwd() / "universe.yaml",
            Path.cwd() / "config.yml",
            Path.cwd() / "config.yaml",
        ]
        
        for location in possible_locations:
            if location.exists():
                return str(location)
        
        return None
    
    def load_config(self) -> None:
        """Load configuration from file."""
        if not self.config_file:
            return
            
        try:
            with open(self.config_file, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            
            # Update scan config
            if 'scan' in config_data:
                scan_data = config_data['scan']
                for key, value in scan_data.items():
                    if hasattr(self.scan, key):
                        setattr(self.scan, key, value)
            
            # Update UI config
            if 'ui' in config_data:
                ui_data = config_data['ui']
                for key, value in ui_data.items():
                    if hasattr(self.ui, key):
                        setattr(self.ui, key, value)
            
            # Update security config
            if 'security' in config_data:
                security_data = config_data['security']
                for key, value in security_data.items():
                    if hasattr(self.security, key):
                        setattr(self.security, key, value)
            
            # Update export config
            if 'export' in config_data:
                export_data = config_data['export']
                for key, value in export_data.items():
                    if hasattr(self.export, key):
                        setattr(self.export, key, value)
            
            # Update monitor config
            if 'monitor' in config_data:
                monitor_data = config_data['monitor']
                for key, value in monitor_data.items():
                    if hasattr(self.monitor, key):
                        setattr(self.monitor, key, value)
                        
        except Exception as e:
            print(f"Warning: Failed to load config file {self.config_file}: {e}")
    
    def save_config(self, config_file: Optional[str] = None) -> None:
        """Save current configuration to file."""
        output_file = config_file or self.config_file
        
        if not output_file:
            # Create default config directory
            config_dir = Path.home() / ".universe"
            config_dir.mkdir(exist_ok=True)
            output_file = str(config_dir / "config.yml")
        
        config_data = {
            'scan': {
                'default_network': self.scan.default_network,
                'default_ports': self.scan.default_ports,
                'timeout': self.scan.timeout,
                'max_threads': self.scan.max_threads,
                'rate_limit': self.scan.rate_limit,
            },
            'ui': {
                'theme': self.ui.theme,
                'default_mode': self.ui.default_mode,
                'refresh_interval': self.ui.refresh_interval,
                'show_animations': self.ui.show_animations,
                'sound_alerts': self.ui.sound_alerts,
            },
            'security': {
                'alert_unknown_devices': self.security.alert_unknown_devices,
                'alert_suspicious_ports': self.security.alert_suspicious_ports,
                'compliance_level': self.security.compliance_level,
                'vulnerability_db_update': self.security.vulnerability_db_update,
                'check_ssl_certs': self.security.check_ssl_certs,
            },
            'export': {
                'default_format': self.export.default_format,
                'include_timestamps': self.export.include_timestamps,
                'compress_large_files': self.export.compress_large_files,
                'template_dir': self.export.template_dir,
            },
            'monitor': {
                'default_interval': self.monitor.default_interval,
                'alert_webhook': self.monitor.alert_webhook,
                'log_level': self.monitor.log_level,
                'max_log_size': self.monitor.max_log_size,
                'retain_history_days': self.monitor.retain_history_days,
            }
        }
        
        try:
            with open(output_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            
            self.config_file = output_file
            
        except Exception as e:
            print(f"Error: Failed to save config file {output_file}: {e}")
    
    def get_config_dir(self) -> Path:
        """Get configuration directory path."""
        config_dir = Path.home() / ".universe"
        config_dir.mkdir(exist_ok=True)
        return config_dir
    
    def get_cache_dir(self) -> Path:
        """Get cache directory path."""
        cache_dir = self.get_config_dir() / "cache"
        cache_dir.mkdir(exist_ok=True)
        return cache_dir
    
    def get_log_dir(self) -> Path:
        """Get logs directory path."""
        log_dir = self.get_config_dir() / "logs"
        log_dir.mkdir(exist_ok=True)
        return log_dir
    
    def get_templates_dir(self) -> Path:
        """Get templates directory path."""
        templates_dir = self.get_config_dir() / "templates"
        templates_dir.mkdir(exist_ok=True)
        return templates_dir
