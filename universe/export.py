"""
Data export and reporting module.
Developed by Desenyon - https://github.com/desenyon/universe
"""

import json
import csv
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from io import StringIO

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.offline import plot
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

from .config import Config
from .utils import format_bytes, format_duration


class DataExporter:
    """Handle data export and report generation."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize data exporter.
        
        Args:
            config: Configuration object
        """
        self.config = config or Config()
        
        # Set up matplotlib style
        plt.style.use('dark_background')
        sns.set_palette("husl")
    
    def export_scan_results(self, scan_data: Dict[str, Any], 
                           output_path: str, format: str = "json") -> None:
        """
        Export scan results to file.
        
        Args:
            scan_data: Scan results dictionary
            output_path: Output file path
            format: Export format (json, csv, md)
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == "json":
            self._export_json(scan_data, output_file)
        elif format.lower() == "csv":
            self._export_csv(scan_data, output_file)
        elif format.lower() == "md":
            self._export_markdown(scan_data, output_file)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def export_data(self, data: Dict[str, Any], output_path: str,
                   format: str = "json", template: Optional[str] = None,
                   include_history: bool = False) -> None:
        """
        Export data with advanced options.
        
        Args:
            data: Data dictionary to export
            output_path: Output file path
            format: Export format
            template: Template name for reports
            include_history: Whether to include historical data
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        if format.lower() == "png":
            self._export_network_map_png(data, output_file)
        elif format.lower() == "svg":
            self._export_network_map_svg(data, output_file)
        elif format.lower() == "json":
            self._export_json(data, output_file)
        elif format.lower() == "csv":
            self._export_csv(data, output_file)
        elif format.lower() == "md":
            if template:
                self._export_templated_markdown(data, output_file, template)
            else:
                self._export_markdown(data, output_file)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_json(self, data: Dict[str, Any], output_file: Path) -> None:
        """Export data as JSON."""
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _export_csv(self, scan_data: Dict[str, Any], output_file: Path) -> None:
        """Export scan data as CSV."""
        devices = scan_data.get('devices', [])
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'IP Address', 'MAC Address', 'Hostname', 'Vendor',
                'Operating System', 'Status', 'Device Type',
                'Open Ports', 'Services', 'Last Seen', 'Response Time'
            ])
            
            # Data rows
            for device in devices:
                open_ports = ', '.join(map(str, device.get('open_ports', [])))
                services = ', '.join(device.get('services', {}).values())
                last_seen = datetime.fromtimestamp(device.get('last_seen', 0)).isoformat()
                
                writer.writerow([
                    device.get('ip', ''),
                    device.get('mac', ''),
                    device.get('hostname', ''),
                    device.get('vendor', ''),
                    device.get('os', ''),
                    device.get('status', ''),
                    device.get('device_type', ''),
                    open_ports,
                    services,
                    last_seen,
                    f"{device.get('response_time', 0):.2f}ms"
                ])
    
    def _export_markdown(self, scan_data: Dict[str, Any], output_file: Path) -> None:
        """Export scan data as Markdown report."""
        with open(output_file, 'w') as f:
            # Header
            f.write("# Network Scan Report\n\n")
            f.write(f"**Network:** {scan_data.get('network', 'Unknown')}\n")
            f.write(f"**Scan Date:** {datetime.fromtimestamp(scan_data.get('timestamp', 0))}\n")
            f.write(f"**Scan Duration:** {format_duration(scan_data.get('scan_duration', 0))}\n")
            f.write(f"**Total Hosts:** {scan_data.get('total_hosts', 0)}\n")
            f.write(f"**Active Hosts:** {scan_data.get('active_hosts', 0)}\n\n")
            
            # Device summary
            devices = scan_data.get('devices', [])
            if devices:
                f.write("## Discovered Devices\n\n")
                f.write("| IP Address | Hostname | Status | OS | Open Ports | Device Type |\n")
                f.write("|------------|----------|--------|----|-----------|-----------|\n")
                
                for device in devices:
                    ports = ', '.join(map(str, device.get('open_ports', [])))
                    if len(ports) > 30:
                        ports = ports[:27] + "..."
                    
                    f.write(f"| {device.get('ip', '')} | "
                           f"{device.get('hostname', '')} | "
                           f"{device.get('status', '')} | "
                           f"{device.get('os', '')} | "
                           f"{ports} | "
                           f"{device.get('device_type', '')} |\n")
                
                # Service summary
                f.write("\n## Services Summary\n\n")
                service_counts = {}
                for device in devices:
                    for service in device.get('services', {}).values():
                        service_counts[service] = service_counts.get(service, 0) + 1
                
                if service_counts:
                    f.write("| Service | Count |\n")
                    f.write("|---------|-------|\n")
                    for service, count in sorted(service_counts.items()):
                        f.write(f"| {service} | {count} |\n")
                
                # Statistics
                f.write("\n## Statistics\n\n")
                active_devices = len([d for d in devices if d.get('status') == 'up'])
                total_ports = sum(len(d.get('open_ports', [])) for d in devices)
                
                f.write(f"- **Active Devices:** {active_devices}\n")
                f.write(f"- **Total Open Ports:** {total_ports}\n")
                f.write(f"- **Average Ports per Device:** {total_ports / len(devices):.1f}\n")
                f.write(f"- **Unique Services:** {len(service_counts)}\n")
            
            f.write("\n---\n")
            f.write("Report generated by Universe Network Scanner\n")
            f.write("Developed by Desenyon - https://github.com/desenyon/universe\n")
    
    def _export_templated_markdown(self, data: Dict[str, Any], 
                                  output_file: Path, template: str) -> None:
        """Export using a specific template."""
        
        templates_dir = self.config.get_templates_dir()
        template_file = templates_dir / f"{template}.md"
        
        if template_file.exists():
            # Load template and substitute variables
            with open(template_file, 'r') as f:
                template_content = f.read()
            
            # Simple template variable substitution
            template_vars = {
                'network': data.get('network', 'Unknown'),
                'timestamp': datetime.fromtimestamp(data.get('timestamp', 0)).isoformat(),
                'device_count': len(data.get('devices', [])),
                'active_count': len([d for d in data.get('devices', []) if d.get('status') == 'up']),
                'scan_duration': format_duration(data.get('scan_duration', 0))
            }
            
            content = template_content
            for var, value in template_vars.items():
                content = content.replace(f"{{{{ {var} }}}}", str(value))
            
            with open(output_file, 'w') as f:
                f.write(content)
        else:
            # Fallback to default markdown export
            self._export_markdown(data, output_file)
    
    def _export_network_map_png(self, scan_data: Dict[str, Any], 
                               output_file: Path) -> None:
        """Export network visualization as PNG."""
        devices = scan_data.get('devices', [])
        
        if not devices:
            raise ValueError("No devices to visualize")
        
        # Create network visualization
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Extract data for plotting
        ips = [device.get('ip', '') for device in devices]
        x_coords = []
        y_coords = []
        colors = []
        sizes = []
        
        for i, device in enumerate(devices):
            # Position based on IP address
            ip_parts = device.get('ip', '0.0.0.0').split('.')
            try:
                x = int(ip_parts[-1])
                y = int(ip_parts[-2])
            except (ValueError, IndexError):
                x = i % 20
                y = i // 20
            
            x_coords.append(x)
            y_coords.append(y)
            
            # Color based on status
            if device.get('status') == 'up':
                colors.append('green')
            elif device.get('status') == 'down':
                colors.append('red')
            else:
                colors.append('orange')
            
            # Size based on number of open ports
            port_count = len(device.get('open_ports', []))
            sizes.append(max(50, port_count * 10))
        
        # Create scatter plot
        scatter = ax.scatter(x_coords, y_coords, c=colors, s=sizes, alpha=0.7)
        
        # Add labels for significant devices
        for i, device in enumerate(devices):
            if len(device.get('open_ports', [])) > 3:  # Label devices with many ports
                ax.annotate(
                    device.get('ip', '').split('.')[-1],
                    (x_coords[i], y_coords[i]),
                    xytext=(5, 5),
                    textcoords='offset points',
                    fontsize=8,
                    color='white'
                )
        
        # Customize plot
        ax.set_title(f"Network Map: {scan_data.get('network', 'Unknown')}", 
                    color='white', fontsize=16)
        ax.set_xlabel('Last IP Octet', color='white')
        ax.set_ylabel('Third IP Octet', color='white')
        ax.grid(True, alpha=0.3)
        
        # Add legend
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker='o', color='w', markerfacecolor='green', 
                      markersize=10, label='Active'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='red', 
                      markersize=10, label='Down'),
            Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', 
                      markersize=10, label='Unknown')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        # Save plot
        plt.tight_layout()
        plt.savefig(output_file, dpi=300, bbox_inches='tight', 
                   facecolor='black', edgecolor='none')
        plt.close()
    
    def _export_network_map_svg(self, scan_data: Dict[str, Any], 
                               output_file: Path) -> None:
        """Export network visualization as SVG."""
        if not HAS_PLOTLY:
            raise ImportError("Plotly is required for SVG export")
        
        devices = scan_data.get('devices', [])
        
        if not devices:
            raise ValueError("No devices to visualize")
        
        # Prepare data for Plotly
        df_data = []
        for device in devices:
            ip_parts = device.get('ip', '0.0.0.0').split('.')
            try:
                x = int(ip_parts[-1])
                y = int(ip_parts[-2])
            except (ValueError, IndexError):
                x = 0
                y = 0
            
            df_data.append({
                'ip': device.get('ip', ''),
                'x': x,
                'y': y,
                'status': device.get('status', 'unknown'),
                'ports': len(device.get('open_ports', [])),
                'hostname': device.get('hostname', ''),
                'device_type': device.get('device_type', 'unknown')
            })
        
        df = pd.DataFrame(df_data)
        
        # Create interactive plot
        fig = px.scatter(
            df, 
            x='x', 
            y='y',
            color='status',
            size='ports',
            hover_data=['ip', 'hostname', 'device_type'],
            title=f"Interactive Network Map: {scan_data.get('network', 'Unknown')}",
            color_discrete_map={
                'up': 'green',
                'down': 'red',
                'unknown': 'orange'
            }
        )
        
        fig.update_layout(
            template='plotly_dark',
            xaxis_title='Last IP Octet',
            yaxis_title='Third IP Octet'
        )
        
        # Save as SVG
        fig.write_image(str(output_file), format='svg')
    
    def export_port_scan_heatmap(self, heatmap_data: Dict[str, Any], 
                                output_path: str, format: str = "png") -> None:
        """
        Export port scan rate heatmap.
        
        Args:
            heatmap_data: Heatmap data from scanner
            output_path: Output file path
            format: Export format (png, svg, html)
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        scan_rates = heatmap_data.get('scan_rates', {})
        
        if not scan_rates:
            raise ValueError("No scan rate data to visualize")
        
        # Prepare data for heatmap
        ports = list(scan_rates.keys())
        ips = set()
        for port_data in scan_rates.values():
            ips.update(port_data.keys())
        ips = sorted(list(ips))
        
        # Create matrix
        matrix = []
        for ip in ips:
            row = []
            for port in ports:
                rate_data = scan_rates.get(port, {}).get(ip, {})
                scan_rate = rate_data.get('scan_rate', 0)
                row.append(scan_rate)
            matrix.append(row)
        
        if format.lower() == "png":
            # Create matplotlib heatmap
            fig, ax = plt.subplots(figsize=(12, 8))
            
            im = ax.imshow(matrix, cmap='viridis', aspect='auto')
            
            # Set ticks and labels
            ax.set_xticks(range(len(ports)))
            ax.set_xticklabels(ports)
            ax.set_yticks(range(len(ips)))
            ax.set_yticklabels([ip.split('.')[-1] for ip in ips])
            
            ax.set_xlabel('Port')
            ax.set_ylabel('IP (Last Octet)')
            ax.set_title(f"Port Scan Rate Heatmap: {heatmap_data.get('network', 'Unknown')}")
            
            # Add colorbar
            cbar = plt.colorbar(im)
            cbar.set_label('Scan Rate (scans/sec)')
            
            plt.tight_layout()
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            plt.close()
        
        elif format.lower() == "html" and HAS_PLOTLY:
            # Create interactive Plotly heatmap
            fig = go.Figure(data=go.Heatmap(
                z=matrix,
                x=ports,
                y=[ip.split('.')[-1] for ip in ips],
                colorscale='Viridis',
                hoverongaps=False
            ))
            
            fig.update_layout(
                title=f"Port Scan Rate Heatmap: {heatmap_data.get('network', 'Unknown')}",
                xaxis_title='Port',
                yaxis_title='IP (Last Octet)',
                template='plotly_dark'
            )
            
            # Save as HTML
            plot(fig, filename=str(output_file), auto_open=False)
        
        else:
            raise ValueError(f"Unsupported format for heatmap: {format}")
    
    def export_monitoring_report(self, monitor_data: Dict[str, Any], 
                                output_path: str) -> None:
        """
        Export monitoring report.
        
        Args:
            monitor_data: Monitoring data
            output_path: Output file path
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write("# Network Monitoring Report\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            f.write(f"**Network:** {monitor_data.get('network', 'Unknown')}\n")
            f.write(f"**Monitoring Duration:** {format_duration(time.time() - monitor_data.get('start_time', 0))}\n")
            f.write(f"**Total Scans:** {monitor_data.get('scan_count', 0)}\n")
            f.write(f"**Active Alerts:** {monitor_data.get('active_alerts', 0)}\n")
            f.write(f"**Recent Changes:** {monitor_data.get('recent_changes', 0)}\n\n")
            
            # Changes
            changes = monitor_data.get('changes', [])
            if changes:
                f.write("## Recent Changes\n\n")
                f.write("| Time | Type | Device | Details |\n")
                f.write("|------|------|--------|--------|\n")
                
                for change in changes[-20:]:  # Last 20 changes
                    timestamp = datetime.fromtimestamp(change.get('timestamp', 0))
                    f.write(f"| {timestamp.strftime('%H:%M:%S')} | "
                           f"{change.get('change_type', '')} | "
                           f"{change.get('device_ip', '')} | "
                           f"{str(change.get('details', ''))} |\n")
            
            # Alerts
            alerts = monitor_data.get('alerts', [])
            if alerts:
                f.write("\n## Active Alerts\n\n")
                for alert in alerts:
                    if not alert.get('acknowledged', False):
                        severity = alert.get('severity', 'unknown').upper()
                        f.write(f"### [{severity}] {alert.get('title', 'Unknown Alert')}\n")
                        f.write(f"**Device:** {alert.get('device_ip', 'Unknown')}\n")
                        f.write(f"**Message:** {alert.get('message', 'No message')}\n")
                        f.write(f"**Time:** {datetime.fromtimestamp(alert.get('timestamp', 0))}\n\n")
            
            f.write("\n---\n")
            f.write("Report generated by Universe Network Scanner\n")
            f.write("Developed by Desenyon - https://github.com/desenyon/universe\n")
    
    def create_default_templates(self) -> None:
        """Create default report templates."""
        templates_dir = self.config.get_templates_dir()
        
        # Network documentation template
        network_template = """# Network Documentation

## Network Information
- **Network Range:** {{ network }}
- **Last Scanned:** {{ timestamp }}
- **Total Devices:** {{ device_count }}
- **Active Devices:** {{ active_count }}
- **Scan Duration:** {{ scan_duration }}

## Device Inventory
<!-- Device table will be generated here -->

## Network Topology
<!-- Network diagram will be inserted here -->

## Security Recommendations
- Regular security scans
- Update device firmware
- Monitor for unauthorized devices
- Implement network segmentation

---
Generated by Universe Network Scanner
Developed by Desenyon - https://github.com/desenyon/universe
"""
        
        with open(templates_dir / "network-docs.md", 'w') as f:
            f.write(network_template)
        
        # Security template
        security_template = """# Security Assessment Report

## Executive Summary
Network security assessment for {{ network }} completed on {{ timestamp }}.

## Key Findings
- {{ device_count }} devices scanned
- Security compliance score: {{ compliance_score }}/100

## Detailed Analysis
<!-- Security findings will be inserted here -->

## Recommendations
1. Address critical security threats immediately
2. Implement security best practices
3. Regular monitoring and assessment

---
Generated by Universe Network Scanner
Developed by Desenyon - https://github.com/desenyon/universe
"""
        
        with open(templates_dir / "security-assessment.md", 'w') as f:
            f.write(security_template)
