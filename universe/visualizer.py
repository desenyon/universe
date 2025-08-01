"""
Interactive TUI visualization module for Universe network scanner.
Developed by Desenyon - https://github.com/desenyon/universe
"""

import asyncio
import math
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Static, Label, Button, 
    DataTable, ProgressBar, Tree, Log
)
from textual.reactive import reactive
from textual.timer import Timer
from textual.coordinate import Coordinate
from textual.screen import Screen
from textual import events
from textual.theme import Theme

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align

from .scanner import NetworkScanner
from .config import Config
from .utils import format_duration, get_default_network


# Define custom themes
COSMIC_THEME = Theme(
    name="cosmic",
    primary="#9A4FE8",
    secondary="#4F8FE8", 
    accent="#E84F8F",
    foreground="#E0E0E0",
    background="#1A0B2E",
    surface="#2D1B3D",
    panel="#3D2B4D",
    boost="#FFE84F",
    warning="#FFA500",
    error="#FF6B6B",
    success="#4ECDC4",
)

DARK_THEME = Theme(
    name="dark",
    primary="#0F4C75",
    secondary="#3282B8",
    accent="#BBE1FA",
    foreground="#FFFFFF",
    background="#000000",
    surface="#1E1E1E",
    panel="#2D2D2D",
    boost="#FFD700",
    warning="#FFA500",
    error="#FF6B6B",
    success="#00FF00",
)

LIGHT_THEME = Theme(
    name="light",
    primary="#2E86AB",
    secondary="#A23B72",
    accent="#F18F01",
    foreground="#000000",
    background="#FFFFFF",
    surface="#F5F5F5",
    panel="#E0E0E0",
    boost="#FF6B35",
    warning="#FF8C00",
    error="#DC143C",
    success="#228B22",
)


@dataclass
class DeviceNode:
    """Represents a device in the visualization."""
    ip: str
    position: Tuple[float, float] = (0.0, 0.0)
    size: float = 1.0
    color: str = "white"
    status: str = "unknown"
    services: Optional[List[str]] = None
    last_seen: float = 0.0
    
    def __post_init__(self):
        if self.services is None:
            self.services = []


class NetworkVisualization(Static):
    """Custom widget for network visualization."""
    
    def __init__(self, mode: str = "orbital", **kwargs):
        super().__init__(**kwargs)
        self.mode = mode
        self.devices: List[DeviceNode] = []
        self.center_x = 40
        self.center_y = 15
        self.scale = 1.0
        self.animation_frame = 0
    
    def add_device(self, device_data: Dict[str, Any]) -> None:
        """Add a device to the visualization."""
        device = DeviceNode(
            ip=device_data.get('ip', 'Unknown'),
            status=device_data.get('status', 'unknown'),
            services=list(device_data.get('services', {}).values()),
            last_seen=device_data.get('last_seen', time.time())
        )
        
        # Position device based on mode
        if self.mode == "orbital":
            self._position_orbital(device)
        elif self.mode == "grid":
            self._position_grid(device)
        elif self.mode == "stargate":
            self._position_stargate(device)
        
        # Set color based on status
        if device.status == "up":
            device.color = "green"
        elif device.status == "down":
            device.color = "red"
        else:
            device.color = "yellow"
        
        self.devices.append(device)
        self.refresh()
    
    def _position_orbital(self, device: DeviceNode) -> None:
        """Position device in orbital mode."""
        num_devices = len(self.devices)
        angle = (2 * math.pi * num_devices) / max(8, num_devices + 1)
        
        # Determine orbit radius based on device type
        radius = 15
        services = device.services or []
        if any(service in ['HTTP', 'HTTPS'] for service in services):
            radius = 20  # Web servers further out
        elif any(service in ['SSH', 'RDP'] for service in services):
            radius = 10  # Admin services closer
        
        # Add some orbital motion
        orbital_offset = math.sin(self.animation_frame * 0.1 + angle) * 2
        
        device.position = (
            self.center_x + (radius + orbital_offset) * math.cos(angle),
            self.center_y + (radius + orbital_offset) * math.sin(angle) * 0.5
        )
    
    def _position_grid(self, device: DeviceNode) -> None:
        """Position device in grid mode."""
        # Parse IP to determine grid position
        try:
            ip_parts = device.ip.split('.')
            x = int(ip_parts[-1]) % 20
            y = int(ip_parts[-2]) % 10
            
            device.position = (x * 4, y * 3)
        except (ValueError, IndexError):
            # Fallback to sequential positioning
            num_devices = len(self.devices)
            device.position = (
                (num_devices % 20) * 4,
                (num_devices // 20) * 3
            )
    
    def _position_stargate(self, device: DeviceNode) -> None:
        """Position device in stargate mode (focused view)."""
        num_devices = len(self.devices)
        
        if num_devices == 0:
            # Central position for main device
            device.position = (self.center_x, self.center_y)
            device.size = 2.0
        else:
            # Arrange around the central device
            angle = (2 * math.pi * (num_devices - 1)) / max(6, num_devices)
            radius = 8
            
            device.position = (
                self.center_x + radius * math.cos(angle),
                self.center_y + radius * math.sin(angle) * 0.5
            )
    
    def render(self) -> Panel:
        """Render the network visualization."""
        # Create the visualization canvas
        lines = [[' ' for _ in range(78)] for _ in range(28)]
        
        # Draw connections (orbital mode)
        if self.mode == "orbital" and len(self.devices) > 1:
            self._draw_connections(lines)
        
        # Draw devices
        for device in self.devices:
            self._draw_device(lines, device)
        
        # Draw legend and info
        self._draw_legend(lines)
        
        # Convert to string
        rendered = '\n'.join(''.join(line) for line in lines)
        
        # Add border and title based on mode
        title_map = {
            "orbital": "🌌 Orbital Network Map",
            "grid": "📍 Grid Network Map", 
            "stargate": "🔍 Stargate Focus View"
        }
        
        return Panel(
            rendered,
            title=title_map.get(self.mode, "Network Map"),
            border_style="blue"
        )
    
    def _draw_device(self, lines: List[List[str]], device: DeviceNode) -> None:
        """Draw a single device on the canvas."""
        x, y = device.position
        x, y = int(x), int(y)
        
        # Ensure coordinates are within bounds
        if 0 <= x < 80 and 0 <= y < 30:
            # Choose symbol based on device status and type
            if device.status == "up":
                symbol = "●" if device.size > 1 else "•"
            elif device.status == "down":
                symbol = "○"
            else:
                symbol = "?"
            
            lines[y][x] = symbol
            
            # Add IP label nearby if space permits
            ip_short = device.ip.split('.')[-1]
            label_x = x + 2
            if label_x + len(ip_short) < 80:
                for i, char in enumerate(ip_short):
                    if label_x + i < 80:
                        lines[y][label_x + i] = char
    
    def _draw_connections(self, lines: List[List[str]]) -> None:
        """Draw connections between devices."""
        # Draw lines from center to each device (orbital mode)
        for device in self.devices:
            x1, y1 = self.center_x, self.center_y
            x2, y2 = int(device.position[0]), int(device.position[1])
            
            # Simple line drawing algorithm
            dx = abs(x2 - x1)
            dy = abs(y2 - y1)
            
            if dx > dy:
                # More horizontal
                steps = dx
                x_inc = 1 if x2 > x1 else -1
                y_inc = (y2 - y1) / steps if steps > 0 else 0
                
                for i in range(steps):
                    x = x1 + i * x_inc
                    y = int(y1 + i * y_inc)
                    if 0 <= x < 80 and 0 <= y < 30 and lines[y][x] == ' ':
                        lines[y][x] = '-' if abs(y_inc) < 0.5 else '/'
    
    def _draw_legend(self, lines: List[List[str]]) -> None:
        """Draw legend and status information."""
        # Legend in bottom right corner  
        legend_y = 25  # Start earlier to fit within 28 lines (0-27)
        legend_items = [
            "● Active",
            "○ Down", 
            "? Unknown"
        ]
        
        for i, item in enumerate(legend_items):
            y = legend_y + i
            if y < len(lines):  # Use actual length instead of hardcoded 30
                for j, char in enumerate(item):
                    x = 65 + j
                    if x < len(lines[0]):  # Use actual width instead of hardcoded 80
                        lines[y][x] = char
    
    def update_animation(self) -> None:
        """Update animation frame."""
        self.animation_frame += 1
        
        # Re-position devices with animation
        for device in self.devices:
            if self.mode == "orbital":
                self._position_orbital(device)
        
        self.refresh()
    
    def clear_devices(self) -> None:
        """Clear all devices from visualization."""
        self.devices.clear()
        self.refresh()


class DeviceDetailsScreen(Screen):
    """Screen showing detailed information about a selected device."""
    
    def __init__(self, device_data: Dict[str, Any], **kwargs):
        super().__init__(**kwargs)
        self.device_data = device_data
    
    def compose(self) -> ComposeResult:
        """Compose the device details screen."""
        with Vertical():
            yield Header()
            
            with Container(id="details-container"):
                yield Static(self._render_device_details())
            
            with Horizontal():
                yield Button("Back", id="back-button")
                yield Button("Ping Test", id="ping-button")
                yield Button("Port Scan", id="port-scan-button")
            
            yield Footer()
    
    def _render_device_details(self) -> str:
        """Render detailed device information."""
        console = Console(width=80, force_terminal=True)
        
        # Create details table
        table = Table(title=f"Device Details: {self.device_data.get('ip', 'Unknown')}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")
        
        # Add device properties
        properties = [
            ("IP Address", self.device_data.get('ip', 'Unknown')),
            ("MAC Address", self.device_data.get('mac', 'Unknown')),
            ("Hostname", self.device_data.get('hostname', 'Unknown')),
            ("Vendor", self.device_data.get('vendor', 'Unknown')),
            ("Operating System", self.device_data.get('os', 'Unknown')),
            ("Status", self.device_data.get('status', 'Unknown')),
            ("Device Type", self.device_data.get('device_type', 'Unknown')),
            ("Last Seen", format_duration(time.time() - self.device_data.get('last_seen', 0))),
            ("Response Time", f"{self.device_data.get('response_time', 0):.2f}ms"),
        ]
        
        for prop, value in properties:
            table.add_row(prop, str(value))
        
        # Add open ports section
        open_ports = self.device_data.get('open_ports', [])
        if open_ports:
            table.add_section()
            table.add_row("Open Ports", ", ".join(map(str, open_ports)))
            
            # Services
            services = self.device_data.get('services', {})
            for port, service in services.items():
                table.add_row(f"  Port {port}", service)
        
        return str(table)
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "back-button":
            self.app.pop_screen()
        elif event.button.id == "ping-button":
            # Implement ping test
            pass
        elif event.button.id == "port-scan-button":
            # Implement detailed port scan
            pass


class NetworkScanProgress(Screen):
    """Screen showing scan progress."""
    
    def __init__(self, network: str, **kwargs):
        super().__init__(**kwargs)
        self.network = network
        self.progress = 0
        self.status_text = "Initializing scan..."
    
    def compose(self) -> ComposeResult:
        """Compose the progress screen."""
        with Vertical():
            yield Header()
            
            with Container(id="progress-container"):
                yield Label(f"Scanning Network: {self.network}")
                yield ProgressBar(id="scan-progress")
                yield Label(self.status_text, id="status-label")
                yield Log(id="scan-log")
            
            yield Footer()
    
    def update_progress(self, progress: int, status: str) -> None:
        """Update scan progress."""
        self.progress = progress
        self.status_text = status
        
        progress_bar = self.query_one("#scan-progress", ProgressBar)
        progress_bar.progress = progress
        
        status_label = self.query_one("#status-label", Label)
        status_label.update(status)
        
        scan_log = self.query_one("#scan-log", Log)
        scan_log.write_line(f"[{time.strftime('%H:%M:%S')}] {status}")


class UniverseMap(App):
    """Main TUI application for network visualization."""
    
    CSS = """
    NetworkVisualization {
        height: 30;
        border: solid blue;
    }
    
    #info-panel {
        height: 10;
        border: solid green;
    }
    
    #controls {
        height: 3;
        border: solid yellow;
    }
    """
    
    def __init__(self, network: str, mode: str = "orbital", 
                 refresh_interval: int = 10, theme: str = "cosmic",
                 config: Optional[Config] = None, **kwargs):
        super().__init__(**kwargs)
        
        # Register custom themes
        self.register_theme(COSMIC_THEME)
        self.register_theme(DARK_THEME)
        self.register_theme(LIGHT_THEME)
        
        self.network = network
        self.mode = mode
        self.refresh_interval = refresh_interval
        self.config = config or Config()
        
        # Set the theme after registration
        if theme in ["cosmic", "dark", "light"]:
            self.theme = theme
        else:
            self.theme = "cosmic"  # fallback to cosmic
        
        self.scanner = NetworkScanner(config=self.config)
        self.visualization: Optional[NetworkVisualization] = None
        self.scan_timer: Optional[Timer] = None
        self.animation_timer: Optional[Timer] = None
        
        # Current scan data
        self.current_scan_data: Dict[str, Any] = {}
        self.selected_device_index = 0
    
    def compose(self) -> ComposeResult:
        """Compose the main application."""
        with Vertical():
            yield Header()
            
            with Horizontal():
                # Main visualization area
                with Vertical():
                    self.visualization = NetworkVisualization(mode=self.mode, id="network-viz")
                    yield self.visualization
                    
                    # Controls
                    with Horizontal(id="controls"):
                        yield Button("Scan", id="scan-button")
                        yield Button("Mode", id="mode-button")
                        yield Button("Export", id="export-button")
                        yield Button("Quit", id="quit-button")
                
                # Info panel
                with Vertical(id="info-panel"):
                    yield Label("Network Information", id="info-title")
                    yield Static("No scan data", id="scan-info")
                    yield Static("Press 'Scan' to start", id="device-info")
            
            yield Footer()
    
    def on_mount(self) -> None:
        """Called when the app is mounted."""
        # Start initial scan
        self.start_scan()
        
        # Set up timers
        self.animation_timer = self.set_interval(0.1, self.update_animation)
        self.scan_timer = self.set_interval(self.refresh_interval, self.start_scan)
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "scan-button":
            self.start_scan()
        elif event.button.id == "mode-button":
            self.cycle_mode()
        elif event.button.id == "export-button":
            await self.export_data()
        elif event.button.id == "quit-button":
            self.exit()
    
    async def on_key(self, event: events.Key) -> None:
        """Handle key presses."""
        if event.key == "q":
            self.exit()
        elif event.key == "r":
            self.start_scan()
        elif event.key == "m":
            self.cycle_mode()
        elif event.key == "up":
            self.select_previous_device()
        elif event.key == "down":
            self.select_next_device()
        elif event.key == "enter":
            await self.show_device_details()
    
    def start_scan(self) -> None:
        """Start a network scan."""
        self.run_worker(self.perform_scan())
    
    async def perform_scan(self) -> None:
        """Perform the actual network scan."""
        try:
            # Update status
            scan_info = self.query_one("#scan-info", Static)
            scan_info.update(f"Scanning {self.network}...")
            
            # Perform scan
            scan_result = await self.scanner.scan_network(self.network, ports="common")
            self.current_scan_data = scan_result
            
            # Update visualization
            if self.visualization:
                self.visualization.clear_devices()
                for device in scan_result.get('devices', []):
                    self.visualization.add_device(device)
            
            # Update info panel
            self.update_info_panel()
            
        except Exception as e:
            scan_info = self.query_one("#scan-info", Static)
            scan_info.update(f"Scan failed: {e}")
    
    def update_info_panel(self) -> None:
        """Update the information panel."""
        scan_info = self.query_one("#scan-info", Static)
        device_info = self.query_one("#device-info", Static)
        
        devices = self.current_scan_data.get('devices', [])
        active_count = len([d for d in devices if d.get('status') == 'up'])
        
        # Scan summary
        scan_text = f"Network: {self.network}\n"
        scan_text += f"Devices: {len(devices)} ({active_count} active)\n"
        scan_text += f"Duration: {self.current_scan_data.get('scan_duration', 0):.1f}s"
        scan_info.update(scan_text)
        
        # Selected device info
        if devices and 0 <= self.selected_device_index < len(devices):
            device = devices[self.selected_device_index]
            device_text = f"Selected: {device.get('ip', 'Unknown')}\n"
            device_text += f"Status: {device.get('status', 'Unknown')}\n"
            device_text += f"Ports: {len(device.get('open_ports', []))}"
            device_info.update(device_text)
        else:
            device_info.update("No device selected")
    
    def cycle_mode(self) -> None:
        """Cycle through visualization modes."""
        modes = ["orbital", "grid", "stargate"]
        current_index = modes.index(self.mode)
        self.mode = modes[(current_index + 1) % len(modes)]
        
        if self.visualization:
            self.visualization.mode = self.mode
            # Re-position all devices
            for device in self.visualization.devices:
                if self.mode == "orbital":
                    self.visualization._position_orbital(device)
                elif self.mode == "grid":
                    self.visualization._position_grid(device)
                elif self.mode == "stargate":
                    self.visualization._position_stargate(device)
            
            self.visualization.refresh()
    
    def select_next_device(self) -> None:
        """Select next device."""
        devices = self.current_scan_data.get('devices', [])
        if devices:
            self.selected_device_index = (self.selected_device_index + 1) % len(devices)
            self.update_info_panel()
    
    def select_previous_device(self) -> None:
        """Select previous device."""
        devices = self.current_scan_data.get('devices', [])
        if devices:
            self.selected_device_index = (self.selected_device_index - 1) % len(devices)
            self.update_info_panel()
    
    async def show_device_details(self) -> None:
        """Show detailed information for selected device."""
        devices = self.current_scan_data.get('devices', [])
        if devices and 0 <= self.selected_device_index < len(devices):
            device = devices[self.selected_device_index]
            details_screen = DeviceDetailsScreen(device)
            self.push_screen(details_screen)
    
    async def export_data(self) -> None:
        """Export current scan data."""
        if self.current_scan_data:
            # This would implement export functionality
            # For now, just show a message
            scan_info = self.query_one("#scan-info", Static)
            scan_info.update("Export functionality not yet implemented")
    
    def update_animation(self) -> None:
        """Update visualization animation."""
        if self.visualization:
            self.visualization.update_animation()
