#!/usr/bin/env python3
"""
Universe Network Scanner CLI - Beautiful command-line interface with
interactive features for the Universe network scanner.

Developed by Desenyon - https://github.com/desenyon/universe
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
from rich.align import Align
from rich import print as rprint
from rich.layout import Layout
from rich.live import Live

from .scanner import NetworkScanner
from .visualizer import UniverseMap
from .monitor import NetworkMonitor
from .security import SecurityAuditor
from .export import DataExporter
from .config import Config
from .utils import get_default_network, validate_network, format_duration

# Create beautiful console
console = Console()

# Beautiful CLI banner
BANNER = """
[bold cyan]
    ██╗   ██╗███╗   ██╗██╗██╗   ██╗███████╗██████╗ ███████╗███████╗
    ██║   ██║████╗  ██║██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝
    ██║   ██║██╔██╗ ██║██║██║   ██║█████╗  ██████╔╝███████╗█████╗  
    ██║   ██║██║╚██╗██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  
    ╚██████╔╝██║ ╚████║██║ ╚████╔╝ ███████╗██║  ██║███████║███████╗
     ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
[/bold cyan]
[italic bright_blue]                Real-time Network Analysis & Visualization[/italic bright_blue]
"""


@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version information')
@click.option('--config', type=click.Path(), help='Configuration file path')
@click.pass_context
def main(ctx: click.Context, version: bool, config: Optional[str]) -> None:
    """
    🌌 Universe - Transform your network into a beautiful galaxy of insights
    
    Discover, visualize, and secure your network with style and precision.
    """
    if version:
        from . import __version__
        console.print(Panel(
            f"[bold cyan]Universe Network Scanner[/bold cyan]\n"
            f"[white]Version:[/white] [bright_green]{__version__}[/bright_green]\n"
            f"[white]Author:[/white] [yellow]Desenyon[/yellow]",
            title="[bold blue]Version Info[/bold blue]",
            border_style="blue"
        ))
        return
    
    # Initialize context
    ctx.ensure_object(dict)
    ctx.obj['config'] = Config(config_file=config)
    
    if ctx.invoked_subcommand is None:
        show_beautiful_help()


def show_beautiful_help():
    """Display a beautiful help screen."""
    console.print(BANNER)
    
    # Commands overview
    commands_table = Table(
        title="[bold bright_blue]Available Commands[/bold bright_blue]",
        border_style="blue",
        show_header=True,
        header_style="bold cyan"
    )
    commands_table.add_column("Command", style="bright_green", width=12)
    commands_table.add_column("Description", style="white")
    commands_table.add_column("Example", style="dim")
    
    commands = [
        ("scan", "🔍 Discover network devices", "universe scan --quick"),
        ("map", "🗺️  Interactive visualization", "universe map --mode orbital"),
        ("monitor", "📡 Real-time monitoring", "universe monitor --alert-new"),
        ("audit", "🔒 Security analysis", "universe audit --deep"),
        ("export", "📁 Export data & reports", "universe export --format png"),
    ]
    
    for cmd, desc, example in commands:
        commands_table.add_row(cmd, desc, example)
    
    console.print(commands_table)
    
    # Quick start panel
    quick_start = Panel(
        "[bold white]Quick Start:[/bold white]\n"
        "[cyan]1.[/cyan] [white]universe scan[/white] - Discover your network\n"
        "[cyan]2.[/cyan] [white]universe map[/white] - Visualize interactively\n"
        "[cyan]3.[/cyan] [white]universe --help[/white] - Learn more\n\n"
        "[dim]💡 Tip: Most commands work better with [bold]sudo[/bold] privileges[/dim]",
        title="[bold green]Get Started[/bold green]",
        border_style="green"
    )
    
    console.print(quick_start)


@main.command()
@click.option('--network', '-n', help='Network range to scan (e.g., 192.168.1.0/24)')
@click.option('--ports', '-p', default='common', help='Port range to scan')
@click.option('--timeout', '-t', default=30, help='Scan timeout in seconds')
@click.option('--output', '-o', help='Save results to file')
@click.option('--format', 'output_format', type=click.Choice(['json', 'csv', 'md']), 
              default='json', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quick', '-q', is_flag=True, help='Quick scan (common ports only)')
@click.option('--interactive', '-i', is_flag=True, help='Interactive scan configuration')
@click.option('--no-escalate', is_flag=True, help='Disable automatic privilege escalation')
@click.pass_context
def scan(ctx: click.Context, network: str, ports: str, timeout: int, 
         output: str, output_format: str, verbose: bool, quick: bool, interactive: bool, no_escalate: bool) -> None:
    """🔍 Discover and analyze network devices with style."""
    
    config = ctx.obj['config']
    
    # Interactive mode
    if interactive:
        network, ports, timeout = interactive_scan_config(network, ports, timeout)
    
    # Determine network range
    if not network:
        network = get_default_network()
        console.print(f"[yellow]🌐 Auto-detected network:[/yellow] [bright_cyan]{network}[/bright_cyan]")
    
    # Validate network
    if not validate_network(network):
        console.print(Panel(
            f"[red]Invalid network range: {network}[/red]\n"
            f"[yellow]Example:[/yellow] 192.168.1.0/24",
            title="[red]Error[/red]",
            border_style="red"
        ))
        sys.exit(1)
    
    # Initialize scanner
    scanner = NetworkScanner(
        timeout=timeout,
        verbose=verbose,
        config=config
    )
    
    try:
        # Beautiful scan progress
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold blue]Scanning network..."),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            scan_task = progress.add_task("Scanning", total=100)
            
            # Run the scan with progress updates
            async def scan_with_progress():
                # Simulate progress updates during scan
                progress.update(scan_task, advance=20)
                
                results = await scanner.scan_network(
                    network=network,
                    ports=ports if not quick else 'quick',
                    include_bluetooth=True,
                    auto_escalate=not no_escalate
                )
                
                progress.update(scan_task, advance=80)
                return results
            
            results = asyncio.run(scan_with_progress())
        
        # Display beautiful results
        display_beautiful_scan_results(results)
        
        # Show privilege guidance if needed
        if not results.get('elevated_privileges', False) and len(results.get('devices', [])) == 0:
            console.print(Panel(
                "[yellow]💡 Pro Tip:[/yellow] For better network discovery, try:\n"
                f"[cyan]sudo universe scan[/cyan]\n\n"
                "[dim]Elevated privileges enable:[/dim]\n"
                "[green]•[/green] ARP scanning for faster host discovery\n"
                "[green]•[/green] Advanced OS fingerprinting\n"
                "[green]•[/green] Comprehensive service detection\n"
                "[green]•[/green] Bluetooth device scanning",
                title="[bold blue]Enhanced Scanning[/bold blue]",
                border_style="blue"
            ))
        
        # Save to file if requested
        if output:
            exporter = DataExporter(config)
            exporter.export_scan_results(results, output, output_format)
            console.print(f"[green]💾 Results saved to:[/green] [cyan]{output}[/cyan]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]⚡ Scan cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(Panel(
            f"[red]Error during scan: {e}[/red]",
            title="[red]Scan Error[/red]",
            border_style="red"
        ))
        sys.exit(1)


def interactive_scan_config(network: str, ports: str, timeout: int) -> tuple:
    """Interactive scan configuration."""
    console.print(Panel(
        "[bold cyan]Interactive Scan Configuration[/bold cyan]",
        border_style="cyan"
    ))
    
    # Network configuration
    if not network:
        network = get_default_network()
        
    network = Prompt.ask(
        "[yellow]Network range to scan[/yellow]",
        default=network,
        show_default=True
    )
    
    # Port configuration
    port_options = {
        "1": ("quick", "Quick scan (SSH, HTTP, HTTPS)"),
        "2": ("common", "Common ports (1-1000)"),
        "3": ("extended", "Extended scan (1-10000)"),
        "4": ("custom", "Custom port range")
    }
    
    console.print("\n[bold]Port Scan Options:[/bold]")
    for key, (value, desc) in port_options.items():
        console.print(f"[cyan]{key}.[/cyan] {desc}")
    
    port_choice = Prompt.ask(
        "\nSelect port scan option",
        choices=list(port_options.keys()),
        default="2"
    )
    
    if port_choice == "4":
        ports = Prompt.ask("Enter custom port range (e.g., 22,80,443 or 1-1000)")
    else:
        ports = port_options[port_choice][0]
    
    # Timeout configuration
    timeout = int(Prompt.ask(
        "[yellow]Scan timeout (seconds)[/yellow]",
        default=str(timeout),
        show_default=True
    ))
    
    return network, ports, timeout


@main.command()
@click.option('--mode', type=click.Choice(['orbital', 'grid', 'stargate']), 
              default='orbital', help='Visualization mode')
@click.option('--refresh', default=10, help='Refresh interval in seconds')
@click.option('--theme', type=click.Choice(['dark', 'light', 'cosmic']), 
              default='cosmic', help='Color theme')
@click.option('--network', help='Network range to visualize')
@click.pass_context
def map(ctx: click.Context, mode: str, refresh: int, theme: str, network: str) -> None:
    """🗺️ Launch beautiful interactive network visualization."""
    
    config = ctx.obj['config']
    
    if not network:
        network = get_default_network()
    
    console.print(Panel(
        f"[bold cyan]Launching Universe Map[/bold cyan]\n"
        f"[white]Network:[/white] [yellow]{network}[/yellow]\n"
        f"[white]Mode:[/white] [green]{mode}[/green]\n"
        f"[white]Theme:[/white] [magenta]{theme}[/magenta]\n\n"
        f"[dim]Press [bold]Ctrl+C[/bold] to exit[/dim]",
        title="[bold blue]Network Visualization[/bold blue]",
        border_style="blue"
    ))
    
    try:
        # Launch the TUI application
        universe_map = UniverseMap(
            network=network,
            mode=mode,
            refresh_interval=refresh,
            theme=theme,
            config=config
        )
        
        universe_map.run()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]🗺️  Map closed by user[/yellow]")
    except Exception as e:
        console.print(Panel(
            f"[red]Error launching map: {e}[/red]",
            title="[red]Map Error[/red]",
            border_style="red"
        ))
        sys.exit(1)


@main.command()
@click.option('--interval', default=60, help='Scan interval in seconds')
@click.option('--alert-new', is_flag=True, help='Alert on new devices')
@click.option('--alert-suspicious', is_flag=True, help='Alert on security threats')
@click.option('--webhook', help='Webhook URL for alerts')
@click.option('--log-file', help='Log file path')
@click.option('--network', help='Network range to monitor')
@click.pass_context
def monitor(ctx: click.Context, interval: int, alert_new: bool, 
           alert_suspicious: bool, webhook: str, log_file: str, network: str) -> None:
    """📡 Real-time network monitoring with beautiful alerts."""
    
    config = ctx.obj['config']
    
    if not network:
        network = get_default_network()
    
    console.print(Panel(
        f"[bold cyan]Starting Network Monitor[/bold cyan]\n"
        f"[white]Network:[/white] [yellow]{network}[/yellow]\n"
        f"[white]Interval:[/white] [green]{interval}s[/green]\n"
        f"[white]New device alerts:[/white] [{'green' if alert_new else 'red'}]{'✓' if alert_new else '✗'}[/]\n"
        f"[white]Security alerts:[/white] [{'green' if alert_suspicious else 'red'}]{'✓' if alert_suspicious else '✗'}[/]\n\n"
        f"[dim]Press [bold]Ctrl+C[/bold] to stop monitoring[/dim]",
        title="[bold blue]Network Monitor[/bold blue]",
        border_style="blue"
    ))
    
    # Initialize monitor
    monitor = NetworkMonitor(
        network=network,
        interval=interval,
        alert_new_devices=alert_new,
        alert_suspicious=alert_suspicious,
        webhook_url=webhook,
        log_file=log_file,
        config=config
    )
    
    try:
        asyncio.run(monitor.start_monitoring())
        
    except KeyboardInterrupt:
        console.print("\n[yellow]📡 Monitoring stopped by user[/yellow]")
    except Exception as e:
        console.print(Panel(
            f"[red]Error during monitoring: {e}[/red]",
            title="[red]Monitor Error[/red]",
            border_style="red"
        ))
        sys.exit(1)


@main.command()
@click.option('--deep', is_flag=True, help='Perform deep security scan')
@click.option('--export-report', help='Export audit report to file')
@click.option('--check-vulns', is_flag=True, help='Check for known vulnerabilities')
@click.option('--compliance', type=click.Choice(['basic', 'strict']), 
              default='basic', help='Security compliance level')
@click.option('--network', help='Network range to audit')
@click.pass_context
def audit(ctx: click.Context, deep: bool, export_report: str, 
          check_vulns: bool, compliance: str, network: str) -> None:
    """🔒 Comprehensive security analysis with beautiful reporting."""
    
    config = ctx.obj['config']
    
    if not network:
        network = get_default_network()
    
    console.print(Panel(
        f"[bold red]Security Audit Starting[/bold red]\n"
        f"[white]Network:[/white] [yellow]{network}[/yellow]\n"
        f"[white]Compliance:[/white] [cyan]{compliance}[/cyan]\n"
        f"[white]Deep scan:[/white] [{'green' if deep else 'red'}]{'✓' if deep else '✗'}[/]\n"
        f"[white]Vulnerability check:[/white] [{'green' if check_vulns else 'red'}]{'✓' if check_vulns else '✗'}[/]",
        title="[bold red]Security Audit[/bold red]",
        border_style="red"
    ))
    
    # Initialize security auditor
    auditor = SecurityAuditor(
        compliance_level=compliance,
        check_vulnerabilities=check_vulns,
        config=config
    )
    
    try:
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold red]Analyzing security..."),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            audit_task = progress.add_task("Auditing", total=100)
            
            # Run security scan
            async def audit_with_progress():
                progress.update(audit_task, advance=30)
                
                audit_results = await auditor.audit_network(
                    network=network,
                    deep_scan=deep
                )
                
                progress.update(audit_task, advance=70)
                return audit_results
            
            audit_results = asyncio.run(audit_with_progress())
        
        # Display beautiful results
        display_beautiful_audit_results(audit_results)
        
        # Export report if requested
        if export_report:
            auditor.export_report(audit_results, export_report)
            console.print(f"[green]📄 Audit report saved to:[/green] [cyan]{export_report}[/cyan]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]🔒 Audit cancelled by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(Panel(
            f"[red]Error during audit: {e}[/red]",
            title="[red]Audit Error[/red]",
            border_style="red"
        ))
        sys.exit(1)


@main.command()
@click.option('--format', 'export_format', 
              type=click.Choice(['json', 'png', 'svg', 'md', 'csv']),
              default='json', help='Export format')
@click.option('--output', '-o', required=True, help='Output file path')
@click.option('--template', help='Report template')
@click.option('--include-history', is_flag=True, help='Include scan history')
@click.option('--network', help='Network range to export')
@click.pass_context
def export(ctx: click.Context, export_format: str, output: str, 
           template: str, include_history: bool, network: str) -> None:
    """📁 Export beautiful network data and visualizations."""
    
    config = ctx.obj['config']
    
    if not network:
        network = get_default_network()
    
    console.print(Panel(
        f"[bold green]Exporting Network Data[/bold green]\n"
        f"[white]Network:[/white] [yellow]{network}[/yellow]\n"
        f"[white]Format:[/white] [cyan]{export_format}[/cyan]\n"
        f"[white]Output:[/white] [magenta]{output}[/magenta]",
        title="[bold green]Data Export[/bold green]",
        border_style="green"
    ))
    
    # Initialize exporter
    exporter = DataExporter(config)
    
    try:
        with Progress(
            SpinnerColumn("dots"),
            TextColumn(f"[bold green]Exporting as {export_format}..."),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            export_task = progress.add_task("Exporting", total=100)
            
            # Perform quick scan if no recent data
            progress.update(export_task, advance=20)
            scanner = NetworkScanner(config=config)
            scan_data = asyncio.run(scanner.scan_network(network))
            
            progress.update(export_task, advance=40)
            
            # Export data
            exporter.export_data(
                data=scan_data,
                output_path=output,
                format=export_format,
                template=template,
                include_history=include_history
            )
            
            progress.update(export_task, advance=40)
        
        console.print(f"[green]✅ Data exported successfully to:[/green] [cyan]{output}[/cyan]")
        
    except Exception as e:
        console.print(Panel(
            f"[red]Error during export: {e}[/red]",
            title="[red]Export Error[/red]",
            border_style="red"
        ))
        sys.exit(1)


def display_beautiful_scan_results(results: dict) -> None:
    """Display scan results with beautiful formatting."""
    
    devices = results.get('devices', [])
    
    if not devices:
        console.print(Panel(
            "[yellow]No devices found on the network[/yellow]\n"
            "[dim]Try running with sudo for better discovery[/dim]",
            title="[yellow]Scan Results[/yellow]",
            border_style="yellow"
        ))
        return
    
    # Summary panel
    active_devices = [d for d in devices if d.get('status') == 'up']
    scan_method = results.get('scan_method', 'unknown')
    elevated = results.get('elevated_privileges', False)
    
    summary = Panel(
        f"[bold white]Network:[/bold white] [cyan]{results.get('network', 'Unknown')}[/cyan]\n"
        f"[bold white]Duration:[/bold white] [yellow]{results.get('scan_duration', 0):.2f}s[/yellow]\n"
        f"[bold white]Method:[/bold white] [{'green' if elevated else 'yellow'}]{scan_method}[/]\n"
        f"[bold white]Privileges:[/bold white] [{'green' if elevated else 'yellow'}]{'elevated' if elevated else 'basic'}[/]\n"
        f"[bold white]Total Devices:[/bold white] [green]{len(devices)}[/green]\n"
        f"[bold white]Active Devices:[/bold white] [bright_green]{len(active_devices)}[/bright_green]",
        title="[bold blue]🌌 Scan Summary[/bold blue]",
        border_style="blue"
    )
    console.print(summary)
    
    # Create beautiful devices table
    table = Table(
        title="[bold bright_blue]Discovered Devices[/bold bright_blue]",
        border_style="blue",
        show_header=True,
        header_style="bold cyan"
    )
    table.add_column("IP Address", style="bright_green", width=15)
    table.add_column("Status", style="white", width=8)
    table.add_column("Hostname", style="yellow", width=20)
    table.add_column("OS", style="magenta", width=15)
    table.add_column("Open Ports", style="red", width=20)
    table.add_column("Type", style="cyan", width=12)
    
    for device in devices:
        # Status icon
        status = device.get('status', 'unknown')
        status_icon = {
            'up': '[green]🟢 Online[/green]',
            'down': '[red]🔴 Offline[/red]',
            'unknown': '[yellow]🟡 Unknown[/yellow]'
        }.get(status, '[dim]❓ Unknown[/dim]')
        
        # Truncate ports for display
        ports = ", ".join(map(str, device.get('open_ports', [])))
        if len(ports) > 18:
            ports = ports[:15] + "..."
        
        table.add_row(
            device.get('ip', 'Unknown'),
            status_icon,
            device.get('hostname', 'Unknown')[:18],
            device.get('os', 'Unknown')[:13],
            ports or '[dim]None[/dim]',
            device.get('device_type', 'Unknown')[:10]
        )
    
    console.print(table)
    
    # Service summary
    if active_devices:
        service_counts = {}
        for device in active_devices:
            for service in device.get('services', {}).values():
                service_counts[service] = service_counts.get(service, 0) + 1
        
        if service_counts:
            services_tree = Tree("🔧 [bold]Discovered Services[/bold]")
            for service, count in sorted(service_counts.items()):
                services_tree.add(f"[cyan]{service}[/cyan] ([yellow]{count}[/yellow])")
            
            console.print(services_tree)


def display_beautiful_audit_results(results: dict) -> None:
    """Display security audit results with beautiful formatting."""
    
    threats = results.get('threats', [])
    warnings = results.get('warnings', [])
    score = results.get('compliance_score', 0)
    
    # Compliance score panel
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
    score_panel = Panel(
        f"[bold {score_color}]{score:.1f}/100[/bold {score_color}]",
        title="[bold]�️ Compliance Score[/bold]",
        border_style=score_color
    )
    
    # Summary panel
    summary_panel = Panel(
        f"[bold white]Threats Found:[/bold white] [red]{len(threats)}[/red]\n"
        f"[bold white]Warnings:[/bold white] [yellow]{len(warnings)}[/yellow]\n"
        f"[bold white]Devices Scanned:[/bold white] [cyan]{results.get('devices_scanned', 0)}[/cyan]",
        title="[bold red]🔒 Security Summary[/bold red]",
        border_style="red"
    )
    
    console.print(Columns([score_panel, summary_panel]))
    
    # Threats table
    if threats:
        threats_table = Table(
            title="[bold red]⚠️ Security Threats[/bold red]",
            border_style="red",
            show_header=True,
            header_style="bold red"
        )
        threats_table.add_column("Severity", style="white", width=10)
        threats_table.add_column("Device", style="cyan", width=15)
        threats_table.add_column("Threat", style="white", width=30)
        threats_table.add_column("Description", style="dim", width=40)
        
        for threat in threats[:10]:  # Show top 10 threats
            severity = threat.get('severity', 'unknown')
            severity_style = {
                'critical': '[bold red]🔥 CRITICAL[/bold red]',
                'high': '[red]⚡ HIGH[/red]',
                'medium': '[yellow]⚠️ MEDIUM[/yellow]',
                'low': '[blue]ℹ️ LOW[/blue]'
            }.get(severity, '[dim]❓ UNKNOWN[/dim]')
            
            threats_table.add_row(
                severity_style,
                threat.get('device_ip', 'Unknown'),
                threat.get('title', 'Unknown')[:28],
                threat.get('description', 'No description')[:38]
            )
        
        console.print(threats_table)
    
    # Warnings summary
    if warnings:
        warnings_tree = Tree("⚡ [bold yellow]Security Warnings[/bold yellow]")
        for warning in warnings[:15]:  # Show top 15 warnings
            warnings_tree.add(f"[yellow]{warning.get('title', 'Unknown')}[/yellow] - {warning.get('device_ip', 'Unknown')}")
        
        console.print(warnings_tree)
    
    if not threats and not warnings:
        success_panel = Panel(
            "[bold green]✅ No security issues found![/bold green]\n"
            "[white]Your network appears to be secure.[/white]",
            title="[bold green]Security Status[/bold green]",
            border_style="green"
        )
        console.print(success_panel)


if __name__ == "__main__":
    main()
