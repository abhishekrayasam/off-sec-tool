#!/usr/bin/env python3
"""
Honeypot Interceptor - Main Application
Offensive security tool for intercepting and redirecting malicious attacks
"""

import sys
import os
import signal
import argparse
import yaml
import logging
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.interceptor import TrafficInterceptor
from core.honeypot_manager import HoneypotManager
from core.attack_detector import AttackDetector
from core.file_replacer import FileReplacer
from core.tracker import AttackerTracker
from core.dashboard import MonitoringDashboard
from utils.logger import setup_logging
from core.anomaly_engine import AnomalyEngine

console = Console()

class HoneypotInterceptor:
    """Main application class for the honeypot interceptor"""
    
    def __init__(self, config_path: str):
        self.config = self.load_config(config_path)
        self.setup_components()
        self.running = False
        
    def load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            console.print(f"[green]✓[/green] Configuration loaded from {config_path}")
            return config
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load config: {e}")
            sys.exit(1)
    
    def setup_components(self):
        """Initialize all system components"""
        try:
            # Setup logging
            setup_logging(self.config.get('logging', {}))
            
            # Initialize components
            self.tracker = AttackerTracker(self.config.get('tracking', {}))
            self.detector = AttackDetector(self.config.get('detection', {}))
            self.anomaly_engine = AnomalyEngine(self.config.get('anomaly_detection', {}))
            self.file_replacer = FileReplacer(self.config.get('file_replacement', {}))
            self.honeypot_manager = HoneypotManager(self.config.get('honeypots', []))
            self.interceptor = TrafficInterceptor(
                self.config.get('network', {}),
                self.detector,
                self.honeypot_manager,
                self.tracker,
                self.anomaly_engine
            )
            self.dashboard = MonitoringDashboard(self.tracker)
            
            console.print("[green]✓[/green] All components initialized successfully")
            
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to initialize components: {e}")
            sys.exit(1)
    
    def start(self):
        """Start the honeypot interceptor"""
        try:
            console.print(Panel.fit(
                Text("Honeypot Interceptor Starting...", style="bold blue"),
                border_style="blue"
            ))
            
            # Start honeypot servers
            self.honeypot_manager.start_all()
            
            # Start traffic interception
            self.interceptor.start()
            
            # Start monitoring dashboard
            self.dashboard.start()
            
            self.running = True
            console.print("[green]✓[/green] Honeypot Interceptor is now running")
            
            # Setup signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            # Keep running until interrupted
            while self.running:
                import time
                time.sleep(1)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Received interrupt signal[/yellow]")
        except Exception as e:
            console.print(f"[red]✗[/red] Error during execution: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the honeypot interceptor"""
        console.print("[yellow]Shutting down Honeypot Interceptor...[/yellow]")
        
        try:
            if hasattr(self, 'interceptor'):
                self.interceptor.stop()
            if hasattr(self, 'honeypot_manager'):
                self.honeypot_manager.stop_all()
            if hasattr(self, 'dashboard'):
                self.dashboard.stop()
                
            console.print("[green]✓[/green] Shutdown complete")
        except Exception as e:
            console.print(f"[red]✗[/red] Error during shutdown: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        console.print(f"\n[yellow]Received signal {signum}[/yellow]")
        self.running = False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Honeypot Interceptor - Offensive Security Tool"
    )
    parser.add_argument(
        "--config", 
        default="config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--mode",
        choices=["intercept", "monitor", "test", "web"],
        default="intercept",
        help="Operation mode"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Check if running with appropriate privileges
    if sys.platform != "win32" and os.geteuid() != 0:
        console.print("[red]✗[/red] This tool requires root privileges")
        sys.exit(1)
    
    # Create and start the interceptor
    interceptor = HoneypotInterceptor(args.config)
    
    if args.mode == "test":
        console.print("[yellow]Running in test mode[/yellow]")
        # Add test functionality here
    elif args.mode == "web":
        console.print("[blue]Starting web interface...[/blue]")
        from web_app import create_web_ui
        web_ui = create_web_ui(interceptor.config)
        web_ui.run(host='0.0.0.0', port=5000, debug=args.verbose)
    else:
        interceptor.start()

if __name__ == "__main__":
    main()
