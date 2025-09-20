"""
Monitoring Dashboard Module
Provides real-time monitoring and visualization of honeypot activity
"""

import threading
import time
import json
from typing import Dict, List
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
import logging

logger = logging.getLogger(__name__)

class MonitoringDashboard:
    """Real-time monitoring dashboard for honeypot activity"""
    
    def __init__(self, tracker):
        self.tracker = tracker
        self.console = Console()
        self.running = False
        self.dashboard_thread = None
        
    def start(self):
        """Start the monitoring dashboard"""
        if self.running:
            logger.warning("Dashboard is already running")
            return
        
        self.running = True
        self.dashboard_thread = threading.Thread(target=self._run_dashboard, daemon=True)
        self.dashboard_thread.start()
        logger.info("Monitoring dashboard started")
    
    def stop(self):
        """Stop the monitoring dashboard"""
        self.running = False
        if self.dashboard_thread:
            self.dashboard_thread.join(timeout=5)
        logger.info("Monitoring dashboard stopped")
    
    def _run_dashboard(self):
        """Main dashboard loop"""
        try:
            with Live(self._create_dashboard(), refresh_per_second=1, console=self.console) as live:
                while self.running:
                    live.update(self._create_dashboard())
                    time.sleep(1)
        except Exception as e:
            logger.error(f"Error in dashboard: {e}")
    
    def _create_dashboard(self) -> Layout:
        """Create the dashboard layout"""
        layout = Layout()
        
        # Split into sections
        layout.split_column(
            Layout(self._create_header(), size=3),
            Layout(self._create_stats_section()),
            Layout(self._create_attacks_section()),
            Layout(self._create_attackers_section())
        )
        
        return layout
    
    def _create_header(self) -> Panel:
        """Create dashboard header"""
        header_text = Text("Honeypot Interceptor - Real-time Monitoring", style="bold blue")
        header_text.append(f" | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", style="dim")
        
        return Panel(header_text, border_style="blue")
    
    def _create_stats_section(self) -> Panel:
        """Create statistics section"""
        stats = self.tracker.get_attacker_stats()
        
        stats_text = Text()
        stats_text.append("Total Attacks: ", style="bold")
        stats_text.append(f"{stats.get('total_attacks', 0)}", style="green")
        stats_text.append(" | Unique Attackers: ", style="bold")
        stats_text.append(f"{stats.get('unique_attackers', 0)}", style="yellow")
        stats_text.append(" | Recent (24h): ", style="bold")
        stats_text.append(f"{stats.get('recent_attacks', 0)}", style="red")
        
        return Panel(stats_text, title="Statistics", border_style="green")
    
    def _create_attacks_section(self) -> Panel:
        """Create recent attacks section"""
        attacks = self.tracker.get_recent_attacks(10)
        
        if not attacks:
            return Panel("No recent attacks", title="Recent Attacks", border_style="yellow")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Time", style="dim", width=12)
        table.add_column("Source IP", style="cyan", width=15)
        table.add_column("Type", style="yellow", width=15)
        table.add_column("Severity", style="red", width=8)
        table.add_column("Payload", style="dim", width=30)
        
        for attack in attacks:
            timestamp = attack['timestamp']
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            time_str = timestamp.strftime('%H:%M:%S')
            severity_str = "🔴" * min(attack['severity'], 5)
            
            payload = attack['payload'] or ""
            if len(payload) > 30:
                payload = payload[:27] + "..."
            
            table.add_row(
                time_str,
                attack['src_ip'],
                attack['attack_type'] or "Unknown",
                severity_str,
                payload
            )
        
        return Panel(table, title="Recent Attacks", border_style="red")
    
    def _create_attackers_section(self) -> Panel:
        """Create top attackers section"""
        attackers = self.tracker.get_top_attackers(5)
        
        if not attackers:
            return Panel("No attackers detected", title="Top Attackers", border_style="yellow")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("IP Address", style="cyan", width=15)
        table.add_column("Attacks", style="red", width=8)
        table.add_column("First Seen", style="dim", width=12)
        table.add_column("Last Seen", style="dim", width=12)
        table.add_column("Country", style="green", width=10)
        
        for attacker in attackers:
            first_seen = attacker['first_seen']
            last_seen = attacker['last_seen']
            
            if isinstance(first_seen, str):
                first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
            if isinstance(last_seen, str):
                last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
            
            table.add_row(
                attacker['src_ip'],
                str(attacker['attack_count']),
                first_seen.strftime('%m-%d %H:%M'),
                last_seen.strftime('%m-%d %H:%M'),
                attacker['country'] or "Unknown"
            )
        
        return Panel(table, title="Top Attackers", border_style="red")
    
    def print_summary(self):
        """Print a summary of current status"""
        stats = self.tracker.get_attacker_stats()
        attackers = self.tracker.get_top_attackers(5)
        
        self.console.print("\n" + "="*60)
        self.console.print("Honeypot Interceptor Status Summary", style="bold blue")
        self.console.print("="*60)
        
        self.console.print(f"Total Attacks: {stats.get('total_attacks', 0)}", style="green")
        self.console.print(f"Unique Attackers: {stats.get('unique_attackers', 0)}", style="yellow")
        self.console.print(f"Recent Attacks (24h): {stats.get('recent_attacks', 0)}", style="red")
        
        if attackers:
            self.console.print("\nTop Attackers:", style="bold red")
            for i, attacker in enumerate(attackers, 1):
                self.console.print(f"  {i}. {attacker['src_ip']} - {attacker['attack_count']} attacks")
        
        self.console.print("="*60)
    
    def export_data(self, filename: str = None):
        """Export tracking data to JSON file"""
        try:
            if not filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"honeypot_data_{timestamp}.json"
            
            data = {
                'export_time': datetime.now().isoformat(),
                'stats': self.tracker.get_attacker_stats(),
                'top_attackers': self.tracker.get_top_attackers(50),
                'recent_attacks': self.tracker.get_recent_attacks(100)
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            self.console.print(f"Data exported to {filename}", style="green")
            
        except Exception as e:
            self.console.print(f"Error exporting data: {e}", style="red")
    
    def get_alerts(self) -> List[Dict]:
        """Get current security alerts"""
        alerts = []
        
        try:
            # Check for high-severity attacks
            recent_attacks = self.tracker.get_recent_attacks(20)
            for attack in recent_attacks:
                if attack.get('severity', 0) >= 8:
                    alerts.append({
                        'type': 'high_severity',
                        'message': f"High severity attack from {attack['src_ip']}: {attack['attack_type']}",
                        'timestamp': attack['timestamp'],
                        'severity': attack['severity']
                    })
            
            # Check for repeated attacks from same IP
            attackers = self.tracker.get_top_attackers(10)
            for attacker in attackers:
                if attacker['attack_count'] > 10:
                    alerts.append({
                        'type': 'repeated_attacks',
                        'message': f"Repeated attacks from {attacker['src_ip']}: {attacker['attack_count']} attacks",
                        'timestamp': attacker['last_seen'],
                        'severity': min(attacker['attack_count'], 10)
                    })
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
        
        return alerts
