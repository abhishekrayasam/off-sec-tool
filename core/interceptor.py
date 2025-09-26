"""
Traffic Interceptor Module
Handles real-time network traffic interception and redirection
"""

import threading
import time
import socket
import struct
from typing import Dict, List, Optional
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import logging
from datetime import datetime

from .attack_detector import AttackDetector
from .honeypot_manager import HoneypotManager
from .tracker import AttackerTracker
from .anomaly_engine import AnomalyEngine

logger = logging.getLogger(__name__)

class TrafficInterceptor:
    """Intercepts network traffic and redirects malicious connections to honeypots"""
    
    def __init__(self, network_config: Dict, detector: AttackDetector, 
                 honeypot_manager: HoneypotManager, tracker: AttackerTracker, anomaly_engine: AnomalyEngine = None):
        self.network_config = network_config
        self.detector = detector
        self.honeypot_manager = honeypot_manager
        self.tracker = tracker
        self.anomaly_engine = anomaly_engine
        
        self.interface = network_config.get('interface', 'eth0')
        self.target_ports = network_config.get('target_ports', [22, 80, 443])
        self.redirect_ports = network_config.get('redirect_ports', [2222, 8080, 8443])
        
        self.running = False
        self.intercept_thread = None
        
        # Port mapping for redirection
        self.port_mapping = dict(zip(self.target_ports, self.redirect_ports))
        
    def start(self):
        """Start traffic interception"""
        if self.running:
            logger.warning("Traffic interceptor is already running")
            return
            
        self.running = True
        self.intercept_thread = threading.Thread(target=self._intercept_loop, daemon=True)
        self.intercept_thread.start()
        logger.info("Traffic interceptor started")
    
    def stop(self):
        """Stop traffic interception"""
        self.running = False
        if self.intercept_thread:
            self.intercept_thread.join(timeout=5)
        logger.info("Traffic interceptor stopped")
    
    def _intercept_loop(self):
        """Main interception loop"""
        try:
            # Set up packet capture
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=self._build_filter(),
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            logger.error(f"Error in interception loop: {e}")
    
    def _build_filter(self) -> str:
        """Build BPF filter for target ports"""
        port_list = " or ".join([f"port {port}" for port in self.target_ports])
        return f"tcp and ({port_list})"
    
    def _process_packet(self, packet):
        """Process intercepted packet"""
        try:
            if not self.running:
                return
                
            # Extract packet information
            if IP in packet and TCP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Check if this is a connection to a target port
                if dst_port in self.target_ports:
                    # Analyze packet for malicious patterns
                    is_malicious = self.detector.analyze_packet(packet)
                    
                    # Run anomaly scoring (best-effort) using src_ip as entity
                    if self.anomaly_engine:
                        try:
                            anomaly_context = {
                                'src_ip': src_ip,
                                'dst_ip': dst_ip,
                                'port': dst_port,
                                'country': self.tracker._get_country_info(src_ip) if self.tracker else 'Unknown',
                                'src_mac': packet[Ether].src if Ether in packet else None,
                                'app': f"tcp:{dst_port}",
                                'timestamp': datetime.utcnow(),
                            }
                            anomaly = self.anomaly_engine.update_and_score(entity_id=src_ip, context=anomaly_context)
                            if anomaly and anomaly.get('total_score', 0) > 0:
                                # Persist anomaly via tracker if available
                                if hasattr(self.tracker, 'record_anomaly'):
                                    self.tracker.record_anomaly(src_ip=src_ip, dst_ip=dst_ip, details=anomaly)
                        except Exception as _:
                            pass

                    if is_malicious:
                        logger.info(f"Malicious packet detected from {src_ip}:{src_port}")
                        
                        # Track the attacker
                        self.tracker.record_attack(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            packet_data=packet
                        )
                        
                        # Redirect to honeypot
                        self._redirect_to_honeypot(packet, dst_port)
                    else:
                        # Allow normal traffic to pass through
                        self._forward_packet(packet)
                        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _redirect_to_honeypot(self, packet, original_port):
        """Redirect packet to appropriate honeypot"""
        try:
            # Get honeypot port for this service
            honeypot_port = self.port_mapping.get(original_port)
            if not honeypot_port:
                logger.warning(f"No honeypot configured for port {original_port}")
                return
            
            # Modify packet destination
            modified_packet = packet.copy()
            modified_packet[TCP].dport = honeypot_port
            
            # Send to honeypot
            send(modified_packet, iface=self.interface, verbose=0)
            logger.info(f"Redirected {packet[IP].src} to honeypot port {honeypot_port}")
            
        except Exception as e:
            logger.error(f"Error redirecting packet: {e}")
    
    def _forward_packet(self, packet):
        """Forward legitimate packet to original destination"""
        try:
            send(packet, iface=self.interface, verbose=0)
        except Exception as e:
            logger.error(f"Error forwarding packet: {e}")
    
    def _create_redirect_rule(self, src_ip: str, dst_port: int, honeypot_port: int):
        """Create iptables rule for traffic redirection"""
        try:
            import subprocess
            
            # Create iptables rule to redirect traffic
            rule = [
                "iptables", "-t", "nat", "-A", "PREROUTING",
                "-s", src_ip,
                "-p", "tcp", "--dport", str(dst_port),
                "-j", "REDIRECT", "--to-port", str(honeypot_port)
            ]
            
            subprocess.run(rule, check=True)
            logger.info(f"Created redirect rule for {src_ip}:{dst_port} -> {honeypot_port}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create redirect rule: {e}")
        except Exception as e:
            logger.error(f"Error creating redirect rule: {e}")
    
    def _remove_redirect_rule(self, src_ip: str, dst_port: int, honeypot_port: int):
        """Remove iptables rule for traffic redirection"""
        try:
            import subprocess
            
            # Remove iptables rule
            rule = [
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-s", src_ip,
                "-p", "tcp", "--dport", str(dst_port),
                "-j", "REDIRECT", "--to-port", str(honeypot_port)
            ]
            
            subprocess.run(rule, check=True)
            logger.info(f"Removed redirect rule for {src_ip}:{dst_port}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove redirect rule: {e}")
        except Exception as e:
            logger.error(f"Error removing redirect rule: {e}")
