"""
Attack Detection Module
Analyzes network traffic and system behavior to identify malicious activities
"""

import re
import time
import hashlib
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)

class AttackDetector:
    """Detects various types of malicious attacks and suspicious behavior"""
    
    def __init__(self, detection_config: Dict):
        self.config = detection_config
        self.suspicious_patterns = detection_config.get('suspicious_patterns', [])
        self.rate_limits = detection_config.get('rate_limits', {})
        self.geo_blocking = detection_config.get('geo_blocking', {})
        
        # Rate limiting tracking
        self.connection_counts = defaultdict(lambda: deque())
        self.failed_attempts = defaultdict(int)
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                for pattern in self.suspicious_patterns]
        
        # Attack signatures
        self.attack_signatures = self._load_attack_signatures()
        
    def _load_attack_signatures(self) -> Dict[str, List[str]]:
        """Load known attack signatures"""
        return {
            'sql_injection': [
                r"union\s+select",
                r"drop\s+table",
                r"insert\s+into",
                r"delete\s+from",
                r"update\s+set",
                r"or\s+1=1",
                r"and\s+1=1"
            ],
            'xss': [
                r"<script[^>]*>",
                r"javascript:",
                r"onload\s*=",
                r"onerror\s*=",
                r"alert\s*\(",
                r"document\.cookie"
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c",
                r"\.\.%2f",
                r"\.\.%5c"
            ],
            'command_injection': [
                r";\s*cat\s+",
                r";\s*ls\s+",
                r";\s*rm\s+",
                r";\s*wget\s+",
                r";\s*curl\s+",
                r"`[^`]+`",
                r"\$\([^)]+\)"
            ],
            'brute_force': [
                r"admin",
                r"password",
                r"root",
                r"administrator",
                r"guest",
                r"test"
            ]
        }
    
    def analyze_packet(self, packet) -> bool:
        """Analyze a network packet for malicious content"""
        try:
            # Extract packet data
            packet_data = self._extract_packet_data(packet)
            if not packet_data:
                return False
            
            # Check for suspicious patterns
            if self._check_suspicious_patterns(packet_data):
                logger.info("Suspicious pattern detected in packet")
                return True
            
            # Check for attack signatures
            attack_type = self._check_attack_signatures(packet_data)
            if attack_type:
                logger.info(f"Attack signature detected: {attack_type}")
                return True
            
            # Check rate limiting
            if self._check_rate_limits(packet_data):
                logger.info("Rate limit exceeded")
                return True
            
            # Check for port scanning
            if self._detect_port_scanning(packet_data):
                logger.info("Port scanning detected")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error analyzing packet: {e}")
            return False
    
    def _extract_packet_data(self, packet) -> Optional[Dict]:
        """Extract relevant data from packet"""
        try:
            data = {}
            
            if packet.haslayer(IP):
                data['src_ip'] = packet[IP].src
                data['dst_ip'] = packet[IP].dst
                data['protocol'] = packet[IP].proto
            
            if packet.haslayer(TCP):
                data['src_port'] = packet[TCP].sport
                data['dst_port'] = packet[TCP].dport
                data['flags'] = packet[TCP].flags
                
                # Extract payload if available
                if packet[TCP].payload:
                    payload = bytes(packet[TCP].payload)
                    data['payload'] = payload.decode('utf-8', errors='ignore')
            
            if packet.haslayer(UDP):
                data['src_port'] = packet[UDP].sport
                data['dst_port'] = packet[UDP].dport
                
                if packet[UDP].payload:
                    payload = bytes(packet[UDP].payload)
                    data['payload'] = payload.decode('utf-8', errors='ignore')
            
            return data
            
        except Exception as e:
            logger.error(f"Error extracting packet data: {e}")
            return None
    
    def _check_suspicious_patterns(self, packet_data: Dict) -> bool:
        """Check for suspicious patterns in packet data"""
        if 'payload' not in packet_data:
            return False
        
        payload = packet_data['payload'].lower()
        
        for pattern in self.compiled_patterns:
            if pattern.search(payload):
                logger.debug(f"Suspicious pattern matched: {pattern.pattern}")
                return True
        
        return False
    
    def _check_attack_signatures(self, packet_data: Dict) -> Optional[str]:
        """Check for known attack signatures"""
        if 'payload' not in packet_data:
            return None
        
        payload = packet_data['payload'].lower()
        
        for attack_type, signatures in self.attack_signatures.items():
            for signature in signatures:
                if re.search(signature, payload, re.IGNORECASE):
                    logger.debug(f"Attack signature matched: {attack_type} - {signature}")
                    return attack_type
        
        return None
    
    def _check_rate_limits(self, packet_data: Dict) -> bool:
        """Check if rate limits are exceeded"""
        src_ip = packet_data.get('src_ip')
        if not src_ip:
            return False
        
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean old entries
        while (self.connection_counts[src_ip] and 
               self.connection_counts[src_ip][0] < minute_ago):
            self.connection_counts[src_ip].popleft()
        
        # Add current connection
        self.connection_counts[src_ip].append(current_time)
        
        # Check rate limits
        max_connections = self.rate_limits.get('max_connections_per_minute', 10)
        if len(self.connection_counts[src_ip]) > max_connections:
            return True
        
        return False
    
    def _detect_port_scanning(self, packet_data: Dict) -> bool:
        """Detect port scanning attempts"""
        # This is a simplified implementation
        # In a real system, you'd track connection attempts across multiple ports
        src_ip = packet_data.get('src_ip')
        dst_port = packet_data.get('dst_port')
        
        if not src_ip or not dst_port:
            return False
        
        # Track unique ports accessed by each IP
        if not hasattr(self, 'port_scan_tracker'):
            self.port_scan_tracker = defaultdict(set)
        
        self.port_scan_tracker[src_ip].add(dst_port)
        
        # If an IP has accessed more than 5 different ports in the last minute
        if len(self.port_scan_tracker[src_ip]) > 5:
            return True
        
        return False
    
    def analyze_http_request(self, request_data: Dict) -> bool:
        """Analyze HTTP request for malicious content"""
        try:
            # Check URL for suspicious patterns
            url = request_data.get('url', '')
            if self._check_suspicious_patterns({'payload': url}):
                return True
            
            # Check headers
            headers = request_data.get('headers', {})
            for header, value in headers.items():
                if self._check_suspicious_patterns({'payload': f"{header}: {value}"}):
                    return True
            
            # Check POST data
            post_data = request_data.get('post_data', '')
            if post_data and self._check_suspicious_patterns({'payload': post_data}):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error analyzing HTTP request: {e}")
            return False
    
    def analyze_ssh_connection(self, connection_data: Dict) -> bool:
        """Analyze SSH connection for brute force attempts"""
        try:
            src_ip = connection_data.get('src_ip')
            username = connection_data.get('username', '')
            password = connection_data.get('password', '')
            
            if not src_ip:
                return False
            
            # Check for common usernames/passwords
            if username.lower() in ['admin', 'root', 'administrator', 'guest']:
                self.failed_attempts[src_ip] += 1
                logger.info(f"Common username attempted: {username} from {src_ip}")
            
            if password.lower() in ['password', 'admin', '123456', 'root']:
                self.failed_attempts[src_ip] += 1
                logger.info(f"Common password attempted from {src_ip}")
            
            # Check failed attempt threshold
            max_failed = self.rate_limits.get('max_failed_attempts', 5)
            if self.failed_attempts[src_ip] > max_failed:
                logger.warning(f"Brute force detected from {src_ip}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error analyzing SSH connection: {e}")
            return False
    
    def get_attack_statistics(self) -> Dict:
        """Get statistics about detected attacks"""
        return {
            'total_connections': sum(len(connections) for connections in self.connection_counts.values()),
            'unique_ips': len(self.connection_counts),
            'failed_attempts': dict(self.failed_attempts),
            'port_scan_ips': list(self.port_scan_tracker.keys()) if hasattr(self, 'port_scan_tracker') else []
        }
