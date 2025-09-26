"""
Attacker Tracking Module
Collects and analyzes attacker behavior and system information
"""

import json
import time
import sqlite3
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class AttackerTracker:
    """Tracks and analyzes attacker behavior"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.database_url = config.get('database', 'sqlite:///attacker_tracking.db')
        self.log_level = config.get('log_level', 'INFO')
        
        # Initialize database
        self._init_database()
        
        # In-memory tracking
        self.active_attacks = {}
        self.attack_history = []
        
    def _init_database(self):
        """Initialize SQLite database for tracking"""
        try:
            # Extract database path from URL
            if self.database_url.startswith('sqlite:///'):
                db_path = self.database_url[10:]  # Remove 'sqlite:///'
            else:
                db_path = 'attacker_tracking.db'
            
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.cursor = self.conn.cursor()
            
            # Create tables
            self._create_tables()
            logger.info(f"Database initialized: {db_path}")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            self.conn = None
            self.cursor = None
    
    def _create_tables(self):
        """Create database tables"""
        try:
            # Attacks table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    attack_type TEXT,
                    payload TEXT,
                    user_agent TEXT,
                    country TEXT,
                    is_blocked BOOLEAN DEFAULT 0,
                    severity INTEGER DEFAULT 1
                )
            ''')
            
            # Anomalies table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT,
                    total_score INTEGER,
                    traffic_patterns INTEGER,
                    location INTEGER,
                    device INTEGER,
                    applications INTEGER,
                    time_bucket INTEGER,
                    country TEXT,
                    device_id TEXT,
                    app TEXT,
                    raw_details TEXT
                )
            ''')
            
            # File access table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    access_type TEXT,
                    file_hash TEXT,
                    tracking_data TEXT
                )
            ''')
            
            # Attacker profiles table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS attacker_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT UNIQUE NOT NULL,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    attack_count INTEGER DEFAULT 0,
                    file_access_count INTEGER DEFAULT 0,
                    country TEXT,
                    isp TEXT,
                    threat_level INTEGER DEFAULT 1,
                    notes TEXT
                )
            ''')
            
            self.conn.commit()
            
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
    
    def record_attack(self, src_ip: str, dst_ip: str = None, src_port: int = None, 
                     dst_port: int = None, attack_type: str = None, 
                     payload: str = None, user_agent: str = None, 
                     packet_data: Any = None):
        """Record an attack attempt"""
        try:
            if not self.enabled:
                return
            
            # Extract additional information from packet
            if packet_data:
                payload = self._extract_payload(packet_data)
                user_agent = self._extract_user_agent(packet_data)
            
            # Calculate severity
            severity = self._calculate_severity(attack_type, payload)
            
            # Get country information
            country = self._get_country_info(src_ip)
            
            # Store in database
            if self.cursor:
                self.cursor.execute('''
                    INSERT INTO attacks 
                    (src_ip, dst_ip, src_port, dst_port, attack_type, payload, user_agent, country, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (src_ip, dst_ip, src_port, dst_port, attack_type, payload, user_agent, country, severity))
                self.conn.commit()
            
            # Update attacker profile
            self._update_attacker_profile(src_ip, attack_type)
            
            # Store in memory for real-time analysis
            attack_data = {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'attack_type': attack_type,
                'payload': payload,
                'user_agent': user_agent,
                'country': country,
                'severity': severity
            }
            
            self.attack_history.append(attack_data)
            
            # Keep only recent attacks in memory
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.attack_history = [a for a in self.attack_history if a['timestamp'] > cutoff_time]
            
            logger.info(f"Recorded attack from {src_ip}: {attack_type}")
            
        except Exception as e:
            logger.error(f"Error recording attack: {e}")

    def record_anomaly(self, src_ip: str, dst_ip: str = None, details: Dict = None):
        """Persist anomaly scoring details to the database."""
        try:
            if not self.enabled or not self.cursor or not details:
                return
            scores = (details.get('scores') or {})
            context = (details.get('context') or {})
            self.cursor.execute('''
                INSERT INTO anomalies (
                    src_ip, dst_ip, total_score,
                    traffic_patterns, location, device, applications, time_bucket,
                    country, device_id, app, raw_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                src_ip,
                dst_ip,
                int(details.get('total_score', 0)),
                int(scores.get('traffic_patterns', 0)),
                int(scores.get('location', 0)),
                int(scores.get('device', 0)),
                int(scores.get('applications', 0)),
                int(context.get('time_bucket', 0)),
                str(context.get('country', 'Unknown')),
                str(context.get('device', 'Unknown')),
                str(context.get('app', 'Unknown')),
                json.dumps(details, default=str)
            ))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Error recording anomaly: {e}")
    
    def record_file_access(self, src_ip: str, file_path: str, access_type: str = 'read', 
                          tracking_data: Dict = None):
        """Record file access by attacker"""
        try:
            if not self.enabled:
                return
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Store in database
            if self.cursor:
                self.cursor.execute('''
                    INSERT INTO file_access 
                    (src_ip, file_path, access_type, file_hash, tracking_data)
                    VALUES (?, ?, ?, ?, ?)
                ''', (src_ip, file_path, access_type, file_hash, json.dumps(tracking_data or {})))
                self.conn.commit()
            
            # Update attacker profile
            self._update_attacker_profile(src_ip, 'file_access')
            
            logger.info(f"Recorded file access from {src_ip}: {file_path}")
            
        except Exception as e:
            logger.error(f"Error recording file access: {e}")
    
    def _extract_payload(self, packet_data) -> str:
        """Extract payload from packet"""
        try:
            if hasattr(packet_data, 'payload'):
                payload = bytes(packet_data.payload)
                return payload.decode('utf-8', errors='ignore')
            return ""
        except:
            return ""
    
    def _extract_user_agent(self, packet_data) -> str:
        """Extract user agent from packet"""
        try:
            # This is a simplified implementation
            # In practice, you'd parse HTTP headers properly
            return "Unknown"
        except:
            return "Unknown"
    
    def _calculate_severity(self, attack_type: str, payload: str) -> int:
        """Calculate attack severity (1-10)"""
        severity = 1
        
        if attack_type:
            severity_map = {
                'sql_injection': 8,
                'xss': 6,
                'command_injection': 9,
                'brute_force': 4,
                'port_scanning': 3,
                'file_access': 2
            }
            severity = severity_map.get(attack_type, 5)
        
        # Increase severity based on payload content
        if payload:
            dangerous_keywords = ['rm -rf', 'wget', 'curl', 'nc -l', 'python -c']
            for keyword in dangerous_keywords:
                if keyword in payload.lower():
                    severity = min(10, severity + 2)
        
        return severity
    
    def _get_country_info(self, ip_address: str) -> str:
        """Get country information for IP address"""
        try:
            # In practice, you'd use a GeoIP service
            # This is a simplified implementation
            return "Unknown"
        except:
            return "Unknown"
    
    def _update_attacker_profile(self, src_ip: str, attack_type: str):
        """Update attacker profile information"""
        try:
            if not self.cursor:
                return
            
            current_time = datetime.now()
            
            # Check if profile exists
            self.cursor.execute('SELECT * FROM attacker_profiles WHERE src_ip = ?', (src_ip,))
            profile = self.cursor.fetchone()
            
            if profile:
                # Update existing profile
                self.cursor.execute('''
                    UPDATE attacker_profiles 
                    SET last_seen = ?, attack_count = attack_count + 1
                    WHERE src_ip = ?
                ''', (current_time, src_ip))
            else:
                # Create new profile
                self.cursor.execute('''
                    INSERT INTO attacker_profiles 
                    (src_ip, first_seen, last_seen, attack_count, country)
                    VALUES (?, ?, ?, 1, ?)
                ''', (src_ip, current_time, current_time, self._get_country_info(src_ip)))
            
            self.conn.commit()
            
        except Exception as e:
            logger.error(f"Error updating attacker profile: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate hash of file"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                return hashlib.sha256(content).hexdigest()
        except:
            return ""
    
    def get_attacker_stats(self) -> Dict:
        """Get attacker statistics"""
        try:
            stats = {}
            
            if self.cursor:
                # Total attacks
                self.cursor.execute('SELECT COUNT(*) FROM attacks')
                stats['total_attacks'] = self.cursor.fetchone()[0]
                
                # Unique attackers
                self.cursor.execute('SELECT COUNT(DISTINCT src_ip) FROM attacks')
                stats['unique_attackers'] = self.cursor.fetchone()[0]
                
                # Attacks by type
                self.cursor.execute('''
                    SELECT attack_type, COUNT(*) 
                    FROM attacks 
                    GROUP BY attack_type 
                    ORDER BY COUNT(*) DESC
                ''')
                stats['attacks_by_type'] = dict(self.cursor.fetchall())
                
                # Recent attacks (last 24 hours)
                cutoff_time = datetime.now() - timedelta(hours=24)
                self.cursor.execute('''
                    SELECT COUNT(*) FROM attacks 
                    WHERE timestamp > ?
                ''', (cutoff_time,))
                stats['recent_attacks'] = self.cursor.fetchone()[0]
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting attacker stats: {e}")
            return {}
    
    def get_top_attackers(self, limit: int = 10) -> List[Dict]:
        """Get top attackers by attack count"""
        try:
            if not self.cursor:
                return []
            
            self.cursor.execute('''
                SELECT src_ip, attack_count, first_seen, last_seen, country, threat_level
                FROM attacker_profiles 
                ORDER BY attack_count DESC 
                LIMIT ?
            ''', (limit,))
            
            attackers = []
            for row in self.cursor.fetchall():
                attackers.append({
                    'src_ip': row[0],
                    'attack_count': row[1],
                    'first_seen': row[2],
                    'last_seen': row[3],
                    'country': row[4],
                    'threat_level': row[5]
                })
            
            return attackers
            
        except Exception as e:
            logger.error(f"Error getting top attackers: {e}")
            return []
    
    def get_recent_attacks(self, limit: int = 50) -> List[Dict]:
        """Get recent attacks"""
        try:
            if not self.cursor:
                return []
            
            self.cursor.execute('''
                SELECT src_ip, dst_ip, attack_type, payload, timestamp, severity
                FROM attacks 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            attacks = []
            for row in self.cursor.fetchall():
                attacks.append({
                    'src_ip': row[0],
                    'dst_ip': row[1],
                    'attack_type': row[2],
                    'payload': row[3],
                    'timestamp': row[4],
                    'severity': row[5]
                })
            
            return attacks
            
        except Exception as e:
            logger.error(f"Error getting recent attacks: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        try:
            if self.conn:
                self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")
