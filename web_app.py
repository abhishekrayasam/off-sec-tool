#!/usr/bin/env python3
"""
Web-based UI for Honeypot Interceptor
Flask application providing real-time monitoring and management interface
"""

import json
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO, emit
import logging

from core.tracker import AttackerTracker
from core.honeypot_manager import HoneypotManager
from core.attack_detector import AttackDetector
from core.file_replacer import FileReplacer
from core.interceptor import TrafficInterceptor

logger = logging.getLogger(__name__)

class WebUI:
    """Web-based user interface for Honeypot Interceptor"""
    
    def __init__(self, config):
        self.config = config
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'honeypot-interceptor-secret-key'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Initialize components
        self.tracker = AttackerTracker(config.get('tracking', {}))
        self.detector = AttackDetector(config.get('detection', {}))
        self.file_replacer = FileReplacer(config.get('file_replacement', {}))
        self.honeypot_manager = HoneypotManager(config.get('honeypots', []))
        self.interceptor = TrafficInterceptor(
            config.get('network', {}),
            self.detector,
            self.honeypot_manager,
            self.tracker
        )
        
        self.running = False
        self.setup_routes()
        self.setup_socketio_events()
        
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            """Main dashboard page"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/stats')
        def api_stats():
            """Get current statistics"""
            try:
                stats = self.tracker.get_attacker_stats()
                return jsonify({
                    'success': True,
                    'data': stats
                })
            except Exception as e:
                logger.error(f"Error getting stats: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/attacks')
        def api_attacks():
            """Get recent attacks"""
            try:
                limit = request.args.get('limit', 50, type=int)
                attacks = self.tracker.get_recent_attacks(limit)
                return jsonify({
                    'success': True,
                    'data': attacks
                })
            except Exception as e:
                logger.error(f"Error getting attacks: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/attackers')
        def api_attackers():
            """Get top attackers"""
            try:
                limit = request.args.get('limit', 20, type=int)
                attackers = self.tracker.get_top_attackers(limit)
                return jsonify({
                    'success': True,
                    'data': attackers
                })
            except Exception as e:
                logger.error(f"Error getting attackers: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/honeypots')
        def api_honeypots():
            """Get honeypot status"""
            try:
                honeypots = []
                for honeypot in self.honeypot_manager.honeypots:
                    honeypots.append({
                        'name': honeypot.name,
                        'port': honeypot.port,
                        'service': honeypot.service,
                        'status': 'running' if honeypot.running else 'stopped',
                        'connections': getattr(honeypot, 'connection_count', 0)
                    })
                
                return jsonify({
                    'success': True,
                    'data': honeypots
                })
            except Exception as e:
                logger.error(f"Error getting honeypots: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/alerts')
        def api_alerts():
            """Get security alerts"""
            try:
                alerts = self.get_alerts()
                return jsonify({
                    'success': True,
                    'data': alerts
                })
            except Exception as e:
                logger.error(f"Error getting alerts: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/export')
        def api_export():
            """Export data as JSON"""
            try:
                data = {
                    'export_time': datetime.now().isoformat(),
                    'stats': self.tracker.get_attacker_stats(),
                    'top_attackers': self.tracker.get_top_attackers(100),
                    'recent_attacks': self.tracker.get_recent_attacks(500)
                }
                
                filename = f"honeypot_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                
                return jsonify({
                    'success': True,
                    'data': data,
                    'filename': filename
                })
            except Exception as e:
                logger.error(f"Error exporting data: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/start', methods=['POST'])
        def api_start():
            """Start the honeypot interceptor"""
            try:
                if not self.running:
                    self.start_interceptor()
                    return jsonify({
                        'success': True,
                        'message': 'Honeypot interceptor started'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': 'Already running'
                    })
            except Exception as e:
                logger.error(f"Error starting interceptor: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/stop', methods=['POST'])
        def api_stop():
            """Stop the honeypot interceptor"""
            try:
                if self.running:
                    self.stop_interceptor()
                    return jsonify({
                        'success': True,
                        'message': 'Honeypot interceptor stopped'
                    })
                else:
                    return jsonify({
                        'success': False,
                        'message': 'Not running'
                    })
            except Exception as e:
                logger.error(f"Error stopping interceptor: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
        
        @self.app.route('/api/status')
        def api_status():
            """Get system status"""
            try:
                return jsonify({
                    'success': True,
                    'data': {
                        'running': self.running,
                        'uptime': self.get_uptime(),
                        'honeypots_active': len([h for h in self.honeypot_manager.honeypots if h.running]),
                        'total_honeypots': len(self.honeypot_manager.honeypots)
                    }
                })
            except Exception as e:
                logger.error(f"Error getting status: {e}")
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 500
    
    def setup_socketio_events(self):
        """Setup SocketIO events for real-time updates"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            logger.info(f"Client connected: {request.sid}")
            emit('status', {'connected': True})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            logger.info(f"Client disconnected: {request.sid}")
        
        @self.socketio.on('request_update')
        def handle_update_request():
            """Handle update request from client"""
            try:
                stats = self.tracker.get_attacker_stats()
                recent_attacks = self.tracker.get_recent_attacks(10)
                top_attackers = self.tracker.get_top_attackers(5)
                
                emit('data_update', {
                    'stats': stats,
                    'recent_attacks': recent_attacks,
                    'top_attackers': top_attackers,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error sending update: {e}")
                emit('error', {'message': str(e)})
    
    def start_interceptor(self):
        """Start the honeypot interceptor"""
        try:
            self.honeypot_manager.start_all()
            self.interceptor.start()
            self.running = True
            self.start_time = time.time()
            logger.info("Honeypot interceptor started")
        except Exception as e:
            logger.error(f"Error starting interceptor: {e}")
            raise
    
    def stop_interceptor(self):
        """Stop the honeypot interceptor"""
        try:
            self.interceptor.stop()
            self.honeypot_manager.stop_all()
            self.running = False
            logger.info("Honeypot interceptor stopped")
        except Exception as e:
            logger.error(f"Error stopping interceptor: {e}")
            raise
    
    def get_uptime(self):
        """Get system uptime"""
        if hasattr(self, 'start_time'):
            return int(time.time() - self.start_time)
        return 0
    
    def get_alerts(self):
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
                        'severity': attack['severity'],
                        'ip': attack['src_ip']
                    })
            
            # Check for repeated attacks from same IP
            attackers = self.tracker.get_top_attackers(10)
            for attacker in attackers:
                if attacker['attack_count'] > 10:
                    alerts.append({
                        'type': 'repeated_attacks',
                        'message': f"Repeated attacks from {attacker['src_ip']}: {attacker['attack_count']} attacks",
                        'timestamp': attacker['last_seen'],
                        'severity': min(attacker['attack_count'], 10),
                        'ip': attacker['src_ip']
                    })
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
        
        return alerts
    
    def broadcast_update(self):
        """Broadcast real-time update to all connected clients"""
        try:
            stats = self.tracker.get_attacker_stats()
            recent_attacks = self.tracker.get_recent_attacks(10)
            top_attackers = self.tracker.get_top_attackers(5)
            alerts = self.get_alerts()
            
            self.socketio.emit('data_update', {
                'stats': stats,
                'recent_attacks': recent_attacks,
                'top_attackers': top_attackers,
                'alerts': alerts,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Error broadcasting update: {e}")
    
    def start_broadcast_thread(self):
        """Start background thread for broadcasting updates"""
        def broadcast_loop():
            while self.running:
                self.broadcast_update()
                time.sleep(5)  # Update every 5 seconds
        
        self.broadcast_thread = threading.Thread(target=broadcast_loop, daemon=True)
        self.broadcast_thread.start()
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the web application"""
        logger.info(f"Starting web UI on {host}:{port}")
        self.socketio.run(self.app, host=host, port=port, debug=debug)

def create_web_ui(config):
    """Create and return a WebUI instance"""
    return WebUI(config)

if __name__ == '__main__':
    import yaml
    
    # Load configuration
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Create and run web UI
    web_ui = create_web_ui(config)
    web_ui.run(debug=True)
