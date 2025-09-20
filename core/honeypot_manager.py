"""
Honeypot Manager Module
Manages deployment and operation of honeypot servers
"""

import threading
import socket
import time
import json
import os
from typing import Dict, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class HoneypotServer:
    """Individual honeypot server instance"""
    
    def __init__(self, name: str, port: int, service: str, decoy_files: List[str]):
        self.name = name
        self.port = port
        self.service = service
        self.decoy_files = decoy_files
        self.running = False
        self.server_thread = None
        self.connections = []
        
    def start(self):
        """Start the honeypot server"""
        if self.running:
            logger.warning(f"Honeypot {self.name} is already running")
            return
        
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        logger.info(f"Honeypot {self.name} started on port {self.port}")
    
    def stop(self):
        """Stop the honeypot server"""
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=5)
        logger.info(f"Honeypot {self.name} stopped")
    
    def _run_server(self):
        """Main server loop"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', self.port))
                server_socket.listen(5)
                
                while self.running:
                    try:
                        client_socket, address = server_socket.accept()
                        connection_thread = threading.Thread(
                            target=self._handle_connection,
                            args=(client_socket, address),
                            daemon=True
                        )
                        connection_thread.start()
                        self.connections.append(connection_thread)
                        
                    except socket.error as e:
                        if self.running:
                            logger.error(f"Error accepting connection: {e}")
                        break
                        
        except Exception as e:
            logger.error(f"Error running honeypot {self.name}: {e}")
    
    def _handle_connection(self, client_socket, address):
        """Handle individual client connection"""
        try:
            logger.info(f"Connection from {address} to honeypot {self.name}")
            
            if self.service == 'ssh':
                self._handle_ssh_connection(client_socket, address)
            elif self.service == 'http':
                self._handle_http_connection(client_socket, address)
            elif self.service == 'rdp':
                self._handle_rdp_connection(client_socket, address)
            else:
                self._handle_generic_connection(client_socket, address)
                
        except Exception as e:
            logger.error(f"Error handling connection from {address}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_ssh_connection(self, client_socket, address):
        """Handle SSH honeypot connection"""
        try:
            # Send SSH banner
            banner = "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10ubuntu0.3\r\n"
            client_socket.send(banner.encode())
            
            # Simulate SSH handshake
            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    # Log the attempt
                    logger.info(f"SSH attempt from {address}: {data.decode('utf-8', errors='ignore')}")
                    
                    # Send fake response
                    response = "Permission denied (publickey,password).\r\n"
                    client_socket.send(response.encode())
                    
                    # Add delay to make it seem realistic
                    time.sleep(2)
                    
                except socket.timeout:
                    break
                except socket.error:
                    break
                    
        except Exception as e:
            logger.error(f"Error in SSH honeypot: {e}")
    
    def _handle_http_connection(self, client_socket, address):
        """Handle HTTP honeypot connection"""
        try:
            # Receive HTTP request
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            logger.info(f"HTTP request from {address}: {request[:200]}...")
            
            # Parse request
            lines = request.split('\n')
            if lines:
                request_line = lines[0]
                method, path, version = request_line.split(' ', 2)
                
                # Check if requesting a decoy file
                if path in self.decoy_files:
                    self._serve_decoy_file(client_socket, path)
                else:
                    self._serve_fake_page(client_socket, path)
                    
        except Exception as e:
            logger.error(f"Error in HTTP honeypot: {e}")
    
    def _handle_rdp_connection(self, client_socket, address):
        """Handle RDP honeypot connection"""
        try:
            # Send RDP banner
            banner = b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
            client_socket.send(banner)
            
            # Simulate RDP handshake
            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    logger.info(f"RDP attempt from {address}: {len(data)} bytes")
                    
                    # Send fake response
                    response = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00"
                    client_socket.send(response)
                    
                    time.sleep(1)
                    
                except socket.timeout:
                    break
                except socket.error:
                    break
                    
        except Exception as e:
            logger.error(f"Error in RDP honeypot: {e}")
    
    def _handle_generic_connection(self, client_socket, address):
        """Handle generic connection"""
        try:
            # Just log the connection attempt
            logger.info(f"Generic connection from {address} to {self.service} honeypot")
            
            # Send a simple response
            response = f"Connection to {self.service} service established\r\n"
            client_socket.send(response.encode())
            
            # Keep connection open briefly
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Error in generic honeypot: {e}")
    
    def _serve_decoy_file(self, client_socket, file_path):
        """Serve a decoy file with tracking capabilities"""
        try:
            # Create fake file content with tracking
            content = self._create_tracking_file(file_path)
            
            response = f"HTTP/1.1 200 OK\r\n"
            response += f"Content-Type: text/plain\r\n"
            response += f"Content-Length: {len(content)}\r\n"
            response += f"Connection: close\r\n\r\n"
            response += content
            
            client_socket.send(response.encode())
            logger.info(f"Served decoy file {file_path}")
            
        except Exception as e:
            logger.error(f"Error serving decoy file: {e}")
    
    def _serve_fake_page(self, client_socket, path):
        """Serve a fake web page"""
        try:
            # Create fake HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Welcome to {self.name}</title>
            </head>
            <body>
                <h1>Welcome to {self.name}</h1>
                <p>This is a honeypot server.</p>
                <p>Requested path: {path}</p>
                <p>Time: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </body>
            </html>
            """
            
            response = f"HTTP/1.1 200 OK\r\n"
            response += f"Content-Type: text/html\r\n"
            response += f"Content-Length: {len(html_content)}\r\n"
            response += f"Connection: close\r\n\r\n"
            response += html_content
            
            client_socket.send(response.encode())
            
        except Exception as e:
            logger.error(f"Error serving fake page: {e}")
    
    def _create_tracking_file(self, file_path):
        """Create a file with embedded tracking code"""
        # This is where you'd embed tracking code that executes on the attacker's system
        tracking_code = f"""
# This file contains tracking code that will execute on the attacker's system
# File: {file_path}
# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

# Embedded tracking payload (would be more sophisticated in practice)
import os, sys, subprocess, socket, time, json

def track_attacker():
    data = {{
        'file_path': '{file_path}',
        'timestamp': '{time.strftime('%Y-%m-%d %H:%M:%S')}',
        'system_info': {{
            'platform': sys.platform,
            'python_version': sys.version,
            'hostname': socket.gethostname(),
            'user': os.getenv('USER', 'unknown')
        }}
    }}
    
    # Send tracking data (in practice, this would be more sophisticated)
    try:
        with open('/tmp/honeypot_tracking.json', 'a') as f:
            f.write(json.dumps(data) + '\\n')
    except:
        pass

# Execute tracking when file is accessed
if __name__ == '__main__':
    track_attacker()

# Original file content would go here
# This is a decoy file designed to track attacker behavior
"""
        return tracking_code

class HoneypotManager:
    """Manages multiple honeypot servers"""
    
    def __init__(self, honeypot_configs: List[Dict]):
        self.honeypots = {}
        self.configs = honeypot_configs
        
        # Initialize honeypot servers
        for config in honeypot_configs:
            name = config['name']
            port = config['port']
            service = config['service']
            decoy_files = config.get('decoy_files', [])
            
            honeypot = HoneypotServer(name, port, service, decoy_files)
            self.honeypots[name] = honeypot
    
    def start_all(self):
        """Start all honeypot servers"""
        for honeypot in self.honeypots.values():
            honeypot.start()
        logger.info(f"Started {len(self.honeypots)} honeypot servers")
    
    def stop_all(self):
        """Stop all honeypot servers"""
        for honeypot in self.honeypots.values():
            honeypot.stop()
        logger.info("Stopped all honeypot servers")
    
    def start_honeypot(self, name: str):
        """Start a specific honeypot"""
        if name in self.honeypots:
            self.honeypots[name].start()
        else:
            logger.error(f"Honeypot {name} not found")
    
    def stop_honeypot(self, name: str):
        """Stop a specific honeypot"""
        if name in self.honeypots:
            self.honeypots[name].stop()
        else:
            logger.error(f"Honeypot {name} not found")
    
    def get_status(self) -> Dict:
        """Get status of all honeypots"""
        status = {}
        for name, honeypot in self.honeypots.items():
            status[name] = {
                'running': honeypot.running,
                'port': honeypot.port,
                'service': honeypot.service,
                'connections': len(honeypot.connections)
            }
        return status
    
    def get_honeypot(self, name: str) -> Optional[HoneypotServer]:
        """Get a specific honeypot instance"""
        return self.honeypots.get(name)
