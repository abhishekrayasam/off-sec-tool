#!/usr/bin/env python3
"""
Test script for Honeypot Interceptor
This script simulates various attack scenarios to test the system
"""

import time
import socket
import requests
import threading
from rich.console import Console
from rich.panel import Panel

console = Console()

def test_ssh_honeypot():
    """Test SSH honeypot"""
    console.print("[yellow]Testing SSH honeypot...[/yellow]")
    
    try:
        # Connect to SSH honeypot
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 2222))
        
        # Receive banner
        banner = sock.recv(1024)
        console.print(f"Received banner: {banner.decode()}")
        
        # Send some test data
        sock.send(b"SSH-2.0-TestClient\r\n")
        response = sock.recv(1024)
        console.print(f"Response: {response.decode()}")
        
        sock.close()
        console.print("[green]✓ SSH honeypot test completed[/green]")
        
    except Exception as e:
        console.print(f"[red]✗ SSH honeypot test failed: {e}[/red]")

def test_http_honeypot():
    """Test HTTP honeypot"""
    console.print("[yellow]Testing HTTP honeypot...[/yellow]")
    
    try:
        # Test various HTTP requests
        test_urls = [
            "http://localhost:8080/",
            "http://localhost:8080/admin/",
            "http://localhost:8080/login.php",
            "http://localhost:8080/config.php"
        ]
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=5)
                console.print(f"GET {url} -> {response.status_code}")
                console.print(f"Response: {response.text[:100]}...")
            except Exception as e:
                console.print(f"Request to {url} failed: {e}")
        
        console.print("[green]✓ HTTP honeypot test completed[/green]")
        
    except Exception as e:
        console.print(f"[red]✗ HTTP honeypot test failed: {e}[/red]")

def test_malicious_requests():
    """Test malicious HTTP requests"""
    console.print("[yellow]Testing malicious requests...[/yellow]")
    
    malicious_payloads = [
        "admin' OR '1'='1",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "; cat /etc/passwd",
        "union select * from users"
    ]
    
    for payload in malicious_payloads:
        try:
            # Test SQL injection
            response = requests.get(f"http://localhost:8080/search?q={payload}", timeout=5)
            console.print(f"Payload: {payload[:30]}... -> {response.status_code}")
        except Exception as e:
            console.print(f"Payload {payload[:30]}... failed: {e}")
    
    console.print("[green]✓ Malicious requests test completed[/green]")

def test_brute_force():
    """Test brute force detection"""
    console.print("[yellow]Testing brute force detection...[/yellow]")
    
    common_passwords = ["admin", "password", "123456", "root", "test"]
    
    for password in common_passwords:
        try:
            # Simulate SSH login attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(('localhost', 2222))
            
            # Send login attempt
            sock.send(f"admin:{password}\r\n".encode())
            response = sock.recv(1024)
            console.print(f"Login attempt: admin:{password} -> {response.decode()[:50]}...")
            
            sock.close()
            time.sleep(0.5)  # Small delay between attempts
            
        except Exception as e:
            console.print(f"Brute force test failed: {e}")
    
    console.print("[green]✓ Brute force test completed[/green]")

def test_port_scanning():
    """Test port scanning detection"""
    console.print("[yellow]Testing port scanning detection...[/yellow]")
    
    ports_to_scan = [22, 23, 80, 443, 3389, 5900, 8080]
    
    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            
            if result == 0:
                console.print(f"Port {port} is open")
            else:
                console.print(f"Port {port} is closed")
            
            sock.close()
            time.sleep(0.1)  # Small delay between scans
            
        except Exception as e:
            console.print(f"Port scan test failed for port {port}: {e}")
    
    console.print("[green]✓ Port scanning test completed[/green]")

def main():
    """Run all tests"""
    console.print(Panel.fit(
        "Honeypot Interceptor Test Suite",
        style="bold blue"
    ))
    
    # Wait a moment for honeypots to start
    console.print("[yellow]Waiting for honeypots to start...[/yellow]")
    time.sleep(2)
    
    # Run tests
    test_ssh_honeypot()
    time.sleep(1)
    
    test_http_honeypot()
    time.sleep(1)
    
    test_malicious_requests()
    time.sleep(1)
    
    test_brute_force()
    time.sleep(1)
    
    test_port_scanning()
    
    console.print(Panel.fit(
        "All tests completed! Check the monitoring dashboard for results.",
        style="bold green"
    ))

if __name__ == "__main__":
    main()
