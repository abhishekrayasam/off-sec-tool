# Honeypot Interceptor - Usage Guide

## Quick Start

1. **Installation**
   ```bash
   sudo ./install.sh
   ```

2. **Configuration**
   Edit `/etc/honeypot-interceptor/config.yaml` to customize settings

3. **Start the service**
   ```bash
   sudo systemctl start honeypot-interceptor
   ```

4. **Monitor activity**
   ```bash
   sudo journalctl -u honeypot-interceptor -f
   ```

## Manual Operation

### Basic Usage
```bash
# Run with default configuration
sudo python3 main.py

# Run with custom configuration
sudo python3 main.py --config /path/to/config.yaml

# Run in test mode
sudo python3 main.py --mode test

# Enable verbose logging
sudo python3 main.py --verbose
```

### Testing the System
```bash
# Run the test suite
python3 test_honeypot.py
```

## Configuration

### Network Settings
```yaml
network:
  interface: "eth0"  # Network interface to monitor
  target_ports: [22, 23, 80, 443, 3389, 5900, 8080]  # Ports to monitor
  redirect_ports: [2222, 2323, 8080, 8443, 33389, 55900, 18080]  # Honeypot ports
```

### Honeypot Servers
```yaml
honeypots:
  - name: "ssh_honeypot"
    port: 2222
    service: "ssh"
    decoy_files: ["/etc/passwd", "/etc/shadow", "/home/user/"]
```

### Attack Detection
```yaml
detection:
  suspicious_patterns:
    - "password"
    - "admin"
    - "exploit"
    - "payload"
  
  rate_limits:
    max_connections_per_minute: 10
    max_failed_attempts: 5
```

## Features

### Traffic Interception
- Real-time network traffic monitoring
- Automatic redirection to honeypot servers
- Support for multiple protocols (SSH, HTTP, RDP, etc.)

### Attack Detection
- Pattern-based attack detection
- Rate limiting and brute force detection
- Port scanning detection
- Geographic blocking (optional)

### Honeypot Management
- Multiple honeypot servers
- Service-specific honeypots
- Decoy file serving
- Realistic service simulation

### File Replacement
- Automatic file replacement with honeypot versions
- Embedded tracking code
- Backup and restore functionality
- Support for various file types

### Attacker Tracking
- Comprehensive attack logging
- Attacker profiling
- Behavioral analysis
- Threat level assessment

### Monitoring Dashboard
- Real-time activity monitoring
- Attack statistics
- Top attackers list
- Security alerts

## Security Considerations

### Legal and Ethical Use
- **Authorized Use Only**: This tool should only be used on systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities through proper channels

### Operational Security
- **Network Isolation**: Run honeypots on isolated networks when possible
- **Data Protection**: Secure logging and monitoring data
- **Access Control**: Restrict access to the system and data
- **Regular Updates**: Keep the system and dependencies updated

### Countermeasures
- **File Entrapment**: Replace files with versions that track access
- **Network Poisoning**: Inject false information to mislead attackers
- **Time Delays**: Slow down attacker operations
- **Fake Vulnerabilities**: Present fake security holes to waste attacker time

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure running with appropriate privileges
   - Check file permissions

2. **Port Already in Use**
   - Change port numbers in configuration
   - Check for conflicting services

3. **Network Interface Issues**
   - Verify interface name
   - Check network configuration

4. **Database Errors**
   - Check database file permissions
   - Verify SQLite installation

### Logs and Debugging

- **Application Logs**: `/var/log/honeypot-interceptor/`
- **System Logs**: `journalctl -u honeypot-interceptor`
- **Debug Mode**: Use `--verbose` flag for detailed logging

## Advanced Configuration

### Custom Honeypots
Create custom honeypot servers by extending the `HoneypotServer` class:

```python
class CustomHoneypot(HoneypotServer):
    def _handle_connection(self, client_socket, address):
        # Custom connection handling
        pass
```

### Custom Attack Detection
Add custom detection rules:

```python
def custom_detection_patterns():
    return [
        r"custom_pattern",
        r"another_pattern"
    ]
```

### Integration with SIEM
Export data for integration with Security Information and Event Management systems:

```python
# Export data in JSON format
dashboard.export_data("siem_export.json")
```

## Performance Tuning

### Network Performance
- Adjust packet capture filters
- Optimize honeypot response times
- Configure rate limiting appropriately

### System Resources
- Monitor CPU and memory usage
- Adjust logging levels
- Configure log rotation

### Database Optimization
- Regular database maintenance
- Index optimization
- Data retention policies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse of this tool.
