# Honeypot Interceptor - Web UI

A modern web-based interface for monitoring and managing the Honeypot Interceptor system.

## Features

### Real-time Dashboard
- Live attack monitoring with WebSocket updates
- Real-time statistics and metrics
- Interactive charts and visualizations
- Responsive design for mobile and desktop

### Attack Management
- View recent attacks with detailed information
- Track attacker IP addresses and patterns
- Severity-based attack classification
- Export attack data for analysis

### Honeypot Control
- Start/stop honeypot services
- Monitor honeypot status and connections
- Configure honeypot settings
- View honeypot performance metrics

### Security Alerts
- Real-time security notifications
- High-severity attack alerts
- Repeated attacker warnings
- Customizable alert thresholds

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Start the web interface:
```bash
python main.py --mode web
```

3. Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

### Starting the Web Interface

```bash
# Start with default configuration
python main.py --mode web

# Start with custom configuration
python main.py --mode web --config custom_config.yaml

# Start with verbose logging
python main.py --mode web --verbose
```

### API Endpoints

The web interface provides several REST API endpoints:

- `GET /api/stats` - Get current statistics
- `GET /api/attacks` - Get recent attacks
- `GET /api/attackers` - Get top attackers
- `GET /api/honeypots` - Get honeypot status
- `GET /api/alerts` - Get security alerts
- `GET /api/status` - Get system status
- `POST /api/start` - Start the interceptor
- `POST /api/stop` - Stop the interceptor
- `GET /api/export` - Export data as JSON

### WebSocket Events

Real-time updates are provided via WebSocket:

- `connect` - Client connection established
- `disconnect` - Client disconnected
- `data_update` - Real-time data update
- `request_update` - Request data update from server

## Configuration

The web interface uses the same configuration file as the main application (`config.yaml`). Additional web-specific settings can be added:

```yaml
web_ui:
  host: "0.0.0.0"
  port: 5000
  debug: false
  auto_start: true  # Automatically start interceptor when web UI starts
```

## Security Considerations

- The web interface runs on all interfaces by default (0.0.0.0)
- Consider using a reverse proxy (nginx, Apache) for production
- Implement authentication for production deployments
- Use HTTPS in production environments
- Restrict access to the web interface using firewall rules

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in the configuration or stop the conflicting service
2. **WebSocket connection failed**: Check firewall settings and ensure port 5000 is accessible
3. **Data not updating**: Verify the interceptor is running and check browser console for errors

### Debug Mode

Enable debug mode for detailed logging:

```bash
python main.py --mode web --verbose
```

### Logs

Check the application logs for detailed information:

```bash
tail -f honeypot_interceptor.log
```

## Development

### Adding New Features

1. Add new routes in `web_app.py`
2. Create corresponding API endpoints
3. Update the frontend JavaScript in `static/js/dashboard.js`
4. Add new UI components in `templates/dashboard.html`

### Customizing the UI

- Modify `static/css/dashboard.css` for styling changes
- Update `templates/dashboard.html` for layout changes
- Add new JavaScript functionality in `static/js/dashboard.js`

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## License

This project is licensed under the MIT License - see the LICENSE file for details.

