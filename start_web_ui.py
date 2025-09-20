#!/usr/bin/env python3
"""
Quick start script for the Honeypot Interceptor Web UI
"""

import sys
import os
import yaml
from pathlib import Path

def main():
    """Start the web UI with proper configuration"""
    
    # Check if config file exists
    config_path = "config.yaml"
    if not os.path.exists(config_path):
        print("Error: config.yaml not found!")
        print("Please ensure you have a valid configuration file.")
        sys.exit(1)
    
    # Load configuration
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        print("✓ Configuration loaded successfully")
    except Exception as e:
        print(f"Error loading configuration: {e}")
        sys.exit(1)
    
    # Import and start web UI
    try:
        from web_app import create_web_ui
        
        print("Starting Honeypot Interceptor Web UI...")
        print("Web interface will be available at: http://localhost:5000")
        print("Press Ctrl+C to stop")
        print("-" * 50)
        
        web_ui = create_web_ui(config)
        web_ui.run(host='0.0.0.0', port=5000, debug=False)
        
    except ImportError as e:
        print(f"Error importing web_app: {e}")
        print("Please install required dependencies: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting web UI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
