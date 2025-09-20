"""
File Replacement Module
Handles replacement of real files with honeypot versions containing tracking code
"""

import os
import shutil
import time
import hashlib
from typing import Dict, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class FileReplacer:
    """Manages replacement of files with honeypot versions"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.enabled = config.get('enabled', True)
        self.decoy_directory = Path(config.get('decoy_directory', './decoy_files'))
        self.tracking_enabled = config.get('tracking_enabled', True)
        self.target_files = config.get('target_files', [])
        
        # Create decoy directory if it doesn't exist
        self.decoy_directory.mkdir(exist_ok=True)
        
        # Track original files
        self.original_files = {}
        self.replaced_files = set()
        
    def replace_file(self, file_path: str) -> bool:
        """Replace a file with a honeypot version"""
        try:
            if not self.enabled:
                return False
                
            file_path = Path(file_path)
            if not file_path.exists():
                logger.warning(f"File {file_path} does not exist")
                return False
            
            # Check if file matches target patterns
            if not self._is_target_file(file_path):
                return False
            
            # Backup original file
            backup_path = self._backup_original_file(file_path)
            if not backup_path:
                return False
            
            # Create honeypot version
            honeypot_path = self._create_honeypot_file(file_path)
            if not honeypot_path:
                return False
            
            # Replace the file
            shutil.copy2(honeypot_path, file_path)
            self.replaced_files.add(str(file_path))
            
            logger.info(f"Replaced {file_path} with honeypot version")
            return True
            
        except Exception as e:
            logger.error(f"Error replacing file {file_path}: {e}")
            return False
    
    def restore_file(self, file_path: str) -> bool:
        """Restore original file from backup"""
        try:
            file_path = Path(file_path)
            backup_path = self.original_files.get(str(file_path))
            
            if not backup_path or not Path(backup_path).exists():
                logger.warning(f"No backup found for {file_path}")
                return False
            
            # Restore original file
            shutil.copy2(backup_path, file_path)
            self.replaced_files.discard(str(file_path))
            
            logger.info(f"Restored {file_path} from backup")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring file {file_path}: {e}")
            return False
    
    def _is_target_file(self, file_path: Path) -> bool:
        """Check if file matches target patterns"""
        file_str = str(file_path)
        
        for pattern in self.target_files:
            if self._match_pattern(file_str, pattern):
                return True
        
        return False
    
    def _match_pattern(self, file_path: str, pattern: str) -> bool:
        """Simple pattern matching (supports * wildcards)"""
        import fnmatch
        return fnmatch.fnmatch(file_path, pattern)
    
    def _backup_original_file(self, file_path: Path) -> Optional[Path]:
        """Create backup of original file"""
        try:
            backup_dir = self.decoy_directory / "backups"
            backup_dir.mkdir(exist_ok=True)
            
            # Create unique backup name
            timestamp = int(time.time())
            backup_name = f"{file_path.name}.backup.{timestamp}"
            backup_path = backup_dir / backup_name
            
            # Copy original file
            shutil.copy2(file_path, backup_path)
            
            # Store backup path
            self.original_files[str(file_path)] = str(backup_path)
            
            return backup_path
            
        except Exception as e:
            logger.error(f"Error backing up file {file_path}: {e}")
            return None
    
    def _create_honeypot_file(self, file_path: Path) -> Optional[Path]:
        """Create honeypot version of file"""
        try:
            honeypot_dir = self.decoy_directory / "honeypots"
            honeypot_dir.mkdir(exist_ok=True)
            
            honeypot_path = honeypot_dir / file_path.name
            
            # Create honeypot content based on file type
            if file_path.suffix == '.py':
                content = self._create_python_honeypot(file_path)
            elif file_path.suffix in ['.sh', '.bash']:
                content = self._create_shell_honeypot(file_path)
            elif file_path.name in ['passwd', 'shadow']:
                content = self._create_auth_honeypot(file_path)
            else:
                content = self._create_generic_honeypot(file_path)
            
            # Write honeypot content
            with open(honeypot_path, 'w') as f:
                f.write(content)
            
            return honeypot_path
            
        except Exception as e:
            logger.error(f"Error creating honeypot file {file_path}: {e}")
            return None
    
    def _create_python_honeypot(self, file_path: Path) -> str:
        """Create Python honeypot with tracking code"""
        tracking_code = f'''
# Honeypot tracking code
import os, sys, subprocess, socket, time, json, hashlib

def track_access():
    """Track file access and collect system information"""
    try:
        data = {{
            'file_path': '{file_path}',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'system_info': {{
                'platform': sys.platform,
                'python_version': sys.version,
                'hostname': socket.gethostname(),
                'user': os.getenv('USER', 'unknown'),
                'pid': os.getpid(),
                'cwd': os.getcwd()
            }},
            'network_info': {{
                'local_ip': socket.gethostbyname(socket.gethostname()),
                'interfaces': get_network_interfaces()
            }}
        }}
        
        # Send tracking data
        send_tracking_data(data)
        
    except Exception as e:
        pass

def get_network_interfaces():
    """Get network interface information"""
    try:
        import psutil
        interfaces = {{}}
        for interface, addrs in psutil.net_if_addrs().items():
            interfaces[interface] = [addr.address for addr in addrs if addr.family == socket.AF_INET]
        return interfaces
    except:
        return {{}}

def send_tracking_data(data):
    """Send tracking data to monitoring system"""
    try:
        # In practice, this would send to a monitoring server
        tracking_file = '/tmp/honeypot_tracking.json'
        with open(tracking_file, 'a') as f:
            f.write(json.dumps(data) + '\\n')
    except:
        pass

# Execute tracking when file is imported/executed
track_access()

# Original file content would be here
# This is a honeypot file designed to track attacker behavior
'''
        return tracking_code
    
    def _create_shell_honeypot(self, file_path: Path) -> str:
        """Create shell script honeypot with tracking"""
        tracking_code = f'''#!/bin/bash
# Honeypot tracking code

# Track file execution
track_execution() {{
    echo "$(date): Honeypot file {file_path} executed by $$" >> /tmp/honeypot_tracking.log
    echo "System info:" >> /tmp/honeypot_tracking.log
    uname -a >> /tmp/honeypot_tracking.log
    whoami >> /tmp/honeypot_tracking.log
    pwd >> /tmp/honeypot_tracking.log
    env >> /tmp/honeypot_tracking.log
}}

# Execute tracking
track_execution

# Original script content would be here
# This is a honeypot file designed to track attacker behavior
'''
        return tracking_code
    
    def _create_auth_honeypot(self, file_path: Path) -> str:
        """Create authentication file honeypot"""
        if file_path.name == 'passwd':
            return '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:107::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:116::/nonexistent:/bin/false
avahi-autoipd:x:110:117:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:118:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/dnsmasq:/bin/false
colord:x:113:121:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:122:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:123:RealtimeKit,,,:/proc:/bin/false
saned:x:119:124::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
'''
        else:  # shadow file
            return '''root:$6$rounds=4096$salt$hash:18000:0:99999:7:::
daemon:*:18000:0:99999:7:::
bin:*:18000:0:99999:7:::
sys:*:18000:0:99999:7:::
sync:*:18000:0:99999:7:::
games:*:18000:0:99999:7:::
man:*:18000:0:99999:7:::
lp:*:18000:0:99999:7:::
mail:*:18000:0:99999:7:::
news:*:18000:0:99999:7:::
uucp:*:18000:0:99999:7:::
proxy:*:18000:0:99999:7:::
www-data:*:18000:0:99999:7:::
backup:*:18000:0:99999:7:::
list:*:18000:0:99999:7:::
irc:*:18000:0:99999:7:::
gnats:*:18000:0:99999:7:::
nobody:*:18000:0:99999:7:::
systemd-timesync:*:18000:0:99999:7:::
systemd-network:*:18000:0:99999:7:::
systemd-resolve:*:18000:0:99999:7:::
systemd-bus-proxy:*:18000:0:99999:7:::
syslog:*:18000:0:99999:7:::
_apt:*:18000:0:99999:7:::
messagebus:*:18000:0:99999:7:::
uuidd:*:18000:0:99999:7:::
lightdm:*:18000:0:99999:7:::
whoopsie:*:18000:0:99999:7:::
avahi-autoipd:*:18000:0:99999:7:::
avahi:*:18000:0:99999:7:::
dnsmasq:*:18000:0:99999:7:::
colord:*:18000:0:99999:7:::
speech-dispatcher:*:18000:0:99999:7:::
hplip:*:18000:0:99999:7:::
kernoops:*:18000:0:99999:7:::
pulse:*:18000:0:99999:7:::
rtkit:*:18000:0:99999:7:::
saned:*:18000:0:99999:7:::
usbmux:*:18000:0:99999:7:::
'''
    
    def _create_generic_honeypot(self, file_path: Path) -> str:
        """Create generic honeypot file"""
        return f'''# Honeypot File: {file_path}
# This file has been replaced with a honeypot version
# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}

# This is a decoy file designed to track attacker behavior
# Original content has been backed up and replaced

# Embedded tracking code would be here in a real implementation
'''
    
    def get_status(self) -> Dict:
        """Get status of file replacement system"""
        return {
            'enabled': self.enabled,
            'replaced_files': list(self.replaced_files),
            'backup_count': len(self.original_files),
            'decoy_directory': str(self.decoy_directory)
        }
