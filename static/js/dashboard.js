// Dashboard JavaScript for Honeypot Interceptor

class HoneypotDashboard {
    constructor() {
        this.socket = null;
        this.isConnected = false;
        this.updateInterval = null;
        this.init();
    }

    init() {
        this.initializeSocket();
        this.bindEvents();
        this.loadInitialData();
        this.startPeriodicUpdates();
    }

    initializeSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.isConnected = true;
            this.updateConnectionStatus(true);
            this.showNotification('Connected to server', 'success');
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.isConnected = false;
            this.updateConnectionStatus(false);
            this.showNotification('Disconnected from server', 'warning');
        });

        this.socket.on('data_update', (data) => {
            this.updateDashboard(data);
        });

        this.socket.on('error', (error) => {
            console.error('Socket error:', error);
            this.showNotification('Error: ' + error.message, 'danger');
        });
    }

    bindEvents() {
        // Control buttons
        document.getElementById('start-btn').addEventListener('click', () => {
            this.startInterceptor();
        });

        document.getElementById('stop-btn').addEventListener('click', () => {
            this.stopInterceptor();
        });

        document.getElementById('refresh-btn').addEventListener('click', () => {
            this.refreshData();
        });

        document.getElementById('export-btn').addEventListener('click', () => {
            this.exportData();
        });
    }

    async loadInitialData() {
        try {
            await Promise.all([
                this.loadStats(),
                this.loadAttacks(),
                this.loadAttackers(),
                this.loadHoneypots(),
                this.loadAlerts(),
                this.loadStatus()
            ]);
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showNotification('Error loading data', 'danger');
        }
    }

    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();
            
            if (data.success) {
                this.updateStats(data.data);
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    }

    async loadAttacks() {
        try {
            const response = await fetch('/api/attacks?limit=20');
            const data = await response.json();
            
            if (data.success) {
                this.updateAttacksTable(data.data);
            }
        } catch (error) {
            console.error('Error loading attacks:', error);
        }
    }

    async loadAttackers() {
        try {
            const response = await fetch('/api/attackers?limit=10');
            const data = await response.json();
            
            if (data.success) {
                this.updateAttackersList(data.data);
            }
        } catch (error) {
            console.error('Error loading attackers:', error);
        }
    }

    async loadHoneypots() {
        try {
            const response = await fetch('/api/honeypots');
            const data = await response.json();
            
            if (data.success) {
                this.updateHoneypotsGrid(data.data);
            }
        } catch (error) {
            console.error('Error loading honeypots:', error);
        }
    }

    async loadAlerts() {
        try {
            const response = await fetch('/api/alerts');
            const data = await response.json();
            
            if (data.success) {
                this.updateAlertsList(data.data);
            }
        } catch (error) {
            console.error('Error loading alerts:', error);
        }
    }

    async loadStatus() {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            
            if (data.success) {
                this.updateSystemStatus(data.data);
            }
        } catch (error) {
            console.error('Error loading status:', error);
        }
    }

    updateDashboard(data) {
        if (data.stats) this.updateStats(data.stats);
        if (data.recent_attacks) this.updateAttacksTable(data.recent_attacks);
        if (data.top_attackers) this.updateAttackersList(data.top_attackers);
        if (data.alerts) this.updateAlertsList(data.alerts);
    }

    updateStats(stats) {
        document.getElementById('total-attacks').textContent = stats.total_attacks || 0;
        document.getElementById('unique-attackers').textContent = stats.unique_attackers || 0;
        document.getElementById('recent-attacks').textContent = stats.recent_attacks || 0;
    }

    updateAttacksTable(attacks) {
        const tbody = document.getElementById('attacks-table');
        
        if (!attacks || attacks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No attacks detected</td></tr>';
            return;
        }

        tbody.innerHTML = attacks.map(attack => {
            const timestamp = new Date(attack.timestamp).toLocaleTimeString();
            const severity = this.getSeverityClass(attack.severity || 0);
            const severityText = this.getSeverityText(attack.severity || 0);
            const payload = attack.payload ? this.truncateText(attack.payload, 50) : 'N/A';
            
            return `
                <tr>
                    <td>${timestamp}</td>
                    <td><code>${attack.src_ip}</code></td>
                    <td>${attack.attack_type || 'Unknown'}</td>
                    <td><span class="${severity}">${severityText}</span></td>
                    <td><small>${payload}</small></td>
                </tr>
            `;
        }).join('');
    }

    updateAttackersList(attackers) {
        const container = document.getElementById('attackers-list');
        
        if (!attackers || attackers.length === 0) {
            container.innerHTML = '<p class="text-muted text-center">No attackers detected</p>';
            return;
        }

        container.innerHTML = attackers.map(attacker => {
            const firstSeen = new Date(attacker.first_seen).toLocaleDateString();
            const lastSeen = new Date(attacker.last_seen).toLocaleDateString();
            
            return `
                <div class="attacker-item">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <div class="attacker-ip">${attacker.src_ip}</div>
                            <small class="text-muted">
                                First: ${firstSeen} | Last: ${lastSeen}
                            </small>
                        </div>
                        <div class="text-end">
                            <div class="attack-count text-danger">${attacker.attack_count}</div>
                            <small class="text-muted">attacks</small>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    updateHoneypotsGrid(honeypots) {
        const container = document.getElementById('honeypots-grid');
        
        if (!honeypots || honeypots.length === 0) {
            container.innerHTML = '<div class="col-12"><p class="text-muted text-center">No honeypots configured</p></div>';
            return;
        }

        container.innerHTML = honeypots.map(honeypot => {
            const statusClass = honeypot.status === 'running' ? 'running' : 'stopped';
            const statusIcon = honeypot.status === 'running' ? 'fa-check-circle' : 'fa-times-circle';
            
            return `
                <div class="col-md-4">
                    <div class="honeypot-card ${statusClass}">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="mb-1">${honeypot.name}</h6>
                                <small class="text-muted">Port ${honeypot.port} - ${honeypot.service}</small>
                            </div>
                            <div class="text-end">
                                <i class="fas ${statusIcon} honeypot-status ${statusClass}"></i>
                                <div class="small text-muted">${honeypot.connections} connections</div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    updateAlertsList(alerts) {
        const container = document.getElementById('alerts-list');
        
        if (!alerts || alerts.length === 0) {
            container.innerHTML = '<p class="text-muted text-center">No alerts</p>';
            return;
        }

        container.innerHTML = alerts.map(alert => {
            const alertClass = this.getAlertClass(alert.type);
            const timestamp = new Date(alert.timestamp).toLocaleString();
            
            return `
                <div class="alert-item ${alertClass}">
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <strong>${alert.message}</strong>
                            <div class="small text-muted">${timestamp}</div>
                        </div>
                        <span class="badge bg-danger">${alert.severity}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    updateSystemStatus(status) {
        const statusElement = document.getElementById('system-status');
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        
        if (status.running) {
            statusElement.textContent = 'Running';
            statusElement.className = 'text-success';
            startBtn.disabled = true;
            stopBtn.disabled = false;
        } else {
            statusElement.textContent = 'Stopped';
            statusElement.className = 'text-danger';
            startBtn.disabled = false;
            stopBtn.disabled = true;
        }
    }

    updateConnectionStatus(connected) {
        const indicator = document.getElementById('status-indicator');
        const icon = indicator.querySelector('i');
        
        if (connected) {
            indicator.className = 'navbar-text connected';
            icon.className = 'fas fa-circle text-success';
            indicator.innerHTML = '<i class="fas fa-circle text-success"></i> Connected';
        } else {
            indicator.className = 'navbar-text disconnected';
            icon.className = 'fas fa-circle text-danger';
            indicator.innerHTML = '<i class="fas fa-circle text-danger"></i> Disconnected';
        }
    }

    async startInterceptor() {
        try {
            const response = await fetch('/api/start', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                this.showNotification('Interceptor started successfully', 'success');
                this.loadStatus();
            } else {
                this.showNotification(data.message || 'Failed to start interceptor', 'danger');
            }
        } catch (error) {
            console.error('Error starting interceptor:', error);
            this.showNotification('Error starting interceptor', 'danger');
        }
    }

    async stopInterceptor() {
        try {
            const response = await fetch('/api/stop', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                this.showNotification('Interceptor stopped successfully', 'success');
                this.loadStatus();
            } else {
                this.showNotification(data.message || 'Failed to stop interceptor', 'danger');
            }
        } catch (error) {
            console.error('Error stopping interceptor:', error);
            this.showNotification('Error stopping interceptor', 'danger');
        }
    }

    async refreshData() {
        this.showNotification('Refreshing data...', 'info');
        await this.loadInitialData();
        this.showNotification('Data refreshed', 'success');
    }

    async exportData() {
        try {
            const response = await fetch('/api/export');
            const data = await response.json();
            
            if (data.success) {
                const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = data.filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
                this.showNotification('Data exported successfully', 'success');
            } else {
                this.showNotification('Failed to export data', 'danger');
            }
        } catch (error) {
            console.error('Error exporting data:', error);
            this.showNotification('Error exporting data', 'danger');
        }
    }

    startPeriodicUpdates() {
        // Update every 30 seconds
        this.updateInterval = setInterval(() => {
            if (this.isConnected) {
                this.socket.emit('request_update');
            }
        }, 30000);
    }

    getSeverityClass(severity) {
        if (severity >= 8) return 'severity-critical';
        if (severity >= 6) return 'severity-high';
        if (severity >= 4) return 'severity-medium';
        return 'severity-low';
    }

    getSeverityText(severity) {
        if (severity >= 8) return 'Critical';
        if (severity >= 6) return 'High';
        if (severity >= 4) return 'Medium';
        return 'Low';
    }

    getAlertClass(type) {
        switch (type) {
            case 'high_severity': return 'alert-danger';
            case 'repeated_attacks': return 'alert-warning';
            default: return 'alert-info';
        }
    }

    truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    showNotification(message, type = 'info') {
        const toast = document.getElementById('notification-toast');
        const toastMessage = document.getElementById('toast-message');
        
        toastMessage.textContent = message;
        toast.className = `toast show`;
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            toast.className = 'toast';
        }, 5000);
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new HoneypotDashboard();
});
