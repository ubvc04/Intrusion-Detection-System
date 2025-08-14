/**
 * Windows IDS - Main JavaScript
 * 
 * This file contains all the client-side functionality for the Windows IDS dashboard,
 * including event handling, chart rendering, and HTMX extensions.
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize variables
    let currentPage = 1;
    let pageSize = 20;
    let totalAlerts = 0;
    let currentFilters = {
        severity: 'all',
        source: 'all',
        timeframe: '24h'
    };
    
    // Initialize charts
    initializeCharts();
    
    // Update current time
    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);
    
    // Set up navigation
    setupNavigation();
    
    // Set up event listeners
    setupEventListeners();
    
    // Load initial data
    loadDashboardData();
});

/**
 * Initialize all charts on the dashboard
 */
function initializeCharts() {
    // Alert Trend Chart
    const alertTrendCtx = document.getElementById('alert-trend-chart').getContext('2d');
    window.alertTrendChart = new Chart(alertTrendCtx, {
        type: 'line',
        data: {
            labels: Array.from({length: 24}, (_, i) => `${23-i}h ago`).reverse(),
            datasets: [
                {
                    label: 'Critical',
                    data: Array(24).fill(0),
                    borderColor: '#991b1b',
                    backgroundColor: 'rgba(153, 27, 27, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'High',
                    data: Array(24).fill(0),
                    borderColor: '#dc2626',
                    backgroundColor: 'rgba(220, 38, 38, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Medium',
                    data: Array(24).fill(0),
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Low',
                    data: Array(24).fill(0),
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: '#e5e7eb'
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(75, 85, 99, 0.2)'
                    },
                    ticks: {
                        color: '#9ca3af'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(75, 85, 99, 0.2)'
                    },
                    ticks: {
                        color: '#9ca3af',
                        precision: 0
                    }
                }
            }
        }
    });
    
    // Alerts by Type Chart
    const alertsByTypeCtx = document.getElementById('alerts-by-type-chart').getContext('2d');
    window.alertsByTypeChart = new Chart(alertsByTypeCtx, {
        type: 'doughnut',
        data: {
            labels: ['Failed Login', 'Port Scan', 'File Change', 'Registry Change', 'Process Creation', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: [
                    '#3b82f6', // blue
                    '#8b5cf6', // purple
                    '#ec4899', // pink
                    '#f59e0b', // amber
                    '#10b981', // emerald
                    '#6b7280'  // gray
                ],
                borderWidth: 1,
                borderColor: '#1f2937'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e5e7eb'
                    }
                }
            }
        }
    });
    
    // Alerts by Source Chart
    const alertsBySourceCtx = document.getElementById('alerts-by-source-chart').getContext('2d');
    window.alertsBySourceChart = new Chart(alertsBySourceCtx, {
        type: 'doughnut',
        data: {
            labels: ['HIDS', 'NIDS', 'Correlation'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: [
                    '#3b82f6', // blue
                    '#f59e0b', // amber
                    '#8b5cf6'  // purple
                ],
                borderWidth: 1,
                borderColor: '#1f2937'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e5e7eb'
                    }
                }
            }
        }
    });
}

/**
 * Update the current time display
 */
function updateCurrentTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    const dateString = now.toLocaleDateString();
    document.getElementById('current-time').textContent = `${dateString} ${timeString}`;
}

/**
 * Set up navigation between sections
 */
function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.section-content');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all links
            navLinks.forEach(l => l.classList.remove('active'));
            
            // Add active class to clicked link
            this.classList.add('active');
            
            // Hide all sections
            sections.forEach(section => section.classList.add('hidden'));
            
            // Show the selected section
            const sectionId = this.getAttribute('data-section');
            document.getElementById(`${sectionId}-section`).classList.remove('hidden');
            
            // Load section-specific data
            if (sectionId === 'alerts') {
                loadAlertsData();
            } else if (sectionId === 'hosts') {
                loadHostsData();
            } else if (sectionId === 'dashboard') {
                loadDashboardData();
            }
        });
    });
    
    // Handle "View All" links
    document.querySelectorAll('a[data-section]').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const sectionId = this.getAttribute('data-section');
            
            // Activate the corresponding nav link
            document.querySelector(`.nav-link[data-section="${sectionId}"]`).click();
        });
    });
}

/**
 * Set up event listeners for various UI elements
 */
function setupEventListeners() {
    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', function() {
        const activeSection = document.querySelector('.section-content:not(.hidden)');
        const sectionId = activeSection.id.replace('-section', '');
        
        if (sectionId === 'dashboard') {
            loadDashboardData();
        } else if (sectionId === 'alerts') {
            loadAlertsData();
        } else if (sectionId === 'hosts') {
            loadHostsData();
        }
    });
    
    // Alert filters
    document.getElementById('severity-filter').addEventListener('change', function() {
        currentFilters.severity = this.value;
        currentPage = 1;
        loadAlertsData();
    });
    
    document.getElementById('source-filter').addEventListener('change', function() {
        currentFilters.source = this.value;
        currentPage = 1;
        loadAlertsData();
    });
    
    document.getElementById('timeframe-filter').addEventListener('change', function() {
        currentFilters.timeframe = this.value;
        currentPage = 1;
        loadAlertsData();
    });
    
    // Pagination
    document.getElementById('prev-page').addEventListener('click', function() {
        if (currentPage > 1) {
            currentPage--;
            loadAlertsData();
        }
    });
    
    document.getElementById('next-page').addEventListener('click', function() {
        if (currentPage * pageSize < totalAlerts) {
            currentPage++;
            loadAlertsData();
        }
    });
    
    // Modal close buttons
    document.getElementById('close-modal').addEventListener('click', closeAlertDetailModal);
    document.getElementById('close-alert-detail').addEventListener('click', closeAlertDetailModal);
    
    // Settings forms
    document.getElementById('general-settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        // Save settings to localStorage
        localStorage.setItem('refresh_interval', document.getElementById('refresh-interval').value);
        localStorage.setItem('data_retention', document.getElementById('data-retention').value);
        
        showNotification('Settings saved successfully');
    });
    
    document.getElementById('notification-settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        // Save settings to localStorage
        localStorage.setItem('browser_notifications', document.getElementById('browser-notifications').checked);
        localStorage.setItem('sound_alerts', document.getElementById('sound-alerts').checked);
        localStorage.setItem('notification_threshold', document.getElementById('notification-threshold').value);
        
        showNotification('Settings saved successfully');
    });
    
    // Load saved settings
    loadSavedSettings();
}

/**
 * Load saved settings from localStorage
 */
function loadSavedSettings() {
    // General settings
    const refreshInterval = localStorage.getItem('refresh_interval');
    if (refreshInterval) {
        document.getElementById('refresh-interval').value = refreshInterval;
    }
    
    const dataRetention = localStorage.getItem('data_retention');
    if (dataRetention) {
        document.getElementById('data-retention').value = dataRetention;
    }
    
    // Notification settings
    const browserNotifications = localStorage.getItem('browser_notifications');
    if (browserNotifications) {
        document.getElementById('browser-notifications').checked = browserNotifications === 'true';
    }
    
    const soundAlerts = localStorage.getItem('sound_alerts');
    if (soundAlerts) {
        document.getElementById('sound-alerts').checked = soundAlerts === 'true';
    }
    
    const notificationThreshold = localStorage.getItem('notification_threshold');
    if (notificationThreshold) {
        document.getElementById('notification-threshold').value = notificationThreshold;
    }
}

/**
 * Load dashboard data and update UI
 */
function loadDashboardData() {
    // Fetch alert statistics
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            updateAlertCounts(data.counts_by_severity);
            updateAlertTrendChart(data.hourly_counts);
            updateAlertsByTypeChart(data.counts_by_type);
            updateAlertsBySourceChart(data.counts_by_source);
        })
        .catch(error => {
            console.error('Error fetching dashboard data:', error);
        });
    
    // Recent alerts are loaded via HTMX
}

/**
 * Load alerts data based on current filters and pagination
 */
function loadAlertsData() {
    // Build query parameters
    const params = new URLSearchParams();
    params.append('page', currentPage);
    params.append('limit', pageSize);
    
    if (currentFilters.severity !== 'all') {
        params.append('severity', currentFilters.severity);
    }
    
    if (currentFilters.source !== 'all') {
        params.append('source', currentFilters.source);
    }
    
    if (currentFilters.timeframe !== 'all') {
        const now = new Date();
        let startTime;
        
        if (currentFilters.timeframe === '24h') {
            startTime = new Date(now - 24 * 60 * 60 * 1000);
        } else if (currentFilters.timeframe === '7d') {
            startTime = new Date(now - 7 * 24 * 60 * 60 * 1000);
        } else if (currentFilters.timeframe === '30d') {
            startTime = new Date(now - 30 * 24 * 60 * 60 * 1000);
        }
        
        if (startTime) {
            params.append('start_time', startTime.toISOString());
        }
    }
    
    // Fetch alerts
    fetch(`/api/events?${params.toString()}`)
        .then(response => response.json())
        .then(data => {
            renderAlertsTable(data.events);
            updatePagination(data.total, data.page, data.limit);
        })
        .catch(error => {
            console.error('Error fetching alerts data:', error);
        });
}

/**
 * Load hosts data
 */
function loadHostsData() {
    // Hosts are loaded via HTMX
}

/**
 * Update alert counts in the sidebar
 */
function updateAlertCounts(countsBySeverity) {
    document.getElementById('critical-count').textContent = countsBySeverity.critical || 0;
    document.getElementById('high-count').textContent = countsBySeverity.high || 0;
    document.getElementById('medium-count').textContent = countsBySeverity.medium || 0;
    document.getElementById('low-count').textContent = countsBySeverity.low || 0;
}

/**
 * Update the alert trend chart with hourly data
 */
function updateAlertTrendChart(hourlyData) {
    if (!hourlyData || !window.alertTrendChart) return;
    
    // Extract data for each severity level
    const criticalData = Array(24).fill(0);
    const highData = Array(24).fill(0);
    const mediumData = Array(24).fill(0);
    const lowData = Array(24).fill(0);
    
    // Populate data arrays
    for (const hour in hourlyData) {
        const hourIndex = parseInt(hour);
        if (hourIndex >= 0 && hourIndex < 24) {
            criticalData[hourIndex] = hourlyData[hour].critical || 0;
            highData[hourIndex] = hourlyData[hour].high || 0;
            mediumData[hourIndex] = hourlyData[hour].medium || 0;
            lowData[hourIndex] = hourlyData[hour].low || 0;
        }
    }
    
    // Update chart data
    window.alertTrendChart.data.datasets[0].data = criticalData;
    window.alertTrendChart.data.datasets[1].data = highData;
    window.alertTrendChart.data.datasets[2].data = mediumData;
    window.alertTrendChart.data.datasets[3].data = lowData;
    
    // Update chart
    window.alertTrendChart.update();
}

/**
 * Update the alerts by type chart
 */
function updateAlertsByTypeChart(countsByType) {
    if (!countsByType || !window.alertsByTypeChart) return;
    
    // Extract data for each type
    const data = [
        countsByType.failed_login || 0,
        countsByType.port_scan || 0,
        countsByType.file_change || 0,
        countsByType.registry_change || 0,
        countsByType.process_creation || 0,
        0 // Other
    ];
    
    // Calculate "Other" category
    let total = 0;
    let categorized = 0;
    
    for (const type in countsByType) {
        total += countsByType[type];
        if (['failed_login', 'port_scan', 'file_change', 'registry_change', 'process_creation'].includes(type)) {
            categorized += countsByType[type];
        }
    }
    
    data[5] = total - categorized; // Set "Other" value
    
    // Update chart data
    window.alertsByTypeChart.data.datasets[0].data = data;
    
    // Update chart
    window.alertsByTypeChart.update();
}

/**
 * Update the alerts by source chart
 */
function updateAlertsBySourceChart(countsBySource) {
    if (!countsBySource || !window.alertsBySourceChart) return;
    
    // Extract data for each source
    const data = [
        countsBySource.hids || 0,
        countsBySource.nids || 0,
        countsBySource.correlation || 0
    ];
    
    // Update chart data
    window.alertsBySourceChart.data.datasets[0].data = data;
    
    // Update chart
    window.alertsBySourceChart.update();
}

/**
 * Render the alerts table with the provided data
 */
function renderAlertsTable(alerts) {
    const tableBody = document.getElementById('alerts-table');
    
    if (!alerts || alerts.length === 0) {
        tableBody.innerHTML = `
            <tr class="text-center">
                <td colspan="7" class="py-4 text-gray-400">No alerts found</td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    
    alerts.forEach(alert => {
        const timestamp = new Date(alert.timestamp).toLocaleString();
        const severityClass = `severity-${alert.severity}`;
        
        html += `
            <tr class="table-row border-b border-gray-700" data-alert-id="${alert.id}">
                <td class="py-3 pr-4">${timestamp}</td>
                <td class="py-3 pr-4">
                    <span class="px-2 py-1 rounded text-xs font-medium ${severityClass}">${alert.severity}</span>
                </td>
                <td class="py-3 pr-4">${alert.source}</td>
                <td class="py-3 pr-4">${alert.type}</td>
                <td class="py-3 pr-4">${alert.details.hostname || alert.details.source_ip || 'N/A'}</td>
                <td class="py-3 pr-4">
                    ${alert.acknowledged ? 
                        '<span class="px-2 py-1 rounded text-xs font-medium bg-gray-600">Acknowledged</span>' : 
                        '<span class="px-2 py-1 rounded text-xs font-medium bg-blue-600">New</span>'}
                </td>
                <td class="py-3">
                    <button class="view-alert-btn px-2 py-1 bg-gray-700 rounded hover:bg-gray-600 text-sm" data-alert-id="${alert.id}">
                        View Details
                    </button>
                </td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
    
    // Add event listeners to view buttons
    document.querySelectorAll('.view-alert-btn').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.getAttribute('data-alert-id');
            openAlertDetailModal(alertId);
        });
    });
}

/**
 * Update pagination controls and info
 */
function updatePagination(total, page, limit) {
    totalAlerts = total;
    currentPage = page;
    pageSize = limit;
    
    // Update count text
    const start = (page - 1) * limit + 1;
    const end = Math.min(page * limit, total);
    document.getElementById('alerts-count').textContent = `Showing ${start}-${end} of ${total} alerts`;
    
    // Update button states
    document.getElementById('prev-page').disabled = page <= 1;
    document.getElementById('next-page').disabled = page * limit >= total;
}

/**
 * Open the alert detail modal for a specific alert
 */
function openAlertDetailModal(alertId) {
    // Fetch alert details
    fetch(`/api/events/${alertId}`)
        .then(response => response.json())
        .then(alert => {
            const modalContent = document.getElementById('alert-detail-content');
            const timestamp = new Date(alert.timestamp).toLocaleString();
            
            let detailsHtml = '';
            if (alert.details) {
                for (const [key, value] of Object.entries(alert.details)) {
                    if (key !== 'raw_data') { // Skip raw data for cleaner display
                        detailsHtml += `<div class="grid grid-cols-3 gap-4 mb-2">
                            <div class="font-medium">${formatKey(key)}</div>
                            <div class="col-span-2">${formatValue(value)}</div>
                        </div>`;
                    }
                }
                
                // Add raw data in a collapsible section if it exists
                if (alert.details.raw_data) {
                    detailsHtml += `
                        <div class="mt-4">
                            <button id="toggle-raw-data" class="text-blue-400 hover:text-blue-300 text-sm">Show Raw Data</button>
                            <pre id="raw-data" class="mt-2 p-3 bg-gray-900 rounded text-xs overflow-auto hidden">${alert.details.raw_data}</pre>
                        </div>
                    `;
                }
            }
            
            modalContent.innerHTML = `
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div>
                        <h4 class="text-lg font-medium mb-3">Alert Information</h4>
                        <div class="space-y-2">
                            <div class="grid grid-cols-3 gap-4">
                                <div class="font-medium">ID</div>
                                <div class="col-span-2">${alert.id}</div>
                            </div>
                            <div class="grid grid-cols-3 gap-4">
                                <div class="font-medium">Timestamp</div>
                                <div class="col-span-2">${timestamp}</div>
                            </div>
                            <div class="grid grid-cols-3 gap-4">
                                <div class="font-medium">Severity</div>
                                <div class="col-span-2">
                                    <span class="px-2 py-1 rounded text-xs font-medium severity-${alert.severity}">${alert.severity}</span>
                                </div>
                            </div>
                            <div class="grid grid-cols-3 gap-4">
                                <div class="font-medium">Source</div>
                                <div class="col-span-2">${alert.source}</div>
                            </div>
                            <div class="grid grid-cols-3 gap-4">
                                <div class="font-medium">Type</div>
                                <div class="col-span-2">${alert.type}</div>
                            </div>
                            <div class="grid grid-cols-3 gap-4">
                                <div class="font-medium">Status</div>
                                <div class="col-span-2">${alert.acknowledged ? 'Acknowledged' : 'New'}</div>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h4 class="text-lg font-medium mb-3">Details</h4>
                        <div class="space-y-2">
                            ${detailsHtml}
                        </div>
                    </div>
                </div>
                
                ${alert.correlated_with ? `
                <div class="mt-4">
                    <h4 class="text-lg font-medium mb-3">Correlation</h4>
                    <p>This event is correlated with event ID: ${alert.correlated_with}</p>
                    <button class="view-correlated-event mt-2 px-3 py-1 bg-blue-600 rounded hover:bg-blue-500 text-sm" data-event-id="${alert.correlated_with}">
                        View Correlated Event
                    </button>
                </div>
                ` : ''}
                
                ${alert.correlated_events && alert.correlated_events.length > 0 ? `
                <div class="mt-4">
                    <h4 class="text-lg font-medium mb-3">Correlated Events</h4>
                    <p>This correlation event includes the following events:</p>
                    <ul class="mt-2 space-y-1">
                        ${alert.correlated_events.map(eventId => `
                            <li>
                                <button class="view-correlated-event text-blue-400 hover:text-blue-300" data-event-id="${eventId}">
                                    Event ID: ${eventId}
                                </button>
                            </li>
                        `).join('')}
                    </ul>
                </div>
                ` : ''}
            `;
            
            // Show the modal
            document.getElementById('alert-detail-modal').classList.remove('hidden');
            
            // Set up the acknowledge button
            const acknowledgeBtn = document.getElementById('acknowledge-alert');
            acknowledgeBtn.setAttribute('data-alert-id', alert.id);
            acknowledgeBtn.textContent = alert.acknowledged ? 'Already Acknowledged' : 'Acknowledge';
            acknowledgeBtn.disabled = alert.acknowledged;
            acknowledgeBtn.classList.toggle('opacity-50', alert.acknowledged);
            acknowledgeBtn.classList.toggle('cursor-not-allowed', alert.acknowledged);
            
            // Add event listener to acknowledge button
            if (!alert.acknowledged) {
                acknowledgeBtn.addEventListener('click', acknowledgeAlert);
            }
            
            // Add event listener to toggle raw data
            const toggleRawDataBtn = document.getElementById('toggle-raw-data');
            if (toggleRawDataBtn) {
                toggleRawDataBtn.addEventListener('click', function() {
                    const rawData = document.getElementById('raw-data');
                    rawData.classList.toggle('hidden');
                    this.textContent = rawData.classList.contains('hidden') ? 'Show Raw Data' : 'Hide Raw Data';
                });
            }
            
            // Add event listeners to view correlated event buttons
            document.querySelectorAll('.view-correlated-event').forEach(button => {
                button.addEventListener('click', function() {
                    const eventId = this.getAttribute('data-event-id');
                    closeAlertDetailModal();
                    openAlertDetailModal(eventId);
                });
            });
        })
        .catch(error => {
            console.error('Error fetching alert details:', error);
        });
}

/**
 * Close the alert detail modal
 */
function closeAlertDetailModal() {
    document.getElementById('alert-detail-modal').classList.add('hidden');
    
    // Remove event listener from acknowledge button
    const acknowledgeBtn = document.getElementById('acknowledge-alert');
    acknowledgeBtn.removeEventListener('click', acknowledgeAlert);
}

/**
 * Acknowledge an alert
 */
function acknowledgeAlert() {
    const alertId = this.getAttribute('data-alert-id');
    
    fetch(`/api/events/${alertId}/acknowledge`, {
        method: 'POST'
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update button state
                this.textContent = 'Already Acknowledged';
                this.disabled = true;
                this.classList.add('opacity-50', 'cursor-not-allowed');
                
                // Update alert in table
                const alertRow = document.querySelector(`tr[data-alert-id="${alertId}"]`);
                if (alertRow) {
                    const statusCell = alertRow.querySelector('td:nth-child(6)');
                    statusCell.innerHTML = '<span class="px-2 py-1 rounded text-xs font-medium bg-gray-600">Acknowledged</span>';
                }
                
                showNotification('Alert acknowledged successfully');
            } else {
                showNotification('Failed to acknowledge alert', 'error');
            }
        })
        .catch(error => {
            console.error('Error acknowledging alert:', error);
            showNotification('Failed to acknowledge alert', 'error');
        });
}

/**
 * Format a key for display
 */
function formatKey(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Format a value for display
 */
function formatValue(value) {
    if (value === null || value === undefined) {
        return 'N/A';
    }
    
    if (typeof value === 'object') {
        return JSON.stringify(value, null, 2);
    }
    
    return value.toString();
}

/**
 * Show a notification
 */
function showNotification(message, type = 'success') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed bottom-4 right-4 px-4 py-2 rounded shadow-lg ${type === 'success' ? 'bg-green-600' : 'bg-red-600'}`;
    notification.textContent = message;
    
    // Add to document
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.classList.add('opacity-0', 'transition-opacity', 'duration-500');
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 500);
    }, 3000);
}

/**
 * HTMX extensions for rendering tables
 */
htmx.onLoad(function(content) {
    // Recent alerts table
    if (content.id === 'recent-alerts-table') {
        const alerts = JSON.parse(content.getAttribute('data-alerts') || '[]');
        let html = '';
        
        if (alerts.length === 0) {
            html = `
                <tr class="text-center">
                    <td colspan="5" class="py-4 text-gray-400">No recent alerts</td>
                </tr>
            `;
        } else {
            alerts.forEach(alert => {
                const timestamp = new Date(alert.timestamp).toLocaleString();
                const severityClass = `severity-${alert.severity}`;
                
                html += `
                    <tr class="table-row border-b border-gray-700" data-alert-id="${alert.id}">
                        <td class="py-3 pr-4">${timestamp}</td>
                        <td class="py-3 pr-4">
                            <span class="px-2 py-1 rounded text-xs font-medium ${severityClass}">${alert.severity}</span>
                        </td>
                        <td class="py-3 pr-4">${alert.source}</td>
                        <td class="py-3 pr-4">${alert.type}</td>
                        <td class="py-3">${alert.details.hostname || alert.details.source_ip || 'N/A'}</td>
                    </tr>
                `;
            });
        }
        
        content.innerHTML = html;
    }
    
    // Hosts grid
    if (content.id === 'hosts-grid') {
        const hosts = JSON.parse(content.getAttribute('data-hosts') || '[]');
        let html = '';
        
        if (hosts.length === 0) {
            html = `
                <div class="col-span-full text-center py-8 text-gray-400">
                    No hosts found
                </div>
            `;
        } else {
            hosts.forEach(host => {
                const lastSeen = new Date(host.last_seen).toLocaleString();
                
                html += `
                    <div class="card p-4">
                        <div class="flex justify-between items-start mb-4">
                            <h3 class="text-lg font-semibold">${host.hostname}</h3>
                            <span class="px-2 py-1 rounded text-xs font-medium bg-green-600">Online</span>
                        </div>
                        <div class="space-y-2 text-sm">
                            <div class="flex justify-between">
                                <span class="text-gray-400">IP Address:</span>
                                <span>${host.ip_address}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-400">OS:</span>
                                <span>${host.os || 'Windows'}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-400">Last Seen:</span>
                                <span>${lastSeen}</span>
                            </div>
                            <div class="flex justify-between">
                                <span class="text-gray-400">Event Count:</span>
                                <span>${host.event_count}</span>
                            </div>
                        </div>
                        <div class="mt-4 pt-4 border-t border-gray-700">
                            <div class="text-sm font-medium mb-2">Recent Alerts</div>
                            <div class="flex space-x-2">
                                <span class="px-2 py-1 rounded text-xs font-medium bg-red-600">${host.critical_count || 0} Critical</span>
                                <span class="px-2 py-1 rounded text-xs font-medium bg-red-500">${host.high_count || 0} High</span>
                                <span class="px-2 py-1 rounded text-xs font-medium bg-yellow-500">${host.medium_count || 0} Medium</span>
                            </div>
                        </div>
                    </div>
                `;
            });
        }
        
        content.innerHTML = html;
    }
});