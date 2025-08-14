// Dashboard JavaScript

// Initialize Socket.IO connection
let socket;
let eventsList = [];
let currentFilters = {};
let darkMode = localStorage.getItem('darkMode') === 'true';
let charts = {};

// DOM Elements
const eventContainer = document.getElementById('events-container');
const statsContainer = document.getElementById('stats-container');
const filterForm = document.getElementById('filter-form');
const searchInput = document.getElementById('search-input');
const darkModeToggle = document.getElementById('dark-mode-toggle');
const filterToggle = document.getElementById('filter-toggle');
const filterPanel = document.getElementById('filter-panel');
const notificationBadge = document.getElementById('notification-badge');
const eventModal = document.getElementById('event-modal');
const modalContent = document.getElementById('modal-content');
const closeModal = document.getElementById('close-modal');

// Apply dark mode if enabled
if (darkMode) {
    document.documentElement.classList.add('dark');
    if (darkModeToggle) {
        darkModeToggle.checked = true;
    }
}

// Initialize the dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeSocketConnection();
    setupEventListeners();
    loadInitialData();
});

// Initialize Socket.IO connection
function initializeSocketConnection() {
    socket = io('/events');
    
    // Socket event handlers
    socket.on('connect', () => {
        console.log('Connected to WebSocket server');
        showToast('Connected to server', 'success');
    });
    
    socket.on('disconnect', () => {
        console.log('Disconnected from WebSocket server');
        showToast('Disconnected from server', 'error');
    });
    
    socket.on('event', (data) => {
        console.log('Received event:', data);
        
        if (data.type === 'new_event') {
            // Add new event to the list
            addEvent(data.event);
            updateNotificationBadge();
            showToast(`New ${data.event.severity} event: ${data.event.type}`, 'info');
        } else if (data.type === 'acknowledge') {
            // Update acknowledged event
            updateAcknowledgedEvent(data.event.id);
        }
    });
}

// Setup event listeners
function setupEventListeners() {
    // Dark mode toggle
    if (darkModeToggle) {
        darkModeToggle.addEventListener('change', toggleDarkMode);
    }
    
    // Filter toggle
    if (filterToggle) {
        filterToggle.addEventListener('click', toggleFilterPanel);
    }
    
    // Filter form
    if (filterForm) {
        filterForm.addEventListener('submit', (e) => {
            e.preventDefault();
            applyFilters();
        });
    }
    
    // Search input
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            applyFilters();
        }, 500));
    }
    
    // Close modal
    if (closeModal) {
        closeModal.addEventListener('click', () => {
            eventModal.classList.remove('show');
        });
    }
    
    // Close modal when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === eventModal) {
            eventModal.classList.remove('show');
        }
    });
}

// Load initial data
function loadInitialData() {
    // Fetch events
    fetch('/api/events')
        .then(response => response.json())
        .then(data => {
            eventsList = data.events;
            renderEvents();
            updateNotificationBadge();
        })
        .catch(error => {
            console.error('Error fetching events:', error);
            showToast('Error fetching events', 'error');
        });
    
    // Fetch statistics
    fetch('/api/statistics')
        .then(response => response.json())
        .then(data => {
            renderStatistics(data);
        })
        .catch(error => {
            console.error('Error fetching statistics:', error);
            showToast('Error fetching statistics', 'error');
        });
}

// Add a new event to the list
function addEvent(event) {
    // Add to the beginning of the list
    eventsList.unshift(event);
    
    // Re-render events
    renderEvents();
    
    // Update statistics
    fetch('/api/statistics')
        .then(response => response.json())
        .then(data => {
            renderStatistics(data);
        })
        .catch(error => {
            console.error('Error fetching statistics:', error);
        });
}

// Render events list
function renderEvents() {
    if (!eventContainer) return;
    
    // Clear container
    eventContainer.innerHTML = '';
    
    // Filter events
    const filteredEvents = filterEvents(eventsList);
    
    if (filteredEvents.length === 0) {
        eventContainer.innerHTML = `
            <div class="p-4 text-center text-gray-500 dark:text-gray-400">
                <p>No events found</p>
            </div>
        `;
        return;
    }
    
    // Render each event
    filteredEvents.forEach(event => {
        const eventElement = createEventElement(event);
        eventContainer.appendChild(eventElement);
    });
}

// Create an event element
function createEventElement(event) {
    const div = document.createElement('div');
    div.className = `event-item p-4 mb-2 rounded-lg severity-${event.severity} ${event.acknowledged ? 'opacity-60' : ''}`;
    div.dataset.id = event.id;
    
    // Format timestamp
    const timestamp = new Date(event.timestamp);
    const formattedTime = timestamp.toLocaleString();
    
    // Get icon for event type
    const icon = getEventIcon(event.type);
    
    div.innerHTML = `
        <div class="flex items-start justify-between">
            <div class="flex items-start space-x-3">
                <div class="text-2xl ${getSeverityTextColor(event.severity)}">
                    <i class="fas ${icon}"></i>
                </div>
                <div>
                    <h3 class="font-semibold text-gray-900 dark:text-white">${event.type}</h3>
                    <p class="text-sm text-gray-600 dark:text-gray-300">${event.source}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400">${formattedTime}</p>
                </div>
            </div>
            <div class="flex items-center space-x-2">
                <span class="badge-${event.severity} text-xs px-2 py-1 rounded-full">${event.severity}</span>
                ${!event.acknowledged ? `
                    <button class="acknowledge-btn text-xs px-2 py-1 bg-gray-200 dark:bg-gray-700 rounded hover:bg-gray-300 dark:hover:bg-gray-600" data-id="${event.id}">
                        <i class="fas fa-check"></i>
                    </button>
                ` : `
                    <span class="text-xs px-2 py-1 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 rounded">
                        <i class="fas fa-check"></i> Acknowledged
                    </span>
                `}
            </div>
        </div>
        <p class="mt-2 text-sm text-gray-700 dark:text-gray-300">${getEventSummary(event)}</p>
        <button class="view-details-btn mt-2 text-xs text-blue-600 dark:text-blue-400 hover:underline" data-id="${event.id}">
            View Details
        </button>
    `;
    
    // Add event listeners
    const acknowledgeBtn = div.querySelector('.acknowledge-btn');
    if (acknowledgeBtn) {
        acknowledgeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            acknowledgeEvent(event.id);
        });
    }
    
    const viewDetailsBtn = div.querySelector('.view-details-btn');
    if (viewDetailsBtn) {
        viewDetailsBtn.addEventListener('click', () => {
            showEventDetails(event);
        });
    }
    
    // Add highlight animation for new events
    if (event.isNew) {
        div.classList.add('event-highlight');
        setTimeout(() => {
            event.isNew = false;
            div.classList.remove('event-highlight');
        }, 2000);
    }
    
    return div;
}

// Show event details in modal
function showEventDetails(event) {
    if (!eventModal || !modalContent) return;
    
    // Format timestamp
    const timestamp = new Date(event.timestamp);
    const formattedTime = timestamp.toLocaleString();
    
    // Format details
    let detailsHtml = '<div class="grid grid-cols-1 gap-2">';
    for (const [key, value] of Object.entries(event.details)) {
        detailsHtml += `
            <div class="border-b dark:border-gray-700 pb-2">
                <span class="font-semibold">${key}:</span> 
                <span class="text-gray-700 dark:text-gray-300">${value}</span>
            </div>
        `;
    }
    detailsHtml += '</div>';
    
    // Set modal content
    modalContent.innerHTML = `
        <div class="p-6">
            <div class="flex justify-between items-start mb-4">
                <h2 class="text-xl font-bold text-gray-900 dark:text-white">${event.type}</h2>
                <span class="badge-${event.severity} text-xs px-2 py-1 rounded-full">${event.severity}</span>
            </div>
            
            <div class="mb-4">
                <p class="text-sm text-gray-600 dark:text-gray-300"><span class="font-semibold">Source:</span> ${event.source}</p>
                <p class="text-sm text-gray-600 dark:text-gray-300"><span class="font-semibold">Time:</span> ${formattedTime}</p>
                <p class="text-sm text-gray-600 dark:text-gray-300"><span class="font-semibold">Status:</span> ${event.acknowledged ? 'Acknowledged' : 'Unacknowledged'}</p>
            </div>
            
            <div class="mb-4">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Details</h3>
                ${detailsHtml}
            </div>
            
            ${!event.acknowledged ? `
                <div class="mt-6 flex justify-end">
                    <button id="modal-acknowledge-btn" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700" data-id="${event.id}">
                        Acknowledge Event
                    </button>
                </div>
            ` : ''}
        </div>
    `;
    
    // Add event listener for acknowledge button
    const acknowledgeBtn = modalContent.querySelector('#modal-acknowledge-btn');
    if (acknowledgeBtn) {
        acknowledgeBtn.addEventListener('click', () => {
            acknowledgeEvent(event.id);
            eventModal.classList.remove('show');
        });
    }
    
    // Show modal
    eventModal.classList.add('show');
}

// Acknowledge an event
function acknowledgeEvent(eventId) {
    fetch(`/api/events/${eventId}/acknowledge`, {
        method: 'POST'
    })
        .then(response => {
            if (response.ok) {
                showToast('Event acknowledged', 'success');
            } else {
                throw new Error('Failed to acknowledge event');
            }
        })
        .catch(error => {
            console.error('Error acknowledging event:', error);
            showToast('Error acknowledging event', 'error');
        });
}

// Update acknowledged event in the UI
function updateAcknowledgedEvent(eventId) {
    // Update in the events list
    const eventIndex = eventsList.findIndex(e => e.id === eventId);
    if (eventIndex !== -1) {
        eventsList[eventIndex].acknowledged = true;
    }
    
    // Re-render events
    renderEvents();
    
    // Update notification badge
    updateNotificationBadge();
    
    // Update statistics
    fetch('/api/statistics')
        .then(response => response.json())
        .then(data => {
            renderStatistics(data);
        })
        .catch(error => {
            console.error('Error fetching statistics:', error);
        });
}

// Render statistics
function renderStatistics(data) {
    if (!statsContainer) return;
    
    // Clear container
    statsContainer.innerHTML = '';
    
    // Create statistics cards
    const totalEventsCard = createStatCard('Total Events', data.total_events, 'fa-chart-bar');
    const unacknowledgedCard = createStatCard('Unacknowledged', data.unacknowledged, 'fa-bell');
    
    // Add cards to container
    statsContainer.appendChild(totalEventsCard);
    statsContainer.appendChild(unacknowledgedCard);
    
    // Create severity distribution chart
    createSeverityChart(data.by_severity);
    
    // Create events over time chart
    createTimelineChart(data.over_time);
    
    // Create event types chart
    createEventTypesChart(data.by_type);
}

// Create a statistics card
function createStatCard(title, value, icon) {
    const div = document.createElement('div');
    div.className = 'stat-card bg-white dark:bg-gray-800 rounded-lg shadow p-4';
    
    div.innerHTML = `
        <div class="flex items-center justify-between">
            <div>
                <h3 class="text-lg font-semibold text-gray-700 dark:text-gray-300">${title}</h3>
                <p class="text-2xl font-bold text-gray-900 dark:text-white">${value}</p>
            </div>
            <div class="text-3xl text-blue-500 dark:text-blue-400">
                <i class="fas ${icon}"></i>
            </div>
        </div>
    `;
    
    return div;
}

// Create severity distribution chart
function createSeverityChart(severityData) {
    const chartContainer = document.createElement('div');
    chartContainer.className = 'chart-container bg-white dark:bg-gray-800 rounded-lg shadow p-4 mt-4';
    chartContainer.innerHTML = `
        <h3 class="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-4">Severity Distribution</h3>
        <canvas id="severity-chart"></canvas>
    `;
    
    statsContainer.appendChild(chartContainer);
    
    const ctx = document.getElementById('severity-chart').getContext('2d');
    
    // Prepare data
    const labels = Object.keys(severityData);
    const data = Object.values(severityData);
    const colors = labels.map(label => {
        if (label === 'critical') return '#ef4444';
        if (label === 'warning') return '#f59e0b';
        if (label === 'info') return '#3b82f6';
        return '#6b7280';
    });
    
    // Create chart
    if (charts.severityChart) {
        charts.severityChart.destroy();
    }
    
    charts.severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: darkMode ? '#f3f4f6' : '#1f2937'
                    }
                }
            }
        }
    });
}

// Create events over time chart
function createTimelineChart(timelineData) {
    const chartContainer = document.createElement('div');
    chartContainer.className = 'chart-container bg-white dark:bg-gray-800 rounded-lg shadow p-4 mt-4';
    chartContainer.innerHTML = `
        <h3 class="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-4">Events Over Time (Last 24 Hours)</h3>
        <canvas id="timeline-chart"></canvas>
    `;
    
    statsContainer.appendChild(chartContainer);
    
    const ctx = document.getElementById('timeline-chart').getContext('2d');
    
    // Prepare data
    const labels = timelineData.map(item => item.hour);
    const data = timelineData.map(item => item.count);
    
    // Create chart
    if (charts.timelineChart) {
        charts.timelineChart.destroy();
    }
    
    charts.timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Events',
                data: data,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        color: darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                    },
                    ticks: {
                        color: darkMode ? '#f3f4f6' : '#1f2937'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                    },
                    ticks: {
                        color: darkMode ? '#f3f4f6' : '#1f2937',
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Create event types chart
function createEventTypesChart(typesData) {
    const chartContainer = document.createElement('div');
    chartContainer.className = 'chart-container bg-white dark:bg-gray-800 rounded-lg shadow p-4 mt-4';
    chartContainer.innerHTML = `
        <h3 class="text-lg font-semibold text-gray-700 dark:text-gray-300 mb-4">Event Types</h3>
        <canvas id="types-chart"></canvas>
    `;
    
    statsContainer.appendChild(chartContainer);
    
    const ctx = document.getElementById('types-chart').getContext('2d');
    
    // Prepare data
    const labels = Object.keys(typesData);
    const data = Object.values(typesData);
    
    // Create chart
    if (charts.typesChart) {
        charts.typesChart.destroy();
    }
    
    charts.typesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Events',
                data: data,
                backgroundColor: '#3b82f6',
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: darkMode ? '#f3f4f6' : '#1f2937'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
                    },
                    ticks: {
                        color: darkMode ? '#f3f4f6' : '#1f2937',
                        precision: 0
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Filter events based on current filters
function filterEvents(events) {
    return events.filter(event => {
        // Apply severity filter
        if (currentFilters.severity && event.severity !== currentFilters.severity) {
            return false;
        }
        
        // Apply type filter
        if (currentFilters.type && event.type !== currentFilters.type) {
            return false;
        }
        
        // Apply source filter
        if (currentFilters.source && event.source !== currentFilters.source) {
            return false;
        }
        
        // Apply acknowledged filter
        if (currentFilters.acknowledged !== undefined) {
            if (currentFilters.acknowledged && !event.acknowledged) {
                return false;
            }
            if (!currentFilters.acknowledged && event.acknowledged) {
                return false;
            }
        }
        
        // Apply search filter
        if (currentFilters.search) {
            const search = currentFilters.search.toLowerCase();
            const matchesType = event.type.toLowerCase().includes(search);
            const matchesSource = event.source.toLowerCase().includes(search);
            const matchesDetails = JSON.stringify(event.details).toLowerCase().includes(search);
            
            if (!matchesType && !matchesSource && !matchesDetails) {
                return false;
            }
        }
        
        return true;
    });
}

// Apply filters from form
function applyFilters() {
    // Get filter values
    const severitySelect = document.getElementById('severity-filter');
    const typeSelect = document.getElementById('type-filter');
    const sourceSelect = document.getElementById('source-filter');
    const acknowledgedSelect = document.getElementById('acknowledged-filter');
    const search = searchInput ? searchInput.value : '';
    
    // Update current filters
    currentFilters = {
        severity: severitySelect && severitySelect.value !== 'all' ? severitySelect.value : null,
        type: typeSelect && typeSelect.value !== 'all' ? typeSelect.value : null,
        source: sourceSelect && sourceSelect.value !== 'all' ? sourceSelect.value : null,
        acknowledged: acknowledgedSelect && acknowledgedSelect.value !== 'all' ? acknowledgedSelect.value === 'true' : undefined,
        search: search
    };
    
    // Re-render events
    renderEvents();
    
    // Update notification badge
    updateNotificationBadge();
}

// Toggle dark mode
function toggleDarkMode() {
    darkMode = !darkMode;
    document.documentElement.classList.toggle('dark');
    localStorage.setItem('darkMode', darkMode);
    
    // Update charts
    if (charts.severityChart) {
        charts.severityChart.options.plugins.legend.labels.color = darkMode ? '#f3f4f6' : '#1f2937';
        charts.severityChart.update();
    }
    
    if (charts.timelineChart) {
        charts.timelineChart.options.scales.x.grid.color = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
        charts.timelineChart.options.scales.y.grid.color = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
        charts.timelineChart.options.scales.x.ticks.color = darkMode ? '#f3f4f6' : '#1f2937';
        charts.timelineChart.options.scales.y.ticks.color = darkMode ? '#f3f4f6' : '#1f2937';
        charts.timelineChart.update();
    }
    
    if (charts.typesChart) {
        charts.typesChart.options.scales.x.ticks.color = darkMode ? '#f3f4f6' : '#1f2937';
        charts.typesChart.options.scales.y.ticks.color = darkMode ? '#f3f4f6' : '#1f2937';
        charts.typesChart.options.scales.y.grid.color = darkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
        charts.typesChart.update();
    }
}

// Toggle filter panel
function toggleFilterPanel() {
    filterPanel.classList.toggle('show');
}

// Update notification badge
function updateNotificationBadge() {
    if (!notificationBadge) return;
    
    const unacknowledgedCount = eventsList.filter(event => !event.acknowledged).length;
    
    if (unacknowledgedCount > 0) {
        notificationBadge.textContent = unacknowledgedCount;
        notificationBadge.classList.remove('hidden');
    } else {
        notificationBadge.classList.add('hidden');
    }
}

// Show a toast notification
function showToast(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = 'toast';
    
    // Set background color based on type
    if (type === 'success') {
        toast.style.borderLeft = '4px solid #10b981';
    } else if (type === 'error') {
        toast.style.borderLeft = '4px solid #ef4444';
    } else {
        toast.style.borderLeft = '4px solid #3b82f6';
    }
    
    // Set content
    toast.innerHTML = `
        <div class="flex items-center">
            <div class="mr-2">
                <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
            </div>
            <div>
                <p class="text-sm font-medium text-gray-900 dark:text-white">${message}</p>
            </div>
        </div>
    `;
    
    // Add to document
    document.body.appendChild(toast);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.classList.add('hidden');
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}

// Get event icon based on type
function getEventIcon(type) {
    switch (type) {
        case 'file_integrity':
            return 'fa-file-alt';
        case 'registry':
            return 'fa-cogs';
        case 'process':
            return 'fa-microchip';
        case 'network':
            return 'fa-network-wired';
        case 'dns':
            return 'fa-globe';
        case 'http':
            return 'fa-cloud';
        case 'smtp':
            return 'fa-envelope';
        default:
            return 'fa-exclamation-circle';
    }
}

// Get severity text color
function getSeverityTextColor(severity) {
    switch (severity) {
        case 'critical':
            return 'text-red-500';
        case 'warning':
            return 'text-yellow-500';
        case 'info':
            return 'text-blue-500';
        default:
            return 'text-gray-500';
    }
}

// Get event summary
function getEventSummary(event) {
    let summary = '';
    
    switch (event.type) {
        case 'file_integrity':
            summary = `File ${event.details.path} was ${event.details.action}`;
            break;
        case 'registry':
            summary = `Registry key ${event.details.key} was ${event.details.action}`;
            break;
        case 'process':
            summary = `Process ${event.details.name} (PID: ${event.details.pid}) was ${event.details.action}`;
            break;
        case 'network':
            summary = `${event.details.protocol} connection from ${event.details.source_ip}:${event.details.source_port} to ${event.details.destination_ip}:${event.details.destination_port}`;
            break;
        case 'dns':
            summary = `DNS query for ${event.details.domain} (${event.details.query_type})`;
            break;
        case 'http':
            summary = `HTTP ${event.details.method} request to ${event.details.url}`;
            break;
        case 'smtp':
            summary = `SMTP message from ${event.details.sender} to ${event.details.recipient}`;
            break;
        default:
            summary = JSON.stringify(event.details);
    }
    
    return summary;
}

// Debounce function for search input
function debounce(func, wait) {
    let timeout;
    return function() {
        const context = this;
        const args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            func.apply(context, args);
        }, wait);
    };
}