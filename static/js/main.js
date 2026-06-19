// Z+ Security UI Actions & Chart Render Engine

/**
 * Renders the dashboard charts using Chart.js.
 * @param {Object} pieData - { Safe: count, Low: count, Medium: count, High: count }
 * @param {Array} barData - Array of { ip_address: str, failed_count: int }
 */
function initDashboardCharts(pieData, barData) {
    // 1. Render Threat Distribution Pie Chart
    const pieCtx = document.getElementById('threatPieChart');
    if (pieCtx) {
        new Chart(pieCtx, {
            type: 'doughnut',
            data: {
                labels: ['Safe Events', 'Low Threat', 'Medium Threat', 'High Threat'],
                datasets: [{
                    data: [
                        pieData.Safe || 0,
                        pieData.Low || 0,
                        pieData.Medium || 0,
                        pieData.High || 0
                    ],
                    backgroundColor: [
                        'rgba(0, 255, 170, 0.65)',  // Neon Green
                        'rgba(0, 243, 255, 0.65)',  // Neon Cyan
                        'rgba(255, 170, 0, 0.65)',  // Neon Orange
                        'rgba(255, 51, 102, 0.65)'  // Neon Red
                    ],
                    borderColor: [
                        '#00ffaa',
                        '#00f3ff',
                        '#ffaa00',
                        '#ff3366'
                    ],
                    borderWidth: 2,
                    hoverOffset: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            font: {
                                family: 'Inter',
                                size: 11
                            },
                            padding: 15
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                label += context.raw;
                                return label;
                            }
                        }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // 2. Render Failed Logins per IP Bar Chart
    const barCtx = document.getElementById('failedBarChart');
    if (barCtx) {
        const labels = barData.map(item => item.ip_address);
        const counts = barData.map(item => item.failed_count);
        
        new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Failed Login Operations',
                    data: counts,
                    backgroundColor: 'rgba(0, 243, 255, 0.2)',
                    borderColor: '#00f3ff',
                    borderWidth: 2,
                    borderRadius: 4,
                    hoverBackgroundColor: 'rgba(0, 243, 255, 0.45)',
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#94a3b8',
                            precision: 0
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#94a3b8',
                            maxRotation: 45,
                            minRotation: 45
                        },
                        grid: {
                            display: false
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
}

// --- Drag & Drop Log Upload Interactivity ---
document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('logFileInput');
    const uploadForm = document.getElementById('uploadForm');

    if (dropzone && fileInput) {
        // Handle clicking the zone to open selector
        dropzone.addEventListener('click', () => fileInput.click());

        // Highlight drop zone on drag events
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('dragover');
            }, false);
        });

        // Handle file drop
        dropzone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateDropzoneLabel(files[0].name);
            }
        });

        // Handle manual file selection
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                updateDropzoneLabel(fileInput.files[0].name);
            }
        });

        function updateDropzoneLabel(filename) {
            const infoText = dropzone.querySelector('.upload-desc');
            const titleText = dropzone.querySelector('.upload-title');
            if (titleText) {
                titleText.textContent = 'File Selected';
            }
            if (infoText) {
                infoText.innerHTML = `<b style="color: #00f3ff;">${filename}</b><br><span style="font-size: 0.8rem; color: #94a3b8;">Click upload to parse log records</span>`;
            }
            
            // Add a visual neon check
            const icon = dropzone.querySelector('.upload-icon i');
            if (icon) {
                icon.className = 'fas fa-file-shield';
                icon.parentElement.style.borderColor = '#00ffaa';
                icon.parentElement.style.color = '#00ffaa';
            }
        }
    }
});

// --- Dynamic Alert Status Management via API ---
function onAlertStatusChange(selectElement, alertId) {
    const newStatus = selectElement.value;
    const badgeElement = document.getElementById(`status-badge-${alertId}`);
    
    // Change select border color to neon temporary loading feedback
    selectElement.style.borderColor = '#00f3ff';
    
    fetch('/alerts/update_status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `alert_id=${alertId}&status=${newStatus}`
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Update badge text and classes dynamically
            if (badgeElement) {
                badgeElement.textContent = newStatus;
                // Remove existing status classes
                badgeElement.className = 'badge';
                // Add new status class
                if (newStatus === 'Open') {
                    badgeElement.classList.add('status-open');
                } else if (newStatus === 'Investigating') {
                    badgeElement.classList.add('status-investigating');
                } else if (newStatus === 'Resolved') {
                    badgeElement.classList.add('status-resolved');
                }
            }
            // Reset border color to normal success feedback
            selectElement.style.borderColor = '#00ffaa';
            setTimeout(() => {
                selectElement.style.borderColor = '';
            }, 1000);
        } else {
            alert('Failed to update alert status: ' + data.error);
            selectElement.style.borderColor = '#ff3366';
        }
    })
    .catch(error => {
        console.error('Error updating status:', error);
        alert('Network error while updating alert status.');
        selectElement.style.borderColor = '#ff3366';
    });
}
