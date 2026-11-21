
const API_BASE_URL = "http://127.0.0.1:8000";


// Fetch JSON data from an API endpoint.
async function fetchAPI(endpoint) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`);

    if (!response.ok) {
        throw new Error(`API request failed: ${response.status}`);
    }

    return await response.json();
}


// Parse database timestamps as UTC when no timezone is specified.
function parseTimestamp(timestamp) {
    if (!timestamp) {
        return null;
    }

    const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/i.test(timestamp);
    const normalizedTimestamp = hasTimezone
        ? timestamp
        : `${timestamp}Z`;

    const date = new Date(normalizedTimestamp);

    return Number.isNaN(date.getTime()) ? null : date;
}


// Format timestamps for dashboard display.
function formatTimestamp(timestamp) {
    const date = parseTimestamp(timestamp);

    if (!date) {
        return "--";
    }

    return date.toLocaleString();
}


// Update system threat status.
async function updateStatus() {
    const status = await fetchAPI("/status");

    document.getElementById("threat-level").textContent =
        status.threat_level;

    document.getElementById("threat-score").textContent =
        status.threat_score;

    document.getElementById("total-events").textContent =
        status.total_events;
}


// Update recent alerts.
async function updateAlerts() {
    const alerts = await fetchAPI("/alerts");
    const table = document.getElementById("alerts-table");

    table.innerHTML = "";

    if (alerts.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="4" class="text-secondary">
                    No alerts recorded.
                </td>
            </tr>
        `;
        return;
    }

    alerts.slice(0, 10).forEach(alert => {
        const row = document.createElement("tr");

        const values = [
            formatTimestamp(alert.timestamp),
            alert.alert_type,
            alert.severity,
            alert.message
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value ?? "--";
            row.appendChild(cell);
        });

        table.appendChild(row);
    });
}


// Update recent filesystem events.
async function updateEvents() {
    const events = await fetchAPI("/events");
    const table = document.getElementById("events-table");

    table.innerHTML = "";

    if (events.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="4" class="text-secondary">
                    No filesystem events recorded.
                </td>
            </tr>
        `;
        return;
    }

    events.slice(0, 10).forEach(event => {
        const row = document.createElement("tr");

        const values = [
            formatTimestamp(event.timestamp),
            event.event_type,
            event.source_path,
            event.entropy
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value ?? "--";
            row.appendChild(cell);
        });

        table.appendChild(row);
    });
}


// Calculate and display the most frequently modified files.
async function updateModifiedFiles() {
    const events = await fetchAPI("/events");
    const fileCounts = {};

    events.forEach(event => {
        const filePath = event.source_path;

        if (!filePath || event.is_directory) {
            return;
        }

        fileCounts[filePath] = (fileCounts[filePath] || 0) + 1;
    });

    const sortedFiles = Object.entries(fileCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    const table = document.getElementById("modified-files-table");

    table.innerHTML = "";

    if (sortedFiles.length === 0) {
        table.innerHTML = `
            <tr>
                <td colspan="2" class="text-secondary">
                    No file activity recorded.
                </td>
            </tr>
        `;
        return;
    }

    sortedFiles.forEach(([filePath, count]) => {
        const row = document.createElement("tr");

        const pathCell = document.createElement("td");
        pathCell.textContent = filePath;

        const countCell = document.createElement("td");
        countCell.textContent = count;

        row.appendChild(pathCell);
        row.appendChild(countCell);

        table.appendChild(row);
    });
}


// Initialize the monitoring chart.
let monitoringChart = null;


// Convert a timestamp into a UTC minute key.
function getMinuteKey(timestamp) {
    const date = parseTimestamp(timestamp);

    if (!date) {
        return null;
    }

    return date.toISOString().slice(0, 16);
}


// Calculate averages for each minute.
function calculateMinuteAverages(records, valueField) {
    const groupedValues = {};

    records.forEach(record => {
        const minuteKey = getMinuteKey(record.timestamp);

        if (!minuteKey) {
            return;
        }

        const value = Number(record[valueField]);

        if (!Number.isFinite(value)) {
            return;
        }

        if (!groupedValues[minuteKey]) {
            groupedValues[minuteKey] = [];
        }

        groupedValues[minuteKey].push(value);
    });

    const averages = {};

    Object.entries(groupedValues).forEach(([minuteKey, values]) => {
        averages[minuteKey] =
            values.reduce((sum, value) => sum + value, 0) / values.length;
    });

    return averages;
}


// Format minute labels in the computer's local timezone.
function formatMinuteLabel(minuteKey) {
    const date = new Date(`${minuteKey}:00Z`);

    return date.toLocaleString(undefined, {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit"
    });
}


// Update CPU and entropy monitoring chart.
async function updateMonitoringChart() {
    const [processes, events] = await Promise.all([
        fetchAPI("/processes"),
        fetchAPI("/events")
    ]);

    // Aggregate CPU readings by minute.
    const cpuAverages = calculateMinuteAverages(
        processes,
        "cpu_percent"
    );

    // Aggregate valid file entropy readings by minute.
    const entropyEvents = events.filter(event =>
        event.entropy !== null &&
        event.entropy !== undefined
    );

    const entropyAverages = calculateMinuteAverages(
        entropyEvents,
        "entropy"
    );

    // Combine timestamps from both datasets.
    const minuteKeys = [
        ...new Set([
            ...Object.keys(cpuAverages),
            ...Object.keys(entropyAverages)
        ])
    ].sort();

    // Generate readable local-time labels.
    const labels = minuteKeys.map(formatMinuteLabel);

    // Preserve gaps when a dataset has no reading for a minute.
    const cpuData = minuteKeys.map(minuteKey =>
        cpuAverages[minuteKey] ?? null
    );

    const entropyData = minuteKeys.map(minuteKey =>
        entropyAverages[minuteKey] ?? null
    );

    const chartData = {
        labels: labels,
        datasets: [
            {
                label: "Average CPU Usage (%)",
                data: cpuData,
                borderColor: "#0d6efd",
                backgroundColor: "rgba(13, 110, 253, 0.2)",
                tension: 0.3,
                spanGaps: false
            },
            {
                label: "Average File Entropy",
                data: entropyData,
                borderColor: "#dc3545",
                backgroundColor: "rgba(220, 53, 69, 0.2)",
                tension: 0.3,
                spanGaps: false
            }
        ]
    };

    if (monitoringChart) {
        monitoringChart.data = chartData;
        monitoringChart.update();
        return;
    }

    const context = document
        .getElementById("monitoring-chart")
        .getContext("2d");

    monitoringChart = new Chart(context, {
        type: "line",
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: "#f1f1f1"
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        color: "#adb5bd",
                        maxRotation: 45,
                        minRotation: 0,
                        autoSkip: true,
                        maxTicksLimit: 12
                    },
                    grid: {
                        color: "#343a40"
                    }
                },
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: "#adb5bd"
                    },
                    grid: {
                        color: "#343a40"
                    }
                }
            }
        }
    });
}


// Refresh all dashboard sections.
async function refreshDashboard() {
    const updates = [
        updateStatus(),
        updateAlerts(),
        updateEvents(),
        updateModifiedFiles(),
        updateMonitoringChart()
    ];

    const results = await Promise.allSettled(updates);

    results.forEach((result, index) => {
        if (result.status === "rejected") {
            console.error(
                `Dashboard section ${index + 1} failed to update:`,
                result.reason
            );
        }
    });
}


// Initial dashboard load.
refreshDashboard();


// Refresh dashboard data every five seconds.
setInterval(refreshDashboard, 5000);
