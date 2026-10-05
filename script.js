
window.myThreatChart = null;
window.addEventListener('DOMContentLoaded', () => {
    const chartCtx = document.getElementById('threatChart');
    if (chartCtx) {
        window.myThreatChart = new Chart(chartCtx.getContext('2d'), {
            type: 'line', 
            data: {
                labels: ['loading data...'], 
                datasets: [{
                    label: 'Threat Count',
                    data: [1], 
                    backgroundColor: ['#334155'],
                    borderColor: '#38bdf8',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, 
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8' 
                        }
                    }
                }
            }
        });
    }
});

function updateChartData(newLabels, newData) {
    if (window.myThreatChart) {
        window.myThreatChart.data.labels = newLabels;
        window.myThreatChart.data.datasets[0].data = newData;
        window.myThreatChart.data.datasets[0].backgroundColor = ['#38bdf8', '#f43f5e', '#f59e0b', '#a855f7'];
        window.myThreatChart.update();
    }
}
function handleNewThreat(threatData) {
    if (threatData.confidence >= 0.85 || threatData.threat_type.includes('Attack')) {
        appendHighRiskNotification(threatData);
    }
}

function appendHighRiskNotification(threatData) {
    const container = document.getElementById('notification-list');
    if (!container) return; 

    const currentTime = threatData.timestamp || new Date().toLocaleString();

    const card = document.createElement('div');
    card.className = 'notification-card';
    
    card.innerHTML = `
        <div class="notification-info">
            <h4>${threatData.threat_type}</h4>
            <p>Source IP: ${threatData.source_ip} &rarr; Port: ${threatData.destination_port} (Confidence: ${threatData.confidence})</p>
        </div>
        <div class="notification-meta">
            <span class="badge-high">HIGH RISK</span>
            <div class="time-text">${currentTime}</div>
        </div>
    `;

    container.insertBefore(card, container.firstChild);
}

// ---------------------------------------------------------------
// Backend connection (reads data served by api.py)
// ---------------------------------------------------------------
const API = 'http://localhost:5000/api';
const seenAlerts = new Set();

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setStatus(online, reason) {
    const el = document.getElementById('status-indicator');
    if (!el) return;

    if (online) {
        el.textContent = 'Active';
        el.title = `Connected to ${API}`;
    } else {
        
        const unreachable = reason && reason.startsWith('Cannot reach');
        el.textContent = unreachable ? 'Backend offline' : 'Backend error';
        el.title = reason || '';   
    }
    el.className = online ? 'status online' : 'status offline';
}

function formatTime(iso) {
    return (iso || '').replace('T', ' ').slice(0, 19);
}

async function fetchJSON(path) {
    let res;
    try {
        res = await fetch(`${API}${path}`);
    } catch (e) {
        throw new Error(`Cannot reach ${API} (is main.py running? port blocked? CORS?)`);
    }
    if (!res.ok) throw new Error(`Backend answered HTTP ${res.status} for ${path}`);
    return res.json();
}

function alertRow(a) {
    return `
        <tr>
            <td>${formatTime(a.timestamp)}</td>
            <td>${a.threat_type}</td>
            <td>${a.source_ip}</td>
            <td>${a.source_port}</td>
            <td>${a.destination_ip}</td>
            <td>${a.destination_port}</td>
            <td><span>${Number(a.confidence).toFixed(2)}</span></td>
        </tr>`;
}

async function loadAlerts() {
    try {
        const { alerts, stats } = await fetchJSON('/alerts?limit=100');

        // stat cards
        setText('total-alerts', stats.total);
        setText('high-alerts', stats.high);
        setText('sig-threats', stats.signature);
        setText('anomaly-threats', stats.anomaly);

        // alert table (newest first)
        const tbody = document.getElementById('alerts-body');
        if (tbody) {
            tbody.innerHTML = alerts.map(alertRow).join('');
        }

        // chart
        updateChartData(Object.keys(stats.by_type), Object.values(stats.by_type));

        // notifications: oldest first so the newest ends up on top
        [...alerts].reverse().forEach(a => {
            const key = `${a.timestamp}|${a.source_ip}|${a.source_port}|${a.threat_type}`;
            if (seenAlerts.has(key)) return;
            seenAlerts.add(key);
            handleNewThreat({ ...a, timestamp: formatTime(a.timestamp) });
        });

        setStatus(true);
    } catch (err) {
        console.error('Failed to load alerts:', err);
        setStatus(false, err.message);
    }
}

async function loadPackets() {
    const tbody = document.getElementById('packets-body');
    if (!tbody) return;

    try {
        const packets = await fetchJSON('/packets?limit=50');
        tbody.innerHTML = packets.map(p => `
            <tr>
                <td>${p.time}</td>
                <td>${p.src}:${p.sport}</td>
                <td>${p.dst}:${p.dport}</td>
                <td>${p.flags}</td>
                <td>${p.length}</td>
            </tr>`).join('');
    } catch (err) {
        console.error('Failed to load packets:', err);
    }
}


let historyAlerts = [];

async function loadHistory() {
    const tbody = document.getElementById('history-alerts-body');
    if (!tbody) return;

    try {
        const { alerts } = await fetchJSON('/alerts?limit=100000');
        historyAlerts = alerts;
        tbody.innerHTML = alerts.map(alertRow).join('');
    } catch (err) {
        console.error('Failed to load history:', err);
    }
}

function downloadFile(filename, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
}

function setupExportButtons() {
    const jsonBtn = document.getElementById('export-json-btn');
    const csvBtn = document.getElementById('export-csv-btn');

    if (jsonBtn) {
        jsonBtn.addEventListener('click', () => {
            downloadFile('ids_alerts.json', JSON.stringify(historyAlerts, null, 2), 'application/json');
        });
    }

    if (csvBtn) {
        csvBtn.addEventListener('click', () => {
            const cols = ['timestamp', 'threat_type', 'source_ip', 'source_port',
                          'destination_ip', 'destination_port', 'confidence'];
            const rows = historyAlerts.map(a =>
                cols.map(c => `"${String(a[c] ?? '').replace(/"/g, '""')}"`).join(','));
            downloadFile('ids_alerts.csv', [cols.join(','), ...rows].join('\n'), 'text/csv');
        });
    }
}


window.addEventListener('DOMContentLoaded', () => {
    loadAlerts();
    loadPackets();
    loadHistory();
    setupExportButtons();
    setInterval(loadAlerts, 3000);
    setInterval(loadPackets, 2000);
    setInterval(loadHistory, 10000);
});