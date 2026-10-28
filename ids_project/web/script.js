
const CHART_HORIZONTAL = false;
const THREAT_COLORS = {
    'Port Scan': '#38bdf8',
    'SYN Flood': '#f97316',
    'ICMP Flood': '#a78bfa',
    'ARP Spoofing': '#f472b6',
    'Known Bad Port': '#facc15',
    'Suspicious Flow': '#2dd4bf',
    'DoS Hulk': '#fb7185',
    'DDoS': '#c084fc',
    'SSH Brute Force': '#4ade80',
    'FTP Brute Force': '#60a5fa',
    'Other': '#94a3b8'
};
const FALLBACK_THREAT_COLORS = ['#818cf8', '#e879f9', '#f87171', '#a3e635', '#22d3ee', '#fbbf24', '#c4b5fd', '#34d399'];

window.myThreatChart = null;
window.addEventListener('DOMContentLoaded', () => {
    const chartCtx = document.getElementById('threatChart');
    if (chartCtx) {
        window.myThreatChart = new Chart(chartCtx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Alerts',
                    data: [],
                    backgroundColor: [],
                    borderWidth: 1,
                    borderRadius: 4,
                    maxBarThickness: 48
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: CHART_HORIZONTAL ? 'y' : 'x',
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            title: items => items[0].label,
                            label: item => `Count: ${item.parsed[CHART_HORIZONTAL ? 'x' : 'y']}`
                        }
                    }
                },
                scales: {
                    x: CHART_HORIZONTAL ? {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            color: '#94a3b8'
                        },
                        grid: {
                            color: 'rgba(148,163,184,0.15)'
                        }
                    } : {
                        ticks: {
                            color: '#94a3b8',
                            maxRotation: 40
                        },
                        grid: {
                            display: false
                        }
                    },
                    y: CHART_HORIZONTAL ? {
                        ticks: {
                            color: '#94a3b8'
                        },
                        grid: {
                            display: false
                        }
                    } : {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            color: '#94a3b8'
                        },
                        grid: {
                            color: 'rgba(148,163,184,0.15)'
                        }
                    }
                }
            }
        });
    }
});

function updateChartData(newLabels, newData) {
    if (window.myThreatChart) {
        const sortedThreats = newLabels.map((label, index) => ({
            label,
            count: newData[index]
        })).sort((a, b) => b.count - a.count);
        const visibleThreats = sortedThreats.slice(0, 8);

        if (sortedThreats.length > 8) {
            visibleThreats.push({
                label: 'Other',
                count: sortedThreats.slice(8).reduce((total, threat) => total + threat.count, 0)
            });
        }

        const getThreatColor = name => {
            if (THREAT_COLORS[name]) return THREAT_COLORS[name];

            let hash = 0;
            for (let index = 0; index < name.length; index++) {
                hash = (hash * 31 + name.charCodeAt(index)) | 0;
            }
            return FALLBACK_THREAT_COLORS[(hash >>> 0) % FALLBACK_THREAT_COLORS.length];
        };

        window.myThreatChart.data.labels = visibleThreats.map(threat => threat.label);
        window.myThreatChart.data.datasets[0].data = visibleThreats.map(threat => threat.count);
        window.myThreatChart.data.datasets[0].backgroundColor = visibleThreats.map(threat => getThreatColor(threat.label));
        window.myThreatChart.update('none');
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
                <td>${p.proto || ''}</td>
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

function setupClearButton() {
    const clearBtn = document.getElementById('clear-history-btn');
    if (!clearBtn) return;

    clearBtn.addEventListener('click', async () => {
        const confirmed = confirm(
            'Delete ALL alerts and traffic history? This cannot be undone. A backup of the JSON alert log will be kept.');
        if (!confirmed) return;

        clearBtn.disabled = true;
        try {
            const res = await fetch(`${API}/clear`, {
                method: 'POST',
                headers: { 'X-IDS-Action': 'clear' }
            });
            let result;
            try {
                result = await res.json();
            } catch (err) {
                if (!res.ok) throw new Error(`Backend answered HTTP ${res.status}`);
                throw err;
            }
            if (!res.ok) {
                throw new Error(result.error || `Backend answered HTTP ${res.status}`);
            }

            seenAlerts.clear();
            historyAlerts = [];
            ['history-alerts-body', 'alerts-body', 'packets-body',
             'traffic-body', 'notification-list'].forEach(id => {
                const element = document.getElementById(id);
                if (element) element.innerHTML = '';
            });
            ['total-alerts', 'high-alerts', 'sig-threats',
             'anomaly-threats'].forEach(id => setText(id, 0));
            updateChartData([], []);
            loadAlerts();
            loadHistory();
            loadPackets();
            alert('All alerts and history have been cleared.');
        } catch (err) {
            alert(`Failed to clear alerts and history: ${err.message}`);
        } finally {
            clearBtn.disabled = false;
        }
    });
}

window.addEventListener('DOMContentLoaded', () => {
    loadAlerts();
    loadPackets();
    loadHistory();
    setupExportButtons();
    setupClearButton();
    setInterval(loadAlerts, 3000);
    setInterval(loadPackets, 2000);
    setInterval(loadHistory, 10000);
});

// ---------------------------------------------------------------
// Live Traffic page (Wireshark-style packet table)
// ---------------------------------------------------------------
let trafficRows = [];
let trafficPaused = false;

// Packet info comes from the network, so escape it before putting it in the page
const esc = s => String(s ?? '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function loadTraffic() {
    const tbody = document.getElementById('traffic-body');
    if (!tbody || trafficPaused) return;

    const q = new URLSearchParams({ limit: 200 });
    ['ip', 'proto', 'port'].forEach(k => {
        const v = document.getElementById('f-' + k).value.trim();
        if (v) q.set(k, v);
    });

    try {
        trafficRows = await fetchJSON('/packets?' + q);
        tbody.innerHTML = trafficRows.map((p, i) => `
            <tr data-i="${i}">
                <td>${esc(p.id)}</td>
                <td>${esc(p.time)}</td>
                <td>${esc(p.src)}${p.sport ? ':' + esc(p.sport) : ''}</td>
                <td>${esc(p.dst)}${p.dport ? ':' + esc(p.dport) : ''}</td>
                <td>${esc(p.proto)}</td>
                <td>${esc(p.length)}</td>
                <td>${esc(p.info)}</td>
            </tr>`).join('');
        setStatus(true);
    } catch (err) {
        console.error('Failed to load traffic:', err);
        setStatus(false, err.message);
    }
}

function setupTraffic() {
    const tbody = document.getElementById('traffic-body');
    if (!tbody) return;

    tbody.addEventListener('click', e => {
        const tr = e.target.closest('tr');
        if (!tr) return;
        document.getElementById('packet-detail').textContent =
            JSON.stringify(trafficRows[tr.dataset.i], null, 2);
    });

    const pause = document.getElementById('pause-btn');
    pause.addEventListener('click', () => {
        trafficPaused = !trafficPaused;
        pause.textContent = trafficPaused ? 'Resume' : 'Pause';
    });
    document.getElementById('apply-btn').addEventListener('click', loadTraffic);

    loadTraffic();
    setInterval(loadTraffic, 2000);
}
window.addEventListener('DOMContentLoaded', setupTraffic);
