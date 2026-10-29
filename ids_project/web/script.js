
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
    if (threatData.id !== undefined && threatData.id !== null) {
        card.dataset.id = threatData.id;
        card.classList.add('clickable');
    }
    
    card.innerHTML = `
        <div class="notification-info">
            <h4>${esc(threatData.threat_type)}</h4>
            <p>Source IP: ${esc(threatData.source_ip)} &rarr; Port: ${esc(threatData.destination_port)} (Confidence: ${esc(threatData.confidence)})</p>
        </div>
        <div class="notification-meta">
            <span class="badge-high">HIGH RISK</span>
            <div class="time-text">${esc(currentTime)}</div>
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
        <tr data-id="${esc(a.id)}" class="clickable">
            <td>${esc(formatTime(a.timestamp))}</td>
            <td>${esc(a.threat_type)}</td>
            <td>${esc(a.source_ip)}</td>
            <td>${esc(a.source_port)}</td>
            <td>${esc(a.destination_ip)}</td>
            <td>${esc(a.destination_port)}</td>
            <td><span>${esc(Number(a.confidence).toFixed(2))}</span></td>
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

const THREAT_INFO = {
    'Port Scan': {
        description: 'One address probed many ports on a target in a short time, usually to find open services before an attack.',
        actions: [
            'Check whether the source is one of your own devices or a known scanner.',
            'If it is not authorised, block the source IP at the firewall.',
            'Look at which ports answered, because those services are exposed.'
        ]
    },
    'PortScan': {
        description: 'One address probed many ports on a target in a short time, usually to find open services before an attack.',
        actions: [
            'Check whether the source is one of your own devices or a known scanner.',
            'If it is not authorised, block the source IP at the firewall.',
            'Look at which ports answered, because those services are exposed.'
        ]
    },
    'SYN Flood': {
        description: 'A source sent a very large number of connection requests (SYN packets) to one service without finishing them, which can use up the server\'s resources.',
        actions: [
            'Check whether the target service is slow or unreachable.',
            'Rate-limit or block the source.',
            'Turn on SYN cookies on the server if available.'
        ]
    },
    'ICMP Flood': {
        description: 'A source sent a large number of ping requests, which can use up bandwidth or slow a device.',
        actions: [
            'Check the target device for slowness.',
            'Rate-limit or block ICMP from the source.',
            'Confirm it is not a monitoring tool you run.'
        ]
    },
    'ARP Spoofing': {
        description: 'A device claimed an IP address that was earlier linked to a different hardware (MAC) address. Attackers do this to intercept traffic. It can also happen after a legitimate change such as replacing a router.',
        actions: [
            'Compare the old and new MAC addresses in Live Traffic (filter by ARP).',
            'Find the device with the new MAC address and disconnect it if it is unknown.',
            'Enable dynamic ARP inspection on the switch if available.'
        ]
    },
    'Known Bad Port': {
        description: 'Traffic used a port often linked to backdoors or malware, such as 4444 or 31337.',
        actions: [
            'Find which program on the device uses that port.',
            'Run an antivirus scan on that device.',
            'Block the port at the firewall if it is not needed.'
        ]
    },
    'Suspicious Flow': {
        description: 'The AI saw traffic that looks unusual compared with normal traffic but does not match a known attack. Confidence is lower and it may be a false alarm or something new.',
        actions: [
            'Check whether the destination is a service you recognise.',
            'Watch whether the same source keeps appearing.',
            'Investigate further only if it repeats or the destination is unknown.'
        ]
    },
    'FTP Brute Force': {
        description: 'Many quick login attempts against an FTP server, trying to guess a password.',
        actions: [
            'Check the FTP server logs for failed logins.',
            'Block the source IP.',
            'Use strong passwords and lock accounts after repeated failures.'
        ]
    },
    'FTP-Patator': {
        description: 'Many quick login attempts against an FTP server, trying to guess a password.',
        actions: [
            'Check the FTP server logs for failed logins.',
            'Block the source IP.',
            'Use strong passwords and lock accounts after repeated failures.'
        ]
    },
    'SSH Brute Force': {
        description: 'Many quick login attempts against an SSH server, trying to guess a password.',
        actions: [
            'Check the SSH logs for failed logins.',
            'Block the source IP.',
            'Use key-based login and disable password login if possible.'
        ]
    },
    'SSH-Patator': {
        description: 'Many quick login attempts against an SSH server, trying to guess a password.',
        actions: [
            'Check the SSH logs for failed logins.',
            'Block the source IP.',
            'Use key-based login and disable password login if possible.'
        ]
    },
    'Slow HTTP DoS': {
        description: 'Connections to a web server were kept open for a long time while sending almost nothing, which can use up the server\'s connection slots.',
        actions: [
            'Shorten connection timeouts on the web server.',
            'Limit connections per IP.',
            'Put a reverse proxy in front of the server.'
        ]
    },
    'DoS slowloris': {
        description: 'Connections to a web server were kept open for a long time while sending almost nothing, which can use up the server\'s connection slots.',
        actions: [
            'Shorten connection timeouts on the web server.',
            'Limit connections per IP.',
            'Put a reverse proxy in front of the server.'
        ]
    },
    'DoS Slowhttptest': {
        description: 'Connections to a web server were kept open for a long time while sending almost nothing, which can use up the server\'s connection slots.',
        actions: [
            'Shorten connection timeouts on the web server.',
            'Limit connections per IP.',
            'Put a reverse proxy in front of the server.'
        ]
    },
    'DoS Hulk': {
        description: 'A flood of web requests meant to overload a server.',
        actions: [
            'Check the web server load.',
            'Rate-limit or block the source addresses.',
            'Contact the network team if the flood continues.'
        ]
    },
    'DoS GoldenEye': {
        description: 'A flood of web requests meant to overload a server.',
        actions: [
            'Check the web server load.',
            'Rate-limit or block the source addresses.',
            'Contact the network team if the flood continues.'
        ]
    },
    'DDoS': {
        description: 'A flood of web requests meant to overload a server. DDoS means it comes from many sources.',
        actions: [
            'Check the web server load.',
            'Rate-limit or block the source addresses.',
            'Contact the network team if the flood continues.'
        ]
    },
    'Port 444 Attack': {
        description: 'The flow used destination port 444, which this IDS treats as suspicious.',
        actions: [
            'Check which program on the device uses this port.',
            'Review the related traffic and determine whether it is expected.',
            'Block the port at the firewall if it is not needed.'
        ]
    },
    'Bot': {
        description: 'The flow was classified as bot-related traffic by the detector.',
        actions: [
            'Check the source device for unfamiliar programs.',
            'Review related traffic and whether the destination is expected.',
            'Run an antivirus scan if the activity is not recognised.'
        ]
    },
    'Web Attack - Brute Force': {
        description: 'The flow was classified as a web attack involving repeated attempts to gain access.',
        actions: [
            'Review the web server logs for repeated failed attempts.',
            'Block the source IP if the activity is not authorised.',
            'Use strong credentials and limit repeated login attempts.'
        ]
    },
    'Web Attack - XSS': {
        description: 'The flow was classified as web traffic associated with a cross-site scripting attack.',
        actions: [
            'Review the affected web server logs and requests.',
            'Check whether the application safely handles user input.',
            'Investigate further if the activity is not expected.'
        ]
    },
    'Web Attack - Sql Injection': {
        description: 'The flow was classified as web traffic associated with an SQL injection attack.',
        actions: [
            'Review the affected web server logs and requests.',
            'Check whether database queries use parameterized inputs.',
            'Investigate further if the activity is not expected.'
        ]
    },
    'Infiltration': {
        description: 'The flow was classified as possible infiltration activity by the detector.',
        actions: [
            'Check the source and destination devices for unfamiliar activity.',
            'Review related traffic and system logs.',
            'Contact the network team if the activity is not recognised.'
        ]
    }
};

let alertModal;
let alertModalData = null;
let alertModalRequest = 0;
let alertModalPreviousFocus = null;

function createAlertModal() {
    if (alertModal) return alertModal;

    const overlay = document.createElement('div');
    overlay.className = 'alert-modal-overlay';
    overlay.hidden = true;
    overlay.innerHTML = `
        <section class="alert-modal" role="dialog" aria-modal="true"
                 aria-label="Alert details" tabindex="-1">
            <button type="button" class="alert-modal-close" aria-label="Close alert details">&times;</button>
            <div class="alert-modal-content" id="alert-modal-content"></div>
        </section>`;
    document.body.appendChild(overlay);
    alertModal = overlay;

    overlay.addEventListener('click', event => {
        if (event.target === overlay) closeAlertDetails();
    });
    overlay.querySelector('.alert-modal-close').addEventListener('click', closeAlertDetails);
    overlay.querySelector('.alert-modal').addEventListener('click', event => {
        const button = event.target.closest('[data-action]');
        if (!button || !alertModalData) return;
        if (button.dataset.action === 'copy') copyAlertAsJson(button);
        if (button.dataset.action === 'traffic') {
            const query = new URLSearchParams({ ip: alertModalData.alert.source_ip || '' });
            window.location.href = `traffic.html?${query}`;
        }
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && !alertModal.hidden) closeAlertDetails();
    });
    return alertModal;
}

function closeAlertDetails() {
    if (!alertModal || alertModal.hidden) return;
    alertModal.hidden = true;
    document.body.classList.remove('alert-modal-open');
    alertModalData = null;
    alertModalRequest++;
    if (alertModalPreviousFocus && alertModalPreviousFocus.isConnected) {
        alertModalPreviousFocus.focus();
    }
}

function detectorName(detector) {
    return ({
        signature: 'Signature rule',
        random_forest: 'Random Forest (AI, known attack type)',
        isolation_forest: 'Isolation Forest (AI, unusual behaviour)'
    })[detector] || detector || 'Unknown';
}

function alertWhyFlagged(alert, confidencePercent) {
    if (alert.detector === 'signature') return 'A fixed rule matched this traffic.';
    if (alert.detector === 'random_forest') {
        return `The Random Forest model classified this flow as ${alert.threat_type} with ${confidencePercent}% certainty.`;
    }
    if (alert.detector === 'isolation_forest') {
        return 'This flow looked unusual compared with normal traffic but did not match a known attack. This is lower confidence and may be a false alarm.';
    }
    return `The ${detectorName(alert.detector)} detector raised this alert.`;
}

function renderAlertDetails(data) {
    alertModalData = data;
    const alert = data.alert;
    const confidence = Number(alert.confidence);
    const safeConfidence = Number.isFinite(confidence) ? confidence : 0;
    const confidencePercent = (safeConfidence * 100).toFixed(1);
    const severity = safeConfidence >= 0.85 ? 'high' : safeConfidence >= 0.70 ? 'medium' : 'low';
    const threatInfo = THREAT_INFO[alert.threat_type] || {
        description: `The detector classified this traffic as ${alert.threat_type || 'an unknown threat'}. Review the related traffic to decide whether it is expected.`,
        actions: [
            'Check whether the source and destination are recognised.',
            'Review the related packets and any matching system logs.',
            'Investigate further if the activity is repeated or unexpected.'
        ]
    };
    const packets = Array.isArray(data.related_packets) ? data.related_packets : [];
    const rows = packets.map(packet => `
        <tr>
            <td>${esc(formatTime(packet.time))}</td>
            <td>${esc(packet.src)}${packet.sport ? ':' + esc(packet.sport) : ''}</td>
            <td>${esc(packet.dst)}${packet.dport ? ':' + esc(packet.dport) : ''}</td>
            <td>${esc(packet.proto)}</td>
            <td>${esc(packet.flags)}</td>
            <td>${esc(packet.length)}</td>
            <td>${esc(packet.info)}</td>
        </tr>`).join('');
    const content = alertModal.querySelector('#alert-modal-content');
    content.innerHTML = `
        <div class="alert-modal-header">
            <div>
                <h2>${esc(alert.threat_type || 'Unknown threat')}</h2>
                <span class="severity-badge severity-${severity}">${severity.toUpperCase()}</span>
                <span class="alert-confidence">${confidencePercent}% confidence</span>
            </div>
        </div>
        <div class="alert-summary-grid">
            <div><span>Time</span><strong>${esc(formatTime(alert.timestamp))}</strong></div>
            <div><span>Source</span><strong>${esc(alert.source_ip)}:${esc(alert.source_port)}</strong></div>
            <div><span>Destination</span><strong>${esc(alert.destination_ip)}:${esc(alert.destination_port)}</strong></div>
            <div><span>Detected by</span><strong>${esc(detectorName(alert.detector))}</strong></div>
            <div><span>Confidence</span><strong>${confidencePercent}%</strong></div>
        </div>
        <section class="alert-modal-section">
            <h3>What is this?</h3>
            <p>${esc(threatInfo.description)}</p>
        </section>
        <section class="alert-modal-section">
            <h3>What to do</h3>
            <ul>${threatInfo.actions.map(action => `<li>${esc(action)}</li>`).join('')}</ul>
        </section>
        <section class="alert-modal-section">
            <h3>Why was it flagged?</h3>
            <p>${esc(alertWhyFlagged(alert, confidencePercent))}</p>
        </section>
        <section class="alert-modal-section">
            <h3>Recent packets between these addresses</h3>
            <p class="alert-packet-note">Most recent packets, which may be empty if they are older than the packet history we keep.</p>
            <div class="alert-packet-table-wrap">
                <table class="alert-packet-table">
                    <thead><tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Flags</th><th>Length</th><th>Info</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="7">No related packets found.</td></tr>'}</tbody>
                </table>
            </div>
        </section>
        <p class="alert-similar-count">Similar alerts from this source: ${esc(data.similar_alerts)}</p>
        <div class="alert-modal-actions">
            <button type="button" class="btn secondary" data-action="copy">Copy alert as JSON</button>
            <button type="button" class="btn" data-action="traffic">View in Live Traffic</button>
            <span class="alert-copy-status" aria-live="polite"></span>
        </div>`;
}

async function openAlertDetails(id) {
    const overlay = createAlertModal();
    alertModalPreviousFocus = document.activeElement;
    alertModalData = null;
    const requestId = ++alertModalRequest;
    overlay.hidden = false;
    document.body.classList.add('alert-modal-open');
    overlay.querySelector('#alert-modal-content').innerHTML =
        '<p class="alert-modal-loading" role="status">Loading...</p>';
    overlay.querySelector('.alert-modal-close').focus();

    try {
        const data = await fetchJSON(`/alerts/${encodeURIComponent(id)}`);
        if (requestId !== alertModalRequest || overlay.hidden) return;
        if (!data || !data.alert) throw new Error('The server returned incomplete alert details.');
        renderAlertDetails(data);
    } catch (error) {
        if (requestId !== alertModalRequest || overlay.hidden) return;
        overlay.querySelector('#alert-modal-content').innerHTML =
            `<p class="alert-modal-error">${esc(`Could not load alert details: ${error.message}`)}</p>`;
    }
}

async function copyAlertAsJson(button) {
    const status = button.closest('.alert-modal-actions').querySelector('.alert-copy-status');
    const json = JSON.stringify(alertModalData.alert, null, 2);
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(json);
        } else {
            throw new Error('Clipboard API unavailable');
        }
    } catch (clipboardError) {
        try {
            const textarea = document.createElement('textarea');
            textarea.value = json;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            const copied = document.execCommand('copy');
            textarea.remove();
            if (!copied) throw new Error('The browser denied clipboard access.');
        } catch (fallbackError) {
            status.textContent = `Copy failed: ${fallbackError.message || clipboardError.message}`;
            return;
        }
    }
    status.textContent = 'Copied';
}

function setupAlertDetailClicks() {
    ['alerts-body', 'history-alerts-body'].forEach(id => {
        const tbody = document.getElementById(id);
        if (!tbody) return;
        tbody.addEventListener('click', event => {
            const row = event.target.closest('tr[data-id]');
            if (row && row.dataset.id) openAlertDetails(row.dataset.id);
        });
    });

    const notifications = document.getElementById('notification-list');
    if (notifications) {
        notifications.addEventListener('click', event => {
            const card = event.target.closest('.notification-card[data-id]');
            if (card && card.dataset.id) openAlertDetails(card.dataset.id);
        });
    }
}

window.addEventListener('DOMContentLoaded', setupAlertDetailClicks);

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

    const ip = new URLSearchParams(window.location.search).get('ip');
    if (ip) document.getElementById('f-ip').value = ip;

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
