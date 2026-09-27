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