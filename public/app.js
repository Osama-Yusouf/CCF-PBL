// System Clock UTC Updater
function updateClock() {
    const timeEl = document.getElementById('system-time');
    if (!timeEl) return;
    const now = new Date();
    const utcStr = now.toISOString().replace('T', ' ').substring(0, 19);
    timeEl.textContent = `UTC: ${utcStr}`;
}
setInterval(updateClock, 1000);
updateClock();

// Global SOC State representation
let socState = {
    threatLevel: 0,
    ingressRate: 0,
    activeAlerts: [],
    auditTrail: [],
    networkNodes: [],
    autopilotBannerActive: true
};

// Chart.js instances
let vectorChart, trendChart;

// Initialize charts once
function initCharts() {
    const ctxVector = document.getElementById('vectorChart').getContext('2d');
    vectorChart = new Chart(ctxVector, {
        type: 'doughnut',
        data: {
            labels: ['Brute Force', 'SQL Injection', 'DDoS Reflection', 'Data Exfiltration', 'Malware Activity'],
            datasets: [{
                data: [35, 25, 20, 15, 5],
                backgroundColor: [
                    '#ffffff', // Pure White
                    '#ff4d4d', // Threat Crimson
                    '#e2e8f0', // Metallic Silver
                    '#94a3b8', // Cool Slate
                    '#00e676'  // Emerald Green
                ],
                borderWidth: 1,
                borderColor: 'rgba(255, 255, 255, 0.08)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#a1b0cb',
                        font: { size: 10, family: "'Plus Jakarta Sans', sans-serif" }
                    }
                }
            },
            cutout: '70%'
        }
    });

    const ctxTrend = document.getElementById('trendChart').getContext('2d');
    const gradAlert = ctxTrend.createLinearGradient(0, 0, 0, 200);
    gradAlert.addColorStop(0, 'rgba(255, 59, 48, 0.25)');
    gradAlert.addColorStop(1, 'rgba(255, 59, 48, 0)');

    const gradMitigated = ctxTrend.createLinearGradient(0, 0, 0, 200);
    gradMitigated.addColorStop(0, 'rgba(48, 209, 88, 0.25)');
    gradMitigated.addColorStop(1, 'rgba(48, 209, 88, 0)');

    trendChart = new Chart(ctxTrend, {
        type: 'line',
        data: {
            labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
            datasets: [
                {
                    label: 'Incoming Threats',
                    data: [42, 65, 38, 85, 71, 92],
                    borderColor: '#ff3b30',
                    borderWidth: 2,
                    fill: true,
                    backgroundColor: gradAlert,
                    tension: 0.4
                },
                {
                    label: 'Mitigated Threats',
                    data: [40, 62, 37, 82, 69, 88],
                    borderColor: '#30d158',
                    borderWidth: 2,
                    fill: true,
                    backgroundColor: gradMitigated,
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
                        color: '#a1b0cb',
                        font: { size: 10, family: "'Plus Jakarta Sans', sans-serif" }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#718096', font: { size: 9 } }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#718096', font: { size: 9 } }
                }
            }
        }
    });
}

// Update charts with live backend metrics
function updateChartsUI() {
    if (!vectorChart || !trendChart) return;

    // Distribute active incident patterns in radar chart dynamically
    let bruteForceCount = 0;
    let sqlInjectCount = 0;
    let ddosCount = 0;
    let exfilCount = 0;
    let privilegeEsc = 0;

    socState.activeAlerts.forEach(a => {
        const title = a.title.toLowerCase();
        if (title.includes("brute") || title.includes("ssh")) bruteForceCount++;
        else if (title.includes("sql") || title.includes("injection")) sqlInjectCount++;
        else if (title.includes("ddos") || title.includes("ssdp") || title.includes("flood")) ddosCount++;
        else if (title.includes("exfil") || title.includes("outbound")) exfilCount++;
        else privilegeEsc++;
    });

    // Baseline counts + dynamic weights
    vectorChart.data.datasets[0].data = [
        bruteForceCount * 5 + 12,
        sqlInjectCount * 5 + 8,
        ddosCount * 5 + 15,
        exfilCount * 5 + 6,
        privilegeEsc * 5 + 3
    ];
    vectorChart.update();

    // Adjust last index of trend lines based on actual unresolved threats vs audit mitigations
    const threatLen = socState.activeAlerts.length;
    const mitigatedLen = socState.auditTrail.length;
    
    let alertData = trendChart.data.datasets[0].data;
    alertData[alertData.length - 1] = Math.min(100, Math.max(10, threatLen * 6 + 65));

    let mitigatedData = trendChart.data.datasets[1].data;
    mitigatedData[mitigatedData.length - 1] = Math.min(100, Math.max(10, mitigatedLen * 4 + 60));

    trendChart.update();
}

// Global Cyber Canvas Network Map Simulator
const canvas = document.getElementById('threat-map-canvas');
const ctx = canvas.getContext('2d');

let width, height;
let attackNodes = [];
let defenders = [];
let packets = [];

// Setup Canvas Size
function resizeCanvas() {
    const rect = canvas.parentElement.getBoundingClientRect();
    width = canvas.width = rect.width;
    height = canvas.height = rect.height;
    initMapSimulation();
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

// Init threat map nodes
function initMapSimulation() {
    defenders = [
        { x: width * 0.5, y: height * 0.5, name: "AEGIS Core Firewall", radius: 18, color: '#10b981', pulse: 0 },
        { x: width * 0.25, y: height * 0.4, name: "DMZ-GW", radius: 8, color: '#8E9BAE', pulse: 0 },
        { x: width * 0.75, y: height * 0.4, name: "API-GW", radius: 8, color: '#8E9BAE', pulse: 0 },
        { x: width * 0.5, y: height * 0.8, name: "DB-PROD", radius: 8, color: '#8E9BAE', pulse: 0 }
    ];

    attackNodes = [
        { x: width * 0.1, y: height * 0.15, name: "Honeypot-US", color: '#FF3333' },
        { x: width * 0.88, y: height * 0.18, name: "ThreatNode-EU", color: '#ffa726' },
        { x: width * 0.35, y: height * 0.12, name: "Botnet-Asia", color: '#FF3333' },
        { x: width * 0.8, y: height * 0.8, name: "Honeypot-SA", color: '#FF3333' },
        { x: width * 0.15, y: height * 0.75, name: "Malware-Source", color: '#ffa726' }
    ];
}

// Spawn packets moving along nodes
function spawnPacket() {
    if (attackNodes.length === 0 || defenders.length === 0) return;
    const fromNode = attackNodes[Math.floor(Math.random() * attackNodes.length)];
    
    // Target active nodes only
    const activeDefenders = defenders.filter(d => {
        if (d.name === "DB-PROD") {
            const dbNode = socState.networkNodes.find(n => n.name === "DB-PROD-01");
            return dbNode && dbNode.status !== "isolated";
        }
        if (d.name === "API-GW") {
            const apiNode = socState.networkNodes.find(n => n.name === "API-GATEWAY");
            return apiNode && apiNode.status !== "isolated";
        }
        return true;
    });

    const toNode = activeDefenders.length > 0 ? activeDefenders[Math.floor(Math.random() * activeDefenders.length)] : defenders[0];
    
    // Check if there are active critical threats on the target
    const hasCriticalThreat = socState.activeAlerts.some(a => a.severity === 'critical' || a.severity === 'high');
    const isMitigated = !hasCriticalThreat && (Math.random() < 0.88); 
    
    packets.push({
        x: fromNode.x,
        y: fromNode.y,
        targetX: toNode.x,
        targetY: toNode.y,
        progress: 0,
        speed: 0.006 + Math.random() * 0.01,
        color: isMitigated ? '#30d158' : fromNode.color,
        size: 2 + Math.random() * 2,
        mitigated: isMitigated
    });
}

// Animate threat map simulator
function drawThreatMap() {
    ctx.clearRect(0, 0, width, height);

    // Draw grid overlay background
    ctx.strokeStyle = 'rgba(59, 130, 246, 0.02)';
    ctx.lineWidth = 1;
    const gridGap = 20;
    for (let x = 0; x < width; x += gridGap) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
    }
    for (let y = 0; y < height; y += gridGap) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    }

    // Connect defenders to each other
    ctx.strokeStyle = 'rgba(113, 113, 122, 0.15)';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 4]);
    for (let i = 1; i < defenders.length; i++) {
        ctx.beginPath();
        ctx.moveTo(defenders[0].x, defenders[0].y);
        ctx.lineTo(defenders[i].x, defenders[i].y);
        ctx.stroke();
    }
    ctx.setLineDash([]);

    // Draw connection channels from threats
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.lineWidth = 1;
    for (let threat of attackNodes) {
        for (let def of defenders) {
            ctx.beginPath();
            ctx.moveTo(threat.x, threat.y);
            ctx.lineTo(def.x, def.y);
            ctx.stroke();
        }
    }

    // Update and draw packets
    for (let i = packets.length - 1; i >= 0; i--) {
        let p = packets[i];
        p.progress += p.speed;
        
        p.x = p.x + (p.targetX - p.x) * p.progress;
        p.y = p.y + (p.targetY - p.y) * p.progress;

        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 6;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        if (p.progress >= 0.98) {
            packets.splice(i, 1);
        }
    }

    // Draw threats nodes
    for (let node of attackNodes) {
        ctx.fillStyle = node.color;
        ctx.shadowColor = node.color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(node.x, node.y, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
        ctx.font = '8px monospace';
        ctx.fillText(node.name, node.x - 24, node.y - 10);
    }

    // Draw defenders nodes
    for (let def of defenders) {
        // Evaluate isolated state
        let isIsolated = false;
        if (def.name === "DB-PROD") {
            const dbNode = socState.networkNodes.find(n => n.name === "DB-PROD-01");
            if (dbNode && dbNode.status === "isolated") isIsolated = true;
        } else if (def.name === "API-GW") {
            const apiNode = socState.networkNodes.find(n => n.name === "API-GATEWAY");
            if (apiNode && apiNode.status === "isolated") isIsolated = true;
        }

        let defColor = isIsolated ? '#718096' : def.color;

        def.pulse += 0.05;
        const pulseRadius = def.radius + Math.sin(def.pulse) * 4;

        // Draw pulsing shell
        ctx.strokeStyle = defColor;
        ctx.globalAlpha = 0.15;
        ctx.beginPath();
        ctx.arc(def.x, def.y, pulseRadius, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1.0;

        // Core fill
        ctx.fillStyle = defColor;
        ctx.shadowColor = defColor;
        ctx.shadowBlur = isIsolated ? 0 : 10;
        ctx.beginPath();
        ctx.arc(def.x, def.y, def.radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowBlur = 0;

        // Label
        ctx.fillStyle = isIsolated ? '#718096' : '#ffffff';
        ctx.font = '9px system-ui';
        ctx.fillText(`${def.name}${isIsolated ? ' [ISOLATED]' : ''}`, def.x - 30, def.y - def.radius - 6);
    }

    requestAnimationFrame(drawThreatMap);
}

// Packet Spawning Loop
setInterval(spawnPacket, 600);
requestAnimationFrame(drawThreatMap);

// Ingress packet stats counter visual update
let totalPkts = 312940;
setInterval(() => {
    // scale based on active ingress rate
    totalPkts += Math.floor(Math.random() * 50 * (socState.ingressRate || 4)) - 20;
    const pktCountEl = document.getElementById('packet-counter');
    if (pktCountEl) {
        pktCountEl.textContent = totalPkts.toLocaleString();
    }
}, 1000);

// Populate Active Alerts UI Queue
let activeFilter = 'all';
function renderAlertFeed() {
    const listEl = document.getElementById('alert-feed-list');
    if (!listEl) return;
    
    const filtered = socState.activeAlerts.filter(a => {
        if (activeFilter === 'all') return true;
        return a.severity === activeFilter;
    });

    if (filtered.length === 0) {
        listEl.innerHTML = `
            <div style="text-align: center; padding: 3rem; color: var(--color-low)">
                <i class="fa-solid fa-circle-check" style="font-size: 2rem; margin-bottom: 0.75rem"></i>
                <p style="font-weight: 600">All Systems Clear</p>
                <p style="font-size: 0.7rem; color: var(--text-muted)">No active ${activeFilter} threats identified</p>
            </div>
        `;
        return;
    }

    listEl.innerHTML = filtered.map(alert => `
        <div class="alert-item ${alert.severity}" onclick="openIncidentDetails('${alert.id}')">
            <div class="alert-top">
                <span class="alert-title">${alert.title}</span>
                <span class="alert-tag ${alert.severity}">${alert.severity} (${alert.score})</span>
            </div>
            <div class="alert-meta">
                <span class="alert-source"><i class="fa-solid fa-circle-nodes"></i> Src: ${alert.sourceIp}</span>
                <span>Target: ${alert.target}</span>
            </div>
            <div class="alert-meta" style="margin-top: 0.15rem;">
                <span style="font-size: 0.7rem;"><i class="fa-regular fa-clock"></i> ${alert.time}</span>
                <div class="alert-actions">
                    <button class="alert-btn alert-btn-action" onclick="event.stopPropagation(); triggerMitigation('${alert.id}')">Mitigate</button>
                    <button class="alert-btn alert-btn-dismiss" onclick="event.stopPropagation(); dismissAlert('${alert.id}')">Dismiss</button>
                </div>
            </div>
        </div>
    `).join('');
}

// Alert filters
function filterAlerts(severity, btn) {
    activeFilter = severity;
    const buttons = btn.parentElement.querySelectorAll('.panel-btn');
    buttons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderAlertFeed();
}

// Render network nodes
function renderNetworkGrid() {
    const gridEl = document.getElementById('network-nodes-grid');
    if (!gridEl) return;
    
    gridEl.innerHTML = socState.networkNodes.map(node => {
        let nodeColor = 'safe';
        if (node.status === "isolated") nodeColor = 'blocked';
        else if (node.risk > 75) nodeColor = 'critical';
        else if (node.risk > 40) nodeColor = 'high';

        return `
            <div class="threat-node" style="${node.status === 'isolated' ? 'border-color: rgba(255,255,255,0.06); filter: opacity(0.65);' : ''}">
                <div class="threat-node-header">
                    <span class="node-ip">${node.name}</span>
                    <span style="font-size: 0.65rem; color: var(--text-muted); font-family: var(--font-mono)">${node.ip}</span>
                    <div class="node-status ${node.status === 'isolated' ? 'blocked' : (node.risk > 75 ? 'active' : 'safe')}"></div>
                </div>
                <div class="threat-node-details">${node.metrics}</div>
                <div class="threat-node-gauge">
                    <div class="threat-node-gauge-fill ${node.risk > 75 ? 'critical' : (node.risk > 40 ? 'high' : 'medium')}" style="width: ${node.status === 'isolated' ? '0' : node.risk}%"></div>
                </div>
                <div style="display:flex; justify-content: space-between; align-items:center; margin-top: 0.35rem; font-size: 0.65rem;">
                    <span style="color: ${node.status === 'isolated' ? 'var(--text-muted)' : (node.risk > 75 ? 'var(--color-critical)' : 'var(--text-muted)')}">
                        ${node.status === 'isolated' ? 'ISOLATED' : `Risk Score: ${node.risk}%`}
                    </span>
                    ${node.status !== 'isolated' ? `
                        <button class="panel-btn" style="padding: 0.1rem 0.3rem; font-size: 0.55rem; background: rgba(255,59,48,0.1); border-color: rgba(255,59,48,0.2); color: var(--color-critical);" onclick="isolateNode('${node.name}')">Isolate</button>
                    ` : `
                        <button class="panel-btn" style="padding: 0.1rem 0.3rem; font-size: 0.55rem; background: rgba(48,209,88,0.1); border-color: rgba(48,209,88,0.2); color: var(--color-low);" onclick="reconnectNode('${node.name}')">Reconnect</button>
                    `}
                </div>
            </div>
        `;
    }).join('');
}

// Populate Playbook Audit table
function renderAuditTable() {
    const tableBody = document.getElementById('playbook-audit-trail-body');
    if (!tableBody) return;

    tableBody.innerHTML = socState.auditTrail.map(audit => `
        <tr>
            <td class="mono" style="color: var(--color-primary); font-weight:700">${audit.id}</td>
            <td class="mono">${audit.target}</td>
            <td>${audit.desc}</td>
            <td>
                <span class="table-badge ${audit.source.includes('AI') ? 'badge-outline-purple' : 'badge-outline-cyan'}">
                    ${audit.source}
                </span>
            </td>
            <td class="mono" style="font-size:0.7rem">${audit.actions}</td>
            <td style="color: var(--color-low); font-weight:600"><i class="fa-solid fa-circle-check"></i> ${audit.status}</td>
        </tr>
    `).join('');
}

// Global visual updates for metrics ribbon
function updateMetricsRibbon() {
    const threatEl = document.getElementById('metric-threat-level');
    if (threatEl) threatEl.textContent = `${socState.threatLevel}%`;
    
    const threatBar = document.getElementById('metric-threat-bar');
    if (threatBar) threatBar.style.width = `${Math.min(100, Math.max(5, socState.threatLevel))}%`;

    const ingressEl = document.getElementById('metric-ingress');
    if (ingressEl) ingressEl.textContent = `${socState.ingressRate.toFixed(2)} GB/s`;
    
    const ingressSubEl = document.getElementById('metric-ingress-subtext');
    if (ingressSubEl) {
        if (socState.ingressRate > 6.0) {
            ingressSubEl.innerHTML = `<i class="fa-solid fa-caret-up"></i> +${((socState.ingressRate - 4.0)*15).toFixed(1)}% high flow`;
            ingressSubEl.style.color = 'var(--color-critical)';
        } else {
            ingressSubEl.innerHTML = `<i class="fa-solid fa-caret-down"></i> normal flow`;
            ingressSubEl.style.color = 'var(--color-tertiary)';
        }
    }
    
    const mitEl = document.getElementById('metric-mitigation');
    if (mitEl && socState.mitigationRate) mitEl.textContent = `${socState.mitigationRate.toFixed(1)}%`;
    
    const mitBar = document.getElementById('metric-mitigation-bar');
    if (mitBar && socState.mitigationRate) mitBar.style.width = `${Math.min(100, Math.max(5, socState.mitigationRate))}%`;
    
    const activeCount = socState.activeAlerts.length;
    const activeAlertsEl = document.getElementById('metric-active-alerts');
    if (activeAlertsEl) activeAlertsEl.textContent = activeCount;
    
    // Critical count text
    const criticalCount = socState.activeAlerts.filter(a => a.severity === 'critical').length;
    const subtextEl = document.getElementById('metric-active-subtext');
    if (subtextEl) {
        subtextEl.innerHTML = `<i class="fa-solid fa-circle-exclamation" style="color: ${criticalCount > 0 ? 'var(--color-critical)' : 'var(--color-high)'}"></i> ${criticalCount} Critical Alerts`;
    }

    // Toggle Autopilot recommendation banner
    const banner = document.getElementById('autopilot-banner');
    if (banner) {
        banner.style.display = socState.autopilotBannerActive ? "flex" : "none";
    }
}

// Connect to Node WebSocket SOC Core Stream
let socket;
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;
    
    console.log(`Connecting to SOC websocket: ${wsUrl}`);
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        console.log("WebSocket Connection secure.");
        addChatMessage("Aegis AI Autopilot", "<i class='fa-solid fa-circle-check' style='color:var(--color-low)'></i> Socket session successfully synchronized with threat databases.", true);
    };

    socket.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === "INITIAL_STATE" || data.type === "STATE_UPDATE") {
                const prevAlertCount = socState.activeAlerts ? socState.activeAlerts.length : 0;
                socState = data.state;
                
                if (socState.activeAlerts && socState.activeAlerts.length > prevAlertCount) {
                    playAttackAlertSound();
                }
                
                // Rerender UI layouts
                updateMetricsRibbon();
                renderAlertFeed();
                renderNetworkGrid();
                renderAuditTable();
                updateChartsUI();
            } else if (data.type === "LOG_STREAM") {
                appendTerminalLog(data.log);
            }
        } catch (err) {
            console.error("Error parsing WebSocket payload:", err);
        }
    };

    socket.onclose = () => {
        console.warn("WebSocket closed. Attempting reconnect in 5s...");
        setTimeout(connectWebSocket, 5000);
    };

    socket.onerror = (err) => {
        console.error("WebSocket transport error:", err);
    };
}

// POST actions calls to Express REST API
async function triggerMitigation(alertId) {
    try {
        playMitigationChime();
        const response = await fetch('/api/mitigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alertId })
        });
        const data = await response.json();
        if (data.success) {
            // State updated automatically via WS broadcast
            console.log(`Mitigated alert ${alertId}`);
        }
    } catch (err) {
        console.error("Mitigation request failed:", err);
    }
}

function dismissAlert(alertId) {
    // Simply resolve it as mitigated on backend
    triggerMitigation(alertId);
}

async function isolateNode(nodeName) {
    try {
        await fetch('/api/isolate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nodeName })
        });
    } catch (err) {
        console.error("Isolation request failed:", err);
    }
}

async function reconnectNode(nodeName) {
    try {
        await fetch('/api/reconnect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nodeName })
        });
    } catch (err) {
        console.error("Reconnect request failed:", err);
    }
}

async function triggerAutopilotPlaybook() {
    const deployBtn = document.getElementById('btn-deploy-autopilot');
    if (deployBtn) {
        deployBtn.disabled = true;
        deployBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Deploying isolation...`;
    }

    try {
        const response = await fetch('/api/autopilot', { method: 'POST' });
        const data = await response.json();
        if (data.success) {
            console.log("Autopilot playbook deployed successfully.");
        }
    } catch (err) {
        console.error("Autopilot deployment failed:", err);
        if (deployBtn) {
            deployBtn.disabled = false;
            deployBtn.innerHTML = `<i class="fa-solid fa-bolt"></i> Deploy AI Playbook`;
        }
    }
}

// Modal management
let currentModalAlertId = "";
function openIncidentDetails(alertId) {
    const alert = socState.activeAlerts.find(a => a.id === alertId);
    if (!alert) return;

    currentModalAlertId = alertId;
    document.getElementById('modal-title').textContent = `Investigation Details: ${alert.title}`;
    document.getElementById('modal-id').textContent = alert.id;
    document.getElementById('modal-severity').textContent = `${alert.score} (${alert.severity.toUpperCase()})`;
    document.getElementById('modal-source-ip').textContent = alert.sourceIp;
    document.getElementById('modal-target').textContent = alert.target;
    document.getElementById('modal-log-payload').textContent = alert.payload;
    document.getElementById('modal-ai-recommendation').textContent = alert.recommendation;

    const severitySpan = document.getElementById('modal-severity');
    severitySpan.className = '';
    if (alert.severity === 'critical') severitySpan.style.color = 'var(--color-critical)';
    else if (alert.severity === 'high') severitySpan.style.color = 'var(--color-high)';
    else severitySpan.style.color = 'var(--color-medium)';

    document.getElementById('incident-modal').classList.add('active');
}

function closeIncidentModal() {
    document.getElementById('incident-modal').classList.remove('active');
}

function mitigateIncidentFromModal() {
    if (currentModalAlertId) {
        triggerMitigation(currentModalAlertId);
        closeIncidentModal();
    }
}

// AI Copilot Chat Console Logic
const chatHistory = document.getElementById('chat-history');

function addChatMessage(sender, text, isAi = false) {
    const bubble = document.createElement('div');
    bubble.className = `chat-bubble ${isAi ? 'ai' : 'user'}`;
    bubble.innerHTML = text;
    chatHistory.appendChild(bubble);
    chatHistory.scrollTop = chatHistory.scrollHeight;
}

function handleChatSubmit(e) {
    e.preventDefault();
    const chatInput = document.getElementById('chat-input');
    const msgText = chatInput.value.trim();
    if (!msgText) return;

    addChatMessage("Operator", msgText, false);
    chatInput.value = '';
    
    askAiCopilotEndpoint(msgText);
}

function askCopilot(question) {
    addChatMessage("Operator", question, false);
    askAiCopilotEndpoint(question);
}

async function askAiCopilotEndpoint(query) {
    // Add temporary loading indicator bubble
    const typingBubble = document.createElement('div');
    typingBubble.className = 'chat-bubble ai';
    typingBubble.innerHTML = `
        <div class="typing-indicator">
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
        </div>
    `;
    chatHistory.appendChild(typingBubble);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await response.json();
        
        chatHistory.removeChild(typingBubble);
        
        if (data.answer) {
            addChatMessage("Aegis AI Autopilot", data.answer, true);
        } else {
            addChatMessage("Aegis AI Autopilot", "Error retrieving core insights. Interface offline.", true);
        }
    } catch (err) {
        console.error("AI chat query failed:", err);
        chatHistory.removeChild(typingBubble);
        addChatMessage("Aegis AI Autopilot", "Fatal error: failed connection to the AI processing core.", true);
    }
}

// --- Real-time Terminal Log Stream Handler ---
function appendTerminalLog(logObj) {
    const termEl = document.getElementById('terminal-log-box');
    if (!termEl) return;

    let logClass = 'system';
    if (logObj.status === 'Active Threat' || logObj.desc.includes('Threat') || logObj.desc.includes('Attack')) {
        logClass = 'threat';
    } else if (logObj.status === 'Mitigated') {
        logClass = 'mitigated';
    } else if (logObj.source.includes('Operator')) {
        logClass = 'operator';
    }

    const timeShort = logObj.timestamp ? logObj.timestamp.substring(11, 19) : new Date().toISOString().substring(11, 19);
    const lineEl = document.createElement('div');
    lineEl.className = `terminal-line ${logClass}`;
    lineEl.innerHTML = `<span class="timestamp">[${timeShort}]</span> <strong>[${logObj.target}]</strong> ${logObj.desc} | Src: ${logObj.source} | Actions: ${logObj.actions} (${logObj.status})`;

    termEl.appendChild(lineEl);

    // Keep log scrollable length capped to 80 lines
    while (termEl.children.length > 80) {
        termEl.removeChild(termEl.firstChild);
    }
    termEl.scrollTop = termEl.scrollHeight;
}

function clearTerminalLogs() {
    const termEl = document.getElementById('terminal-log-box');
    if (termEl) {
        termEl.innerHTML = '<div class="terminal-line system"><span class="timestamp">[SYSTEM]</span> Terminal log buffer cleared. Connected to event stream...</div>';
    }
}

// --- Attack Burst Canvas Visual Animation ---
function triggerAttackBurst(targetHostName) {
    if (attackNodes.length === 0 || defenders.length === 0) return;

    // Find defender matching target host or fallback to DB-PROD
    let targetDef = defenders.find(d => {
        if (targetHostName === "DB-PROD-01" && d.name === "DB-PROD") return true;
        if (targetHostName === "API-GATEWAY" && d.name === "API-GW") return true;
        return d.name === "AEGIS Core Firewall";
    }) || defenders[0];

    // Spawn 12 rapid laser packets on canvas
    for (let i = 0; i < 12; i++) {
        setTimeout(() => {
            const fromNode = attackNodes[Math.floor(Math.random() * attackNodes.length)];
            packets.push({
                x: fromNode.x,
                y: fromNode.y,
                targetX: targetDef.x,
                targetY: targetDef.y,
                progress: 0,
                speed: 0.02 + Math.random() * 0.015,
                color: '#ff3b30',
                size: 4 + Math.random() * 3,
                mitigated: false
            });
        }, i * 70);
    }
}

// --- Attack Simulator Modal & Preset Handlers ---
const attackPresets = {
    sql: {
        title: "Malicious User Agent (SQL Injection)",
        severity: "critical",
        score: 9.5,
        payload: "POST /api/v1/checkout HTTP/1.1\nHost: secure-pay.internal.local\nUser-Agent: sqlmap/1.4.12#stable\n\nid=5' OR 1=1; DROP TABLE Transactions; --&verify=true",
        recommendation: "Deploy immediate Web Application Firewall (WAF) payload rules on target node & block source IP."
    },
    ddos: {
        title: "DDoS Reflection Attack (SSDP)",
        severity: "high",
        score: 8.8,
        payload: "UDP 203.0.113.14:1900 -> 10.142.0.10:80\nLength: 1024 bytes\nType: SSDP Search Response Reflection\nThreshold: > 140,000 req/sec",
        recommendation: "Enable edge router rate-limiting thresholds and execute DDoS null-routing rules."
    },
    ssh: {
        title: "Brute Force SSH Attack",
        severity: "high",
        score: 8.0,
        payload: "Failed password for root from attacker IP port 49210 ssh2\nRepeated 128 times in 10 seconds",
        recommendation: "Trigger fail2ban isolation, block attacker IP temporarily, and enforce SSH key authentication only."
    },
    webshell: {
        title: "Malicious File Upload (Webshell RCE)",
        severity: "critical",
        score: 9.8,
        payload: "POST /uploads/profile.php HTTP/1.1\nContent-Type: multipart/form-data\n\n<?php system($_GET['cmd']); ?>",
        recommendation: "Immediate web container isolation. Terminate process list & audit folder permissions."
    },
    dns: {
        title: "Anomalous DNS Tunneling Activity",
        severity: "medium",
        score: 6.8,
        payload: "DNS lookup queries: sub.long-exfil-hash-domain.com TXT records.\nLength limit: 255 chars, count: 489/sec.",
        recommendation: "Block domain queries on DNS perimeter router. Isolate outbound lookup nodes."
    },
    privesc: {
        title: "Local Privilege Escalation Attempt",
        severity: "medium",
        score: 6.2,
        payload: "user@web-srv-01:~$ ./dirtycow\n[+] Exploit initialized. Accessing kernel memory space...",
        recommendation: "Unprivileged user executing exploit pattern. Apply latest Linux security kernel patches."
    }
};

let currentSelectedPresetKey = 'sql';

function selectAttackPreset(key, cardEl) {
    currentSelectedPresetKey = key;
    const cards = document.querySelectorAll('.sim-preset-card');
    cards.forEach(c => c.classList.remove('active'));
    if (cardEl) cardEl.classList.add('active');

    const preset = attackPresets[key];
    if (preset) {
        document.getElementById('sim-severity').value = preset.severity;
    }
}

function openSimulatorModal() {
    document.getElementById('simulator-modal').classList.add('active');
}

function closeSimulatorModal() {
    document.getElementById('simulator-modal').classList.remove('active');
}

async function executeManualAttackLaunch() {
    const preset = attackPresets[currentSelectedPresetKey] || attackPresets.sql;
    const targetNode = document.getElementById('sim-target-node').value;
    const customIp = document.getElementById('sim-source-ip').value.trim();
    const severity = document.getElementById('sim-severity').value;

    let score = preset.score;
    if (severity === 'critical') score = 9.5;
    else if (severity === 'high') score = 8.2;
    else if (severity === 'medium') score = 6.0;
    else if (severity === 'low') score = 3.5;

    const launchBtn = document.querySelector('.btn-launch-attack');
    if (launchBtn) {
        launchBtn.disabled = true;
        launchBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Launching Attack Vector...`;
    }

    try {
        const response = await fetch('/api/simulate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                title: preset.title,
                severity: severity,
                score: score,
                targetNode: targetNode,
                sourceIp: customIp || null,
                payload: preset.payload,
                recommendation: preset.recommendation
            })
        });

        const data = await response.json();
        if (data.success) {
            triggerAttackBurst(targetNode);
            closeSimulatorModal();
        }
    } catch (err) {
        console.error("Failed to launch simulated attack:", err);
    } finally {
        if (launchBtn) {
            launchBtn.disabled = false;
            launchBtn.innerHTML = `<i class="fa-solid fa-bolt"></i> LAUNCH SIMULATED ATTACK NOW`;
        }
    }
}

// --- SOC State Reset Handler ---
async function resetSocState() {
    try {
        const response = await fetch('/api/reset', { method: 'POST' });
        const data = await response.json();
        if (data.success) {
            clearTerminalLogs();
            console.log("SOC State successfully reset to baseline.");
        }
    } catch (err) {
        console.error("Reset request failed:", err);
    }
}

// --- Simulation Mode Speed Controls ---
async function setSimulationMode(mode) {
    try {
        const response = await fetch('/api/simulation-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode })
        });
        const data = await response.json();
        if (data.success) {
            ['fast', 'normal', 'paused'].forEach(m => {
                const btn = document.getElementById(`sim-mode-${m}`);
                if (btn) {
                    if (m === mode) btn.classList.add('active');
                    else btn.classList.remove('active');
                }
            });
        }
    } catch (err) {
        console.error("Failed to update simulation speed mode:", err);
    }
}

// --- Web Audio API Tactical SFX Synthesizer ---
let sfxEnabled = true;
let audioCtx = null;
function getAudioContext() {
    if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    return audioCtx;
}

function toggleAudioSFX() {
    sfxEnabled = !sfxEnabled;
    const btn = document.getElementById('sfx-toggle-btn');
    if (btn) {
        if (sfxEnabled) {
            btn.className = "header-btn btn-sfx";
            btn.innerHTML = '<i class="fa-solid fa-volume-high"></i> SFX: ON';
            playClickSound();
        } else {
            btn.className = "header-btn btn-sfx muted";
            btn.innerHTML = '<i class="fa-solid fa-volume-xmark"></i> SFX: OFF';
        }
    }
}

function playAttackAlertSound() {
    if (!sfxEnabled) return;
    try {
        const ctx = getAudioContext();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.25);
        gain.gain.setValueAtTime(0.12, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.25);
    } catch(e){}
}

function playMitigationChime() {
    if (!sfxEnabled) return;
    try {
        const ctx = getAudioContext();
        const now = ctx.currentTime;
        [523.25, 659.25, 783.99].forEach((freq, idx) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.setValueAtTime(freq, now + idx * 0.08);
            gain.gain.setValueAtTime(0.08, now + idx * 0.08);
            gain.gain.exponentialRampToValueAtTime(0.001, now + idx * 0.08 + 0.3);
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.start(now + idx * 0.08);
            osc.stop(now + idx * 0.08 + 0.3);
        });
    } catch(e){}
}

function playClickSound() {
    if (!sfxEnabled) return;
    try {
        const ctx = getAudioContext();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(1200, ctx.currentTime);
        gain.gain.setValueAtTime(0.04, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.05);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start();
        osc.stop(ctx.currentTime + 0.05);
    } catch(e){}
}

// --- Threat Hunting Search Filter Handler ---
let threatSearchQuery = "";
function handleThreatSearchInput(e) {
    threatSearchQuery = e.target.value.toLowerCase().trim();
    renderAlertFeed();
}

// --- Executive Security Audit Report Generator ---
function openAuditReportModal() {
    playClickSound();
    const modal = document.getElementById('report-modal');
    const body = document.getElementById('report-modal-body');
    if (!modal || !body) return;

    const criticalCount = socState.activeAlerts.filter(a => a.severity === 'critical').length;
    const highCount = socState.activeAlerts.filter(a => a.severity === 'high').length;
    const safeHosts = socState.networkNodes.filter(n => n.status === 'safe').length;

    body.innerHTML = `
        <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 1rem;" class="grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
            <div>
                <div style="font-size: 0.7rem; color: #94a3b8; font-family: var(--font-mono)">GLOBAL THREAT INDEX</div>
                <div style="font-size: 1.5rem; font-weight: 800; color: ${socState.threatLevel > 40 ? '#ff4d4d' : '#00e676'}">${socState.threatLevel}%</div>
            </div>
            <div>
                <div style="font-size: 0.7rem; color: #94a3b8; font-family: var(--font-mono)">ACTIVE INCIDENTS</div>
                <div style="font-size: 1.5rem; font-weight: 800; color: #ffffff">${socState.activeAlerts.length} (${criticalCount} Crit)</div>
            </div>
            <div>
                <div style="font-size: 0.7rem; color: #94a3b8; font-family: var(--font-mono)">HOST SUBNETS</div>
                <div style="font-size: 1.5rem; font-weight: 800; color: #00e676">${safeHosts} / ${socState.networkNodes.length} Safe</div>
            </div>
            <div>
                <div style="font-size: 0.7rem; color: #94a3b8; font-family: var(--font-mono)">INGRESS FLOW</div>
                <div style="font-size: 1.5rem; font-weight: 800; color: #ffffff">${socState.ingressRate.toFixed(2)} GB/s</div>
            </div>
        </div>

        <div>
            <h4 style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700; color: #ffffff; margin-bottom: 0.5rem; text-transform: uppercase;">
                <i class="fa-solid fa-server mr-1"></i> Infrastructure Nodes Status Summary
            </h4>
            <table class="cyber-table">
                <thead>
                    <tr>
                        <th>Node Name</th>
                        <th>IP Address</th>
                        <th>Status</th>
                        <th>Risk Score</th>
                        <th>Workload Telemetry</th>
                    </tr>
                </thead>
                <tbody>
                    ${socState.networkNodes.map(n => `
                        <tr>
                            <td><strong>${n.name}</strong></td>
                            <td class="mono">${n.ip}</td>
                            <td style="color: ${n.status === 'safe' ? '#00e676' : (n.status === 'isolated' ? '#94a3b8' : '#ff4d4d')}">${n.status.toUpperCase()}</td>
                            <td class="mono">${n.risk}%</td>
                            <td class="mono">${n.metrics}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>

        <div>
            <h4 style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700; color: #ffffff; margin-bottom: 0.5rem; text-transform: uppercase;">
                <i class="fa-solid fa-triangle-exclamation mr-1"></i> Active Incident Queue (${socState.activeAlerts.length})
            </h4>
            ${socState.activeAlerts.length === 0 ? '<p style="color: #00e676; font-size: 0.8rem;">No unresolved security incidents in queue.</p>' : `
                <table class="cyber-table">
                    <thead>
                        <tr>
                            <th>Incident ID</th>
                            <th>Threat Vector</th>
                            <th>Severity</th>
                            <th>Attacker IP</th>
                            <th>Target Host</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${socState.activeAlerts.map(a => `
                            <tr>
                                <td class="mono"><code>${a.id}</code></td>
                                <td>${a.title}</td>
                                <td style="color: ${a.severity === 'critical' ? '#ff4d4d' : '#ffa726'}">${a.severity.toUpperCase()} (${a.score})</td>
                                <td class="mono">${a.sourceIp}</td>
                                <td class="mono"><strong>${a.target}</strong></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `}
        </div>

        <div>
            <h4 style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: 700; color: #ffffff; margin-bottom: 0.5rem; text-transform: uppercase;">
                <i class="fa-solid fa-list-check mr-1"></i> Recent Mitigation Audit Log (${socState.auditTrail.length})
            </h4>
            <table class="cyber-table">
                <thead>
                    <tr>
                        <th>Mitigation ID</th>
                        <th>Target</th>
                        <th>Description</th>
                        <th>Executed Action</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${socState.auditTrail.slice(0, 5).map(m => `
                        <tr>
                            <td class="mono"><code>${m.id}</code></td>
                            <td>${m.target}</td>
                            <td>${m.desc}</td>
                            <td class="mono">${m.actions}</td>
                            <td style="color: #00e676">${m.status}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;

    modal.classList.add('active');
}

function closeAuditReportModal() {
    playClickSound();
    const modal = document.getElementById('report-modal');
    if (modal) modal.classList.remove('active');
}

// Init on Document Load
window.addEventListener('DOMContentLoaded', () => {
    initCharts();
    connectWebSocket();
});
