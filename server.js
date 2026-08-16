const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

const PORT = process.env.PORT || 8080;
const LOG_FILE = path.join(__dirname, 'soc_audit_trail.log');

// Express Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Global State
let socState = {
    threatLevel: 42.8,
    ingressRate: 4.82,
    mitigationRate: 94.2,
    activeAlerts: [
        {
            id: "INC-8042",
            title: "Malicious User Agent (SQL Injection)",
            severity: "critical",
            score: "9.2",
            sourceIp: "198.51.100.89",
            target: "VM-PAYMENTS-03",
            time: "Just Now",
            payload: `POST /api/v1/checkout HTTP/1.1\nHost: secure-pay.internal.local\nUser-Agent: sqlmap/1.4.12#stable (http://sqlmap.org)\nAccept: */*\nContent-Length: 104\n\nid=5' OR 1=1; DROP TABLE Transactions; --&verify=true`,
            recommendation: "SQL Injection attack detected via SQLMap User-Agent headers. Automated recommendation: deploy immediate Web Application Firewall (WAF) payload rules on VM-PAYMENTS-03 and block attacker source IP address."
        },
        {
            id: "INC-7911",
            title: "DDoS Reflection Attack (SSDP)",
            severity: "high",
            score: "8.5",
            sourceIp: "203.0.113.14",
            target: "API-GATEWAY",
            time: "2 mins ago",
            payload: `UDP 203.0.113.14:1900 -> 10.142.0.10:80\nLength: 1024 bytes\nType: SSDP Search Response Reflection\nAlert Threshold Exceeded: > 140,000 requests/sec`,
            recommendation: "SSDP Reflection flooding API-GATEWAY. Recommended action: Enable Cloudflare/Edge rate-limiting thresholds and execute DDoS protection null-routing rules on edge router API-RT-01."
        },
        {
            id: "INC-7804",
            title: "Brute Force SSH Attack",
            severity: "high",
            score: "7.8",
            sourceIp: "185.190.140.22",
            target: "AUTH-SERVICE",
            time: "10 mins ago",
            payload: `Aug  5 08:42:01 auth-srv sshd[28104]: Failed password for root from 185.190.140.22 port 49210 ssh2\nAug  5 08:42:04 auth-srv sshd[28104]: Failed password for root from 185.190.140.22 port 49214 ssh2\nAug  5 08:42:06 auth-srv sshd[28104]: Repeated 42 times`,
            recommendation: "Continuous failed SSH root authentication attempts on AUTH-SERVICE. Recommendation: trigger fail2ban isolation, block attacker IP temporarily, and enforce SSH Key Auth only."
        },
        {
            id: "INC-7501",
            title: "Data Exfiltration (Anomalous Outbound)",
            severity: "medium",
            score: "5.4",
            sourceIp: "10.142.45.92",
            target: "DEV-STAGE-01",
            time: "24 mins ago",
            payload: `OUTBOUND connection from 10.142.45.92:5432 -> external-ftp-backup.ru:21\nVolume: 1.4 GB sent in 24 seconds\nBaseline Exceeded: +1200%`,
            recommendation: "Internal server DEV-STAGE-01 transferring excessive volumes to an unverified external endpoint. Recommend isolating the staging server virtual machine and auditing database client permissions."
        },
        {
            id: "INC-7102",
            title: "Local Privilege Escalation attempt",
            severity: "low",
            score: "3.2",
            sourceIp: "10.142.45.101",
            target: "WEB-CLUSTER-01",
            time: "48 mins ago",
            payload: `user@web-srv-01:~$ sudo -l\nuser@web-srv-01:~$ ./dirtycow\n[+] Exploit initialized. Accessing kernel space...`,
            recommendation: "Unprivileged user attempting exploit pattern match on WEB-CLUSTER-01. Recommendation: Apply latest Linux security kernel patches to web nodes."
        }
    ],
    auditTrail: [
        { id: "MIT-901", target: "VM-PAYMENTS-03", desc: "SQL injection payload blocked", source: "AI Autopilot", actions: "WAF Rule 409 Activated", status: "Mitigated" },
        { id: "MIT-899", target: "EDGE-ROUTER-01", desc: "DDoS flow null-routed", source: "AI Autopilot", actions: "IP 203.0.113.14 blocked", status: "Mitigated" },
        { id: "MIT-884", target: "AUTH-SERVICE", desc: "SSH Brute force containment", source: "Operator Admin", actions: "Fail2ban trigger IP block", status: "Mitigated" }
    ],
    networkNodes: [
        { name: "DB-PROD-01", ip: "10.142.45.189", risk: 85, status: "active", metrics: "CPU: 92% | SQL load high", rawCpu: 92 },
        { name: "WEB-CLUSTER-01", ip: "10.142.45.101", risk: 15, status: "safe", metrics: "CPU: 24% | Normal", rawCpu: 24 },
        { name: "AUTH-SERVICE", ip: "10.142.45.12", risk: 10, status: "safe", metrics: "CPU: 12% | Normal", rawCpu: 12 },
        { name: "API-GATEWAY", ip: "10.142.0.10", risk: 65, status: "active", metrics: "CPU: 68% | Ingress 2.1 GB/s", rawCpu: 68 },
        { name: "DEV-STAGE-01", ip: "10.142.45.92", risk: 45, status: "active", metrics: "CPU: 8% | SFTP session active", rawCpu: 8 },
        { name: "VM-PAYMENTS-03", ip: "10.142.90.4", risk: 92, status: "active", metrics: "CPU: 97% | Suspicious logs", rawCpu: 97 }
    ],
    autopilotBannerActive: true
};

// Helper: Append entries to local physical log file & stream live over WebSocket
function broadcastLog(logObj) {
    const data = JSON.stringify({ type: "LOG_STREAM", log: logObj });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
}

function logAuditEvent(target, desc, source, actions, status) {
    const timestamp = new Date().toISOString();
    const logObj = { timestamp, target, desc, source, actions, status };
    
    fs.appendFile(LOG_FILE, JSON.stringify(logObj) + '\n', (err) => {
        if (err) console.error("Error writing to audit log:", err);
    });

    broadcastLog(logObj);
}

// Log initial startup event
logAuditEvent("SYSTEM", "Aegis SOC Core Autopilot Initialized", "SYSTEM", "Port binding successful", "ONLINE");

// Helper: Broadcast current state to all WebSocket clients
function broadcastState() {
    const data = JSON.stringify({ type: "STATE_UPDATE", state: socState });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
}

// REST APIs
// 1. Mitigate alert
app.post('/api/mitigate', (req, res) => {
    const { alertId } = req.body;
    const alertIndex = socState.activeAlerts.findIndex(a => a.id === alertId);
    
    if (alertIndex !== -1) {
        const alert = socState.activeAlerts[alertIndex];
        
        const mitId = `MIT-${Math.floor(Math.random() * 900) + 100}`;
        const actions = `Secured target ${alert.target} & blocked source IP ${alert.sourceIp}`;
        
        socState.auditTrail.unshift({
            id: mitId,
            target: alert.target,
            desc: alert.title,
            source: "Operator Action",
            actions: actions,
            status: "Mitigated"
        });

        // Restore target node status & metrics
        const node = socState.networkNodes.find(n => n.name === alert.target);
        if (node && node.status !== "isolated") {
            node.risk = Math.max(10, node.risk - 45);
            node.rawCpu = Math.floor(Math.random() * 10) + 15;
            node.metrics = `CPU: ${node.rawCpu}% | Operational Safe`;
        }

        // Multi-phase mitigation terminal stream logs
        logAuditEvent(alert.target, `FIREWALL RULE ACTIVATED: WAF Rule 409 deployed`, "Operator Action", `Blocked IP ${alert.sourceIp}`, "Mitigated");
        setTimeout(() => {
            logAuditEvent(alert.target, `NULL ROUTE EXECUTION: Attacker IP ${alert.sourceIp} dropped at perimeter`, "Gateway Firewall", "Null-route active", "Mitigated");
        }, 150);
        setTimeout(() => {
            logAuditEvent(alert.target, `HOST RESTORED: Node ${alert.target} load normalized to 18% CPU`, "Node Monitor", "Operational baseline restored", "ONLINE");
        }, 300);

        // Remove alert
        socState.activeAlerts.splice(alertIndex, 1);
        
        // Adjust metrics
        socState.threatLevel = Math.max(12.4, parseFloat((socState.threatLevel - 7.5).toFixed(1)));
        
        broadcastState();
        res.json({ success: true, state: socState });
    } else {
        res.status(404).json({ success: false, error: "Alert not found" });
    }
});

// 2. Isolate network node
app.post('/api/isolate', (req, res) => {
    const { nodeName } = req.body;
    const node = socState.networkNodes.find(n => n.name === nodeName);
    
    if (node) {
        node.status = "isolated";
        node.metrics = "OFFLINE - ISOLATED BY OPERATOR";
        node.rawCpu = 0;
        node.risk = 0;
        
        const actions = `Isolated host subnet gateway IP ${node.ip}`;
        socState.auditTrail.unshift({
            id: `MIT-${Math.floor(Math.random() * 900) + 100}`,
            target: node.name,
            desc: "Operator Isolation Triggered",
            source: "Operator Admin",
            actions: actions,
            status: "Mitigated"
        });

        logAuditEvent(node.name, `SUBNET ISOLATION: Host Gateway Interface ${node.ip} disabled`, "Operator Admin", actions, "Mitigated");
        setTimeout(() => {
            logAuditEvent(node.name, `CONTAINMENT ACTIVE: Node ${node.name} disconnected from gateway routing`, "Cluster Firewall", "Host Offline", "Mitigated");
        }, 150);
        
        broadcastState();
        res.json({ success: true, state: socState });
    } else {
        res.status(404).json({ success: false, error: "Node not found" });
    }
});

// 3. Reconnect network node
app.post('/api/reconnect', (req, res) => {
    const { nodeName } = req.body;
    const node = socState.networkNodes.find(n => n.name === nodeName);
    
    if (node) {
        node.status = "safe";
        node.risk = 10;
        node.rawCpu = 18;
        node.metrics = "CPU: 18% | Reconnected. Normal.";

        const actions = `Restored gateway interface to IP ${node.ip}`;
        socState.auditTrail.unshift({
            id: `MIT-${Math.floor(Math.random() * 900) + 100}`,
            target: node.name,
            desc: "Subnet Connection Re-established",
            source: "Operator Admin",
            actions: actions,
            status: "Mitigated"
        });

        logAuditEvent(node.name, `INTERFACE RESTORED: Host Subnet Gateway IP ${node.ip} re-enabled`, "Operator Admin", actions, "ONLINE");
        
        broadcastState();
        res.json({ success: true, state: socState });
    } else {
        res.status(404).json({ success: false, error: "Node not found" });
    }
});

// 4. Autopilot playbook trigger
app.post('/api/autopilot', (req, res) => {
    if (!socState.autopilotBannerActive) {
        return res.status(400).json({ success: false, error: "Autopilot playbook already executed" });
    }

    const prodNode = socState.networkNodes.find(n => n.name === 'DB-PROD-01');
    if (prodNode) {
        prodNode.status = "isolated";
        prodNode.rawCpu = 0;
        prodNode.risk = 0;
        prodNode.metrics = "OFFLINE - ISOLATED BY AUTOPILOT";
    }

    const actions = "Isolated database host subnet due to credential dump attempt";
    socState.auditTrail.unshift({
        id: `MIT-AUT-04`,
        target: "DB-PROD-01",
        desc: "AI Autopilot: Suspicious Host Isolation",
        source: "AI Autopilot",
        actions: actions,
        status: "Mitigated"
    });

    logAuditEvent("DB-PROD-01", "AI AUTOPILOT EXECUTION: Suspicious Host Isolation Triggered", "AI Autopilot", actions, "Mitigated");

    socState.threatLevel = 18.5;
    socState.autopilotBannerActive = false;

    broadcastState();
    res.json({ success: true, state: socState });
});

// 5. Copilot Chat Endpoint (Dynamic Real-Time SOC Intelligence)
app.post('/api/chat', (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });

    let lowercaseQuery = query.toLowerCase();
    let aiAnswer = "";

    // Search for matched node in query
    const matchedNode = socState.networkNodes.find(n => lowercaseQuery.includes(n.name.toLowerCase()) || lowercaseQuery.includes(n.name.replace('-', '').toLowerCase()));

    if (matchedNode) {
        const activeNodeAlerts = socState.activeAlerts.filter(a => a.target === matchedNode.name);
        const isIsolated = matchedNode.status === 'isolated';

        aiAnswer = `
            <strong>Node ${matchedNode.name} (${matchedNode.ip}) Real-Time Intelligence:</strong><br>
            - Host Operational Status: <code>${matchedNode.status.toUpperCase()}</code><br>
            - Current CPU Workload: <strong>${matchedNode.rawCpu}%</strong> capacity<br>
            - Calculated Risk Score: <strong>${matchedNode.risk}%</strong><br>
            - Active Incidents Targeting Host: <strong>${activeNodeAlerts.length}</strong><br>
            ${activeNodeAlerts.length > 0 ? `
                <div style="margin-top: 4px; padding: 6px; background: rgba(255,59,48,0.1); border-left: 3px solid #ff3b30; border-radius: 4px;">
                    <strong>Active Threat Vector:</strong> ${activeNodeAlerts[0].title}<br>
                    <strong>Attacker Source IP:</strong> <code>${activeNodeAlerts[0].sourceIp}</code> | Severity: <code>${activeNodeAlerts[0].score}</code><br>
                    <strong>Recommended Action:</strong> Click <em>Mitigate</em> on incident ID <code>${activeNodeAlerts[0].id}</code> or run:<br>
                    <code>iptables -A INPUT -s ${activeNodeAlerts[0].sourceIp} -j DROP</code>
                </div>
            ` : `
                <span style="color: #30d158;"><i class="fa-solid fa-circle-check"></i> No active threat vectors currently targeting this host subnet.</span>
            `}
        `;
    } else if (lowercaseQuery.includes("summarize") || lowercaseQuery.includes("threat") || lowercaseQuery.includes("attack") || lowercaseQuery.includes("status")) {
        const criticalCount = socState.activeAlerts.filter(a => a.severity === 'critical').length;
        aiAnswer = `
            <strong>Active SOC Threat Landscape Summary:</strong><br>
            - Global Threat Index: <strong style="color:${socState.threatLevel > 40 ? '#ff3b30' : '#30d158'}">${socState.threatLevel}%</strong><br>
            - Unresolved Incidents in Queue: <strong>${socState.activeAlerts.length}</strong> (${criticalCount} Critical)<br>
            - Active Network Ingress Flow: <strong>${socState.ingressRate.toFixed(2)} GB/s</strong><br>
            - Top Target Subnet: <code>${socState.activeAlerts.length > 0 ? socState.activeAlerts[0].target : 'DB-PROD-01'}</code><br>
            - Mitigation Recommendation: Deploy WAF filtering rules or execute manual host isolation on high-risk nodes.
        `;
    } else if (lowercaseQuery.includes("firewall") || lowercaseQuery.includes("recommendation") || lowercaseQuery.includes("rule") || lowercaseQuery.includes("guidelines")) {
        aiAnswer = `
            <strong>AEGIS Tactical Firewall Policy Guidelines:</strong><br>
            1. <strong>WAF Payload Rule 409:</strong> Filter incoming URI parameters matching regex: <code>/\\s*OR\\s+1\\s*=\\s*1/i</code>.<br>
            2. <strong>Perimeter Rate Limiting:</strong> Drop incoming UDP reflection flows exceeding 100,000 req/sec on port 1900/123.<br>
            3. <strong>SSH Containment:</strong> Enforce SSH Key Authentication only and drop root auth attempts after 5 failures via <code>fail2ban-client set sshd banip &lt;IP&gt;</code>.
        `;
    } else if (lowercaseQuery.includes("ip") || lowercaseQuery.includes("block")) {
        aiAnswer = `
            <strong>Attacker IP Blocklist Protocol:</strong><br>
            Attacking source IPs can be blocklisted at the perimeter router by clicking <strong>Mitigate</strong> on any active incident card. You can also run CLI command:<br>
            <code>route add -host &lt;Attacker_IP&gt; reject</code>
        `;
    } else {
        aiAnswer = `
            Aegis AI Security Engine evaluated prompt <strong>"${query}"</strong>.<br>
            Current System Telemetry: <strong>${socState.activeAlerts.length}</strong> active threat vectors detected. Global Threat Index is at <strong>${socState.threatLevel}%</strong>. Select a host card or active incident to trigger automated mitigations.
        `;
    }

    res.json({ answer: aiAnswer });
});

// 6. Manual Attack Simulation Endpoint
app.post('/api/simulate-attack', (req, res) => {
    const { title, severity, score, targetNode, sourceIp, payload, recommendation } = req.body;
    
    let target = targetNode;
    if (!target) {
        const activeNodes = socState.networkNodes.filter(n => n.status !== 'isolated');
        target = activeNodes.length > 0 ? activeNodes[Math.floor(Math.random() * activeNodes.length)].name : 'DB-PROD-01';
    }

    const selectedNode = socState.networkNodes.find(n => n.name === target);

    const randomIp = sourceIp || `${Math.floor(Math.random() * 190) + 10}.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
    const randomIncId = `INC-SIM-${Math.floor(Math.random() * 8000) + 1000}`;

    const newAlert = {
        id: randomIncId,
        title: title || "Simulated Security Incident",
        severity: severity || "high",
        score: (score || 8.5).toString(),
        sourceIp: randomIp,
        target: target,
        time: "Just Now",
        payload: payload || `MANUAL SIMULATION INJECTION\nTarget Endpoint: ${selectedNode ? selectedNode.ip : '10.142.0.1'}\nPayload signature matched attack vector database.`,
        recommendation: recommendation || "Simulated attack in progress. Execute target subnet isolation or deploy WAF rules immediately."
    };

    socState.activeAlerts.unshift(newAlert);
    
    const attackScore = parseFloat(newAlert.score);
    socState.threatLevel = Math.min(100.0, parseFloat((socState.threatLevel + attackScore / 2).toFixed(1)));
    
    if (selectedNode && selectedNode.status !== 'isolated') {
        selectedNode.risk = Math.min(99, selectedNode.risk + 35);
        selectedNode.rawCpu = Math.min(99, selectedNode.rawCpu + 45);
        selectedNode.metrics = `CPU: ${selectedNode.rawCpu}% | HIGH LOAD - UNDER ATTACK`;
    }

    // Multi-phase attack simulation logging over WebSockets
    logAuditEvent(target, `PACKET INGRESS: TCP ${randomIp}:49152 -> ${selectedNode ? selectedNode.ip : '10.142.0.1'}:80 (SYN)`, "Perimeter Gateway API-RT-01", "Packet Inspection Active", "Telemetry Stream");
    
    setTimeout(() => {
        logAuditEvent(target, `SECURITY THREAT MATCH: ${newAlert.title}`, "Signature Detection Engine", `Source IP: ${randomIp}`, "Active Threat");
    }, 150);

    setTimeout(() => {
        logAuditEvent(target, `HOST LOAD ALERT: Target ${target} CPU load spiked to ${selectedNode ? selectedNode.rawCpu : 98}%`, "Node Monitor", "Subnet threshold exceeded", "Active Threat");
    }, 300);

    setTimeout(() => {
        logAuditEvent(target, `AUTOPILOT ADVISORY: ${newAlert.recommendation}`, "AI Autopilot", "Action ready for deployment", "Advisory");
    }, 450);

    broadcastState();
    res.json({ success: true, alert: newAlert, state: socState });
});

// 7. Reset SOC System State Endpoint
app.post('/api/reset', (req, res) => {
    socState.activeAlerts = [];
    socState.threatLevel = 12.4;
    socState.ingressRate = 3.25;
    socState.mitigationRate = 98.5;
    socState.autopilotBannerActive = true;

    socState.networkNodes.forEach(node => {
        node.status = "safe";
        node.risk = Math.floor(Math.random() * 15) + 10;
        node.rawCpu = Math.floor(Math.random() * 20) + 15;
        node.metrics = `CPU: ${node.rawCpu}% | Normal Operational State`;
    });

    logAuditEvent("SYSTEM", "SOC Dashboard State Reset Executed", "Operator Admin", "Cleared active incidents & restored nodes", "ONLINE");

    broadcastState();
    res.json({ success: true, state: socState });
});

// Dynamic Threat Simulation Speed Config
let simulationMode = "normal"; // "fast", "normal", "paused"
let threatTimer = null;

function getIntervalForMode(mode) {
    if (mode === "fast") return 5000;
    if (mode === "paused") return 99999999;
    return 12000; // normal
}

// Threat generator templates
const threatTemplates = [
    {
        title: "DDoS Reflection Flood",
        severity: "high",
        score: "8.1",
        payload: "UDP reflection flow targeting port 80. Protocol: NTP reflection. Bandwidth threshold: 820MB/s.",
        recommendation: "Enable edge router rate filtering for UDP port 123. Enable firewall null-route actions."
    },
    {
        title: "Suspicious Host Scan (Port Scan)",
        severity: "medium",
        score: "6.0",
        payload: "TCP SYN port scan. Port range scanned: 1-1024. Pattern: horizontal sweep search from external node.",
        recommendation: "Rate limit connection attempts per IP. Block source scan host at perimeter router."
    },
    {
        title: "Malicious File Upload (Webshell)",
        severity: "critical",
        score: "9.5",
        payload: "POST /uploads/profile.php HTTP/1.1\nContent-Type: multipart/form-data\n\n<?php system($_GET['cmd']); ?>",
        recommendation: "Immediate web container isolation. Terminate active container. Delete uploaded profile.php and audit folder access."
    },
    {
        title: "Anomalous DNS Tunneling Activity",
        severity: "high",
        score: "7.6",
        payload: "DNS lookup queries: sub.long-exfil-hash-domain.com TXT records. Length limit: 255 chars, count: 489/sec.",
        recommendation: "Block domain queries on DNS level. Isolate outbound DNS lookup nodes and examine system process lists."
    }
];

function spawnBackgroundThreat() {
    if (simulationMode === "paused") return;
    if (socState.activeAlerts.length >= 10) return;

    const activeTargetNodes = socState.networkNodes.filter(n => n.status !== 'isolated');
    if (activeTargetNodes.length === 0) return;

    const selectedTarget = activeTargetNodes[Math.floor(Math.random() * activeTargetNodes.length)];
    const template = threatTemplates[Math.floor(Math.random() * threatTemplates.length)];

    const randomIp = `${Math.floor(Math.random() * 190) + 10}.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
    const randomIncId = `INC-${Math.floor(Math.random() * 8000) + 1000}`;

    const newAlert = {
        id: randomIncId,
        title: template.title,
        severity: template.severity,
        score: template.score,
        sourceIp: randomIp,
        target: selectedTarget.name,
        time: "Just Now",
        payload: `Target Endpoint: ${selectedTarget.ip}\nTelemetry logs:\n${template.payload}`,
        recommendation: template.recommendation
    };

    socState.activeAlerts.unshift(newAlert);
    socState.threatLevel = Math.min(100.0, parseFloat((socState.threatLevel + parseFloat(template.score) / 2).toFixed(1)));
    
    logAuditEvent(selectedTarget.name, `Threat Detected: ${template.title}`, "Threat Intelligence Engine", `Source IP: ${randomIp}`, "Active Threat");

    selectedTarget.risk = Math.min(98, selectedTarget.risk + 15);

    broadcastState();
}

function resetThreatTimer() {
    if (threatTimer) clearInterval(threatTimer);
    if (simulationMode !== "paused") {
        threatTimer = setInterval(spawnBackgroundThreat, getIntervalForMode(simulationMode));
    }
}

app.post('/api/simulation-config', (req, res) => {
    const { mode } = req.body;
    if (['fast', 'normal', 'paused'].includes(mode)) {
        simulationMode = mode;
        resetThreatTimer();
        logAuditEvent("SYSTEM", `Simulation Mode updated to: ${mode.toUpperCase()}`, "Operator Admin", `Interval set to ${mode}`, "CONFIG_CHANGED");
        return res.json({ success: true, mode: simulationMode });
    }
    res.status(400).json({ success: false, error: "Invalid mode" });
});

// Periodic Telemetry updates simulator (Fluctuates CPU and Ingress Rate every 800ms sub-second)
setInterval(() => {
    socState.networkNodes.forEach(node => {
        if (node.status !== "isolated") {
            const fluctuation = Math.floor(Math.random() * 7) - 3;
            node.rawCpu = Math.min(99, Math.max(5, node.rawCpu + fluctuation));
            
            if (node.name === "API-GATEWAY") {
                node.metrics = `CPU: ${node.rawCpu}% | Ingress ${(socState.ingressRate).toFixed(2)} GB/s`;
            } else if (node.name === "DEV-STAGE-01") {
                node.metrics = `CPU: ${node.rawCpu}% | SFTP session active`;
            } else if (node.name === "DB-PROD-01" && node.rawCpu > 80) {
                node.metrics = `CPU: ${node.rawCpu}% | SQL load high`;
            } else {
                node.metrics = `CPU: ${node.rawCpu}% | ${node.rawCpu > 50 ? 'Medium Load' : 'Normal'}`;
            }
        }
    });

    const flowFluctuation = (Math.random() * 0.4) - 0.2;
    socState.ingressRate = Math.min(10.0, Math.max(1.1, socState.ingressRate + flowFluctuation));
    
    const mitFluctuation = (Math.random() * 0.2) - 0.1;
    socState.mitigationRate = Math.min(99.9, Math.max(75.0, socState.mitigationRate + mitFluctuation));

    broadcastState();
}, 800);

// Start background auto threat generator
resetThreatTimer();

// WebSocket Setup
server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

wss.on('connection', (ws) => {
    console.log("Client connected to SOC WebSocket gateway");
    
    // Send initial complete state upon connecting
    ws.send(JSON.stringify({
        type: "INITIAL_STATE",
        state: socState
    }));

    ws.on('close', () => {
        console.log("Client disconnected from WebSocket gateway");
    });
});

// Start Server
server.listen(PORT, () => {
    console.log(`AEGIS SOC Core running on port ${PORT}`);
    console.log(`Audit log: ${LOG_FILE}`);
});
