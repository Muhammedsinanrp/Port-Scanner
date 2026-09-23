// AEGIS-X Tactical Cyber Dashboard Logic & Sound Engine

let currentScanId = null;
let pollInterval = null;
let audioEnabled = true;

// Web Audio API Synthesizer (100% Client-Side, zero audio files required)
let audioCtx = null;

function getAudioContext() {
    if (!audioCtx) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) {
            audioCtx = new AudioContext();
        }
    }
    if (audioCtx && audioCtx.state === 'suspended') {
        audioCtx.resume();
    }
    return audioCtx;
}

function playCyberSound(type) {
    if (!audioEnabled) return;
    try {
        const ctx = getAudioContext();
        if (!ctx) return;

        const now = ctx.currentTime;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);

        if (type === 'click') {
            osc.type = 'sine';
            osc.frequency.setValueAtTime(800, now);
            osc.frequency.exponentialRampToValueAtTime(400, now + 0.05);
            gain.gain.setValueAtTime(0.08, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
            osc.start(now);
            osc.stop(now + 0.05);
        } else if (type === 'engage') {
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(220, now);
            osc.frequency.exponentialRampToValueAtTime(880, now + 0.25);
            gain.gain.setValueAtTime(0.12, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
            osc.start(now);
            osc.stop(now + 0.25);
        } else if (type === 'port_found') {
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(950, now);
            osc.frequency.setValueAtTime(1250, now + 0.06);
            gain.gain.setValueAtTime(0.1, now);
            gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
            osc.start(now);
            osc.stop(now + 0.12);
        } else if (type === 'complete') {
            // High-tech completion chime
            [523.25, 659.25, 783.99, 1046.50].forEach((freq, i) => {
                const o = ctx.createOscillator();
                const g = ctx.createGain();
                o.connect(g);
                g.connect(ctx.destination);
                o.type = 'sine';
                o.frequency.setValueAtTime(freq, now + (i * 0.08));
                g.gain.setValueAtTime(0.09, now + (i * 0.08));
                g.gain.exponentialRampToValueAtTime(0.001, now + (i * 0.08) + 0.3);
                o.start(now + (i * 0.08));
                o.stop(now + (i * 0.08) + 0.3);
            });
        }
    } catch (e) {
        // Audio error ignored safely
    }
}

function toggleAudio() {
    audioEnabled = !audioEnabled;
    const icon = document.getElementById("audio-icon");
    const txt = document.getElementById("audio-state-text");
    if (audioEnabled) {
        icon.innerText = "🔊";
        txt.innerText = "ON";
        playCyberSound('click');
    } else {
        icon.innerText = "🔇";
        txt.innerText = "OFF";
    }
}

function setPreset(target, ports, mode) {
    playCyberSound('click');
    document.getElementById("target-input").value = target;
    document.getElementById("ports-input").value = ports;
    document.getElementById("mode-select").value = mode;
}

function switchTab(tabName) {
    playCyberSound('click');
    document.querySelectorAll(".cyber-tab").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".cyber-tab-pane").forEach(pane => pane.classList.remove("active"));

    if (event && event.currentTarget) {
        event.currentTarget.classList.add("active");
    }
    const targetPane = document.getElementById("tab-" + tabName);
    if (targetPane) targetPane.classList.add("active");
}

function clearLogs() {
    playCyberSound('click');
    const term = document.getElementById("terminal-logs");
    term.innerHTML = '<div class="term-line"><span class="term-prompt">aegis@sec:~$</span> Logs purged. Buffer clear.</div>';
}

function copyLogs() {
    playCyberSound('click');
    const term = document.getElementById("terminal-logs");
    const text = term.innerText;
    navigator.clipboard.writeText(text).then(() => {
        alert("Tactical console logs copied to clipboard.");
    });
}

function escapeHtml(text) {
    if (!text) return "";
    const div = document.createElement("div");
    div.innerText = text;
    return div.innerHTML;
}

// Common ports for the live visual matrix
const MATRIX_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
    8000, 8080, 8443, 8888, 9000, 9200, 11211, 27017
];

function initPortMatrix() {
    const grid = document.getElementById("port-matrix-grid");
    if (!grid) return;
    grid.innerHTML = MATRIX_PORTS.map(port => `
        <div class="matrix-tile" id="tile-${port}">
            <div class="tile-port">${port}</div>
            <div class="tile-status">INACTIVE</div>
        </div>
    `).join("");
}

function updatePortMatrix(openPorts) {
    const openSet = new Set((openPorts || []).map(p => p.port));
    MATRIX_PORTS.forEach(port => {
        const tile = document.getElementById(`tile-${port}`);
        if (tile) {
            if (openSet.has(port)) {
                tile.className = "matrix-tile tile-is-open";
                tile.querySelector(".tile-status").innerText = "OPEN";
            } else {
                tile.className = "matrix-tile";
                tile.querySelector(".tile-status").innerText = "INACTIVE";
            }
        }
    });
}

async function startScan() {
    playCyberSound('engage');
    const target = document.getElementById("target-input").value.trim();
    const ports = document.getElementById("ports-input").value.trim() || "top-100";
    const mode = document.getElementById("mode-select").value;

    if (!target) {
        alert("Please specify a target IP or domain.");
        return;
    }

    const startBtn = document.getElementById("btn-start");
    startBtn.disabled = true;
    startBtn.classList.add("btn-busy");
    startBtn.querySelector(".btn-text").innerText = "ENGAGING RECON...";

    // Show Progress HUD
    const progSec = document.getElementById("progress-section");
    progSec.style.display = "block";
    updateProgress(5, "Initializing socket threads and target verification...");

    // Reset Metrics
    document.getElementById("stat-open-ports").innerText = "0";
    document.getElementById("stat-vulns").innerText = "0";
    document.getElementById("stat-latency").innerText = "—";
    document.getElementById("stat-duration").innerText = "0.00s";
    document.getElementById("export-bar").style.display = "none";
    document.getElementById("hud-live-open").innerText = "0";
    document.getElementById("hud-scanned-count").innerText = "0";

    document.getElementById("ports-tbody").innerHTML = '<tr><td colspan="5" class="empty-cyber-cell"><span class="empty-icon">⚡</span><div>SCANNING IN PROGRESS. STREAMING DISCOVERED PORTS...</div></td></tr>';
    document.getElementById("vulns-container").innerHTML = '<div class="empty-cyber-cell"><span class="empty-icon">🛡️</span><div>ANALYZING CVE SIGNATURES AND PROTOCOL EXPOSURES...</div></td>';

    initPortMatrix();

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target, ports, mode })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || "Failed to start scan");
        }

        currentScanId = data.scan_id;

        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollScanStatus, 450);

    } catch (err) {
        alert("Scan Engagement Error: " + err.message);
        startBtn.disabled = false;
        startBtn.classList.remove("btn-busy");
        startBtn.querySelector(".btn-text").innerText = "ENGAGE SCAN";
        progSec.style.display = "none";
    }
}

let lastDiscoveredCount = 0;

async function pollScanStatus() {
    if (!currentScanId) return;

    try {
        const res = await fetch(`/api/scan/${currentScanId}`);
        if (!res.ok) return;

        const scan = await res.json();

        // Update progress bar & label
        updateProgress(scan.progress, scan.status === "completed" ? "MISSION SCAN COMPLETE" : "SCAN ENGAGED: PROBING PORTS...");

        const openPorts = scan.open_ports || [];
        const vulns = scan.vulnerabilities || [];

        // Audio blip if new port found
        if (openPorts.length > lastDiscoveredCount) {
            playCyberSound('port_found');
            lastDiscoveredCount = openPorts.length;
        }

        // Metrics
        document.getElementById("stat-open-ports").innerText = openPorts.length;
        document.getElementById("hud-live-open").innerText = openPorts.length;
        document.getElementById("tab-ports-count").innerText = openPorts.length;

        document.getElementById("stat-vulns").innerText = vulns.length;
        document.getElementById("tab-vulns-count").innerText = vulns.length;

        document.getElementById("hud-scanned-count").innerText = `${scan.scanned_count || 0} / ${scan.total_ports || '?'}`;

        if (scan.ping && scan.ping.rtt_ms) {
            document.getElementById("stat-latency").innerText = `${scan.ping.rtt_ms} ms`;
        }

        if (scan.duration_sec) {
            document.getElementById("stat-duration").innerText = `${scan.duration_sec}s`;
        }

        renderPortsTable(openPorts);
        renderVulnerabilities(vulns);
        renderReconData(scan);
        updatePortMatrix(openPorts);

        // Terminal logs
        if (scan.logs && scan.logs.length > 0) {
            const term = document.getElementById("terminal-logs");
            term.innerHTML = scan.logs.map(log => 
                `<div class="term-line"><span class="term-prompt">aegis@sec:~$</span> ${escapeHtml(log)}</div>`
            ).join("");
            term.scrollTop = term.scrollHeight;
        }

        // Check if finished
        if (scan.status === "completed" || scan.status === "error") {
            clearInterval(pollInterval);
            const startBtn = document.getElementById("btn-start");
            startBtn.disabled = false;
            startBtn.classList.remove("btn-busy");
            startBtn.querySelector(".btn-text").innerText = "ENGAGE SCAN";

            if (scan.status === "completed") {
                playCyberSound('complete');
                document.getElementById("export-bar").style.display = "flex";
            }
        }

    } catch (e) {
        console.error("Telemetry error:", e);
    }
}

function updateProgress(pct, statusText) {
    const fill = document.getElementById("progress-bar-fill");
    const pctLabel = document.getElementById("progress-pct-text");
    const statusLabel = document.getElementById("progress-status-text");

    fill.style.width = pct + "%";
    pctLabel.innerText = pct + "%";
    if (statusText) statusLabel.innerText = statusText;
}

function renderPortsTable(ports) {
    const tbody = document.getElementById("ports-tbody");
    if (!ports || ports.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-cyber-cell"><span class="empty-icon">⬡</span><div>NO OPEN PORTS DISCOVERED IN CURRENT PROBE.</div></td></tr>';
        return;
    }

    tbody.innerHTML = ports.map(p => {
        const portNum = p.port;
        const svc = escapeHtml(p.service || "unknown");
        const banner = escapeHtml(p.banner || "None");
        const lat = p.latency_ms !== undefined ? `${p.latency_ms} ms` : "—";

        let scriptsHtml = "";
        if (p.scripts && Object.keys(p.scripts).length > 0) {
            scriptsHtml = `<div class="nse-scripts-box"><strong>[NSE DISCOVERY]:</strong> ` + 
                Object.keys(p.scripts).map(k => `<code>${escapeHtml(k)}</code>`).join(" ") +
                `</div>`;
        }

        return `
            <tr>
                <td><span class="port-pill">${portNum} / TCP</span></td>
                <td><span class="badge-state-open">OPEN</span></td>
                <td><strong class="cyber-neon-cyan">${svc}</strong></td>
                <td><span class="banner-code-box">${banner}</span>${scriptsHtml}</td>
                <td><span class="cyber-neon-green">${lat}</span></td>
            </tr>
        `;
    }).join("");
}

function renderVulnerabilities(vulns) {
    const container = document.getElementById("vulns-container");
    if (!vulns || vulns.length === 0) {
        container.innerHTML = '<div class="empty-cyber-cell"><span class="empty-icon">🛡️</span><div>TARGET EVALUATED: NO CRITICAL EXPLOITS DETECTED IN THIS SCAN.</div></div>';
        return;
    }

    container.innerHTML = vulns.map(v => {
        const sev = v.severity || "INFO";
        const title = escapeHtml(v.title || "");
        const desc = escapeHtml(v.description || "");
        const port = v.port ? `PORT ${v.port}` : "HOST";
        const evidence = v.evidence ? `<div class="vuln-evidence-box"><strong>TELEMETRY EVIDENCE:</strong> ${escapeHtml(v.evidence)}</div>` : "";

        const sevClass = sev.toLowerCase().slice(0, 4);

        return `
            <div class="vuln-cyber-card vuln-${sevClass}">
                <div class="vuln-header-flex">
                    <span class="badge-sev badge-${sevClass}">${sev}</span>
                    <span class="vuln-port-label">${port}</span>
                    <span class="vuln-headline">${title}</span>
                </div>
                <div class="vuln-description">${desc}</div>
                ${evidence}
            </div>
        `;
    }).join("");
}

function renderReconData(scan) {
    // DNS Box
    const dnsBox = document.getElementById("dns-info-box");
    const dns = scan.dns || {};
    dnsBox.innerHTML = `
        <ul>
            <li><strong>RESOLVED IPv4:</strong> <span class="cyber-neon-cyan">${escapeHtml(scan.target_ip || scan.target)}</span></li>
            <li><strong>REVERSE DNS (PTR):</strong> ${escapeHtml(dns.reverse_ptr || 'None')}</li>
            <li><strong>MX SERVERS:</strong> ${(dns.mx_records && dns.mx_records.length) ? escapeHtml(dns.mx_records.join(", ")) : 'None'}</li>
            <li><strong>NAMESERVERS (NS):</strong> ${(dns.ns_records && dns.ns_records.length) ? escapeHtml(dns.ns_records.join(", ")) : 'None'}</li>
        </ul>
    `;

    // SSL Box
    const sslBox = document.getElementById("ssl-info-box");
    const ssl = scan.ssl_cert;
    if (ssl) {
        sslBox.innerHTML = `
            <ul>
                <li><strong>TLS PROTOCOL:</strong> <span class="cyber-neon-cyan">${escapeHtml(ssl.tls_version || 'Unknown')}</span></li>
                <li><strong>CIPHER SUITE:</strong> <code>${escapeHtml(ssl.cipher_suite || 'Unknown')}</code></li>
                <li><strong>VALID UNTIL:</strong> ${escapeHtml(ssl.not_after || 'Unknown')} (${ssl.days_until_expiration || '—'} days remaining)</li>
                <li><strong>CERT STATUS:</strong> ${ssl.is_expired ? '<span class="cyber-neon-red">EXPIRED</span>' : '<span class="cyber-neon-green">ACTIVE & VALID</span>'}</li>
            </ul>
        `;
    } else {
        sslBox.innerHTML = '<p class="cyber-muted">No SSL/TLS certificate found on probed ports.</p>';
    }

    // HTTP Box
    const httpBox = document.getElementById("http-info-box");
    const http = scan.http_info;
    if (http) {
        httpBox.innerHTML = `
            <ul>
                <li><strong>URL ENDPOINT:</strong> <span class="cyber-neon-cyan">${escapeHtml(http.url)}</span></li>
                <li><strong>HTTP STATUS:</strong> <span class="cyber-neon-green">${http.status_code}</span></li>
                <li><strong>PAGE TITLE:</strong> ${escapeHtml(http.title || 'None')}</li>
                <li><strong>SERVER HEADER:</strong> ${escapeHtml(http.server || 'Unknown')}</li>
                <li><strong>POWERED BY:</strong> ${escapeHtml(http.powered_by || 'Unknown')}</li>
            </ul>
        `;
    } else {
        httpBox.innerHTML = '<p class="cyber-muted">No web application endpoint probed.</p>';
    }
}

function exportReport(format) {
    playCyberSound('click');
    if (!currentScanId) {
        alert("No completed scan data available to export.");
        return;
    }
    window.open(`/api/export/${currentScanId}/${format}`, "_blank");
}

// Initialize on DOM load
document.addEventListener("DOMContentLoaded", () => {
    initPortMatrix();
});
