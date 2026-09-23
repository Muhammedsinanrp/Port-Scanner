// AegisScan Web Dashboard Logic

let currentScanId = null;
let pollInterval = null;

function setPreset(target, ports, mode) {
    document.getElementById("target-input").value = target;
    document.getElementById("ports-input").value = ports;
    document.getElementById("mode-select").value = mode;
}

function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(content => content.classList.remove("active"));

    const btn = event.target;
    if (btn) btn.classList.add("active");
    const activeSection = document.getElementById("tab-" + tabName);
    if (activeSection) activeSection.classList.add("active");
}

function clearLogs() {
    const term = document.getElementById("terminal-logs");
    term.innerHTML = '<div class="log-line"><span class="log-tag">[SYSTEM]</span> Console logs cleared.</div>';
}

function appendLog(msg) {
    const term = document.getElementById("terminal-logs");
    const line = document.createElement("div");
    line.className = "log-line";
    line.innerHTML = `<span class="log-tag">[SCAN]</span> ${escapeHtml(msg)}`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

function escapeHtml(text) {
    if (!text) return "";
    const div = document.createElement("div");
    div.innerText = text;
    return div.innerHTML;
}

async function startScan() {
    const target = document.getElementById("target-input").value.trim();
    const ports = document.getElementById("ports-input").value.trim() || "top-100";
    const mode = document.getElementById("mode-select").value;

    if (!target) {
        alert("Please enter a target IP or domain.");
        return;
    }

    const startBtn = document.getElementById("btn-start");
    startBtn.disabled = true;
    startBtn.innerHTML = '<span class="btn-icon">⏳</span> Scanning...';

    // Engage 3D Cyber Globe Scan Animation
    if (typeof triggerScan3DAnimation === 'function') {
        triggerScan3DAnimation(true);
    }

    // Show progress bar
    const progSec = document.getElementById("progress-section");
    progSec.style.display = "block";
    updateProgress(5, "Initializing scanner and target verification...");

    // Reset Metrics & UI
    document.getElementById("stat-open-ports").innerText = "0";
    document.getElementById("stat-vulns").innerText = "0";
    document.getElementById("stat-latency").innerText = "—";
    document.getElementById("stat-duration").innerText = "0.0s";
    document.getElementById("export-bar").style.display = "none";
    document.getElementById("ports-tbody").innerHTML = '<tr><td colspan="5" class="empty-state">Scan in progress... Discovered open ports will appear here in real time.</td></tr>';
    document.getElementById("vulns-container").innerHTML = '<div class="empty-state">Vulnerability heuristics running...</div>';

    clearLogs();
    appendLog(`Sending scan request for ${target} (${ports}) via engine '${mode}'...`);

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
        appendLog(`Scan task registered with ID: ${currentScanId}`);

        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollScanStatus, 500);

    } catch (err) {
        alert("Error: " + err.message);
        startBtn.disabled = false;
        startBtn.innerHTML = '<span class="btn-icon">⚡</span> Launch Scan';
        progSec.style.display = "none";
    }
}

async function pollScanStatus() {
    if (!currentScanId) return;

    try {
        const res = await fetch(`/api/scan/${currentScanId}`);
        if (!res.ok) return;

        const scan = await res.json();

        // Update progress
        updateProgress(scan.progress, scan.status === "completed" ? "Scan Completed!" : "Scanning in progress...");

        // Update Metrics
        const openPorts = scan.open_ports || [];
        const vulns = scan.vulnerabilities || [];

        document.getElementById("stat-open-ports").innerText = openPorts.length;
        document.getElementById("tab-ports-count").innerText = openPorts.length;

        document.getElementById("stat-vulns").innerText = vulns.length;
        document.getElementById("tab-vulns-count").innerText = vulns.length;

        if (scan.ping && scan.ping.rtt_ms) {
            document.getElementById("stat-latency").innerText = `${scan.ping.rtt_ms} ms`;
        }

        if (scan.duration_sec) {
            document.getElementById("stat-duration").innerText = `${scan.duration_sec}s`;
        }

        // Render Open Ports Table
        if (openPorts.length > 0 && typeof triggerPortDiscoveredPulse === 'function') {
            triggerPortDiscoveredPulse();
        }
        renderPortsTable(openPorts);

        // Render Vulnerabilities
        renderVulnerabilities(vulns);

        // Render Recon Data
        renderReconData(scan);

        // Render Terminal logs
        if (scan.logs && scan.logs.length > 0) {
            const term = document.getElementById("terminal-logs");
            term.innerHTML = scan.logs.map(log => 
                `<div class="log-line"><span class="log-tag">[SCAN]</span> ${escapeHtml(log)}</div>`
            ).join("");
            term.scrollTop = term.scrollHeight;
        }

        // Check if finished
        if (scan.status === "completed" || scan.status === "error") {
            clearInterval(pollInterval);
            if (typeof triggerScan3DAnimation === 'function') {
                triggerScan3DAnimation(false);
            }
            const startBtn = document.getElementById("btn-start");
            startBtn.disabled = false;
            startBtn.innerHTML = '<span class="btn-icon">⚡</span> Engage 3D Recon Scan';

            if (scan.status === "completed") {
                document.getElementById("export-bar").style.display = "flex";
                appendLog(`[COMPLETE] Scan successfully concluded in ${scan.duration_sec} seconds.`);
            } else {
                appendLog(`[ERROR] Scan terminated: ${scan.error || 'Unknown error'}`);
            }
        }

    } catch (e) {
        console.error("Error polling scan status:", e);
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
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No open ports discovered yet.</td></tr>';
        return;
    }

    tbody.innerHTML = ports.map(p => {
        const portNum = p.port;
        const svc = escapeHtml(p.service || "unknown");
        const banner = escapeHtml(p.banner || "None");
        const lat = p.latency_ms !== undefined ? `${p.latency_ms} ms` : "—";

        let scriptsHtml = "";
        if (p.scripts && Object.keys(p.scripts).length > 0) {
            scriptsHtml = `<div class="nse-scripts-box"><strong>NSE:</strong> ` + 
                Object.keys(p.scripts).map(k => `<code>${escapeHtml(k)}</code>`).join(" ") +
                `</div>`;
        }

        return `
            <tr>
                <td><span class="badge port-badge">${portNum}</span></td>
                <td><span class="badge badge-open">OPEN</span></td>
                <td><strong>${svc}</strong></td>
                <td><span class="banner-code">${banner}</span>${scriptsHtml}</td>
                <td>${lat}</td>
            </tr>
        `;
    }).join("");
}

function renderVulnerabilities(vulns) {
    const container = document.getElementById("vulns-container");
    if (!vulns || vulns.length === 0) {
        container.innerHTML = '<div class="empty-state">No known vulnerabilities or critical exposures detected in this scan.</div>';
        return;
    }

    container.innerHTML = vulns.map(v => {
        const sev = v.severity || "INFO";
        const title = escapeHtml(v.title || "");
        const desc = escapeHtml(v.description || "");
        const port = v.port ? `Port ${v.port}` : "Host";
        const evidence = v.evidence ? `<div class="vuln-evidence-tag">Evidence: ${escapeHtml(v.evidence)}</div>` : "";

        return `
            <div class="vuln-item vuln-${sev.toLowerCase()}">
                <div class="vuln-header-row">
                    <span class="sev-badge sev-badge-${sev.toLowerCase()}">${sev}</span>
                    <span class="vuln-port-tag">${port}</span>
                    <span class="vuln-title">${title}</span>
                </div>
                <div class="vuln-desc-text">${desc}</div>
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
            <li><strong>Resolved IPv4:</strong> ${escapeHtml(scan.target_ip || scan.target)}</li>
            <li><strong>Reverse DNS (PTR):</strong> ${escapeHtml(dns.reverse_ptr || 'None')}</li>
            <li><strong>MX Records:</strong> ${(dns.mx_records && dns.mx_records.length) ? escapeHtml(dns.mx_records.join(", ")) : 'None'}</li>
            <li><strong>NS Records:</strong> ${(dns.ns_records && dns.ns_records.length) ? escapeHtml(dns.ns_records.join(", ")) : 'None'}</li>
        </ul>
    `;

    // SSL Box
    const sslBox = document.getElementById("ssl-info-box");
    const ssl = scan.ssl_cert;
    if (ssl) {
        sslBox.innerHTML = `
            <ul>
                <li><strong>TLS Protocol:</strong> ${escapeHtml(ssl.tls_version || 'Unknown')}</li>
                <li><strong>Cipher Suite:</strong> ${escapeHtml(ssl.cipher_suite || 'Unknown')}</li>
                <li><strong>Valid Until:</strong> ${escapeHtml(ssl.not_after || 'Unknown')} (${ssl.days_until_expiration || '—'} days remaining)</li>
                <li><strong>Expired:</strong> ${ssl.is_expired ? '<span class="text-danger">EXPIRED</span>' : '<span class="text-success">VALID</span>'}</li>
            </ul>
        `;
    } else {
        sslBox.innerHTML = '<p class="text-muted">No SSL/TLS certificate detected on scanned endpoints.</p>';
    }

    // HTTP Box
    const httpBox = document.getElementById("http-info-box");
    const http = scan.http_info;
    if (http) {
        httpBox.innerHTML = `
            <ul>
                <li><strong>URL Endpoint:</strong> <code>${escapeHtml(http.url)}</code></li>
                <li><strong>Status Code:</strong> ${http.status_code}</li>
                <li><strong>Page Title:</strong> ${escapeHtml(http.title || 'None')}</li>
                <li><strong>Server Header:</strong> ${escapeHtml(http.server || 'Unknown')}</li>
                <li><strong>Powered By:</strong> ${escapeHtml(http.powered_by || 'Unknown')}</li>
            </ul>
        `;
    } else {
        httpBox.innerHTML = '<p class="text-muted">No web application endpoint probed.</p>';
    }
}

function exportReport(format) {
    if (!currentScanId) {
        alert("No completed scan to export.");
        return;
    }
    window.open(`/api/export/${currentScanId}/${format}`, "_blank");
}

/* ==============================================================================
   PRO UPGRADE & UPI PAYMENT LOGIC (Starts at ₹10)
   ============================================================================== */
let currentSelectedPrice = 10;
let currentSelectedPlan = 'single';
let currentAdminUPI = 'muhammedsinan@upi';

function openPaymentModal() {
    const modal = document.getElementById("payment-modal");
    if (modal) modal.style.display = "flex";
}

function closePaymentModal() {
    const modal = document.getElementById("payment-modal");
    if (modal) modal.style.display = "none";
}

function selectPlan(price, planId, elem) {
    currentSelectedPrice = price;
    currentSelectedPlan = planId;

    // Update active class
    document.querySelectorAll(".plan-option").forEach(el => el.classList.remove("active"));
    if (elem) elem.classList.add("active");

    // Update QR code dynamically with price
    const qrImg = document.getElementById("upi-qr-image");
    const upiUri = `upi://pay?pa=${encodeURIComponent(currentAdminUPI)}&pn=MuhammedSinan&am=${price}&cu=INR&tn=AegisScan_${planId}`;
    qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(upiUri)}`;
}

function copyUPI() {
    navigator.clipboard.writeText(currentAdminUPI).then(() => {
        alert(`UPI ID '${currentAdminUPI}' copied to clipboard.`);
    });
}

async function submitPaymentVerification() {
    const input = document.getElementById("utr-input");
    const feedback = document.getElementById("utr-feedback");
    const btn = document.getElementById("btn-verify-utr");
    const code = input.value.trim();

    if (!code) {
        feedback.className = "utr-feedback-msg msg-error";
        feedback.innerText = "Please enter 12-digit UPI UTR / Reference number or Promo code.";
        return;
    }

    btn.disabled = true;
    btn.innerText = "Verifying...";
    feedback.innerText = "";

    try {
        const resp = await fetch("/api/payment/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: code, plan_id: currentSelectedPlan })
        });

        const data = await resp.json();

        if (resp.ok && data.success) {
            feedback.className = "utr-feedback-msg msg-success";
            feedback.innerText = "Payment verified! Pro features unlocked.";
            localStorage.setItem("aegis_pro_token", data.token);

            // Update Header Button
            updateProHeaderStatus(true);

            setTimeout(() => {
                closePaymentModal();
                alert("🎉 Congratulations! PRO access is now unlocked on your account.");
            }, 1200);
        } else {
            feedback.className = "utr-feedback-msg msg-error";
            feedback.innerText = data.error || "Verification failed. Check your UTR number.";
        }
    } catch (err) {
        feedback.className = "utr-feedback-msg msg-error";
        feedback.innerText = "Network error. Please try again.";
    } finally {
        btn.disabled = false;
        btn.innerText = "Verify & Unlock";
    }
}

function updateProHeaderStatus(isPro) {
    const proBtn = document.getElementById("btn-pro-plan");
    if (!proBtn) return;
    if (isPro) {
        proBtn.className = "btn-pro-upgrade btn-pro-unlocked";
        proBtn.innerHTML = "<span>🛡️</span> PRO VIP ACTIVE";
    } else {
        proBtn.className = "btn-pro-upgrade";
        proBtn.innerHTML = `<span class="pro-sparkle">✨</span> UNLOCK PRO (<span id="header-pro-price">₹10</span>)`;
    }
}

// On load, check pro status & fetch admin payment config
document.addEventListener("DOMContentLoaded", async () => {
    const savedToken = localStorage.getItem("aegis_pro_token");
    if (savedToken) {
        updateProHeaderStatus(true);
    }

    // Fetch payment config if available
    try {
        const res = await fetch("/api/payment/info");
        if (res.ok) {
            const info = await res.json();
            if (info.upi_id) {
                currentAdminUPI = info.upi_id;
                const upiEl = document.getElementById("display-upi-id");
                if (upiEl) upiEl.innerText = info.upi_id;
                selectPlan(10, 'single', document.querySelector(".plan-option.active"));
            }
        }
    } catch (e) {
        // Fallback to default
    }
});

