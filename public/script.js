/**
 * 404 — AI-Powered Web Vulnerability Scanner
 * Frontend Logic
 *
 * 1. Quick Scan (POST /api/scan)
 * 2. Active OWASP Scan (GET /api/active-scan SSE)
 * 3. Header Audit (POST /api/owasp-check)
 * 4. PDF Report
 * 5. Directory Fuzzer (POST /api/fuzz-start → GET /api/fuzz-stream SSE)
 * 6. Traffic Analyzer
 * 7. Tabs
 * 8. View switcher + sidebar
 * 9. Recent scan history
 * 10. AI Integration (per-tab, Drana Infinity)
 */

// ── State ──────────────────────────────────────────────────────────────────────
let lastScanData = null;
let activeEventSource = null;
let fuzzSessionId = null;
let fuzzEventSource = null;
let fuzzRunning = false;

// Per-tab AI analysis cache: stores the last analysis text for each tab
const tabAiCache = { scanner: null, fuzzer: null, analyzer: null };
// Per-tab raw payload cache: used to regenerate analysis
const tabPayloadCache = { scanner: null, fuzzer: null, analyzer: null };

const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

// In-memory scan history (mock initially, augmented by real scans)
const scanHistory = [
    { domain: 'example.com', date: 'Feb 24, 09:49', status: 'completed' },
    { domain: 'testphp.vulnweb.com', date: 'Feb 24, 08:12', status: 'completed' },
    { domain: 'juice-shop.local', date: 'Feb 23, 22:05', status: 'failed' },
    { domain: 'dvwa.local', date: 'Feb 23, 19:30', status: 'completed' },
];

// ── DOM helper ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Error / status banner ──────────────────────────────────────────────────────
function showError(msg) {
    const banner = $('error-banner');
    banner.textContent = '⚠️  ' + msg;
    banner.classList.add('visible');
    setTimeout(() => banner.classList.remove('visible'), 7000);
}

function showLoader(text) {
    $('loader').classList.remove('hidden');
    $('loader-text').textContent = text || 'Scanning…';
}
function hideLoader() { $('loader').classList.add('hidden'); }

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── 8. View switcher ───────────────────────────────────────────────────────────
const viewTitles = { scanner: '⚡ Scanner', fuzzer: '🗂️ Fuzzer', analyzer: '🔬 Analyzer' };

function showView(name) {
    document.querySelectorAll('.view').forEach(v => {
        v.classList.toggle('active', v.id === 'view-' + name);
        v.classList.toggle('hidden', v.id !== 'view-' + name);
    });
    document.querySelectorAll('.nav-item').forEach(b => {
        b.classList.toggle('active', b.id === 'nav-' + name);
    });
    $('topbar-title').innerHTML = `<i class="fa fa-crosshairs"></i> ${viewTitles[name] || name}`;

    // Sync fuzz target URL with main URL
    if (name === 'fuzzer') {
        const main = $('target-url').value.trim();
        if (main) $('fuzz-target-url').value = main;
    }

    // Restore per-tab AI panel when switching tabs
    restoreTabAiState(name);

    // Close sidebar on mobile after nav click
    if (window.innerWidth <= 900) {
        $('sidebar').classList.remove('open');
    }
}

// Sidebar toggle (mobile)
$('sidebar-toggle').addEventListener('click', () => {
    $('sidebar').classList.toggle('open');
});
// Close sidebar when clicking outside
document.addEventListener('click', e => {
    if (window.innerWidth <= 900
        && !$('sidebar').contains(e.target)
        && !$('sidebar-toggle').contains(e.target)) {
        $('sidebar').classList.remove('open');
    }
});

// ── 9. Scan History (DB-backed) ──────────────────────────────────────────────

/**
 * Fetch the 10 most recent scans from the DB and render the sidebar list.
 * Falls back silently if the endpoint returns an empty array (no DB).
 */
async function loadRecentScans() {
    try {
        const res = await fetch('/api/recent-scans');
        const data = await res.json();
        renderDbHistory(data);
    } catch {
        // DB unavailable — keep the current in-memory list
    }
}

function renderDbHistory(scans) {
    const list = $('scan-history-list');
    list.innerHTML = '';

    if (!scans || scans.length === 0) {
        list.innerHTML = '<li class="scan-history-item empty-msg" style="padding:10px 12px">No scans yet.</li>';
        return;
    }

    scans.forEach(item => {
        const li = document.createElement('li');
        li.className = 'scan-history-item';
        li.dataset.id = item.id;
        li.dataset.type = item.scan_type;

        // Format date nicely
        const d = new Date(item.created_at);
        const date = d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' })
            + ', ' + d.toTimeString().slice(0, 5);

        // Badge colours per scan type
        const typeColour = { scanner: 'badge-danger', fuzzer: 'badge-warn', analyzer: 'badge-ok' };
        const typeBadge = typeColour[item.scan_type] || 'badge-ok';

        // Extract hostname for display
        let display = item.target_url;
        try { display = new URL(item.target_url).hostname; } catch { }

        li.innerHTML = `
            <div class="shi-row">
                <span class="shi-domain" title="${escapeHtml(item.target_url)}">${escapeHtml(display)}</span>
                <button class="shi-delete" data-id="${item.id}" title="Delete scan" aria-label="Delete">
                    <i class="fa fa-trash"></i>
                </button>
            </div>
            <div class="shi-meta">
                <span class="shi-badge ${typeBadge}">${escapeHtml(item.scan_type)}</span>
                <span class="shi-date"><i class="fa fa-clock"></i> ${escapeHtml(date)}</span>
            </div>`;

        list.appendChild(li);
    });
}

// Event delegation: handle delete + click-to-load on the history list
$('scan-history-list').addEventListener('click', async e => {
    // ── Delete button ──────────────────────────────────────────
    const delBtn = e.target.closest('.shi-delete');
    if (delBtn) {
        e.stopPropagation();
        const id = delBtn.dataset.id;
        if (!confirm('Delete this scan and all its findings?')) return;
        try {
            const res = await fetch('/api/scan/' + id, { method: 'DELETE' });
            if (!res.ok) throw new Error((await res.json()).error || 'Delete failed');
            // Remove the row instantly, then refresh
            delBtn.closest('li').remove();
            await loadRecentScans();
        } catch (err) {
            showError('Delete failed: ' + err.message);
        }
        return;
    }

    // ── Click row → load scan details ─────────────────────────────
    const li = e.target.closest('.scan-history-item[data-id]');
    if (!li) return;
    const { id, type } = li.dataset;
    await loadScanDetails(parseInt(id, 10), type);
});

async function loadScanDetails(id, type) {
    try {
        showLoader('Loading scan …');
        const res = await fetch('/api/scan/' + id);
        hideLoader();
        if (!res.ok) { showError('Could not load scan.'); return; }
        const data = await res.json();

        if (type === 'scanner') {
            // Re-populate the scanner results panel
            lastScanData = {
                target: data.target_url,
                timestamp: data.created_at,
                owasp: { headers: {} },
                jsAnalysis: data.jsAnalysis || [],
                activeFindings: data.vulnerabilities
                    ? data.vulnerabilities.map(v => ({
                        severity: v.severity,
                        name: v.vulnerability_type,
                        url: v.url,
                        param: v.parameter,
                        evidence: v.evidence,
                    }))
                    : [],
                directories: [],
            };
            // Populate OWASP header display from vulnerabilities
            (data.vulnerabilities || []).forEach(v => {
                const m = v.vulnerability_type.match(/^Missing Header: (.+)$/);
                if (m) lastScanData.owasp.headers[m[1]] = 'Missing';
            });
            renderScanResults(lastScanData);
            $('report-btn').classList.remove('hidden');
            showView('scanner');
        } else if (type === 'fuzzer') {
            // Re-populate fuzzer results table
            $('fuzz-table-body').innerHTML = '';
            (data.directories || []).forEach(d => {
                const tr = document.createElement('tr');
                const sc = d.status >= 200 && d.status < 300 ? 'status-ok'
                    : d.status >= 300 && d.status < 400 ? 'status-redirect' : 'status-other';
                tr.innerHTML = `<td><code>${escapeHtml(d.path || '')}</code></td>
                    <td><span class="status-badge ${sc}">${d.status || ''}</span></td>
                    <td>${escapeHtml(String(d.size || 'N/A'))}</td>
                    <td><a href="${escapeHtml(d.path || '')}" target="_blank" rel="noopener">${escapeHtml(d.path || '')}</a></td>`;
                $('fuzz-table-body').appendChild(tr);
            });
            $('fuzz-results-container').classList.remove('hidden');
            $('fuzz-found-count').textContent = (data.directories || []).length + ' found';
            showView('fuzzer');
        } else if (type === 'analyzer') {
            const list = $('findings-list');
            list.innerHTML = '';
            (data.findings || []).forEach(f => {
                const li2 = document.createElement('li');
                const cls = f.severity === 'High' ? 'badge-danger' : f.severity === 'Medium' ? 'badge-warn' : 'badge-ok';
                li2.innerHTML = `<span class="${cls}">[${f.severity}]</span> ${escapeHtml(f.issue)}`;
                list.appendChild(li2);
            });
            $('analyze-results').classList.remove('hidden');
            showView('analyzer');
        }
    } catch (err) {
        hideLoader();
        showError('Load error: ' + err.message);
    }
}

// Keep a local helper for immediately adding a NEW scan to the sidebar
function addToHistory(domain, status) {
    // Refresh from DB after a short delay so the new record is visible
    setTimeout(loadRecentScans, 800);
}

// Initial load on page start
loadRecentScans();


// ── 1. Quick Scan ──────────────────────────────────────────────────────────────
$('scan-btn').addEventListener('click', async () => {
    const url = $('target-url').value.trim();
    if (!url) return showError('Enter a target URL.');

    showLoader('Running quick scan (headers + JS)…');
    $('results').classList.add('hidden');
    $('report-btn').classList.add('hidden');
    $('scan-btn').disabled = true;

    // Extract domain for history
    let domain = url;
    try { domain = new URL(url).hostname; } catch { }

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || 'Server error');

        lastScanData = data;
        renderQuickResults(data);
        $('results').classList.remove('hidden');
        $('report-btn').classList.remove('hidden');
        activateTab('owasp');
        addToHistory(domain, 'completed');
        afterScanSuccess();
    } catch (err) {
        showError('Scan failed: ' + err.message);
        addToHistory(domain, 'failed');
    } finally {
        hideLoader();
        $('scan-btn').disabled = false;
    }
});

function renderQuickResults(data) {
    // Headers
    const hl = $('header-list');
    hl.innerHTML = '';
    Object.entries(data.owasp.headers).forEach(([k, v]) => {
        const ok = v === 'Present' || v === 'SECURE';
        const li = document.createElement('li');
        li.innerHTML = `<strong>${escapeHtml(k)}:</strong> <span class="${ok ? 'badge-ok' : 'badge-warn'}">${escapeHtml(v)}</span>`;
        hl.appendChild(li);
    });

    // Info disclosure
    const il = $('info-list');
    il.innerHTML = '';
    if (data.owasp.infoDisclosure && data.owasp.infoDisclosure.length) {
        data.owasp.infoDisclosure.forEach(item => {
            const li = document.createElement('li');
            li.textContent = `${item.type}: ${item.value}`;
            il.appendChild(li);
        });
    } else {
        il.innerHTML = '<li class="empty-msg">No disclosures detected.</li>';
    }

    // Directory results
    const db = $('dir-table-body');
    db.innerHTML = '';
    (data.directories || []).forEach(d => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${escapeHtml(d.url)}</td><td>${d.status}</td><td>${d.size}</td>`;
        db.appendChild(tr);
    });
    $('dir-empty').style.display = (data.directories?.length) ? 'none' : 'block';

    // JS analysis
    const jl = $('js-list');
    jl.innerHTML = '';
    if (data.jsAnalysis && data.jsAnalysis.length) {
        data.jsAnalysis.forEach(js => {
            const div = document.createElement('div');
            div.className = 'js-card';
            div.innerHTML = `
                <h4 class="js-url">${escapeHtml(js.url)}</h4>
                <p><strong>Secrets:</strong> ${js.secrets.length
                    ? js.secrets.map(s => `<span class="badge-danger">${escapeHtml(s)}</span>`).join(' ')
                    : '<span class="empty-msg">None</span>'}</p>
                <p><strong>Endpoints:</strong> ${js.endpoints.length
                    ? js.endpoints.map(e => `<code>${escapeHtml(e)}</code>`).join(', ')
                    : '<span class="empty-msg">None</span>'}</p>
                <p><strong>Dangerous Functions:</strong> ${js.dangerousFunctions.length
                    ? js.dangerousFunctions.map(f => `<code class="danger-fn">${escapeHtml(f)}</code>`).join(', ')
                    : '<span class="empty-msg">None</span>'}</p>`;
            jl.appendChild(div);
        });
    } else {
        jl.innerHTML = '<p class="empty-msg">No external JS files found.</p>';
    }
}

// ── 2. Active OWASP Scan ───────────────────────────────────────────────────────
$('active-scan-btn').addEventListener('click', () => {
    const url = $('target-url').value.trim();
    if (!url) return showError('Enter a target URL first.');

    if (activeEventSource) { activeEventSource.close(); activeEventSource = null; }

    // Reset UI
    Object.keys(severityCounts).forEach(k => severityCounts[k] = 0);
    updateSeverityCounts();
    $('findings-container').innerHTML = '<p id="no-findings" class="empty-msg">Running tests… findings will appear here.</p>';
    $('active-progress-bar').style.width = '0%';
    $('active-progress-container').classList.add('hidden');
    $('active-phase').textContent = '';
    $('active-results').classList.remove('hidden');
    $('active-scan-btn').disabled = true;
    $('active-scan-btn').innerHTML = '<i class="fa fa-spinner fa-spin"></i> Scanning…';

    let domain = url;
    try { domain = new URL(url).hostname; } catch { }

    const encodedUrl = encodeURIComponent(url);
    activeEventSource = new EventSource(`/api/active-scan?url=${encodedUrl}`);

    activeEventSource.addEventListener('finding', e => {
        const f = JSON.parse(e.data);
        appendFinding(f);
        $('active-scan-btn').innerHTML = `<i class="fa fa-spinner fa-spin"></i> Scanning… (${getTotalFindings()} found)`;
    });

    activeEventSource.addEventListener('phase', e => {
        const { message } = JSON.parse(e.data);
        $('active-phase').textContent = '🔎 ' + message;
    });

    activeEventSource.addEventListener('progress', e => {
        const { done, total } = JSON.parse(e.data);
        $('active-progress-container').classList.remove('hidden');
        $('active-progress-bar').style.width = Math.round((done / total) * 100) + '%';
    });

    activeEventSource.addEventListener('done', () => {
        $('active-phase').textContent = '✅ Scan complete.';
        activeEventSource.close();
        activeEventSource = null;
        $('active-scan-btn').disabled = false;
        $('active-scan-btn').innerHTML = '<i class="fa fa-flask"></i> Active OWASP Scan';
        if (!lastScanData) lastScanData = { target: url, timestamp: new Date().toISOString(), owasp: { headers: {}, infoDisclosure: [] }, directories: [], jsAnalysis: [] };
        lastScanData.activeFindings = collectFindings();
        $('report-btn').classList.remove('hidden');
        addToHistory(domain, 'completed');
        afterScanSuccess();
    });

    activeEventSource.addEventListener('error', () => {
        $('active-phase').textContent = '❌ Connection error.';
        activeEventSource.close();
        activeEventSource = null;
        $('active-scan-btn').disabled = false;
        $('active-scan-btn').innerHTML = '<i class="fa fa-flask"></i> Active OWASP Scan';
        addToHistory(domain, 'failed');
    });
});

function appendFinding(f) {
    const placeholder = $('no-findings');
    if (placeholder) placeholder.remove();

    if (severityCounts[f.severity] !== undefined) {
        severityCounts[f.severity]++;
    } else {
        severityCounts['Low'] = (severityCounts['Low'] || 0) + 1;
    }
    updateSeverityCounts();

    const card = document.createElement('details');
    card.className = `finding-card sev-${f.severity.toLowerCase()}`;

    const vulnIcons = { XSS: '⚡', SQLi: '💉', CMDi: '💀', PathTraversal: '📁', SSTI: '🧪', Header: '🔒', InfoDisc: '🔓' };
    const icon = vulnIcons[f.type] || '🔍';

    card.innerHTML = `
        <summary class="finding-summary">
            <span class="finding-icon">${icon}</span>
            <span class="finding-name">${escapeHtml(f.name)}</span>
            <span class="sev-badge sev-badge-${f.severity.toLowerCase()}">${f.severity}</span>
        </summary>
        <div class="finding-body">
            <div class="finding-grid">
                <div class="fg-row"><span class="fg-label">Type</span><span class="fg-val">${escapeHtml(f.type)}</span></div>
                <div class="fg-row"><span class="fg-label">Parameter</span><code class="fg-val">${escapeHtml(f.param)}</code></div>
                <div class="fg-row"><span class="fg-label">Payload</span><code class="fg-val payload">${escapeHtml(String(f.payload))}</code></div>
                <div class="fg-row"><span class="fg-label">URL</span><a href="${escapeHtml(f.url)}" target="_blank" class="fg-val" rel="noopener">${escapeHtml(f.url)}</a></div>
            </div>
            <div class="finding-evidence">
                <strong>Evidence</strong>
                <pre>${escapeHtml(String(f.evidence))}</pre>
            </div>
            <div class="finding-desc">
                <p><strong>Description:</strong> ${escapeHtml(f.description)}</p>
                <p class="remediation"><strong>🛠 Remediation:</strong> ${escapeHtml(f.remediation)}</p>
            </div>
        </div>`;

    $('findings-container').appendChild(card);
}

function updateSeverityCounts() {
    $('count-critical').textContent = `${severityCounts.Critical} Critical`;
    $('count-high').textContent = `${severityCounts.High} High`;
    $('count-medium').textContent = `${severityCounts.Medium} Medium`;
    $('count-low').textContent = `${severityCounts.Low} Low`;
}

function getTotalFindings() {
    return Object.values(severityCounts).reduce((a, b) => a + b, 0);
}

function collectFindings() {
    const cards = document.querySelectorAll('.finding-card');
    return Array.from(cards).map(card => ({
        name: card.querySelector('.finding-name')?.textContent || '',
        severity: card.querySelector('.sev-badge')?.textContent || '',
        param: card.querySelector('.fg-val')?.textContent || '',
        payload: card.querySelectorAll('.fg-val')[2]?.textContent || '',
        evidence: card.querySelector('pre')?.textContent || '',
        description: '',
        remediation: '',
    }));
}

// ── 3. Header Audit ────────────────────────────────────────────────────────────
$('manual-owasp-btn').addEventListener('click', async () => {
    const url = $('target-url').value.trim();
    if (!url) return showError('Enter a target URL first.');
    showLoader('Running header audit…');
    $('manual-owasp-btn').disabled = true;
    try {
        const res = await fetch('/api/owasp-check', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error);
        lastScanData = data;
        renderQuickResults(data);
        $('results').classList.remove('hidden');
        activateTab('owasp');
    } catch (err) { showError('Header audit failed: ' + err.message); }
    finally { hideLoader(); $('manual-owasp-btn').disabled = false; }
});

// ── 4. PDF Report ──────────────────────────────────────────────────────────────
$('report-btn').addEventListener('click', async () => {
    if (!lastScanData) return;
    try {
        const res = await fetch('/api/report', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(lastScanData)
        });
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'nexusguard_report.pdf';
        a.click();
    } catch { showError('Failed to generate PDF.'); }
});

// ── 5. Directory Fuzzer ────────────────────────────────────────────────────────
$('wordlist-input').addEventListener('change', () => {
    const f = $('wordlist-input').files[0];
    $('file-name-display').textContent = f ? '📄 ' + f.name : 'Choose wordlist (.txt)';
});

$('fuzz-toggle-btn').addEventListener('click', () => {
    fuzzRunning ? stopFuzz() : startFuzz();
});

async function startFuzz() {
    // Use the fuzzer view URL input, fall back to scanner URL
    const fuzzUrl = $('fuzz-target-url').value.trim() || $('target-url').value.trim();
    if (!fuzzUrl) return showError('Enter a target URL before starting the fuzzer.');

    const fileInput = $('wordlist-input');
    if (!fileInput.files || !fileInput.files.length) {
        return showError('Select a wordlist .txt file by clicking the "Choose wordlist" area.');
    }

    // Reset UI
    $('fuzz-table-body').innerHTML = '';
    $('fuzz-found-count').textContent = '0 found';
    $('fuzz-results-container').classList.add('hidden');
    $('fuzz-progress-bar').style.width = '0%';
    $('fuzz-status-text').textContent = 'Uploading wordlist…';
    $('fuzz-progress-container').classList.remove('hidden');
    setFuzzRunning(true);

    const fd = new FormData();
    fd.append('target', fuzzUrl);
    fd.append('wordlist', fileInput.files[0]);

    try {
        const res = await fetch('/api/fuzz-start', { method: 'POST', body: fd });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || 'Upload failed');

        fuzzSessionId = data.sessionId;
        $('fuzz-status-text').textContent = `Starting — ${data.total} paths queued…`;
        openFuzzStream(data.sessionId, data.total);
    } catch (err) {
        showError('Fuzzer error: ' + err.message);
        setFuzzRunning(false);
        $('fuzz-progress-container').classList.add('hidden');
    }
}

function openFuzzStream(sid, total) {
    if (fuzzEventSource) { fuzzEventSource.close(); fuzzEventSource = null; }
    fuzzEventSource = new EventSource('/api/fuzz-stream/' + sid);
    let found = 0;

    fuzzEventSource.addEventListener('result', e => {
        const d = JSON.parse(e.data);
        found++;
        $('fuzz-found-count').textContent = found + ' found';
        $('fuzz-results-container').classList.remove('hidden');
        const tr = document.createElement('tr');
        const sc = d.status >= 200 && d.status < 300 ? 'status-ok'
            : d.status >= 300 && d.status < 400 ? 'status-redirect' : 'status-other';
        tr.innerHTML = `<td><code>${escapeHtml(d.path)}</code></td>
                        <td><span class="status-badge ${sc}">${d.status}</span></td>
                        <td>${escapeHtml(String(d.size))}</td>
                        <td><a href="${escapeHtml(d.url)}" target="_blank" rel="noopener">${escapeHtml(d.url)}</a></td>`;
        $('fuzz-table-body').appendChild(tr);
    });

    fuzzEventSource.addEventListener('progress', e => {
        const { done } = JSON.parse(e.data);
        $('fuzz-progress-bar').style.width = Math.round((done / total) * 100) + '%';
        $('fuzz-status-text').textContent = `Testing ${done} / ${total} (${found} found)`;
    });

    fuzzEventSource.addEventListener('done', e => {
        const { found: f, total: t } = JSON.parse(e.data);
        $('fuzz-progress-bar').style.width = '100%';
        $('fuzz-status-text').textContent = `✅ Done — ${f} paths found out of ${t}`;
        cleanupFuzz();
        setFuzzRunning(false);
        afterFuzzSuccess($('fuzz-target-url').value.trim(), f);
    });

    fuzzEventSource.addEventListener('error', () => {
        if (fuzzRunning) {
            $('fuzz-status-text').textContent = '❌ Stream error. Fuzzer stopped.';
            cleanupFuzz();
            setFuzzRunning(false);
        }
    });
}

async function stopFuzz() {
    if (fuzzSessionId) {
        try { await fetch('/api/fuzz-stop/' + fuzzSessionId, { method: 'POST' }); } catch { }
    }
    $('fuzz-status-text').textContent = '⛔ Stopped by user.';
    cleanupFuzz();
    setFuzzRunning(false);
}

function cleanupFuzz() {
    if (fuzzEventSource) { fuzzEventSource.close(); fuzzEventSource = null; }
    fuzzSessionId = null;
}

function setFuzzRunning(r) {
    fuzzRunning = r;
    const btn = $('fuzz-toggle-btn');
    btn.innerHTML = r
        ? '<i class="fa fa-stop"></i> Stop Attack'
        : '<i class="fa fa-play"></i> Start Attack';
    btn.className = 'btn ' + (r ? 'btn-stop' : 'btn-success');
}

// ── 6. Traffic Analyzer ────────────────────────────────────────────────────────
$('analyze-btn').addEventListener('click', async () => {
    $('analyze-btn').disabled = true;
    try {
        const res = await fetch('/api/analyze-request', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request: $('raw-req').value, response: $('raw-res').value })
        });
        const data = await res.json();
        const list = $('findings-list');
        list.innerHTML = '';
        if (data.findings && data.findings.length) {
            data.findings.forEach(f => {
                const li = document.createElement('li');
                const cls = f.severity === 'High' ? 'badge-danger' : f.severity === 'Medium' ? 'badge-warn' : 'badge-ok';
                li.innerHTML = `<span class="${cls}">[${f.severity}]</span> ${escapeHtml(f.issue)}`;
                list.appendChild(li);
            });
        } else {
            list.innerHTML = '<li class="empty-msg">No findings detected.</li>';
        }
        $('analyze-results').classList.remove('hidden');
        afterAnalyzerSuccess(data.findings || []);
    } catch { showError('Traffic analysis failed.'); }
    finally { $('analyze-btn').disabled = false; }
});

// ── 7. Tabs ────────────────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => activateTab(btn.dataset.tab));
});
function activateTab(id) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === id));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === id));
}

// ══════════════════════════════════════════════════════════════════════════════
// 8. AI INTEGRATION — Drana Infinity
// Status shape: { installed: bool, running: bool, modelReady: bool, models[] }
// ══════════════════════════════════════════════════════════════════════════════

// ── DOM refs ──────────────────────────────────────────────────────────────────
const aiToggle = $('aiToggle');
const aiPanel = $('ai-panel');          // outer panel (replaces old status-bar)
const aiResults = $('ai-results');
const aiInstallLog = $('ai-install-log');
const aiContent = $('ai-content');
const aiRegenBtn = $('regenerateAiBtn');

// ── 8a. Fetch status from backend ────────────────────────────────────────────
async function checkAiStatus() {
    try {
        const res = await fetch('/api/ai/status');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return await res.json();
    } catch {
        return { installed: false, running: false, modelReady: false, models: [] };
    }
}

// ── 8b. Render the correct panel state ───────────────────────────────────────
//
//  STATE A — not installed  → setup guide + download script button
//  STATE B — installed, not running → "Start Ollama" button
//  STATE C — running + model ready  → "AI Ready" + auto-analyse
//  STATE D — running, model missing → pull model prompt
//
function renderAiPanel(status) {
    aiPanel.classList.remove('hidden');

    if (status.modelReady) {
        // ── STATE C: fully ready ──────────────────────────────────────────────
        aiPanel.innerHTML = `
            <div class="ai-state-ready">
                <span class="ai-ready-dot"></span>
                <strong>Drana Infinity is ready</strong>
                <span class="ai-muted">${status.models?.[0] || 'IHA089/drana-infinity-v1'}</span>
            </div>`;
        aiResults.classList.remove('hidden');
        if (lastScanData) requestAiAnalysis();

    } else if (!status.installed) {
        // ── STATE A: ollama not installed ─────────────────────────────────────
        aiPanel.innerHTML = `
            <div class="ai-setup-card">
                <div class="ai-setup-icon">🤖</div>
                <div class="ai-setup-body">
                    <h4>Drana Infinity not detected</h4>
                    <p>To enable AI-powered analysis you need <strong>Ollama</strong> and the <strong>Drana Infinity</strong> model installed on this machine.</p>
                    <div class="ai-setup-steps">
                        <div class="ai-step">
                            <span class="ai-step-num">1</span>
                            <div>
                                <strong>Download the setup script</strong>
                                <a href="/api/ai/install-script" download="install_drana.sh" class="btn btn-info btn-sm" id="dlScriptBtn">
                                    <i class="fa fa-download"></i> Download install_drana.sh
                                </a>
                            </div>
                        </div>
                        <div class="ai-step">
                            <span class="ai-step-num">2</span>
                            <div>
                                <strong>Run it in a terminal on this machine</strong>
                                <code class="ai-cmd">chmod +x install_drana.sh && sudo ./install_drana.sh</code>
                            </div>
                        </div>
                        <div class="ai-step">
                            <span class="ai-step-num">3</span>
                            <div>
                                <strong>Click Verify when done</strong>
                                <button class="btn btn-ghost btn-sm" id="verifyAiBtn">
                                    <i class="fa fa-rotate-right"></i> Verify Connection
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>`;
        $('verifyAiBtn').addEventListener('click', () => refreshAiStatus(true));

    } else if (!status.running) {
        // ── STATE B: ollama installed but not running ──────────────────────────
        aiPanel.innerHTML = `
            <div class="ai-setup-card ai-setup-warn">
                <div class="ai-setup-icon">⚙️</div>
                <div class="ai-setup-body">
                    <h4>Ollama is installed but not running</h4>
                    <p>Click <strong>Start Ollama</strong> to launch the service, or run <code>ollama serve</code> in a terminal.</p>
                    <div class="ai-setup-steps">
                        <div class="ai-step">
                            <button class="btn btn-info btn-sm" id="startOllamaBtn">
                                <i class="fa fa-play"></i> Start Ollama
                            </button>
                            <span class="ai-muted" style="margin-left:8px">or run <code>ollama serve</code> in a terminal</span>
                        </div>
                        <div class="ai-step" style="margin-top:10px">
                            <button class="btn btn-ghost btn-sm" id="verifyAiBtn2">
                                <i class="fa fa-rotate-right"></i> Check Again
                            </button>
                        </div>
                    </div>
                    <div id="start-ollama-msg" class="ai-muted" style="margin-top:8px"></div>
                </div>
            </div>`;
        $('verifyAiBtn2').addEventListener('click', () => refreshAiStatus(true));
        $('startOllamaBtn').addEventListener('click', startOllamaService);

    } else {
        // ── STATE D: running but model missing ────────────────────────────────
        aiPanel.innerHTML = `
            <div class="ai-setup-card ai-setup-warn">
                <div class="ai-setup-icon">📦</div>
                <div class="ai-setup-body">
                    <h4>Ollama is running — model not found</h4>
                    <p>The Drana Infinity model has not been downloaded yet. Run this command in a terminal:</p>
                    <code class="ai-cmd">ollama pull IHA089/drana-infinity-v1</code>
                    <p style="margin-top:10px">This downloads ~4.7 GB. When done, click <strong>Check Again</strong>.</p>
                    <button class="btn btn-ghost btn-sm" id="verifyAiBtn3" style="margin-top:8px">
                        <i class="fa fa-rotate-right"></i> Check Again
                    </button>
                </div>
            </div>`;
        $('verifyAiBtn3').addEventListener('click', () => refreshAiStatus(true));
    }
}

// ── 8c. Refresh status (optionally show spinner) ──────────────────────────────
async function refreshAiStatus(showSpinner = false) {
    if (showSpinner) {
        aiPanel.classList.remove('hidden');
        aiPanel.innerHTML = `<div class="ai-checking"><span class="ai-spin"></span> Checking Drana Infinity at localhost:11434…</div>`;
    }
    const status = await checkAiStatus();
    renderAiPanel(status);
}

// ── 8d. AI Toggle ─────────────────────────────────────────────────────────────
aiToggle.addEventListener('change', async (e) => {
    if (!e.target.checked) {
        aiPanel.classList.add('hidden');
        aiResults.classList.add('hidden');
        return;
    }
    refreshAiStatus(true);
});

// ── 8e. Start Ollama via backend ──────────────────────────────────────────────
async function startOllamaService() {
    const msgEl = $('start-ollama-msg');
    const btn = $('startOllamaBtn');
    btn.disabled = true;
    btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Starting…';
    if (msgEl) msgEl.textContent = 'Attempting to start ollama serve…';

    try {
        const res = await fetch('/api/ai/start', { method: 'POST' });
        const data = await res.json();
        if (data.already || data.started) {
            await refreshAiStatus(true);
        } else {
            if (msgEl) msgEl.textContent = data.message || 'Could not start Ollama automatically. Run `ollama serve` in a terminal.';
            btn.disabled = false;
            btn.innerHTML = '<i class="fa fa-play"></i> Start Ollama';
        }
    } catch {
        if (msgEl) msgEl.textContent = 'Request failed — try running `ollama serve` manually.';
        btn.disabled = false;
        btn.innerHTML = '<i class="fa fa-play"></i> Start Ollama';
    }
}

// ── 8f. Request AI Analysis ───────────────────────────────────────────────────
async function requestAiAnalysis() {
    if (!lastScanData) {
        aiContent.innerHTML = '<p class="empty-msg">Run a scan first, then the AI will analyse the results.</p>';
        aiResults.classList.remove('hidden');
        return;
    }

    const targetUrl = $('target-url').value.trim() || lastScanData.target || 'Unknown';
    const payload = {
        targetUrl,
        date: new Date().toISOString(),
        owasp: lastScanData.owasp || {},
        directories: lastScanData.directories || [],
        jsAnalysis: lastScanData.jsAnalysis || [],
        activeFindings: lastScanData.activeFindings || []
    };

    aiResults.classList.remove('hidden');
    aiInstallLog.classList.add('hidden');
    aiContent.innerHTML = '<div class="ai-thinking">Drana Infinity is analysing the findings…</div>';

    try {
        const res = await fetch('/api/ai/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (!res.ok || data.error) {
            aiContent.innerHTML = `<p class="empty-msg" style="color:var(--red)">❌ ${escapeHtml(data.error || 'Analysis failed')}</p>`;
            return;
        }
        renderAiInsight(data.insight);
    } catch (err) {
        aiContent.innerHTML = `<p class="empty-msg" style="color:var(--red)">❌ AI error: ${escapeHtml(err.message)}</p>`;
    }
}

// ── 8g. Render AI markdown output ────────────────────────────────────────────
function renderAiInsight(text) {
    if (!text) {
        aiContent.innerHTML = '<p class="empty-msg">No response received from Drana Infinity.</p>';
        return;
    }
    let html = escapeHtml(text)
        .replace(/```[\w]*\n([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/^## (.+)$/gm, '<h3 style="color:var(--purple);margin:14px 0 4px;font-size:1.05rem">$1</h3>')
        .replace(/^# (.+)$/gm, '<h2 style="color:var(--accent);margin:16px 0 4px;font-size:1.15rem">$1</h2>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/^\s*[-*] (.+)$/gm, '<li style="margin:2px 0 2px 18px">$1</li>')
        .replace(/^\d+\. (.+)$/gm, '<li style="margin:2px 0 2px 18px">$1</li>')
        .replace(/\n{2,}/g, '<br><br>');
    aiContent.innerHTML = html;
}

// ── 8h. Regenerate button ────────────────────────────────────────────────────
aiRegenBtn.addEventListener('click', () => requestAiAnalysis());

// ── 8i. Hook into scan completion ────────────────────────────────────────────
function afterScanSuccess() {
    if (!aiToggle.checked) return;
    checkAiStatus().then(status => {
        if (status.modelReady) {
            requestAiAnalysis();
        } else {
            renderAiPanel(status);
        }
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// 10. PER-TAB AI — Fuzzer & Analyzer integration
// ══════════════════════════════════════════════════════════════════════════════

// ── Panel / result-card lookup per tab ───────────────────────────────────────
const tabAiElements = {
    scanner: { panel: 'ai-panel', results: 'ai-results', content: 'ai-content' },
    fuzzer: { panel: 'fuzzer-ai-panel', results: 'fuzzer-ai-results', content: 'fuzzer-ai-content' },
    analyzer: { panel: 'analyzer-ai-panel', results: 'analyzer-ai-results', content: 'analyzer-ai-content' },
};

// ── General analyze function for any tab ─────────────────────────────────────
async function analyzeTab(tab, payload) {
    if (!aiToggle.checked) return;
    const els = tabAiElements[tab];
    tabPayloadCache[tab] = payload;
    $(els.results).classList.remove('hidden');
    $(els.content).innerHTML = '<div class="ai-thinking">Drana Infinity is analysing the findings…</div>';

    try {
        const res = await fetch('/api/ai/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok || data.error) {
            $(els.content).innerHTML = `<p class="empty-msg" style="color:var(--red)">❌ ${escapeHtml(data.error || 'Analysis failed')}</p>`;
            return;
        }
        tabAiCache[tab] = data.insight;
        renderTabInsight(els.content, data.insight);
    } catch (err) {
        $(els.content).innerHTML = `<p class="empty-msg" style="color:var(--red)">❌ AI error: ${escapeHtml(err.message)}</p>`;
    }
}

// ── Shared markdown renderer for tab AI output ────────────────────────────────
function renderTabInsight(contentId, text) {
    if (!text) { $(contentId).innerHTML = '<p class="empty-msg">No response from Drana Infinity.</p>'; return; }
    let html = escapeHtml(text)
        .replace(/```[\w]*\n([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/^## (.+)$/gm, '<h3 style="color:var(--purple);margin:14px 0 4px;font-size:1.05rem">$1</h3>')
        .replace(/^# (.+)$/gm, '<h2 style="color:var(--accent);margin:16px 0 4px;font-size:1.15rem">$1</h2>')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/^\s*[-*] (.+)$/gm, '<li style="margin:2px 0 2px 18px">$1</li>')
        .replace(/^\d+\. (.+)$/gm, '<li style="margin:2px 0 2px 18px">$1</li>')
        .replace(/\n{2,}/g, '<br><br>');
    $(contentId).innerHTML = html;
}

// ── restoreTabAiState — called by showView() on every tab switch ──────────────
function restoreTabAiState(tab) {
    const els = tabAiElements[tab];
    if (!els || !aiToggle.checked || tab === 'scanner') return;
    if (tabAiCache[tab]) {
        $(els.results).classList.remove('hidden');
        renderTabInsight(els.content, tabAiCache[tab]);
    } else {
        $(els.results).classList.add('hidden');
    }
}

// ── afterFuzzSuccess — called by fuzzer SSE done event ───────────────────────
function afterFuzzSuccess(targetUrl, foundCount) {
    if (!aiToggle.checked) return;
    const rows = Array.from($('fuzz-table-body').querySelectorAll('tr'));
    const directories = rows.map(r => {
        const cells = r.querySelectorAll('td');
        return { path: cells[0]?.textContent, status: cells[1]?.textContent, url: cells[3]?.querySelector('a')?.href };
    }).filter(d => d.url);
    const payload = {
        targetUrl: targetUrl || 'Unknown',
        date: new Date().toISOString(),
        scanType: 'fuzzer',
        directories,
        foundCount,
        owasp: {}, jsAnalysis: [], activeFindings: []
    };
    analyzeTab('fuzzer', payload);
}

// ── afterAnalyzerSuccess — called after traffic analyzer renders findings ─────
function afterAnalyzerSuccess(findings) {
    if (!aiToggle.checked) return;
    const rawReq = $('raw-req').value;
    const rawRes = $('raw-res').value;
    const hostMatch = rawReq.match(/^Host:\s*(.+)$/im);
    const targetUrl = hostMatch ? 'http://' + hostMatch[1].trim() : 'Unknown (Traffic Analysis)';
    const payload = {
        targetUrl,
        date: new Date().toISOString(),
        scanType: 'analyzer',
        rawRequest: rawReq.substring(0, 2000),
        rawResponse: rawRes.substring(0, 2000),
        owasp: {}, directories: [], jsAnalysis: [],
        activeFindings: findings.map(f => ({ severity: f.severity, name: f.issue }))
    };
    analyzeTab('analyzer', payload);
}

// ── Regenerate buttons for Fuzzer & Analyzer ─────────────────────────────────
$('fuzzerRegenBtn').addEventListener('click', () => {
    if (tabPayloadCache.fuzzer) analyzeTab('fuzzer', tabPayloadCache.fuzzer);
});
$('analyzerRegenBtn').addEventListener('click', () => {
    if (tabPayloadCache.analyzer) analyzeTab('analyzer', tabPayloadCache.analyzer);
});
