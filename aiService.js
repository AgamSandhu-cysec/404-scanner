/**
 * aiService.js — Drana Infinity AI Integration Service (v2)
 *
 * Status detection uses two parallel strategies for reliability:
 *   1. HTTP request to Ollama API (with 8s timeout)
 *   2. `ollama list` CLI fallback
 *
 * Status shape returned to frontend:
 *   { installed: bool, running: bool, modelReady: bool, models: string[], method: string }
 */

import axios from 'axios';
import { exec, execFile } from 'child_process';
import { writeFileSync } from 'fs';
import { promisify } from 'util';

const execAsync = promisify(exec);

export const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
export const DRANA_MODEL = process.env.DRANA_MODEL || 'IHA089/drana-infinity-v1';
const SCRIPT_PATH = '/tmp/install_drana.sh';
const ANALYSIS_TIMEOUT = 120_000;  // 2 min (large model may be slow)
const STATUS_TIMEOUT = 8_000;    // 8 s for Ollama HTTP check

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Check via CLI — fastest, works even if HTTP port isn't ready yet */
async function cliStatus() {
    try {
        const { stdout } = await execAsync('ollama list 2>&1', { timeout: 5000 });
        const lines = stdout.split('\n').filter(l => l.trim());
        const installed = lines.some(l => l.toLowerCase().includes('drana-infinity'));
        const ollamaExists = true; // `ollama list` ran without ENOENT
        return { ollamaExists, installed, models: lines.slice(1).map(l => l.split(/\s+/)[0]).filter(Boolean) };
    } catch (err) {
        // If ollama binary not found
        const notFound = err.code === 'ENOENT' || err.message.includes('not found') || err.message.includes('No such file');
        return { ollamaExists: !notFound, installed: false, models: [] };
    }
}

/** Check via HTTP to Ollama REST API */
async function httpStatus() {
    try {
        const res = await axios.get(`${OLLAMA_URL}/api/tags`, { timeout: STATUS_TIMEOUT });
        const models = (res.data?.models || []).map(m => m.name);
        const modelReady = models.some(m => m.toLowerCase().includes('drana-infinity'));
        return { running: true, modelReady, models };
    } catch (err) {
        return { running: false, modelReady: false, models: [], error: err.code || err.message };
    }
}

// ── Main status function ───────────────────────────────────────────────────────
export async function checkStatus() {
    // Run both checks concurrently
    const [http, cli] = await Promise.all([httpStatus(), cliStatus()]);

    const ollamaInstalled = cli.ollamaExists;
    const running = http.running;
    const modelReady = http.modelReady || cli.installed;
    const models = http.models.length ? http.models : cli.models;

    return {
        installed: ollamaInstalled,   // Ollama binary exists
        running: running,            // ollama serve is up
        modelReady: modelReady,         // Drana model is pulled
        models,
        method: http.running ? 'http' : 'cli'
    };
}

// ── Start Ollama service ───────────────────────────────────────────────────────
export async function startOllama() {
    try {
        // Check if already running
        const { running } = await httpStatus();
        if (running) return { already: true };

        // Start in background
        exec('nohup ollama serve > /tmp/ollama.log 2>&1 &');

        // Wait up to 20s for it to come up
        for (let i = 0; i < 10; i++) {
            await new Promise(r => setTimeout(r, 2000));
            const s = await httpStatus();
            if (s.running) return { started: true };
        }
        return { started: false, message: 'Ollama did not start in time. Check /tmp/ollama.log' };
    } catch (err) {
        return { started: false, message: err.message };
    }
}

// ── AI Analysis (Ollama /api/generate) ────────────────────────────────────────
export async function analyzeWithDrana(scanData) {
    const prompt = buildPrompt(scanData);
    const response = await axios.post(
        `${OLLAMA_URL}/api/generate`,
        { model: DRANA_MODEL, prompt, stream: false },
        { timeout: ANALYSIS_TIMEOUT }
    );
    return response.data?.response || '(No response from model)';
}

// ── Prompt builder (dispatcher) ───────────────────────────────────────────────
export function buildPrompt(data) {
    const type = data.scanType || 'scanner';
    if (type === 'fuzzer') return fuzzerPrompt(data);
    if (type === 'analyzer') return analyzerPrompt(data);
    return scannerPrompt(data);
}

// ── Scanner prompt ────────────────────────────────────────────────────────────
function scannerPrompt(data) {
    const {
        targetUrl = 'Unknown',
        date = new Date().toISOString(),
        owasp = {},
        directories = [],
        jsAnalysis = [],
        activeFindings = []
    } = data;

    const fmtHeaders = h => Object.entries(h || {}).map(([k, v]) => `  • ${k}: ${v}`).join('\n') || '  None detected.';
    const fmtDirs = dirs => dirs.length ? dirs.slice(0, 30).map(d => `  • ${typeof d === 'object' ? d.url || JSON.stringify(d) : d}`).join('\n') : '  None found.';
    const fmtJs = js => js.length ? js.map(j =>
        `  Script: ${j.url}\n` +
        (j.secrets?.length ? `    Secrets: ${j.secrets.join(', ')}\n` : '') +
        (j.dangerousFunctions?.length ? `    Dangerous Fns: ${j.dangerousFunctions.join(', ')}\n` : '') +
        (j.endpoints?.length ? `    Endpoints: ${j.endpoints.slice(0, 5).join(', ')}` : '')
    ).join('\n\n') : '  No JavaScript files analyzed.';
    const fmtFindings = f => f.length ? f.map(x => `  [${x.severity || '?'}] ${x.name || x.issue || JSON.stringify(x)}`).join('\n') : '  No active vulnerability findings.';

    return `You are Drana-Infinity, a senior cybersecurity researcher and penetration tester AI.

I have performed a security scan and need your expert analysis.

=== SCAN DETAILS ===
Target URL: ${targetUrl}
Scan Date:  ${date}

=== OWASP SECURITY HEADERS ===
${fmtHeaders(owasp.headers)}

=== ACTIVE VULNERABILITY FINDINGS ===
${fmtFindings(activeFindings)}

=== DISCOVERED DIRECTORIES ===
${fmtDirs(directories)}

=== JAVASCRIPT ANALYSIS ===
${fmtJs(jsAnalysis)}

=== ANALYSIS REQUEST ===
Please provide:
1. **Executive Summary** — Overall risk level (Critical/High/Medium/Low).
2. **Severity Assessment** — Rate each finding with CVSS context.
3. **Exploitation Guidance** — Step-by-step for the top 3 critical issues.
4. **Payload Examples** — Ready-to-use payloads for XSS, SQLi, SSTI, etc.
5. **Attack Chaining** — Opportunities to chain vulnerabilities.
6. **Remediation Roadmap** — Prioritized developer fix list.
7. **Bug Bounty Notes** — Estimated CVSS + bounty tier per critical finding.

Format with markdown ## headings, bullet points, and \`\`\`code blocks\`\`\` for all payloads.`;
}

// ── Fuzzer prompt ─────────────────────────────────────────────────────────────
function fuzzerPrompt(data) {
    const { targetUrl = 'Unknown', date = new Date().toISOString(), directories = [], foundCount = 0 } = data;
    const interesting = directories.filter(d => {
        const s = String(d.status || '');
        return s.startsWith('2') || s.startsWith('3') || s === '401' || s === '403';
    });
    const fmtPaths = arr => arr.length
        ? arr.slice(0, 40).map(d => `  [${d.status}] ${d.url || d.path}`).join('\n')
        : '  (none)';

    return `You are Drana-Infinity, a senior offensive-security researcher specializing in directory and path enumeration.

I ran a directory fuzzer against a web target. Analyze the discovered paths for security implications.

=== FUZZER RESULTS ===
Target URL:    ${targetUrl}
Scan Date:     ${date}
Paths Found:   ${foundCount}

=== INTERESTING PATHS (2xx/3xx/401/403) ===
${fmtPaths(interesting)}

=== ALL DISCOVERED PATHS ===
${fmtPaths(directories)}

=== ANALYSIS REQUEST ===
Please provide:
1. **Executive Summary** — What does this attack surface reveal?
2. **High-Value Targets** — Which paths are most interesting for exploitation?
3. **Sensitive Paths** — Admin panels, config files, backups, API endpoints.
4. **Authentication Bypass Clues** — What do 403/401 responses hint at?
5. **Follow-up Attacks** — What to try next (IDOR, parameter fuzzing, auth bypass payloads).
6. **Wordlist Recommendations** — Suggest next wordlists or extensions to try.

Format with markdown ## headings and \`\`\`code blocks\`\`\` for command examples.`;
}

// ── Analyzer prompt ───────────────────────────────────────────────────────────
function analyzerPrompt(data) {
    const {
        targetUrl = 'Unknown',
        date = new Date().toISOString(),
        rawRequest = '',
        rawResponse = '',
        activeFindings = []
    } = data;
    const fmtFindings = f => f.length
        ? f.map(x => `  [${x.severity || '?'}] ${x.name || x.issue || JSON.stringify(x)}`).join('\n')
        : '  No findings from static analysis.';

    return `You are Drana-Infinity, a senior web security researcher specializing in HTTP traffic analysis.

I have captured raw HTTP request/response traffic for you to analyze.

=== TARGET ===
URL:  ${targetUrl}
Date: ${date}

=== RAW HTTP REQUEST ===
\`\`\`http
${rawRequest || '(not provided)'}
\`\`\`

=== RAW HTTP RESPONSE ===
\`\`\`http
${rawResponse || '(not provided)'}
\`\`\`

=== STATIC ANALYSIS FINDINGS ===
${fmtFindings(activeFindings)}

=== ANALYSIS REQUEST ===
Please provide:
1. **Executive Summary** — What does this traffic reveal about the application?
2. **Security Header Review** — Missing or misconfigured HTTP security headers.
3. **Reflected Parameters** — Any user input reflected in the response (XSS vectors).
4. **Sensitive Data Exposure** — Tokens, credentials, internal paths, stack traces.
5. **Session & Cookie Security** — Cookie flags, session fixation risks.
6. **Injection Vectors** — Parameters that could be injectable (SQLi, SSTI, command injection).
7. **Remediation** — Prioritized fixes for the most critical issues.

Format with markdown ## headings, bullet points, and \`\`\`code blocks\`\`\` for payloads.`;
}


// ── Install script generator ──────────────────────────────────────────────────
export function generateInstallScript(appPort = 5000) {
    return `#!/usr/bin/env bash
# NexusGuard — Drana Infinity AI Setup Script
# Run with: bash install_drana.sh
# Safe to re-run multiple times (idempotent).

set -uo pipefail
export TERM=xterm

GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; RED='\\033[0;31m'; NC='\\033[0m'

print_step() { echo -e "\\n$GREEN>>> $1$NC"; }
print_warn() { echo -e "$YELLOW⚠  $1$NC"; }
print_err()  { echo -e "$RED✗  $1$NC"; }

print_step "NexusGuard: Setting up Drana Infinity AI (Ollama)"

# ─── 1. Install Ollama ────────────────────────────────────────────────────────
if command -v ollama &>/dev/null; then
    echo "✅ Ollama already installed: $(ollama --version 2>&1 | head -1)"
else
    print_step "Installing Ollama..."
    if [ "$EUID" -ne 0 ]; then
        print_warn "Not running as root. Ollama installer may ask for sudo."
    fi
    curl -fsSL https://ollama.com/install.sh | sh
    echo "✅ Ollama installed."
fi

# ─── 2. Start Ollama service ──────────────────────────────────────────────────
if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "✅ Ollama service already running."
else
    print_step "Starting Ollama service..."
    nohup ollama serve >/tmp/ollama.log 2>&1 &
    echo "   PID: $!"
    echo "   Waiting up to 30s for service..."
    for i in $(seq 1 15); do
        sleep 2
        if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
            echo "✅ Ollama is up after $((i*2))s."
            break
        fi
        echo "   ... $((i*2))s"
    done
    if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
        print_err "Ollama did not start. Check /tmp/ollama.log"
        exit 1
    fi
fi

# ─── 3. Pull Drana Infinity model ─────────────────────────────────────────────
if ollama list 2>/dev/null | grep -qi "drana-infinity"; then
    echo "✅ Drana Infinity model already downloaded."
else
    print_step "Downloading Drana Infinity model (~4.7 GB, this will take a few minutes)..."
    ollama pull IHA089/drana-infinity-v1
    echo "✅ Drana Infinity model ready."
fi

# ─── 4. Verify & notify ───────────────────────────────────────────────────────
STATUS=$(ollama list 2>/dev/null | grep -ci "drana-infinity" || true)
if [ "$STATUS" -gt 0 ]; then
    echo ""
    echo "🎉 Success! Drana Infinity is ready."
    echo "   API:   http://localhost:11434"
    echo "   Model: IHA089/drana-infinity-v1"
    echo ""
    # Notify the web app
    curl -sf -X POST http://localhost:${appPort}/api/ai/notify \\
        -H "Content-Type: application/json" \\
        -d '{"status":"ready"}' >/dev/null 2>&1 && \\
        echo "✅ NexusGuard notified — toggle AI on and start scanning!" || \\
        echo "ℹ️  Could not reach NexusGuard at port ${appPort} — make sure the app is running."
else
    print_err "Model does not appear in \`ollama list\` but may still work. Try running NexusGuard AI toggle."
fi
`;
}

// ── Run install script (streaming) ────────────────────────────────────────────
export function runInstallScript(onLog, appPort = 5000) {
    const script = generateInstallScript(appPort);
    writeFileSync(SCRIPT_PATH, script, { encoding: 'utf8', mode: 0o755 });

    return new Promise((resolve, reject) => {
        const child = exec(`bash ${SCRIPT_PATH}`, {
            timeout: 15 * 60 * 1000,
            env: { ...process.env, TERM: 'xterm' }
        });
        child.stdout.on('data', chunk => onLog(chunk.toString()));
        child.stderr.on('data', chunk => onLog('[stderr] ' + chunk.toString()));
        child.on('close', code => {
            if (code === 0) resolve({ success: true });
            else reject(new Error(`Install script exited with code ${code}`));
        });
        child.on('error', err => reject(err));
    });
}
