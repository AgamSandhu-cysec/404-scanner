/**
 * owaspScanner.js — Active OWASP Top 10 Vulnerability Scanner
 *
 * Tests for:
 *  - XSS (Reflected)
 *  - SQL Injection (Error-based)
 *  - Command Injection (Reflection-based)
 *  - Path Traversal
 *  - SSTI (Server-Side Template Injection)
 *  - Security Misconfigurations (headers, debug info)
 *  - Information Disclosure (headers, comments)
 *
 * Usage:
 *   import { runActiveScan } from './owaspScanner.js';
 *   for await (const finding of runActiveScan(targetUrl)) { ... }
 */

import axios from 'axios';
import * as cheerio from 'cheerio';

// ── Payload libraries ─────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
    '<iframe src="javascript:alert(1)">',
    '"><body onload=alert(1)>',
    'javascript:alert(1)',
];

const SQLI_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' UNION SELECT NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "'; SELECT SLEEP(0)--",
];

const SQLI_ERROR_PATTERNS = [
    /SQL syntax.*?MySQL/i,
    /Warning.*?mysqli?_/i,
    /MySqlException/i,
    /PostgreSQL.*?ERROR/i,
    /pg_query\(\)/i,
    /sqlite_.*?error/i,
    /ORA-\d{5}/i,
    /Driver.*? SQL[\-\s]Server/i,
    /ODBC SQL Server Driver/i,
    /Unclosed quotation mark/i,
    /syntax error.*?query/i,
    /Microsoft OLE DB/i,
    /JET Database Engine/i,
    /Incorrect syntax near/i,
    /quoted string not properly terminated/i,
    /Division by zero/i,
];

const CMDI_PAYLOADS = [
    '; echo nexus_cmdi_probe',
    '| echo nexus_cmdi_probe',
    '&& echo nexus_cmdi_probe',
    '`echo nexus_cmdi_probe`',
    '; id',
    '| id',
    '; whoami',
    '$(echo nexus_cmdi_probe)',
];

const CMDI_INDICATORS = [
    /nexus_cmdi_probe/,
    /uid=\d+\(\w+\)/,          // Unix id output
    /root|daemon|www-data/,     // common usernames
];

const PATH_TRAVERSAL_PAYLOADS = [
    '../../etc/passwd',
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '..%2f..%2fetc%2fpasswd',
    '%2e%2e/%2e%2e/etc/passwd',
    '....//....//etc/passwd',
    '..\\..\\windows\\win.ini',
    '%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
];

const PATH_TRAVERSAL_INDICATORS = [
    /root:x:0:0/,
    /daemon:x:\d+:\d+/,
    /\[extensions\]/i,
    /\[fonts\]/i,
    /for 16-bit app support/i,
];

const SSTI_PAYLOADS = [
    { payload: '{{7*7}}', expected: '49' },
    { payload: '${7*7}', expected: '49' },
    { payload: '<%= 7*7 %>', expected: '49' },
    { payload: '#{7*7}', expected: '49' },
    { payload: '*{7*7}', expected: '49' },
    { payload: '{{7*\'7\'}}', expected: '7777777' },  // Jinja2 vs Twig detection
];

// Common parameter names to probe if none found in the page
const DEFAULT_PARAMS = ['id', 'q', 'search', 'query', 'page', 'file', 'path', 'cmd', 'url', 'redirect', 'user', 'name', 'input', 'data', 'lang', 'view', 'cat', 'dir'];

// ── Axios instance with hardened settings ─────────────────────────────────────
const http = axios.create({
    timeout: 8000,
    validateStatus: () => true,   // accept any HTTP status
    maxRedirects: 3,
    headers: { 'User-Agent': 'Mozilla/5.0 (NexusGuard-OWASP-Scanner/2.0)' }
});

// ── Concurrency limiter ───────────────────────────────────────────────────────
async function runInBatches(items, batchSize, fn) {
    const results = [];
    for (let i = 0; i < items.length; i += batchSize) {
        const batch = items.slice(i, i + batchSize);
        const batchResults = await Promise.all(batch.map(fn));
        results.push(...batchResults.flat());
    }
    return results;
}

// ── Parameter extractor ───────────────────────────────────────────────────────
/**
 * Extract testable parameters from a URL and its HTML content.
 * Returns an array of { baseUrl, param, originalValue } objects.
 */
function extractParameters(pageUrl, html) {
    const params = [];
    const parsedUrl = new URL(pageUrl);
    const base = `${parsedUrl.protocol}//${parsedUrl.host}`;

    // 1. URL query parameters
    for (const [k, v] of parsedUrl.searchParams.entries()) {
        params.push({ baseUrl: pageUrl, param: k, originalValue: v, source: 'url' });
    }

    // 2. If no URL params, probe with common names
    if (params.length === 0) {
        const cleanUrl = pageUrl.split('?')[0];
        DEFAULT_PARAMS.slice(0, 8).forEach(p => {
            params.push({ baseUrl: `${cleanUrl}?${p}=FUZZ`, param: p, originalValue: 'test', source: 'probe' });
        });
    }

    // 3. HTML form inputs
    if (html) {
        const $ = cheerio.load(html);
        $('form').each((_, form) => {
            const action = $(form).attr('action') || pageUrl;
            const method = ($(form).attr('method') || 'get').toLowerCase();
            const formUrl = action.startsWith('http') ? action : new URL(action, base).href;

            $(form).find('input[name], textarea[name], select[name]').each((_, el) => {
                const name = $(el).attr('name');
                const val = $(el).attr('value') || $(el).val() || 'test';
                if (name) {
                    params.push({ baseUrl: formUrl, param: name, originalValue: val, source: `form-${method}` });
                }
            });
        });
    }

    // Deduplicate by param name (keep first occurrence)
    const seen = new Set();
    return params.filter(p => {
        if (seen.has(p.param)) return false;
        seen.add(p.param);
        return true;
    }).slice(0, 15); // cap at 15 params to avoid too many requests
}

// ── Inject a payload into a parameter ────────────────────────────────────────
async function fetchWithPayload(paramObj, payload) {
    try {
        const testUrl = new URL(paramObj.baseUrl);
        testUrl.searchParams.set(paramObj.param, payload);
        const res = await http.get(testUrl.href);
        return { status: res.status, body: String(res.data || ''), url: testUrl.href };
    } catch {
        return null;
    }
}

// ── XSS Tester ───────────────────────────────────────────────────────────────
async function testXSS(param) {
    const findings = [];
    for (const payload of XSS_PAYLOADS) {
        const result = await fetchWithPayload(param, payload);
        if (!result) continue;

        // Check if the raw unencoded payload appears in the response
        if (result.body.includes(payload)) {
            findings.push({
                type: 'XSS',
                name: 'Reflected Cross-Site Scripting (XSS)',
                severity: 'High',
                param: param.param,
                payload,
                evidence: extractSnippet(result.body, payload, 150),
                url: result.url,
                description: `The parameter "${param.param}" reflects user input without encoding. An attacker can inject malicious scripts.`,
                remediation: 'HTML-encode all user-supplied output. Implement a strict Content-Security-Policy.',
            });
            break; // One finding per param is sufficient
        }
    }
    return findings;
}

// ── SQLi Tester ───────────────────────────────────────────────────────────────
async function testSQLi(param) {
    const findings = [];
    for (const payload of SQLI_PAYLOADS) {
        const result = await fetchWithPayload(param, payload);
        if (!result) continue;

        const matchedError = SQLI_ERROR_PATTERNS.find(p => p.test(result.body));
        if (matchedError) {
            const errorMatch = result.body.match(matchedError);
            findings.push({
                type: 'SQLi',
                name: 'SQL Injection (Error-Based)',
                severity: 'Critical',
                param: param.param,
                payload,
                evidence: extractSnippet(result.body, errorMatch?.[0] || 'SQL error', 200),
                url: result.url,
                description: `SQL error revealed in response when injecting into "${param.param}". The application may be vulnerable to SQL injection.`,
                remediation: 'Use parameterised queries / prepared statements. Never interpolate user input into SQL strings.',
            });
            break;
        }
    }
    return findings;
}

// ── Command Injection Tester ──────────────────────────────────────────────────
async function testCommandInjection(param) {
    const findings = [];
    for (const payload of CMDI_PAYLOADS) {
        const result = await fetchWithPayload(param, payload);
        if (!result) continue;

        const matched = CMDI_INDICATORS.find(p => p.test(result.body));
        if (matched) {
            const hit = result.body.match(matched);
            findings.push({
                type: 'CMDi',
                name: 'OS Command Injection',
                severity: 'Critical',
                param: param.param,
                payload,
                evidence: extractSnippet(result.body, hit?.[0] || 'command output', 150),
                url: result.url,
                description: `Command output reflected in response when injecting into "${param.param}". The server may be executing OS commands.`,
                remediation: 'Never pass user input to shell commands. Use language-level APIs instead of system calls.',
            });
            break;
        }
    }
    return findings;
}

// ── Path Traversal Tester ─────────────────────────────────────────────────────
async function testPathTraversal(param) {
    const findings = [];
    for (const payload of PATH_TRAVERSAL_PAYLOADS) {
        const result = await fetchWithPayload(param, payload);
        if (!result) continue;

        const matched = PATH_TRAVERSAL_INDICATORS.find(p => p.test(result.body));
        if (matched) {
            const hit = result.body.match(matched);
            findings.push({
                type: 'PathTraversal',
                name: 'Path / Directory Traversal',
                severity: 'High',
                param: param.param,
                payload,
                evidence: extractSnippet(result.body, hit?.[0] || 'file content', 150),
                url: result.url,
                description: `File content leaked via parameter "${param.param}". An attacker can read sensitive server files.`,
                remediation: 'Canonicalise and validate all file paths. Use allowlists for permitted file locations.',
            });
            break;
        }
    }
    return findings;
}

// ── SSTI Tester ───────────────────────────────────────────────────────────────
async function testSSTI(param) {
    const findings = [];
    for (const { payload, expected } of SSTI_PAYLOADS) {
        const result = await fetchWithPayload(param, payload);
        if (!result) continue;

        if (result.body.includes(expected)) {
            findings.push({
                type: 'SSTI',
                name: 'Server-Side Template Injection (SSTI)',
                severity: 'Critical',
                param: param.param,
                payload,
                evidence: extractSnippet(result.body, expected, 150),
                url: result.url,
                description: `Template expression "${payload}" was evaluated server-side (result: ${expected}). This can lead to remote code execution.`,
                remediation: 'Never pass user input directly into template engines. Use sandboxed rendering or a logic-less template engine.',
            });
            break;
        }
    }
    return findings;
}

// ── Security Header Checker ───────────────────────────────────────────────────
async function checkSecurityHeaders(targetUrl) {
    const findings = [];
    try {
        const res = await http.get(targetUrl);
        const h = res.headers;

        const checks = [
            {
                header: 'strict-transport-security', name: 'HSTS Missing', severity: 'Medium',
                description: 'The Strict-Transport-Security header is absent, allowing downgrade attacks.'
            },
            {
                header: 'content-security-policy', name: 'CSP Missing', severity: 'High',
                description: 'No Content-Security-Policy header. XSS attacks can load arbitrary scripts.'
            },
            {
                header: 'x-frame-options', name: 'Clickjacking Protection Missing', severity: 'Medium',
                description: 'X-Frame-Options is absent. The page may be embedded in iframes for clickjacking.'
            },
            {
                header: 'x-content-type-options', name: 'MIME Sniffing Enabled', severity: 'Low',
                description: 'X-Content-Type-Options: nosniff is not set, allowing MIME-type sniffing.'
            },
            {
                header: 'referrer-policy', name: 'Referrer Policy Missing', severity: 'Low',
                description: 'No Referrer-Policy header. Sensitive URL data may leak via the Referer header.'
            },
            {
                header: 'permissions-policy', name: 'Permissions Policy Missing', severity: 'Low',
                description: 'Permissions-Policy header absent — browser features are not explicitly restricted.'
            },
        ];

        checks.forEach(c => {
            if (!h[c.header]) {
                findings.push({
                    type: 'Header',
                    name: c.name,
                    severity: c.severity,
                    param: 'HTTP Header',
                    payload: 'N/A',
                    evidence: `Header "${c.header}" not present in response`,
                    url: targetUrl,
                    description: c.description,
                    remediation: `Add the "${c.header}" response header with appropriate values.`,
                });
            }
        });

        // Server fingerprinting
        if (h['server']) {
            findings.push({
                type: 'InfoDisc',
                name: 'Server Version Disclosure',
                severity: 'Low',
                param: 'HTTP Header',
                payload: 'N/A',
                evidence: `Server: ${h['server']}`,
                url: targetUrl,
                description: `The Server header reveals technology version: "${h['server']}". Attackers can target known CVEs.`,
                remediation: 'Configure the web server to suppress or anonymise the Server header.',
            });
        }
        if (h['x-powered-by']) {
            findings.push({
                type: 'InfoDisc',
                name: 'Technology Fingerprinting via X-Powered-By',
                severity: 'Low',
                param: 'HTTP Header',
                payload: 'N/A',
                evidence: `X-Powered-By: ${h['x-powered-by']}`,
                url: targetUrl,
                description: `X-Powered-By header exposes the application framework: "${h['x-powered-by']}".`,
                remediation: 'Remove or suppress the X-Powered-By header.',
            });
        }

        // Check for debug/stack trace info in body
        const body = String(res.data || '');
        const debugPatterns = [
            { pattern: /stack trace|stacktrace/i, name: 'Stack Trace Exposed' },
            { pattern: /exception in thread/i, name: 'Java Exception Exposed' },
            { pattern: /Traceback \(most recent call\)/i, name: 'Python Traceback Exposed' },
            { pattern: /at [\w$.<>]+\([\w.]+:\d+\)/m, name: 'Stack Frame Exposed' },
            { pattern: /DEBUG\s*=\s*True/i, name: 'Debug Mode Active' },
        ];
        debugPatterns.forEach(({ pattern, name }) => {
            const m = body.match(pattern);
            if (m) {
                findings.push({
                    type: 'InfoDisc',
                    name,
                    severity: 'High',
                    param: 'Response Body',
                    payload: 'N/A',
                    evidence: extractSnippet(body, m[0], 200),
                    url: targetUrl,
                    description: 'Debug information or stack traces are visible in the response. This leaks internal paths, library versions, and logic.',
                    remediation: 'Disable debug mode in production. Catch exceptions and show generic error pages.',
                });
            }
        });

    } catch { /* skip on network error */ }
    return findings;
}

// ── HTML Comment Scanner ──────────────────────────────────────────────────────
async function checkComments(targetUrl) {
    const findings = [];
    try {
        const res = await http.get(targetUrl);
        const $ = cheerio.load(String(res.data || ''));
        const sensitiveKeywords = ['todo', 'fixme', 'password', 'passwd', 'secret', 'key', 'token', 'api', 'config', 'admin', 'test', 'debug', 'credential'];

        $('*').contents().each((_, el) => {
            if (el.type === 'comment') {
                const text = el.data.toLowerCase();
                const hit = sensitiveKeywords.find(k => text.includes(k));
                if (hit) {
                    findings.push({
                        type: 'InfoDisc',
                        name: 'Sensitive Data in HTML Comment',
                        severity: 'Medium',
                        param: 'HTML Comment',
                        payload: 'N/A',
                        evidence: el.data.trim().substring(0, 200),
                        url: targetUrl,
                        description: `An HTML comment contains the keyword "${hit}", potentially exposing sensitive information to anyone who views the source.`,
                        remediation: 'Remove all sensitive information from HTML comments before deploying to production.',
                    });
                }
            }
        });
    } catch { /* skip */ }
    return findings;
}

// ── Helper: extract a context snippet ────────────────────────────────────────
function extractSnippet(body, needle, context = 150) {
    const idx = body.indexOf(needle);
    if (idx === -1) return needle;
    const start = Math.max(0, idx - Math.floor(context / 2));
    const end = Math.min(body.length, idx + needle.length + Math.floor(context / 2));
    return (start > 0 ? '…' : '') + body.slice(start, end).replace(/\s+/g, ' ').trim() + (end < body.length ? '…' : '');
}

// ── Main exported scanner ─────────────────────────────────────────────────────
/**
 * Async generator — yields findings one by one as they are discovered.
 * Also yields { type: 'progress', done, total, phase } events.
 *
 * @param {string} targetUrl
 * @param {function} onProgress  optional callback(done, total, phase)
 */
export async function* runActiveScan(targetUrl, onProgress) {
    // Phase 1: security headers & comments (fast, no parameter needed)
    yield { type: '_phase', phase: 'Checking security headers & information disclosure…' };

    const headerFindings = await checkSecurityHeaders(targetUrl);
    for (const f of headerFindings) yield f;

    const commentFindings = await checkComments(targetUrl);
    for (const f of commentFindings) yield f;

    // Phase 2: fetch page and extract parameters
    yield { type: '_phase', phase: 'Extracting parameters from page…' };
    let html = '';
    try {
        const res = await http.get(targetUrl);
        html = String(res.data || '');
    } catch {
        yield { type: '_phase', phase: 'Could not fetch page — skipping parameter tests.' };
        return;
    }

    const params = extractParameters(targetUrl, html);
    if (params.length === 0) {
        yield { type: '_phase', phase: 'No testable parameters found.' };
        return;
    }

    const testSuites = [
        { name: 'XSS', fn: testXSS },
        { name: 'SQLi', fn: testSQLi },
        { name: 'CMDi', fn: testCommandInjection },
        { name: 'Path Traversal', fn: testPathTraversal },
        { name: 'SSTI', fn: testSSTI },
    ];

    const total = params.length * testSuites.length;
    let done = 0;

    // Phase 3: run active tests for each parameter × vulnerability type
    for (const suite of testSuites) {
        yield { type: '_phase', phase: `Testing ${suite.name} on ${params.length} parameter(s)…` };

        // Batch 5 params at a time per test type
        for (let i = 0; i < params.length; i += 5) {
            const batch = params.slice(i, i + 5);
            const batchResults = await Promise.all(batch.map(p => suite.fn(p)));
            for (const findings of batchResults) {
                for (const f of findings) yield f;
                done++;
                yield { type: '_progress', done, total };
            }
        }
    }
}
