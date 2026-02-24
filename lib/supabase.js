/**
 * lib/supabase.js — Supabase client singleton
 *
 * Reads credentials from environment variables so they are never
 * hard-coded in source files. Loads .env automatically via the
 * native Node.js --env-file flag OR dotenv (whichever is available).
 *
 * Tables used:
 *   scans, vulnerabilities, discovered_directories, js_analysis, ai_chat_history
 */

import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    console.warn('[Supabase] ⚠  SUPABASE_URL or SUPABASE_ANON_KEY not set — DB features disabled.');
}

// Export null if unconfigured so callers can guard with `if (db)`
export const db = (SUPABASE_URL && SUPABASE_ANON_KEY)
    ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
    : null;

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Insert a row into `scans` and return the generated id.
 * Returns null on failure (fail-safe — scan still returns results to user).
 */
export async function createScanRecord(targetUrl, scanType) {
    if (!db) return null;
    try {
        const { data, error } = await db
            .from('scans')
            .insert({ target_url: targetUrl, scan_type: scanType, status: 'completed' })
            .select('id')
            .single();
        if (error) throw error;
        return data.id;
    } catch (err) {
        console.error('[Supabase] createScanRecord error:', err.message);
        return null;
    }
}

/**
 * Insert vulnerability records tied to a scan_id.
 * findings: array of { name, severity, url, param, evidence, description, remediation }
 */
export async function saveVulnerabilities(scanId, findings = []) {
    if (!db || !scanId || !findings.length) return;
    try {
        const rows = findings.map(f => ({
            scan_id: scanId,
            vulnerability_type: f.name || f.type || 'Unknown',
            severity: f.severity || 'Info',
            url: f.url || null,
            parameter: f.param || f.parameter || null,
            evidence: f.evidence ? String(f.evidence).substring(0, 500) : null,
            description: f.description || f.name || null,
            remediation: f.remediation || null,
        }));
        const { error } = await db.from('vulnerabilities').insert(rows);
        if (error) throw error;
    } catch (err) {
        console.error('[Supabase] saveVulnerabilities error:', err.message);
    }
}

/**
 * Insert discovered directories tied to a scan_id.
 * dirs: array of { path, status, size, url }
 */
export async function saveDirectories(scanId, dirs = []) {
    if (!db || !scanId || !dirs.length) return;
    try {
        const rows = dirs.map(d => ({
            scan_id: scanId,
            path: d.path || d.url || null,
            status_code: parseInt(d.status, 10) || null,
            content_length: isNaN(parseInt(d.size, 10)) ? null : parseInt(d.size, 10),
        }));
        const { error } = await db.from('discovered_directories').insert(rows);
        if (error) throw error;
    } catch (err) {
        console.error('[Supabase] saveDirectories error:', err.message);
    }
}

/**
 * Insert JS analysis results tied to a scan_id.
 * jsFiles: array of { url, secrets, endpoints, dangerousFunctions }
 */
export async function saveJsAnalysis(scanId, jsFiles = []) {
    if (!db || !scanId || !jsFiles.length) return;
    try {
        const rows = jsFiles.map(j => ({
            scan_id: scanId,
            js_url: j.url || null,
            secrets_found: j.secrets || [],
            endpoints_found: j.endpoints || [],
            dangerous_functions: j.dangerousFunctions || [],
        }));
        const { error } = await db.from('js_analysis').insert(rows);
        if (error) throw error;
    } catch (err) {
        console.error('[Supabase] saveJsAnalysis error:', err.message);
    }
}

/**
 * Save a single AI chat message.
 */
export async function saveAiMessage(sessionId, role, message) {
    if (!db) return;
    try {
        const { error } = await db
            .from('ai_chat_history')
            .insert({ session_id: sessionId, role, message });
        if (error) throw error;
    } catch (err) {
        console.error('[Supabase] saveAiMessage error:', err.message);
    }
}

/**
 * Fetch AI chat history for a session.
 */
export async function getAiHistory(sessionId) {
    if (!db) return [];
    try {
        const { data, error } = await db
            .from('ai_chat_history')
            .select('role, message, created_at')
            .eq('session_id', sessionId)
            .order('created_at', { ascending: true });
        if (error) throw error;
        return data || [];
    } catch (err) {
        console.error('[Supabase] getAiHistory error:', err.message);
        return [];
    }
}
