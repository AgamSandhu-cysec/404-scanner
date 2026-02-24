/**
 * routes/ai.js — AI API Endpoints (v2)
 *
 * GET  /api/ai/status        → { installed, running, modelReady, models }
 * GET  /api/ai/install-script → download bash install script
 * POST /api/ai/install       → run installer (SSE log stream)
 * POST /api/ai/start         → attempt to start ollama serve
 * POST /api/ai/notify        → script callback when install completes
 * POST /api/ai/analyze       → analyze scan data with Drana
 */

import express from 'express';
import {
    checkStatus,
    generateInstallScript,
    runInstallScript,
    startOllama,
    analyzeWithDrana
} from '../aiService.js';

const router = express.Router();

// ── GET /api/ai/status ────────────────────────────────────────────────────────
// Returns: { installed: bool, running: bool, modelReady: bool, models: [] }
router.get('/status', async (req, res) => {
    try {
        const status = await checkStatus();
        res.json(status);
    } catch (err) {
        res.json({ installed: false, running: false, modelReady: false, models: [], error: err.message });
    }
});

// ── GET /api/ai/install-script ────────────────────────────────────────────────
// Serves the bash install script for direct download / copy
router.get('/install-script', (req, res) => {
    const port = process.env.PORT || 5000;
    const script = generateInstallScript(port);
    res.setHeader('Content-Type', 'application/x-sh');
    res.setHeader('Content-Disposition', 'attachment; filename="install_drana.sh"');
    res.send(script);
});

// Keep old /script alias working
router.get('/script', (req, res) => res.redirect('/api/ai/install-script'));

// ── POST /api/ai/install ──────────────────────────────────────────────────────
// Runs install script server-side, streams output via SSE
router.post('/install', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const send = (type, data) => {
        if (!res.writableEnded) res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    runInstallScript(line => send('log', { line }), process.env.PORT || 5000)
        .then(() => { send('done', { success: true, message: '✅ Drana Infinity installed and ready!' }); res.end(); })
        .catch(err => { send('error', { message: err.message }); res.end(); });
});

// ── POST /api/ai/start ────────────────────────────────────────────────────────
// Starts `ollama serve` if not already running
router.post('/start', async (req, res) => {
    try {
        const result = await startOllama();
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── POST /api/ai/notify ───────────────────────────────────────────────────────
// Called by the bash script after successful install
router.post('/notify', (req, res) => {
    console.log('[AI] Notify received — Drana is ready:', req.body);
    res.json({ ok: true });
});

// (back-compat)
router.post('/install-done', (req, res) => res.redirect(307, '/api/ai/notify'));

// ── POST /api/ai/analyze ──────────────────────────────────────────────────────
router.post('/analyze', async (req, res) => {
    const scanData = req.body;
    if (!scanData?.targetUrl) return res.status(400).json({ error: 'targetUrl is required in body.' });

    try {
        const insight = await analyzeWithDrana(scanData);
        res.json({ insight });
    } catch (err) {
        const isConnRefused = err.code === 'ECONNREFUSED';
        const isTimeout = err.code === 'ETIMEDOUT' || err.message?.includes('timeout');
        const msg = isConnRefused
            ? 'Ollama is not running. Start it by toggling AI on and clicking "Start Ollama".'
            : isTimeout
                ? 'Drana Infinity timed out. The model may be loading — wait a moment and try again.'
                : err.message;
        res.status(500).json({ error: msg });
    }
});

export default router;
