// api/index.js — Vercel Serverless Function entry point
//
// Vercel runs this file as a Node.js serverless function.
// It imports the Express app from server.js (which does NOT call app.listen()
// when imported as a module) and exports it as the default handler.

import app from '../server.js';

export default app;
