/**
 * @shield/api
 * Minimal Node.js / TypeScript server scaffold for Shield.
 *
 * Phase 0: Health check endpoint and basic lifecycle only.
 * No databases, authentication, or telemetry systems.
 */

import http from 'node:http';
import { EXTENSION_VERSION } from '@shield/shared';

const PORT = Number(process.env.SHIELD_API_PORT ?? process.env.PORT ?? 3001);
const HOST = process.env.SHIELD_API_HOST ?? 'localhost';

export function createApiServer(): http.Server {
  return http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

    // Set standard security and CORS headers
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Access-Control-Allow-Origin', '*');

    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/api/health')) {
      const responseBody = JSON.stringify({
        status: 'ok',
        service: 'shield-api',
        version: EXTENSION_VERSION,
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      });
      res.writeHead(200);
      res.end(responseBody);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/') {
      const responseBody = JSON.stringify({
        name: 'Shield API Scaffold',
        version: EXTENSION_VERSION,
        milestone: 'Phase 0 — Repository Bootstrap',
        endpoints: ['/health'],
      });
      res.writeHead(200);
      res.end(responseBody);
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not Found', path: url.pathname }));
  });
}

// Start server when executed directly
if (process.env.NODE_ENV !== 'test' && !process.env.VITEST) {
  const server = createApiServer();
  server.listen(PORT, HOST, () => {
    console.log(`[Shield API] Running at http://${HOST}:${PORT}`);
    console.log(`[Shield API] Health endpoint available at http://${HOST}:${PORT}/health`);
  });
}
