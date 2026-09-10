import { describe, it, expect } from 'vitest';
import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse, Server } from 'node:http';
import { createApiServer } from '../apps/api/src';

interface SimulatedResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

function simulateRequest(server: Server, method: string, path: string): Promise<SimulatedResponse> {
  return new Promise((resolve) => {
    const reqEmitter = new EventEmitter();
    const req = Object.assign(reqEmitter, {
      method,
      url: path,
      headers: { host: 'localhost:3001' },
    }) as unknown as IncomingMessage;

    const resEmitter = new EventEmitter();
    const headers: Record<string, string> = {};
    let statusCode = 200;
    let body = '';

    const res = Object.assign(resEmitter, {
      setHeader(key: string, value: string) {
        headers[key.toLowerCase()] = value;
      },
      writeHead(code: number) {
        statusCode = code;
      },
      end(chunk?: string) {
        if (chunk) {
          body += chunk;
        }
        resolve({
          statusCode,
          headers,
          body,
        });
      },
    }) as unknown as ServerResponse;

    server.emit('request', req, res);
  });
}

describe('Shield API Server Scaffold', () => {
  const server = createApiServer();

  it('responds with status ok on GET /health', async () => {
    const res = await simulateRequest(server, 'GET', '/health');
    expect(res.statusCode).toBe(200);

    const data = JSON.parse(res.body);
    expect(data.status).toBe('ok');
    expect(data.service).toBe('shield-api');
    expect(data.version).toBe('0.1.0');
  });

  it('responds on GET / with API info', async () => {
    const res = await simulateRequest(server, 'GET', '/');
    expect(res.statusCode).toBe(200);

    const data = JSON.parse(res.body);
    expect(data.name).toBe('Shield API Scaffold');
    expect(data.endpoints).toContain('/health');
  });
});
