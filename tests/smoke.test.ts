import { describe, it, expect } from 'vitest';
import {
  EXTENSION_NAME,
  EXTENSION_VERSION,
  createMessage,
  STORAGE_KEYS,
} from '../packages/shared/src';
import { InMemoryAdapterRegistry } from '../packages/adapters/src';

describe('Shield Monorepo Smoke Tests', () => {
  it('should export foundational shared constants and utilities', () => {
    expect(EXTENSION_NAME).toBe('Shield');
    expect(EXTENSION_VERSION).toBe('0.1.0');
    expect(STORAGE_KEYS.ENABLED).toBe('shield:enabled');

    const msg = createMessage('PING', 'content', { sample: true });
    expect(msg.type).toBe('PING');
    expect(msg.sender).toBe('content');
    expect(msg.payload).toEqual({ sample: true });
    expect(typeof msg.id).toBe('string');
    expect(typeof msg.timestamp).toBe('number');
  });

  it('should instantiate platform adapter registry', () => {
    const registry = new InMemoryAdapterRegistry();
    expect(registry.getAll()).toEqual([]);
    expect(registry.findAdapterForUrl('https://chatgpt.com')).toBeUndefined();
  });
});
