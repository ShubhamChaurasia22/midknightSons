import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

describe('Chrome Extension Manifest V3 Validation', () => {
  it('contains valid manifest json with least-privilege permissions', () => {
    const manifestPath = resolve(__dirname, '../apps/extension/public/manifest.json');
    const content = readFileSync(manifestPath, 'utf-8');
    const manifest = JSON.parse(content);

    expect(manifest.manifest_version).toBe(3);
    expect(manifest.name).toBe('Shield — Privacy & Security for AI');
    expect(manifest.version).toBe('0.1.0');
    expect(manifest.permissions).toEqual(['storage']);
    expect(manifest.action?.default_popup).toBe('popup.html');
    expect(manifest.options_page).toBe('options.html');
    expect(manifest.background?.service_worker).toBe('background.js');
    expect(Array.isArray(manifest.content_scripts)).toBe(true);
    expect(manifest.content_scripts[0].js).toContain('content.js');
  });
});
