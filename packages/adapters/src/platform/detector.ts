/**
 * @shield/adapters - AI Platform Detector (M2.3)
 *
 * Deterministic detection of supported AI platforms based on origin, hostname,
 * and page-level signals with fail-closed handling for unsupported origins.
 */

import type { DetectedPlatformId } from './contracts';

/**
 * Extract hostname from a URL string or return the raw string if already a hostname.
 */
export function normalizeHostname(urlOrHostname: string): string {
  if (!urlOrHostname || typeof urlOrHostname !== 'string') {
    return '';
  }

  const trimmed = urlOrHostname.trim();
  if (trimmed.includes('://')) {
    try {
      const parsed = new URL(trimmed);
      return parsed.hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  // Could be "hostname/path" or bare hostname
  const slashIndex = trimmed.indexOf('/');
  const rawHost = slashIndex >= 0 ? trimmed.substring(0, slashIndex) : trimmed;
  // Strip port if present
  const colonIndex = rawHost.indexOf(':');
  return (colonIndex >= 0 ? rawHost.substring(0, colonIndex) : rawHost).toLowerCase();
}

/**
 * Deterministically detect the AI platform from a URL or hostname.
 * Returns 'unsupported' if the platform is not one of the verified initial platforms.
 */
export function detectPlatform(urlOrHostname: string): DetectedPlatformId {
  const host = normalizeHostname(urlOrHostname);
  if (!host) {
    return 'unsupported';
  }

  // ChatGPT detection
  if (
    host === 'chatgpt.com' ||
    host.endsWith('.chatgpt.com') ||
    host === 'chat.openai.com' ||
    host.endsWith('.openai.com')
  ) {
    return 'chatgpt';
  }

  // Claude detection
  if (host === 'claude.ai' || host.endsWith('.claude.ai')) {
    return 'claude';
  }

  // Gemini detection
  if (host === 'gemini.google.com') {
    return 'gemini';
  }

  return 'unsupported';
}

/**
 * Returns true if the URL or hostname corresponds to a supported AI platform.
 */
export function isSupportedAiPlatform(urlOrHostname: string): boolean {
  return detectPlatform(urlOrHostname) !== 'unsupported';
}
