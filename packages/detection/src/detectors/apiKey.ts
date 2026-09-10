/**
 * API Key and Token-like Secrets Detector
 *
 * Category: API_KEY
 * Severity: HIGH | CRITICAL
 * Deterministic detection of recognizable vendor API keys and structured tokens.
 * Zero raw secret logging.
 */

import type { DetectionCategory, DetectionEntity, Severity } from '@shield/core';
import type { Detector, DetectorContext } from '../types';
import { maskToken } from '../utils/masking';

interface TokenRule {
  readonly name: string;
  readonly category: DetectionCategory;
  readonly severity: Severity;
  readonly confidence: number;
  readonly regex: RegExp;
  readonly extractGroup?: number; // 0 for full match, >0 for capture group
}

const TOKEN_RULES: readonly TokenRule[] = [
  // OpenAI API Keys (legacy and project-scoped)
  {
    name: 'openai-api-key',
    category: 'API_KEY',
    severity: 'CRITICAL',
    confidence: 0.99,
    regex: /\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b/g,
  },
  // GitHub Tokens (ghp_, gho_, ghu_, ghs_, ghr_)
  {
    name: 'github-token',
    category: 'API_KEY',
    severity: 'CRITICAL',
    confidence: 0.99,
    regex: /\bgh[pousr]_[a-zA-Z0-9]{36,}\b/g,
  },
  // AWS Access Key ID
  {
    name: 'aws-access-key-id',
    category: 'API_KEY',
    severity: 'CRITICAL',
    confidence: 0.98,
    regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
  },
  // Slack Tokens (xoxb, xoxp, xoxa, xoxr, xoxs)
  {
    name: 'slack-token',
    category: 'API_KEY',
    severity: 'HIGH',
    confidence: 0.95,
    regex: /\bxox[baprs]-[a-zA-Z0-9-]{20,}\b/g,
  },
  // Bearer Authorization Tokens
  {
    name: 'bearer-token',
    category: 'API_KEY',
    severity: 'HIGH',
    confidence: 0.9,
    regex: /\bBearer\s+([a-zA-Z0-9_.-]{24,})\b/gi,
    extractGroup: 1,
  },
  // Generic API Key assignment: api_key=xyz123...
  {
    name: 'prefixed-api-key-assignment',
    category: 'API_KEY',
    severity: 'HIGH',
    confidence: 0.88,
    regex: /\b(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?/gi,
    extractGroup: 1,
  },
];

export interface ApiKeyDetectorConfig {
  includeRawValue?: boolean;
}

export class ApiKeyDetector implements Detector<ApiKeyDetectorConfig> {
  readonly id = 'detector-api-key';
  readonly name = 'API Key & Token Detector';
  readonly category = 'API_KEY' as const;
  readonly description = 'Detects vendor API keys (OpenAI, GitHub, AWS, Slack, Bearer tokens)';
  readonly enabled = true;

  async detect(
    context: DetectorContext,
    config?: ApiKeyDetectorConfig,
  ): Promise<readonly DetectionEntity[]> {
    const text = context.text;
    if (!text || text.length < 16) {
      return [];
    }

    const results: DetectionEntity[] = [];
    const seenRanges = new Set<string>();

    for (const rule of TOKEN_RULES) {
      const regex = new RegExp(rule.regex);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        let token = match[0];
        let startIndex = match.index;

        if (rule.extractGroup !== undefined) {
          const groupVal = match[rule.extractGroup];
          if (typeof groupVal === 'string') {
            const offsetInMatch = match[0].indexOf(groupVal);
            startIndex += offsetInMatch;
            token = groupVal;
          }
        }

        const endIndex = startIndex + token.length;
        const rangeKey = `${startIndex}:${endIndex}`;

        if (seenRanges.has(rangeKey)) {
          continue;
        }
        seenRanges.add(rangeKey);

        results.push({
          id: `apikey-${startIndex}-${endIndex}`,
          detectorId: this.id,
          category: rule.category,
          severity: rule.severity,
          confidence: rule.confidence,
          range: { startIndex, endIndex },
          evidence: {
            tokenLength: token.length,
            hasRawValue: Boolean(config?.includeRawValue),
            ruleName: rule.name,
            previewMasked: maskToken(token),
          },
          rawValue: config?.includeRawValue ? token : undefined,
        });
      }
    }

    return results.sort((a, b) => a.range.startIndex - b.range.startIndex);
  }
}
