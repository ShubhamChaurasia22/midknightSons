/**
 * Email Address Detector
 *
 * Category: PII
 * Severity: MEDIUM
 * Deterministic detection of email addresses with false-positive resistance.
 */

import type { DetectionEntity } from '@shield/core';
import type { Detector, DetectorContext } from '../types';
import { maskEmail } from '../utils/masking';

// Regex matching standard email addresses without matching invalid code syntax
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;

export interface EmailDetectorConfig {
  includeRawValue?: boolean;
}

export class EmailDetector implements Detector<EmailDetectorConfig> {
  readonly id = 'detector-email';
  readonly name = 'Email Address Detector';
  readonly category = 'PII' as const;
  readonly description = 'Detects personal and corporate email addresses in text';
  readonly enabled = true;

  async detect(
    context: DetectorContext,
    config?: EmailDetectorConfig,
  ): Promise<readonly DetectionEntity[]> {
    const text = context.text;
    if (!text || !text.includes('@')) {
      return [];
    }

    const results: DetectionEntity[] = [];
    const regex = new RegExp(EMAIL_REGEX);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const email = match[0];
      const startIndex = match.index;
      const endIndex = startIndex + email.length;

      // Filter out common false positives like trailing punctuation or invalid TLDs
      const domainParts = email.split('@')[1]?.split('.') ?? [];
      const tld = domainParts[domainParts.length - 1] ?? '';
      if (tld.length < 2 || !/^[a-zA-Z]+$/.test(tld)) {
        continue;
      }

      results.push({
        id: `email-${startIndex}-${endIndex}`,
        detectorId: this.id,
        category: this.category,
        severity: 'MEDIUM',
        confidence: 0.95,
        range: {
          startIndex,
          endIndex,
        },
        evidence: {
          tokenLength: email.length,
          hasRawValue: Boolean(config?.includeRawValue),
          ruleName: 'email-standard',
          previewMasked: maskEmail(email),
        },
        rawValue: config?.includeRawValue ? email : undefined,
      });
    }

    return results;
  }
}
