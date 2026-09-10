/**
 * Generic Secret Assignment Detector
 *
 * Category: SECRET
 * Severity: HIGH
 * Conservative detection of secrets, access tokens, and credentials in assignment syntax.
 * Avoids flagging ordinary prose or code keywords.
 */

import type { DetectionEntity } from '@shield/core';
import type { Detector, DetectorContext } from '../types';
import { maskGenericSecret } from '../utils/masking';

const GENERIC_SECRET_REGEX =
  /(?:^|(?<=[^\w]))\b(client_secret|access_token|auth_token|refresh_token|api_secret|app_secret|secret_key|private_key)\s*[:=]\s*['"]?([a-zA-Z0-9_\-.~+/=]{12,})['"]?/gi;

const IGNORED_VALUES = new Set([
  'your_secret_here',
  'your_client_secret',
  'your_token_here',
  'placeholder_secret',
  'change_this_value',
]);

export interface GenericSecretDetectorConfig {
  includeRawValue?: boolean;
}

export class GenericSecretDetector implements Detector<GenericSecretDetectorConfig> {
  readonly id = 'detector-generic-secret';
  readonly name = 'Generic Secret Assignment Detector';
  readonly category = 'SECRET' as const;
  readonly description = 'Detects secret keys and tokens assigned in code or config contexts';
  readonly enabled = true;

  async detect(
    context: DetectorContext,
    config?: GenericSecretDetectorConfig,
  ): Promise<readonly DetectionEntity[]> {
    const text = context.text;
    if (!text || text.length < 16) {
      return [];
    }

    const results: DetectionEntity[] = [];
    const regex = new RegExp(GENERIC_SECRET_REGEX);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const keyName = match[1];
      const secretValue = match[2];

      if (!keyName || !secretValue) {
        continue;
      }

      const trimmedVal = secretValue.trim();
      if (IGNORED_VALUES.has(trimmedVal.toLowerCase())) {
        continue;
      }

      const matchStart = match.index;
      const valOffset = match[0].indexOf(secretValue);
      const startIndex = matchStart + valOffset;
      const endIndex = startIndex + trimmedVal.length;

      const isHighEntropy = /[A-Z]/.test(trimmedVal) && /[0-9]/.test(trimmedVal);
      const confidence = isHighEntropy ? 0.9 : 0.82;

      results.push({
        id: `sec-${startIndex}-${endIndex}`,
        detectorId: this.id,
        category: this.category,
        severity: 'HIGH',
        confidence,
        range: { startIndex, endIndex },
        evidence: {
          tokenLength: trimmedVal.length,
          hasRawValue: Boolean(config?.includeRawValue),
          ruleName: `generic-secret-${keyName.toLowerCase()}`,
          previewMasked: maskGenericSecret(trimmedVal),
          metadata: {
            keyField: keyName,
          },
        },
        rawValue: config?.includeRawValue ? trimmedVal : undefined,
      });
    }

    return results.sort((a, b) => a.range.startIndex - b.range.startIndex);
  }
}
