/**
 * Password and Credential Assignment Detector
 *
 * Category: PASSWORD
 * Severity: HIGH
 * Deterministic detection of passwords defined in assignment structures.
 * Strictly ignores prose occurrences of the word "password".
 */

import type { DetectionEntity } from '@shield/core';
import type { Detector, DetectorContext } from '../types';
import { maskGenericSecret } from '../utils/masking';

// Matches assignments like password=..., passwd: ..., pwd="...", db_password: ...
const PASSWORD_ASSIGNMENT_REGEX =
  /(?:^|(?<=[^\w]))\b((?:db_|admin_|user_|root_)?(?:password|passwd|pwd))\s*[:=]\s*['"]?([^\s'";,]+)['"]?/gi;

// Values that indicate code placeholders or non-secrets
const IGNORED_PLACEHOLDERS = new Set([
  'null',
  'undefined',
  'none',
  'true',
  'false',
  'string',
  'your_password',
  'password',
  'changeme',
  'placeholder',
]);

export interface PasswordDetectorConfig {
  includeRawValue?: boolean;
}

export class PasswordDetector implements Detector<PasswordDetectorConfig> {
  readonly id = 'detector-password';
  readonly name = 'Password Assignment Detector';
  readonly category = 'PASSWORD' as const;
  readonly description = 'Detects credentials defined in assignment contexts (e.g. password=...)';
  readonly enabled = true;

  async detect(
    context: DetectorContext,
    config?: PasswordDetectorConfig,
  ): Promise<readonly DetectionEntity[]> {
    const text = context.text;
    if (!text || text.length < 8) {
      return [];
    }

    const results: DetectionEntity[] = [];
    const regex = new RegExp(PASSWORD_ASSIGNMENT_REGEX);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const fieldName = match[1];
      const passwordValue = match[2];

      if (!fieldName || !passwordValue) {
        continue;
      }

      const trimmedVal = passwordValue.trim();
      if (trimmedVal.length < 4 || IGNORED_PLACEHOLDERS.has(trimmedVal.toLowerCase())) {
        continue;
      }

      // Calculate exact range of the sensitive password value
      const matchStart = match.index;
      const valOffset = match[0].indexOf(passwordValue);
      const startIndex = matchStart + valOffset;
      const endIndex = startIndex + trimmedVal.length;

      results.push({
        id: `pwd-${startIndex}-${endIndex}`,
        detectorId: this.id,
        category: this.category,
        severity: 'HIGH',
        confidence: trimmedVal.length >= 8 ? 0.9 : 0.82,
        range: { startIndex, endIndex },
        evidence: {
          tokenLength: trimmedVal.length,
          hasRawValue: Boolean(config?.includeRawValue),
          ruleName: `password-assignment-${fieldName.toLowerCase()}`,
          previewMasked: maskGenericSecret(trimmedVal),
          metadata: {
            assignedField: fieldName,
          },
        },
        rawValue: config?.includeRawValue ? trimmedVal : undefined,
      });
    }

    return results.sort((a, b) => a.range.startIndex - b.range.startIndex);
  }
}
