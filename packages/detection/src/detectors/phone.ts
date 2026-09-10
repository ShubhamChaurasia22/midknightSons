/**
 * Phone Number Detector
 *
 * Category: PII
 * Severity: MEDIUM
 * Deterministic detection of international and formatted local phone numbers.
 * Strictly avoids matching raw arbitrary digits or dates.
 */

import type { DetectionEntity } from '@shield/core';
import type { Detector, DetectorContext } from '../types';
import { maskPhone } from '../utils/masking';
import { doRangesOverlap } from '../utils/overlaps';

// Match international phone numbers with '+' prefix (e.g. +1-555-555-5555, +44 20 7946 0958)
const INTL_PHONE_REGEX = /\+\d{1,3}(?:[-. ]\(?\d{1,4}\)?){1,4}\b/g;

// Match standard structured local phone numbers (e.g. (555) 123-4567, 555-123-4567, 555.123.4567)
const LOCAL_PHONE_REGEX = /(?:\(\d{3}\)[- ]|\b\d{3}[-.])\d{3}[-.]\d{4}\b/g;

// Date patterns to exclude (e.g. YYYY-MM-DD or YYYY/MM/DD)
const DATE_EXCLUDE_REGEX = /^\d{4}[-./]\d{1,2}[-./]\d{1,2}$/;

export interface PhoneDetectorConfig {
  includeRawValue?: boolean;
}

export class PhoneDetector implements Detector<PhoneDetectorConfig> {
  readonly id = 'detector-phone';
  readonly name = 'Phone Number Detector';
  readonly category = 'PII' as const;
  readonly description = 'Detects international and structured local phone numbers';
  readonly enabled = true;

  async detect(
    context: DetectorContext,
    config?: PhoneDetectorConfig,
  ): Promise<readonly DetectionEntity[]> {
    const text = context.text;
    if (!text || text.length < 7) {
      return [];
    }

    const results: DetectionEntity[] = [];
    const seenRanges = new Set<string>();

    const checkMatch = (
      phoneStr: string,
      startIndex: number,
      confidence: number,
      ruleName: string,
    ) => {
      const trimmed = phoneStr.trim();
      const endIndex = startIndex + trimmed.length;
      const rangeKey = `${startIndex}:${endIndex}`;

      if (seenRanges.has(rangeKey)) {
        return;
      }

      // Avoid matching a sub-range of an already matched number (e.g. local slice inside international)
      if (results.some((existing) => doRangesOverlap(existing.range, { startIndex, endIndex }))) {
        return;
      }

      // Check not date
      if (DATE_EXCLUDE_REGEX.test(trimmed)) {
        return;
      }

      // Count digits: must be between 7 and 15
      const digitsCount = trimmed.replace(/\D/g, '').length;
      if (digitsCount < 7 || digitsCount > 15) {
        return;
      }

      seenRanges.add(rangeKey);
      results.push({
        id: `phone-${startIndex}-${endIndex}`,
        detectorId: this.id,
        category: this.category,
        severity: 'MEDIUM',
        confidence,
        range: { startIndex, endIndex },
        evidence: {
          tokenLength: trimmed.length,
          hasRawValue: Boolean(config?.includeRawValue),
          ruleName,
          previewMasked: maskPhone(trimmed),
        },
        rawValue: config?.includeRawValue ? trimmed : undefined,
      });
    };

    // 1. Scan for international format (+ prefix)
    const intlRegex = new RegExp(INTL_PHONE_REGEX);
    let match: RegExpExecArray | null;
    while ((match = intlRegex.exec(text)) !== null) {
      const fullMatch = match[0];
      checkMatch(fullMatch, match.index, 0.95, 'phone-international');
    }

    // 2. Scan for local structured formats
    const localRegex = new RegExp(LOCAL_PHONE_REGEX);
    while ((match = localRegex.exec(text)) !== null) {
      const fullMatch = match[0];
      const confidence = fullMatch.startsWith('(') ? 0.9 : 0.85;
      checkMatch(fullMatch, match.index, confidence, 'phone-local-structured');
    }

    return results.sort((a, b) => a.range.startIndex - b.range.startIndex);
  }
}
