/**
 * Overlap and Duplicate Resolution Utilities
 *
 * Provides deterministic deduplication and conflict resolution
 * for overlapping detection ranges.
 */

import type { DetectionEntity, Severity } from '@shield/core';
import type { OverlapResolutionStrategy } from '../types';

export function severityRank(severity: Severity): number {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
  }
}

/**
 * Compare two detection entities to determine which is higher priority.
 * Returns > 0 if a > b, < 0 if b > a, 0 if equal.
 */
export function compareDetectionPriority(a: DetectionEntity, b: DetectionEntity): number {
  const rankDiff = severityRank(a.severity) - severityRank(b.severity);
  if (rankDiff !== 0) {
    return rankDiff;
  }

  const confDiff = a.confidence - b.confidence;
  if (Math.abs(confDiff) > 0.0001) {
    return confDiff;
  }

  // Stable fallback: detector ID string comparison
  return a.detectorId.localeCompare(b.detectorId);
}

/**
 * Remove exact duplicates where startIndex and endIndex are identical.
 * Keeps the entity with highest severity, then highest confidence.
 */
export function deduplicateExactRanges(entities: readonly DetectionEntity[]): DetectionEntity[] {
  const byRange = new Map<string, DetectionEntity>();

  for (const entity of entities) {
    const key = `${entity.range.startIndex}:${entity.range.endIndex}`;
    const existing = byRange.get(key);

    if (!existing) {
      byRange.set(key, entity);
    } else if (compareDetectionPriority(entity, existing) > 0) {
      byRange.set(key, entity);
    }
  }

  return Array.from(byRange.values()).sort(
    (a, b) => a.range.startIndex - b.range.startIndex || a.range.endIndex - b.range.endIndex,
  );
}

/**
 * Check if two half-open ranges [s1, e1) and [s2, e2) overlap.
 */
export function doRangesOverlap(
  a: { startIndex: number; endIndex: number },
  b: { startIndex: number; endIndex: number },
): boolean {
  return a.startIndex < b.endIndex && b.startIndex < a.endIndex;
}

/**
 * Resolve overlapping entities deterministically based on chosen strategy.
 */
export function resolveOverlaps(
  entities: readonly DetectionEntity[],
  strategy: OverlapResolutionStrategy = 'KEEP_HIGHEST_SEVERITY',
): DetectionEntity[] {
  const deduplicated = deduplicateExactRanges(entities);

  if (strategy === 'KEEP_ALL' || deduplicated.length <= 1) {
    return deduplicated;
  }

  // Sort by start index ascending, then length descending
  const sorted = [...deduplicated].sort((a, b) => {
    if (a.range.startIndex !== b.range.startIndex) {
      return a.range.startIndex - b.range.startIndex;
    }
    const lenA = a.range.endIndex - a.range.startIndex;
    const lenB = b.range.endIndex - b.range.startIndex;
    return lenB - lenA;
  });

  const accepted: DetectionEntity[] = [];

  for (const candidate of sorted) {
    const overlappingIdx = accepted.findIndex((existing) =>
      doRangesOverlap(existing.range, candidate.range),
    );

    if (overlappingIdx === -1) {
      accepted.push(candidate);
      continue;
    }

    const existing = accepted[overlappingIdx];
    if (!existing) continue;

    if (strategy === 'KEEP_HIGHEST_SEVERITY') {
      if (compareDetectionPriority(candidate, existing) > 0) {
        // Replace existing with higher priority candidate
        accepted[overlappingIdx] = candidate;
      }
    } else if (strategy === 'PREFER_SPECIFIC') {
      // Specific = shorter range
      const lenCandidate = candidate.range.endIndex - candidate.range.startIndex;
      const lenExisting = existing.range.endIndex - existing.range.startIndex;
      if (lenCandidate < lenExisting) {
        accepted[overlappingIdx] = candidate;
      }
    }
  }

  // Return final list sorted by range.startIndex
  return accepted.sort(
    (a, b) => a.range.startIndex - b.range.startIndex || a.range.endIndex - b.range.endIndex,
  );
}
