/**
 * Verification Domain Model & Deterministic Verification Engine
 *
 * Stage 8 (VERIFY) of the canonical Shield pipeline:
 * DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND
 *
 * Validates whether the final deliverable is safe, sound, and internally consistent
 * before it is allowed to proceed to SEND.
 */

import type { RiskAssessment } from './risk';
import type { TransformationResult, AppliedTransformation } from './transformation';
import type { PolicyDecision } from './policy';
import type { PipelineContext } from './context';
import type { DetectionEntity } from './detection';
import type { Verifier } from './orchestrator';

export type VerificationStatus = 'SUCCESS' | 'FAILED' | 'NOT_REQUIRED';

export interface VerificationResult {
  status: VerificationStatus;
  verified: boolean;
  residualRisk: RiskAssessment;
  leaksDetected: boolean;
  failedChecks?: readonly string[];
  notes?: string;
}

/**
 * Deterministic Verification Engine
 *
 * Validates post-transformation invariants, leak absence, and boundary integrity.
 */
export class DeterministicVerificationEngine implements Verifier {
  readonly id = 'shield-deterministic-verifier';
  readonly name = 'Shield Deterministic Verification Engine';

  verify(
    transformation: TransformationResult,
    decision: PolicyDecision,
    context: PipelineContext,
  ): VerificationResult {
    const originalText = context.normalized?.normalizedText ?? transformation.originalText;
    const transformedText = transformation.transformedText;
    const entities = context.detections?.entities ?? [];
    const applied = transformation.transformationsApplied ?? [];
    const timestamp = context.timestamp ?? 0;

    return this.verifySync(
      transformation,
      decision,
      entities,
      originalText,
      transformedText,
      applied,
      timestamp,
    );
  }

  /**
   * Synchronous verification implementation allowing direct testing without full pipeline context.
   */
  verifySync(
    transformation: TransformationResult,
    decision: PolicyDecision,
    entities: readonly DetectionEntity[],
    originalText: string,
    transformedText: string,
    applied: readonly AppliedTransformation[],
    timestamp = 0,
  ): VerificationResult {
    // ------------------------------------------------------------------------
    // 1. Non-MASK Decisions (ALLOW, WARN, BLOCK)
    // ------------------------------------------------------------------------
    if (decision.action !== 'MASK') {
      // Invariant: For non-MASK actions, text must not be modified
      if (
        transformation.isModified ||
        transformation.transformationsApplied.length > 0 ||
        transformedText !== originalText
      ) {
        return {
          status: 'FAILED',
          verified: false,
          residualRisk: {
            score: 95,
            severity: 'CRITICAL',
            confidence: 1.0,
            factors: [
              {
                detectorId: 'verifier-engine',
                category: 'PRIVATE_DATA',
                severity: 'CRITICAL',
                weight: 95,
                reason: `Unexpected modification under ${decision.action} policy action`,
              },
            ],
            summary: `Verification failed: unauthorized text mutation under ${decision.action}`,
            evaluationTimestamp: timestamp,
          },
          leaksDetected: false,
          failedChecks: [`UNAUTHORIZED_MUTATION:${decision.action}`],
          notes: `Verification failed: text was modified under ${decision.action} policy`,
        };
      }

      return {
        status: 'NOT_REQUIRED',
        verified: true,
        residualRisk: {
          score: 0,
          severity: 'NONE',
          confidence: 1.0,
          factors: [],
          summary: `No transformation required for ${decision.action} policy`,
          evaluationTimestamp: timestamp,
        },
        leaksDetected: false,
        notes: `${decision.action} policy verified: deliverable preserved unmodified`,
      };
    }

    // ------------------------------------------------------------------------
    // 2. MASK Action Invariant Checks
    // ------------------------------------------------------------------------
    const failedChecks: string[] = [];
    let leaksDetected = false;

    // 2a. Completeness check: if detections exist, transformations must exist
    if (entities.length > 0 && applied.length === 0) {
      failedChecks.push('MISSING_ALL_TRANSFORMATIONS');
    }

    // 2b. Range validity & monotonicity of applied transformations
    for (let i = 0; i < applied.length; i++) {
      const app = applied[i]!;
      const orig = app.originalRange;
      const repl = app.replacedRange;

      if (
        orig.startIndex < 0 ||
        orig.endIndex < orig.startIndex ||
        orig.endIndex > originalText.length
      ) {
        failedChecks.push(`INVALID_ORIGINAL_RANGE:${app.category}`);
      }

      if (
        repl.startIndex < 0 ||
        repl.endIndex < repl.startIndex ||
        repl.endIndex > transformedText.length
      ) {
        failedChecks.push(`INVALID_REPLACED_RANGE:${app.category}`);
      }

      if (i > 0) {
        const prev = applied[i - 1]!;
        if (orig.startIndex < prev.originalRange.endIndex) {
          failedChecks.push(`OVERLAPPING_ORIGINAL_RANGE:${app.category}`);
        }
        if (repl.startIndex < prev.replacedRange.endIndex) {
          failedChecks.push(`OVERLAPPING_REPLACED_RANGE:${app.category}`);
        }
      }
    }

    // 2c. Surrounding characters & neighboring text preservation
    if (applied.length > 0 && failedChecks.length === 0) {
      // Prefix before first transformation
      const first = applied[0]!;
      const origPrefix = originalText.slice(0, first.originalRange.startIndex);
      const transPrefix = transformedText.slice(0, first.replacedRange.startIndex);
      if (origPrefix !== transPrefix) {
        failedChecks.push('SURROUNDING_TEXT_CORRUPTED:PREFIX');
      }

      // Slices between consecutive transformations
      for (let i = 0; i < applied.length - 1; i++) {
        const curr = applied[i]!;
        const next = applied[i + 1]!;
        const origBetween = originalText.slice(
          curr.originalRange.endIndex,
          next.originalRange.startIndex,
        );
        const transBetween = transformedText.slice(
          curr.replacedRange.endIndex,
          next.replacedRange.startIndex,
        );
        if (origBetween !== transBetween) {
          failedChecks.push('SURROUNDING_TEXT_CORRUPTED:BETWEEN');
        }
      }

      // Suffix after last transformation
      const last = applied[applied.length - 1]!;
      const origSuffix = originalText.slice(last.originalRange.endIndex);
      const transSuffix = transformedText.slice(last.replacedRange.endIndex);
      if (origSuffix !== transSuffix) {
        failedChecks.push('SURROUNDING_TEXT_CORRUPTED:SUFFIX');
      }
    }

    // 2d. Entity accounting & residual leak detection
    for (const entity of entities) {
      const raw =
        entity.rawValue ?? originalText.slice(entity.range.startIndex, entity.range.endIndex);

      // Find applied transformations specifically matching this entity
      const matchingApps = applied.filter((app) => app.entityId === entity.id);

      if (matchingApps.length > 0) {
        for (const app of matchingApps) {
          // Check if app originalRange matches entity.range
          if (app.originalRange.startIndex > entity.range.startIndex) {
            leaksDetected = true;
            failedChecks.push(`RESIDUAL_PREFIX_LEAK:${entity.category}`);
          }
          if (app.originalRange.startIndex < entity.range.startIndex) {
            failedChecks.push('SURROUNDING_TEXT_CORRUPTED:PREFIX');
          }
          if (app.originalRange.endIndex < entity.range.endIndex) {
            leaksDetected = true;
            failedChecks.push(`RESIDUAL_SUFFIX_LEAK:${entity.category}`);
          }
          if (app.originalRange.endIndex > entity.range.endIndex) {
            failedChecks.push('SURROUNDING_TEXT_CORRUPTED:SUFFIX');
          }
        }
      } else {
        // Check if entity is fully covered by an encompassing transformation (e.g. overlapping entities)
        const isCovered = applied.some(
          (app) =>
            app.originalRange.startIndex <= entity.range.startIndex &&
            entity.range.endIndex <= app.originalRange.endIndex,
        );

        if (!isCovered) {
          const partialOverlaps = applied.filter(
            (app) =>
              entity.range.startIndex < app.originalRange.endIndex &&
              app.originalRange.startIndex < entity.range.endIndex,
          );
          if (partialOverlaps.length === 0) {
            failedChecks.push(`UNACCOUNTED_DETECTION:${entity.category}`);
          } else {
            const minStart = Math.min(...partialOverlaps.map((a) => a.originalRange.startIndex));
            const maxEnd = Math.max(...partialOverlaps.map((a) => a.originalRange.endIndex));
            if (minStart > entity.range.startIndex) {
              leaksDetected = true;
              failedChecks.push(`RESIDUAL_PREFIX_LEAK:${entity.category}`);
            }
            if (maxEnd < entity.range.endIndex) {
              leaksDetected = true;
              failedChecks.push(`RESIDUAL_SUFFIX_LEAK:${entity.category}`);
            }
          }
        }
      }

      if (!raw || raw.length === 0) {
        continue;
      }

      // Exact raw sensitive leak check
      if (transformedText.includes(raw)) {
        leaksDetected = true;
        failedChecks.push(`RESIDUAL_RAW_LEAK:${entity.category}`);
      }

      // Partial prefix & suffix leak check around replacements
      for (const app of applied) {
        if (app.category !== entity.category) {
          continue;
        }

        // Check for residual prefix attached to replacement
        const transBefore = transformedText.slice(0, app.replacedRange.startIndex);
        const origBefore = originalText.slice(0, app.originalRange.startIndex);
        for (let k = Math.min(raw.length - 1, 10); k >= 2; k--) {
          const prefixCandidate = raw.slice(0, k);
          if (transBefore.endsWith(prefixCandidate) && !origBefore.endsWith(prefixCandidate)) {
            leaksDetected = true;
            failedChecks.push(`RESIDUAL_PREFIX_LEAK:${entity.category}`);
            break;
          }
        }

        // Check for residual suffix attached to replacement
        const transAfter = transformedText.slice(app.replacedRange.endIndex);
        const origAfter = originalText.slice(app.originalRange.endIndex);
        for (let k = Math.min(raw.length - 1, 10); k >= 2; k--) {
          const suffixCandidate = raw.slice(-k);
          if (transAfter.startsWith(suffixCandidate) && !origAfter.startsWith(suffixCandidate)) {
            leaksDetected = true;
            failedChecks.push(`RESIDUAL_SUFFIX_LEAK:${entity.category}`);
            break;
          }
        }
      }
    }

    // 2e. Replacement slice sanity
    for (const app of applied) {
      const replSlice = transformedText.slice(
        app.replacedRange.startIndex,
        app.replacedRange.endIndex,
      );
      if (replSlice.length === 0) {
        failedChecks.push(`EMPTY_REPLACEMENT:${app.category}`);
      }
    }

    // ------------------------------------------------------------------------
    // 3. Result Construction
    // ------------------------------------------------------------------------
    if (failedChecks.length > 0 || leaksDetected) {
      const uniqueChecks = Array.from(new Set(failedChecks));
      return {
        status: 'FAILED',
        verified: false,
        residualRisk: {
          score: 95,
          severity: 'CRITICAL',
          confidence: 1.0,
          factors: uniqueChecks.map((code) => ({
            detectorId: 'verifier-engine',
            category: 'SECRET',
            severity: 'CRITICAL',
            weight: 95,
            reason: `Verification failed check: ${code}`,
          })),
          summary: `Verification failed: ${uniqueChecks.length} issue(s) detected`,
          evaluationTimestamp: timestamp,
        },
        leaksDetected: leaksDetected || uniqueChecks.some((c) => c.includes('LEAK')),
        failedChecks: uniqueChecks,
        notes: `Verification check failed: ${uniqueChecks.join(', ')}`,
      };
    }

    return {
      status: 'SUCCESS',
      verified: true,
      residualRisk: {
        score: 0,
        severity: 'NONE',
        confidence: 1.0,
        factors: [],
        summary: 'Zero residual sensitive entities found after transformation',
        evaluationTimestamp: timestamp,
      },
      leaksDetected: false,
      notes: 'All detected sensitive entities verified masked',
    };
  }
}

/**
 * Factory for creating deterministic verification engines
 */
export function createVerificationEngine(): DeterministicVerificationEngine {
  return new DeterministicVerificationEngine();
}
