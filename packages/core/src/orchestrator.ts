/**
 * Pipeline Orchestrator & Stage Dependency Contracts
 *
 * Coordinates the canonical 9-stage sequence:
 * INPUT → NORMALIZE → DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND
 *
 * Designed with strict dependency injection, complete policy/detection decoupling,
 * and deterministic execution.
 */

import { type Result, ok, generateId } from '@shield/shared';
import type {
  PipelineInput,
  NormalizedInput,
  PipelineContext,
  PipelineExecutionMetadata,
  PipelineStageError,
} from './context';
import type { PipelineStage } from './stages';
import type {
  DetectionResult,
  ClassificationResult,
  ClassificationEntity,
  SensitivityLevel,
} from './detection';
import {
  type RiskAssessment,
  type RiskEvaluatorConfig,
  DeterministicRiskEvaluator,
  createRiskEvaluator,
} from './risk';
import type { PolicyDecision } from './policy';
import type { TransformationResult, AppliedTransformation } from './transformation';
import type { VerificationResult } from './verification';
import type {
  PipelineResult,
  PipelineAllowResult,
  PipelineWarnResult,
  PipelineMaskResult,
  PipelineBlockResult,
  PipelineErrorResult,
  FinalDelivery,
} from './result';

// ============================================================================
// Stage Handler Interfaces
// ============================================================================

export interface Normalizer {
  normalize(input: PipelineInput): Promise<NormalizedInput> | NormalizedInput;
}

export interface DetectorEngine {
  detect(normalized: NormalizedInput, context: PipelineContext): Promise<DetectionResult>;
}

export interface Classifier {
  classify(
    detections: DetectionResult,
    context: PipelineContext,
  ): Promise<ClassificationResult> | ClassificationResult;
}

export interface RiskEvaluator {
  evaluate(
    detections: DetectionResult,
    classification: ClassificationResult,
    context: PipelineContext,
  ): Promise<RiskAssessment> | RiskAssessment;
}

export interface PolicyEvaluator {
  evaluate(
    risk: RiskAssessment,
    detections: DetectionResult,
    classification: ClassificationResult,
    context: PipelineContext,
  ): Promise<PolicyDecision> | PolicyDecision;
}

export interface Transformer {
  transform(
    normalized: NormalizedInput,
    decision: PolicyDecision,
    detections: DetectionResult,
    context: PipelineContext,
  ): Promise<TransformationResult> | TransformationResult;
}

export interface Verifier {
  verify(
    transformation: TransformationResult,
    decision: PolicyDecision,
    context: PipelineContext,
  ): Promise<VerificationResult> | VerificationResult;
}

export interface Sender {
  send(delivery: FinalDelivery, context: PipelineContext): Promise<void>;
}

export type StageObserver = (stage: PipelineStage, context: Readonly<PipelineContext>) => void;

// ============================================================================
// Dependency Injection Container
// ============================================================================

export interface PipelineDependencies {
  readonly normalizer: Normalizer;
  readonly detectorEngine: DetectorEngine;
  readonly classifier: Classifier;
  readonly riskEvaluator: RiskEvaluator;
  readonly policyEvaluator: PolicyEvaluator;
  readonly transformer: Transformer;
  readonly verifier: Verifier;
  readonly sender: Sender;
  readonly stageObserver?: StageObserver;
}

// ============================================================================
// Orchestrator Interface
// ============================================================================

export interface PipelineOrchestrator {
  /**
   * Execute the full 9-stage pipeline on given input.
   */
  process(input: PipelineInput): Promise<Result<PipelineResult, Error>>;
}

// ============================================================================
// Core Pipeline Orchestrator Implementation
// ============================================================================

export class CorePipelineOrchestrator implements PipelineOrchestrator {
  constructor(private readonly deps: PipelineDependencies) {}

  async process(input: PipelineInput): Promise<Result<PipelineResult, Error>> {
    const startedAt = Date.now();
    const stageTimings: Partial<Record<PipelineStage, number>> = {};
    const errors: PipelineStageError[] = [];

    const executionMetadata: PipelineExecutionMetadata = {
      startedAt,
      stageTimings,
      errors,
    };

    const context: PipelineContext = {
      id: `ctx-${generateId()}`,
      timestamp: startedAt,
      currentStage: 'INPUT',
      input: Object.freeze({ ...input }),
      platformContext: Object.freeze({ ...input.platformContext }),
      executionMetadata,
    };

    const notify = (stage: PipelineStage) => {
      context.currentStage = stage;
      this.deps.stageObserver?.(stage, context);
    };

    const recordTiming = (stage: PipelineStage, start: number) => {
      stageTimings[stage] = Math.max(0, Date.now() - start);
    };

    const failStage = (stage: PipelineStage, err: unknown): PipelineErrorResult => {
      const message = err instanceof Error ? err.message : String(err);
      const code = `${stage}_ERROR`;
      const stageError: PipelineStageError = {
        stage,
        code,
        message,
        recoverable: false,
      };
      errors.push(stageError);
      executionMetadata.completedAt = Date.now();

      return {
        status: 'ERROR',
        contextId: context.id,
        failedStage: stage,
        error: {
          code,
          message,
          details: err instanceof Error ? err.stack : undefined,
        },
        metadata: context.executionMetadata,
      };
    };

    // ------------------------------------------------------------------------
    // Stage 1: INPUT
    // ------------------------------------------------------------------------
    notify('INPUT');
    const inputStart = Date.now();
    if (!input || typeof input.rawText !== 'string' || !input.platformContext) {
      recordTiming('INPUT', inputStart);
      return ok(
        failStage(
          'INPUT',
          new Error('Invalid pipeline input: rawText and platformContext are required'),
        ),
      );
    }
    recordTiming('INPUT', inputStart);

    // ------------------------------------------------------------------------
    // Stage 2: NORMALIZE
    // ------------------------------------------------------------------------
    notify('NORMALIZE');
    const normStart = Date.now();
    try {
      context.normalized = await this.deps.normalizer.normalize(context.input);
    } catch (err) {
      recordTiming('NORMALIZE', normStart);
      return ok(failStage('NORMALIZE', err));
    }
    recordTiming('NORMALIZE', normStart);

    // ------------------------------------------------------------------------
    // Stage 3: DETECT
    // ------------------------------------------------------------------------
    notify('DETECT');
    const detectStart = Date.now();
    try {
      context.detections = await this.deps.detectorEngine.detect(context.normalized, context);
    } catch (err) {
      recordTiming('DETECT', detectStart);
      return ok(failStage('DETECT', err));
    }
    recordTiming('DETECT', detectStart);

    // ------------------------------------------------------------------------
    // Stage 4: CLASSIFY
    // ------------------------------------------------------------------------
    notify('CLASSIFY');
    const classifyStart = Date.now();
    try {
      context.classification = await this.deps.classifier.classify(context.detections, context);
    } catch (err) {
      recordTiming('CLASSIFY', classifyStart);
      return ok(failStage('CLASSIFY', err));
    }
    recordTiming('CLASSIFY', classifyStart);

    // ------------------------------------------------------------------------
    // Stage 5: RISK
    // ------------------------------------------------------------------------
    notify('RISK');
    const riskStart = Date.now();
    try {
      context.risk = await this.deps.riskEvaluator.evaluate(
        context.detections,
        context.classification,
        context,
      );
    } catch (err) {
      recordTiming('RISK', riskStart);
      return ok(failStage('RISK', err));
    }
    recordTiming('RISK', riskStart);

    // ------------------------------------------------------------------------
    // Stage 6: POLICY
    // ------------------------------------------------------------------------
    notify('POLICY');
    const policyStart = Date.now();
    try {
      context.policyDecision = await this.deps.policyEvaluator.evaluate(
        context.risk,
        context.detections,
        context.classification,
        context,
      );
    } catch (err) {
      recordTiming('POLICY', policyStart);
      return ok(failStage('POLICY', err));
    }
    recordTiming('POLICY', policyStart);

    const decision = context.policyDecision;

    // ------------------------------------------------------------------------
    // Stage 7: TRANSFORM
    // ------------------------------------------------------------------------
    notify('TRANSFORM');
    const transformStart = Date.now();
    if (decision.action === 'MASK') {
      try {
        context.transformation = await this.deps.transformer.transform(
          context.normalized,
          decision,
          context.detections,
          context,
        );
      } catch (err) {
        recordTiming('TRANSFORM', transformStart);
        return ok(failStage('TRANSFORM', err));
      }
    } else {
      context.transformation = {
        originalText: context.normalized.normalizedText,
        transformedText: context.normalized.normalizedText,
        isModified: false,
        transformationsApplied: [],
      };
    }
    recordTiming('TRANSFORM', transformStart);

    // ------------------------------------------------------------------------
    // Stage 8: VERIFY
    // ------------------------------------------------------------------------
    notify('VERIFY');
    const verifyStart = Date.now();
    try {
      context.verification = await this.deps.verifier.verify(
        context.transformation,
        decision,
        context,
      );

      if (
        !context.verification.verified ||
        context.verification.status === 'FAILED' ||
        context.verification.leaksDetected
      ) {
        recordTiming('VERIFY', verifyStart);
        const failureNote =
          context.verification.notes ||
          'Verification check failed: residual sensitive leaks detected in deliverable';
        return ok(failStage('VERIFY', new Error(failureNote)));
      }
    } catch (err) {
      recordTiming('VERIFY', verifyStart);
      return ok(failStage('VERIFY', err));
    }
    recordTiming('VERIFY', verifyStart);

    // ------------------------------------------------------------------------
    // Stage 9: SEND
    // ------------------------------------------------------------------------
    notify('SEND');
    const sendStart = Date.now();
    executionMetadata.completedAt = Date.now();

    switch (decision.action) {
      case 'ALLOW': {
        const deliverableText = context.normalized.normalizedText;
        const delivery: FinalDelivery = {
          canSend: true,
          deliverableText,
          actionTaken: 'ALLOW',
          reason: decision.reason,
        };

        try {
          await this.deps.sender.send(delivery, context);
        } catch (err) {
          recordTiming('SEND', sendStart);
          return ok(failStage('SEND', err));
        }

        recordTiming('SEND', sendStart);
        const allowResult: PipelineAllowResult = {
          status: 'ALLOW',
          contextId: context.id,
          deliverableText,
          decision,
          risk: context.risk,
          metadata: executionMetadata,
        };
        return ok(allowResult);
      }

      case 'WARN': {
        recordTiming('SEND', sendStart);
        // Warning: user interaction required; do not send automatically
        const warnResult: PipelineWarnResult = {
          status: 'WARN',
          contextId: context.id,
          deliverableText: context.normalized.normalizedText,
          warningNotice: decision.userNotice || decision.reason,
          allowOverride: decision.allowOverride,
          decision,
          risk: context.risk,
          metadata: executionMetadata,
        };
        return ok(warnResult);
      }

      case 'MASK': {
        const deliverableText = context.transformation.transformedText;
        const delivery: FinalDelivery = {
          canSend: true,
          deliverableText,
          actionTaken: 'MASK',
          reason: decision.reason,
        };

        try {
          await this.deps.sender.send(delivery, context);
        } catch (err) {
          recordTiming('SEND', sendStart);
          return ok(failStage('SEND', err));
        }

        recordTiming('SEND', sendStart);
        const maskResult: PipelineMaskResult = {
          status: 'MASK',
          contextId: context.id,
          deliverableText,
          transformation: context.transformation,
          verification: context.verification,
          decision,
          risk: context.risk,
          metadata: executionMetadata,
        };
        return ok(maskResult);
      }

      case 'BLOCK': {
        recordTiming('SEND', sendStart);
        // Blocked: transmission prohibited
        const blockResult: PipelineBlockResult = {
          status: 'BLOCK',
          contextId: context.id,
          blockedReason: decision.reason,
          decision,
          risk: context.risk,
          metadata: executionMetadata,
        };
        return ok(blockResult);
      }
    }
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

export function createPipelineOrchestrator(deps: PipelineDependencies): PipelineOrchestrator {
  return new CorePipelineOrchestrator(deps);
}

// ============================================================================
// Deterministic Default Implementations (for testing & standard fallbacks)
// ============================================================================

export class DefaultNormalizer implements Normalizer {
  normalize(input: PipelineInput): NormalizedInput {
    const normalizedText = input.rawText.normalize('NFC');
    return {
      original: input,
      normalizedText,
      encoding: 'UTF-8',
      normalizationApplied: ['unicode-nfc'],
    };
  }
}

export class DefaultClassifier implements Classifier {
  classify(detections: DetectionResult): ClassificationResult {
    const classifiedEntities: ClassificationEntity[] = detections.entities.map((entity) => {
      let sensitivityLevel: SensitivityLevel = 'INTERNAL';
      switch (entity.severity) {
        case 'CRITICAL':
          sensitivityLevel = 'RESTRICTED';
          break;
        case 'HIGH':
          sensitivityLevel = 'CONFIDENTIAL';
          break;
        case 'MEDIUM':
          sensitivityLevel = 'INTERNAL';
          break;
        case 'LOW':
          sensitivityLevel = 'PUBLIC';
          break;
      }
      return {
        entityId: entity.id,
        category: entity.category,
        sensitivityLevel,
      };
    });

    return { classifiedEntities };
  }
}

export class DefaultRiskEvaluator implements RiskEvaluator {
  private readonly engine: DeterministicRiskEvaluator;

  constructor(config?: RiskEvaluatorConfig) {
    this.engine = createRiskEvaluator(config);
  }

  evaluate(
    detections: DetectionResult,
    classification?: ClassificationResult,
    context?: PipelineContext,
  ): RiskAssessment {
    return this.engine.evaluate(detections, classification, context);
  }
}

export class DefaultPolicyEvaluator implements PolicyEvaluator {
  evaluate(
    risk: RiskAssessment,
    detections: DetectionResult,
    _classification?: ClassificationResult,
    _context?: PipelineContext,
  ): PolicyDecision {
    if (
      !detections ||
      !detections.hasDetections ||
      detections.entities.length === 0 ||
      risk.severity === 'NONE'
    ) {
      return {
        action: 'ALLOW',
        reason: 'Clean input allowed: no sensitive entities detected',
        triggeredRules: [],
        allowOverride: false,
      };
    }

    switch (risk.severity) {
      case 'CRITICAL':
        return {
          action: 'BLOCK',
          reason: `Critical risk detected (score ${risk.score}/100): transmission blocked by default policy`,
          matchedRuleId: 'default-block-critical',
          triggeredRules: ['default-block-critical'],
          allowOverride: false,
        };
      case 'HIGH':
        return {
          action: 'MASK',
          reason: `High risk detected (score ${risk.score}/100): masking sensitive entities per default policy`,
          matchedRuleId: 'default-mask-high',
          triggeredRules: ['default-mask-high'],
          allowOverride: false,
        };
      case 'MEDIUM':
        return {
          action: 'WARN',
          reason: `Medium risk detected (score ${risk.score}/100): prompt contains sensitive data`,
          matchedRuleId: 'default-warn-medium',
          triggeredRules: ['default-warn-medium'],
          allowOverride: true,
          userNotice:
            'This prompt contains potentially sensitive information. Please review before proceeding.',
        };
      case 'LOW':
      default:
        return {
          action: 'ALLOW',
          reason: `Low risk detected (score ${risk.score}/100): allowed under default policy`,
          matchedRuleId: 'default-allow-low',
          triggeredRules: ['default-allow-low'],
          allowOverride: false,
        };
    }
  }
}

export class DefaultTransformer implements Transformer {
  transform(
    normalized: NormalizedInput,
    decision: PolicyDecision,
    detections: DetectionResult,
  ): TransformationResult {
    if (
      decision.action !== 'MASK' ||
      !detections.hasDetections ||
      detections.entities.length === 0
    ) {
      return {
        originalText: normalized.normalizedText,
        transformedText: normalized.normalizedText,
        isModified: false,
        transformationsApplied: [],
      };
    }

    const originalText = normalized.normalizedText;
    // Sort ascending by startIndex to build transformed text in a single deterministic forward pass
    const sorted = [...detections.entities].sort(
      (a, b) => a.range.startIndex - b.range.startIndex || a.range.endIndex - b.range.endIndex,
    );

    const transformationsApplied: AppliedTransformation[] = [];
    const pieces: string[] = [];
    let lastOriginalIndex = 0;
    let currentTransformedIndex = 0;

    for (const entity of sorted) {
      const { startIndex, endIndex } = entity.range;

      // Range validity and non-overlapping check
      if (
        startIndex < lastOriginalIndex ||
        endIndex < startIndex ||
        startIndex < 0 ||
        endIndex > originalText.length
      ) {
        continue;
      }

      // Append untouched prefix before this entity
      const before = originalText.slice(lastOriginalIndex, startIndex);
      pieces.push(before);
      currentTransformedIndex += before.length;

      // Append replacement token
      const replacement = `[REDACTED_${entity.category}]`;
      const replStart = currentTransformedIndex;
      pieces.push(replacement);
      currentTransformedIndex += replacement.length;
      const replEnd = currentTransformedIndex;

      transformationsApplied.push({
        entityId: entity.id,
        type: 'MASK',
        originalRange: entity.range,
        replacedRange: { startIndex: replStart, endIndex: replEnd },
        category: entity.category,
      });

      lastOriginalIndex = endIndex;
    }

    // Append untouched suffix after the last entity
    pieces.push(originalText.slice(lastOriginalIndex));
    const transformedText = pieces.join('');

    return {
      originalText,
      transformedText,
      isModified: transformedText !== originalText,
      transformationsApplied,
    };
  }
}

export class DefaultVerifier implements Verifier {
  verify(
    transformation: TransformationResult,
    decision: PolicyDecision,
    context: PipelineContext,
  ): VerificationResult {
    if (decision.action !== 'MASK') {
      return {
        status: 'NOT_REQUIRED',
        verified: true,
        residualRisk: context.risk ?? {
          score: 0,
          severity: 'NONE',
          confidence: 1.0,
          factors: [],
          summary: 'No transformation required',
          evaluationTimestamp: Date.now(),
        },
        leaksDetected: false,
      };
    }

    const detections = context.detections?.entities ?? [];
    const leaks: string[] = [];

    for (const entity of detections) {
      const raw =
        entity.rawValue ??
        context.normalized?.normalizedText.slice(entity.range.startIndex, entity.range.endIndex);
      if (raw && raw.length > 0 && transformation.transformedText.includes(raw)) {
        leaks.push(`Residual raw value leak for entity ${entity.id}`);
      }
    }

    if (leaks.length > 0) {
      return {
        status: 'FAILED',
        verified: false,
        residualRisk: {
          score: 90,
          severity: 'CRITICAL',
          confidence: 0.99,
          factors: [
            {
              detectorId: 'verifier-leak-check',
              category: 'SECRET',
              severity: 'CRITICAL',
              weight: 90,
              reason: 'Residual sensitive value detected after transformation',
            },
          ],
          summary: 'Residual leak detected in transformed content',
          evaluationTimestamp: Date.now(),
        },
        leaksDetected: true,
        failedChecks: leaks,
        notes: 'Verification failed: sensitive pattern remained after transformation',
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
        summary: 'All sensitive entities successfully transformed',
        evaluationTimestamp: Date.now(),
      },
      leaksDetected: false,
    };
  }
}

export class InMemorySender implements Sender {
  readonly deliveries: FinalDelivery[] = [];
  readonly contexts: PipelineContext[] = [];

  async send(delivery: FinalDelivery, context: PipelineContext): Promise<void> {
    this.deliveries.push(delivery);
    this.contexts.push(context);
  }

  clear(): void {
    this.deliveries.length = 0;
    this.contexts.length = 0;
  }
}
