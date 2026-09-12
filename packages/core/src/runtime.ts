/**
 * Shield Runtime Composition Layer (M1.9)
 *
 * Canonical 9-Stage Pipeline Architecture:
 * INPUT → NORMALIZE → DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND
 *
 * Wires the completed M1.x engines into ONE coherent, deterministic, fail-closed,
 * and zero-leakage Shield execution runtime.
 */

import type {
  PlatformContext,
  PipelineInput,
  PipelineExecutionMetadata,
  PipelineContext,
} from './context';
import type { PipelineStage } from './stages';
import type { DetectionResult } from './detection';
import { type RiskAssessment } from './risk';
import type { PolicyAction, PolicyDecision } from './policy';
import type { AppliedTransformation } from './transformation';
import type { VerificationResult } from './verification';
import { createVerificationEngine } from './verification';
import {
  type DeliveryReceipt,
  DeterministicDeliveryEngine,
  createDeliveryEngine,
} from './delivery';
import type { PipelineResult } from './result';
import {
  type Normalizer,
  type DetectorEngine,
  type Classifier,
  type RiskEvaluator,
  type PolicyEvaluator,
  type Transformer,
  type Verifier,
  type Sender,
  type StageObserver,
  type PipelineDependencies,
  type PipelineOrchestrator,
  CorePipelineOrchestrator,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultRiskEvaluator,
  DefaultPolicyEvaluator,
  DefaultTransformer,
} from './orchestrator';

// ============================================================================
// Safe Public Runtime Result Contracts (Zero-Leakage)
// ============================================================================

/**
 * Sanitized transformation result omitting raw original text to prevent accidental secrets leakage.
 */
export interface SafeTransformationResult {
  readonly transformedText: string;
  readonly isModified: boolean;
  readonly transformationsApplied: readonly AppliedTransformation[];
  readonly originalLength: number;
}

/**
 * Public execution result returned by ShieldRuntime.execute().
 *
 * Guarantees:
 * - Structured access to decision, risk, transformation, and verification metadata.
 * - Zero raw secrets in result fields, error details, or serialized JSON output.
 * - Deliverable text is only provided for transmissible actions (ALLOW, MASK, and WARN preview).
 * - Deliverable text is strictly omitted for BLOCK and ERROR actions.
 */
export interface ShieldRuntimeResult {
  readonly ok: boolean;
  readonly status: 'ALLOW' | 'WARN' | 'MASK' | 'BLOCK' | 'ERROR';
  readonly action: PolicyAction | 'ERROR';
  readonly deliverableText?: string;
  readonly contextId: string;
  readonly risk?: RiskAssessment;
  readonly decision?: PolicyDecision;
  readonly transformation?: SafeTransformationResult;
  readonly verification?: VerificationResult;
  readonly deliveryReceipt?: DeliveryReceipt;
  readonly failedStage?: PipelineStage;
  readonly error?: {
    readonly code: string;
    readonly message: string;
    readonly details?: string;
  };
  readonly executionTimeMs: number;
  readonly metadata?: PipelineExecutionMetadata;
}

// ============================================================================
// Dependency Injection & Configuration
// ============================================================================

/**
 * Generic interface for registry-like detector containers (e.g. DefaultDetectorRegistry).
 */
export interface DetectorRegistryLike {
  runAll(
    context: { text: string; includeRawValue?: boolean; platformContext?: PlatformContext },
    options?: unknown,
  ): Promise<DetectionResult>;
}

/**
 * Configuration options for ShieldRuntime composition.
 */
export interface ShieldRuntimeOptions {
  /**
   * Stage 2 Normalizer (default: DefaultNormalizer)
   */
  readonly normalizer?: Normalizer;

  /**
   * Stage 3 Detector Engine (default: DefaultDetectorEngine or adapted detector registry)
   */
  readonly detectorEngine?: DetectorEngine;

  /**
   * Stage 3 Detector Registry to adapt automatically into a DetectorEngine
   */
  readonly detectorRegistry?: DetectorRegistryLike;

  /**
   * Stage 4 Classifier (default: DefaultClassifier)
   */
  readonly classifier?: Classifier;

  /**
   * Stage 5 Risk Evaluator (default: DefaultRiskEvaluator wrapping DeterministicRiskEvaluator)
   */
  readonly riskEvaluator?: RiskEvaluator;

  /**
   * Stage 6 Policy Evaluator (default: DefaultPolicyEvaluator)
   */
  readonly policyEvaluator?: PolicyEvaluator;

  /**
   * Stage 7 Transformer (default: DefaultTransformer)
   */
  readonly transformer?: Transformer;

  /**
   * Stage 8 Verifier (default: DeterministicVerificationEngine)
   */
  readonly verifier?: Verifier;

  /**
   * Stage 9 Sender destination (default: DeterministicDeliveryEngine)
   */
  readonly sender?: Sender;

  /**
   * Stage 9 Delivery Engine destination for audit receipts
   */
  readonly deliveryEngine?: DeterministicDeliveryEngine;

  /**
   * Stage transition observer for telemetry or progress tracking
   */
  readonly stageObserver?: StageObserver;

  /**
   * Default platform context when not specified in execute()
   */
  readonly defaultPlatformContext?: PlatformContext;

  /**
   * Fixed timestamp for deterministic testing
   */
  readonly fixedTimestamp?: number;
}

// ============================================================================
// Detector Engine Adapters & Default Fallbacks
// ============================================================================

/**
 * Adapts any DetectorRegistryLike instance into a standard DetectorEngine stage handler.
 */
export class RegistryDetectorEngineAdapter implements DetectorEngine {
  constructor(private readonly registry: DetectorRegistryLike) {}

  async detect(
    normalized: { normalizedText: string },
    context: { platformContext?: PlatformContext },
  ): Promise<DetectionResult> {
    return this.registry.runAll(
      {
        text: normalized.normalizedText,
        platformContext: context.platformContext,
      },
      {
        includeRawValue: true,
      },
    );
  }
}

/**
 * Deterministic default detector engine.
 *
 * Uses an injected detector registry if provided, or defaults to deterministic baseline
 * regex detectors for API keys and emails.
 */
export class DefaultDetectorEngine implements DetectorEngine {
  private readonly registry?: DetectorRegistryLike;

  constructor(initialRegistry?: DetectorRegistryLike) {
    this.registry = initialRegistry;
  }

  async detect(
    normalized: { normalizedText: string },
    context: { platformContext?: PlatformContext },
  ): Promise<DetectionResult> {
    if (this.registry) {
      return this.registry.runAll(
        {
          text: normalized.normalizedText,
          platformContext: context.platformContext,
        },
        {
          includeRawValue: true,
        },
      );
    }

    // Deterministic fallback regex matching for standard sensitive patterns
    const text = normalized.normalizedText;
    const entities: import('./detection').DetectionEntity[] = [];

    // 1. API Keys (e.g. sk-proj-..., sk-...)
    const apiKeyRegex = /\b(sk-[a-zA-Z0-9_-]{16,})\b/g;
    let match: RegExpExecArray | null;
    while ((match = apiKeyRegex.exec(text)) !== null) {
      const rawValue = match[0];
      entities.push({
        id: `det-apikey-${match.index}`,
        detectorId: 'detector-api-key',
        category: 'API_KEY',
        severity: 'HIGH',
        confidence: 0.99,
        range: { startIndex: match.index, endIndex: match.index + rawValue.length },
        evidence: { tokenLength: rawValue.length, hasRawValue: true },
        rawValue,
      });
    }

    // 2. Email addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    while ((match = emailRegex.exec(text)) !== null) {
      const rawValue = match[0];
      entities.push({
        id: `det-email-${match.index}`,
        detectorId: 'detector-email',
        category: 'PII',
        severity: 'MEDIUM',
        confidence: 0.95,
        range: { startIndex: match.index, endIndex: match.index + rawValue.length },
        evidence: { tokenLength: rawValue.length, hasRawValue: true },
        rawValue,
      });
    }

    return {
      entities,
      hasDetections: entities.length > 0,
      durationMs: 0,
    };
  }
}

// ============================================================================
// Shield Runtime Interface & Implementation
// ============================================================================

/**
 * Public Shield Runtime Interface
 */
export interface ShieldRuntime {
  /**
   * Execute the full 9-stage pipeline on input prompt and platform context.
   */
  execute(
    input: string | PipelineInput,
    platformContext?: PlatformContext,
  ): Promise<ShieldRuntimeResult>;

  /**
   * Access to the active delivery engine for audit receipt inspection.
   */
  readonly deliveryEngine: DeterministicDeliveryEngine;

  /**
   * Access to the active pipeline orchestrator.
   */
  readonly orchestrator: PipelineOrchestrator;
}

/**
 * Deterministic Shield Runtime Implementation
 */
export class CoreShieldRuntime implements ShieldRuntime {
  readonly deliveryEngine: DeterministicDeliveryEngine;
  readonly orchestrator: PipelineOrchestrator;
  private readonly defaultPlatformContext?: PlatformContext;
  private readonly fixedTimestamp?: number;

  constructor(options: ShieldRuntimeOptions = {}) {
    this.defaultPlatformContext = options.defaultPlatformContext;
    this.fixedTimestamp = options.fixedTimestamp;

    // 1. Stage 9 Delivery Engine & Sender
    if (options.deliveryEngine) {
      this.deliveryEngine = options.deliveryEngine;
    } else if (options.sender instanceof DeterministicDeliveryEngine) {
      this.deliveryEngine = options.sender;
    } else {
      this.deliveryEngine = createDeliveryEngine();
    }

    const sender: Sender = options.sender ?? this.deliveryEngine;

    // 2. Stage 3 Detector Engine
    let detectorEngine: DetectorEngine;
    if (options.detectorEngine) {
      detectorEngine = options.detectorEngine;
    } else if (options.detectorRegistry) {
      detectorEngine = new RegistryDetectorEngineAdapter(options.detectorRegistry);
    } else {
      detectorEngine = new DefaultDetectorEngine();
    }

    // 3. Stage Handlers (with sensible deterministic defaults)
    const normalizer: Normalizer = options.normalizer ?? new DefaultNormalizer();
    const classifier: Classifier = options.classifier ?? new DefaultClassifier();
    const riskEvaluator: RiskEvaluator = options.riskEvaluator ?? new DefaultRiskEvaluator();
    const policyEvaluator: PolicyEvaluator =
      options.policyEvaluator ?? new DefaultPolicyEvaluator();
    const transformer: Transformer = options.transformer ?? new DefaultTransformer();
    const verifier: Verifier = options.verifier ?? createVerificationEngine();

    // 4. Compose 9-Stage Dependencies
    const dependencies: PipelineDependencies = {
      normalizer,
      detectorEngine,
      classifier,
      riskEvaluator,
      policyEvaluator,
      transformer,
      verifier,
      sender,
      stageObserver: options.stageObserver,
    };

    // 5. Build Pipeline Orchestrator
    this.orchestrator = new CorePipelineOrchestrator(dependencies);
  }

  async execute(
    input: string | PipelineInput,
    platformContext?: PlatformContext,
  ): Promise<ShieldRuntimeResult> {
    const startedAt = this.fixedTimestamp ?? Date.now();

    // 1. Input Sanitization & Structuring
    let pipelineInput: PipelineInput;

    if (typeof input === 'string') {
      const resolvedContext: PlatformContext = platformContext ??
        this.defaultPlatformContext ?? {
          site: 'unknown',
          isAiSite: false,
        };

      pipelineInput = {
        rawText: input,
        timestamp: startedAt,
        platformContext: resolvedContext,
        metadata: {},
      };
    } else if (input && typeof input === 'object' && typeof input.rawText === 'string') {
      const resolvedContext: PlatformContext = platformContext ??
        input.platformContext ??
        this.defaultPlatformContext ?? {
          site: 'unknown',
          isAiSite: false,
        };

      pipelineInput = {
        rawText: input.rawText,
        timestamp: this.fixedTimestamp ?? input.timestamp ?? startedAt,
        platformContext: resolvedContext,
        metadata: input.metadata ? { ...input.metadata } : {},
      };
    } else {
      // Invalid input fail-closed
      const elapsed = Math.max(0, (this.fixedTimestamp ?? Date.now()) - startedAt);
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: 'invalid-input-context',
        failedStage: 'INPUT',
        error: {
          code: 'INPUT_ERROR',
          message: 'Invalid pipeline input: rawText string is required',
        },
        executionTimeMs: elapsed,
      };
    }

    // 2. Execute 9-Stage Pipeline Orchestrator
    const result = await this.orchestrator.process(pipelineInput);
    const completedAt = this.fixedTimestamp ?? Date.now();
    const executionTimeMs = Math.max(0, completedAt - startedAt);

    // 3. Process Pipeline Orchestration Result
    if (!result.ok) {
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: (pipelineInput.metadata?.requestId as string) ?? 'error-context',
        failedStage: 'INPUT',
        error: {
          code: 'PIPELINE_ERROR',
          message: result.error.message,
        },
        executionTimeMs,
      };
    }

    const pResult: PipelineResult = result.value;
    const latestReceipt = this.deliveryEngine.getLastReceipt();
    const effectiveReceipt =
      latestReceipt && this.fixedTimestamp !== undefined
        ? { ...latestReceipt, timestamp: this.fixedTimestamp }
        : latestReceipt;

    // 4. Map to Structured, Non-Leaking ShieldRuntimeResult
    switch (pResult.status) {
      case 'ALLOW': {
        return {
          ok: true,
          status: 'ALLOW',
          action: 'ALLOW',
          deliverableText: pResult.deliverableText,
          contextId: pResult.contextId,
          risk: pResult.risk,
          decision: pResult.decision,
          deliveryReceipt: effectiveReceipt,
          executionTimeMs,
          metadata: pResult.metadata,
        };
      }

      case 'WARN': {
        const warnContext: PipelineContext = {
          id: pResult.contextId,
          timestamp: startedAt,
          currentStage: 'SEND',
          input: {
            rawText: typeof input === 'string' ? input : input.rawText,
            timestamp: startedAt,
            platformContext: pipelineInput.platformContext,
          },
          platformContext: pipelineInput.platformContext,
          executionMetadata: pResult.metadata ?? {
            startedAt,
            stageTimings: {},
            errors: [],
          },
        };

        const warnReceipt = this.deliveryEngine.sendSync(
          {
            canSend: false,
            deliverableText: pResult.deliverableText,
            actionTaken: 'WARN',
            reason: pResult.warningNotice,
          },
          warnContext,
        );

        return {
          ok: true,
          status: 'WARN',
          action: 'WARN',
          deliverableText: pResult.deliverableText,
          contextId: pResult.contextId,
          risk: pResult.risk,
          decision: pResult.decision,
          deliveryReceipt: warnReceipt,
          executionTimeMs,
          metadata: pResult.metadata,
        };
      }

      case 'MASK': {
        // Zero-leakage: omit originalText from public result
        const safeTransformation: SafeTransformationResult = {
          transformedText: pResult.transformation.transformedText,
          isModified: pResult.transformation.isModified,
          transformationsApplied: pResult.transformation.transformationsApplied,
          originalLength: pResult.transformation.originalText.length,
        };

        return {
          ok: true,
          status: 'MASK',
          action: 'MASK',
          deliverableText: pResult.deliverableText,
          contextId: pResult.contextId,
          risk: pResult.risk,
          decision: pResult.decision,
          transformation: safeTransformation,
          verification: pResult.verification,
          deliveryReceipt: effectiveReceipt,
          executionTimeMs,
          metadata: pResult.metadata,
        };
      }

      case 'BLOCK': {
        const blockContext: PipelineContext = {
          id: pResult.contextId,
          timestamp: startedAt,
          currentStage: 'SEND',
          input: {
            rawText: typeof input === 'string' ? input : input.rawText,
            timestamp: startedAt,
            platformContext: pipelineInput.platformContext,
          },
          platformContext: pipelineInput.platformContext,
          executionMetadata: pResult.metadata ?? {
            startedAt,
            stageTimings: {},
            errors: [],
          },
        };

        const blockReceipt = this.deliveryEngine.sendSync(
          {
            canSend: false,
            actionTaken: 'BLOCK',
            reason: pResult.blockedReason,
          },
          blockContext,
        );

        return {
          ok: true,
          status: 'BLOCK',
          action: 'BLOCK',
          deliverableText: undefined, // Strictly omitted on block
          contextId: pResult.contextId,
          risk: pResult.risk,
          decision: pResult.decision,
          deliveryReceipt: blockReceipt,
          executionTimeMs,
          metadata: pResult.metadata,
        };
      }

      case 'ERROR': {
        return {
          ok: false,
          status: 'ERROR',
          action: 'ERROR',
          deliverableText: undefined, // Strictly omitted on error
          contextId: pResult.contextId,
          failedStage: pResult.failedStage,
          error: pResult.error,
          executionTimeMs,
          metadata: pResult.metadata,
        };
      }
    }
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Factory for creating a deterministic Shield Runtime.
 *
 * Wires default M1.x engines if not injected:
 * - DefaultNormalizer (M1.3)
 * - DefaultDetectorEngine (M1.2)
 * - DefaultClassifier (M1.3)
 * - DefaultRiskEvaluator / DeterministicRiskEvaluator (M1.4)
 * - DefaultPolicyEvaluator (M1.5)
 * - DefaultTransformer (M1.6)
 * - DeterministicVerificationEngine (M1.7)
 * - DeterministicDeliveryEngine (M1.8)
 * - CorePipelineOrchestrator (M1.3)
 */
export function createShieldRuntime(options?: ShieldRuntimeOptions): ShieldRuntime {
  return new CoreShieldRuntime(options);
}
