/**
 * @shield/adapters - Browser & DOM Adapter Contracts (M2.1)
 *
 * Defines the contract boundary between browser/DOM abstractions and the
 * deterministic M1.x core engines.
 *
 * Invariants:
 * - Zero direct document/window/chrome API imports in @shield/core.
 * - Testable in-memory without requiring a real browser or JSDOM.
 * - Complete fail-closed semantics across extraction, evaluation, and delivery.
 * - Zero raw secrets leakage in public boundary results or serialization.
 */

import type {
  PipelineStage,
  PolicyAction,
  PolicyDecision,
  RiskAssessment,
  PlatformContext,
  ShieldRuntime,
  SafeTransformationResult,
  VerificationResult,
  DeliveryReceipt,
} from '@shield/core';

/**
 * Representation of a targeted DOM input element.
 */
export interface DomTargetElement {
  readonly elementId?: string;
  readonly tagName?: string;
  readonly inputType?: 'textarea' | 'contenteditable' | 'input' | 'custom';
  readonly selector?: string;
}

/**
 * Context provided to extract user input from the DOM.
 */
export interface DomExtractionContext {
  readonly url: string;
  readonly targetElement?: DomTargetElement;
  readonly timestamp?: number;
  readonly platformId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Normalized input extracted from a DOM element.
 */
export interface DomExtractedInput {
  readonly text: string;
  readonly platformContext: PlatformContext;
  readonly sourceElement?: DomTargetElement;
  readonly extractedAt: number;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Strategy interface for extracting user prompt content from the DOM.
 */
export interface DomInputExtractor {
  extract(context: DomExtractionContext): Promise<DomExtractedInput>;
}

/**
 * Payload provided to apply deliverable content back to the DOM.
 */
export interface DomDeliveryPayload {
  readonly deliverableText: string;
  readonly action: 'ALLOW' | 'MASK';
  readonly targetElement?: DomTargetElement;
  readonly contextId: string;
  readonly timestamp: number;
}

/**
 * Result of applying deliverable content back to the DOM.
 */
export interface DomDeliveryResult {
  readonly success: boolean;
  readonly appliedText: string;
  readonly targetElement?: DomTargetElement;
  readonly deliveredAt: number;
  readonly error?: string;
}

/**
 * Strategy interface for delivering safe text back into the DOM.
 */
export interface DomOutputApplier {
  apply(payload: DomDeliveryPayload): Promise<DomDeliveryResult>;
}

/**
 * Configuration options for the DOM runtime boundary.
 */
export interface DomRuntimeBoundaryOptions {
  /**
   * Underlying ShieldRuntime instance (defaults to M1.9 createShieldRuntime())
   */
  readonly runtime?: ShieldRuntime;

  /**
   * Strategy for extracting content from the DOM
   */
  readonly extractor: DomInputExtractor;

  /**
   * Strategy for applying verified safe content to the DOM
   */
  readonly applier: DomOutputApplier;

  /**
   * Default platform context when not inferred from URL
   */
  readonly defaultPlatformContext?: PlatformContext;

  /**
   * Fixed timestamp for deterministic, wall-clock-independent testing
   */
  readonly fixedTimestamp?: number;
}

/**
 * Structured, sanitized result returned by the DOM runtime boundary.
 * Guarantees zero leakage of raw sensitive values.
 */
export interface DomBoundaryExecutionResult {
  readonly ok: boolean;
  readonly status: 'ALLOW' | 'WARN' | 'MASK' | 'BLOCK' | 'ERROR';
  readonly action: PolicyAction | 'ERROR';
  readonly contextId: string;
  readonly deliverableText?: string;
  readonly decision?: PolicyDecision;
  readonly risk?: RiskAssessment;
  readonly transformation?: SafeTransformationResult;
  readonly verification?: VerificationResult;
  readonly deliveryReceipt?: DeliveryReceipt;
  readonly domDelivery?: DomDeliveryResult;
  readonly failedStage?: PipelineStage;
  readonly error?: {
    readonly code: string;
    readonly message: string;
    readonly details?: string;
  };
  readonly executionTimeMs: number;
}
