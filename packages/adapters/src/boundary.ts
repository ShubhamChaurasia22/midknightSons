/**
 * @shield/adapters - DOM Runtime Boundary (M2.1)
 *
 * Implements the deterministic bridge between browser/DOM abstractions and
 * the M1.9 ShieldRuntime core pipeline.
 */

import { createShieldRuntime, type ShieldRuntime, type PlatformContext } from '@shield/core';
import type {
  DomBoundaryExecutionResult,
  DomDeliveryPayload,
  DomDeliveryResult,
  DomExtractionContext,
  DomInputExtractor,
  DomOutputApplier,
  DomRuntimeBoundaryOptions,
} from './contracts';

/**
 * Deterministic DOM Runtime Boundary.
 * Coordinates input extraction, M1.9 core execution, output delivery, and safe result reporting.
 */
export class DomRuntimeBoundary {
  private readonly runtime: ShieldRuntime;
  private readonly extractor: DomInputExtractor;
  private readonly applier: DomOutputApplier;
  private readonly defaultPlatformContext?: PlatformContext;
  private readonly fixedTimestamp?: number;

  constructor(options: DomRuntimeBoundaryOptions) {
    if (!options.extractor) {
      throw new Error('DomRuntimeBoundary requires a valid DomInputExtractor');
    }
    if (!options.applier) {
      throw new Error('DomRuntimeBoundary requires a valid DomOutputApplier');
    }

    this.extractor = options.extractor;
    this.applier = options.applier;
    this.defaultPlatformContext = options.defaultPlatformContext;
    this.fixedTimestamp = options.fixedTimestamp;

    // Use injected runtime or instantiate default deterministic M1.9 runtime
    this.runtime =
      options.runtime ??
      createShieldRuntime({
        defaultPlatformContext: options.defaultPlatformContext,
        fixedTimestamp: options.fixedTimestamp,
      });
  }

  /**
   * Access to the underlying core ShieldRuntime instance.
   */
  get underlyingRuntime(): ShieldRuntime {
    return this.runtime;
  }

  /**
   * Execute the full end-to-end flow:
   * DOM Extraction → M1.9 Core Pipeline → DOM Application (if authorized) → Safe Result
   */
  async execute(context: DomExtractionContext): Promise<DomBoundaryExecutionResult> {
    const startedAt = this.fixedTimestamp ?? Date.now();
    const boundaryContextId = `dom-boundary-${startedAt}`;

    // ------------------------------------------------------------------------
    // Step 1: Validate extraction context
    // ------------------------------------------------------------------------
    if (!context || typeof context.url !== 'string') {
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: boundaryContextId,
        failedStage: 'INPUT',
        error: {
          code: 'EXTRACTION_CONTEXT_INVALID',
          message: 'Invalid DOM extraction context: url is required',
        },
        executionTimeMs: 0,
      };
    }

    // ------------------------------------------------------------------------
    // Step 2: Extract input from DOM
    // ------------------------------------------------------------------------
    let extracted;
    try {
      extracted = await this.extractor.extract(context);
    } catch (err) {
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: boundaryContextId,
        failedStage: 'INPUT',
        error: {
          code: 'EXTRACTION_FAILED',
          message: err instanceof Error ? err.message : String(err),
        },
        executionTimeMs: Math.max(0, (this.fixedTimestamp ?? Date.now()) - startedAt),
      };
    }

    if (!extracted || typeof extracted.text !== 'string') {
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: boundaryContextId,
        failedStage: 'INPUT',
        error: {
          code: 'EXTRACTED_INPUT_INVALID',
          message: 'Extractor yielded invalid or missing prompt text',
        },
        executionTimeMs: Math.max(0, (this.fixedTimestamp ?? Date.now()) - startedAt),
      };
    }

    // ------------------------------------------------------------------------
    // Step 3: Execute Core M1.9 ShieldRuntime
    // ------------------------------------------------------------------------
    const effectivePlatformContext: PlatformContext = extracted.platformContext ??
      this.defaultPlatformContext ?? {
        site: 'unknown',
        isAiSite: false,
      };

    const runtimeResult = await this.runtime.execute(extracted.text, effectivePlatformContext);

    const executionTimeMs = Math.max(0, (this.fixedTimestamp ?? Date.now()) - startedAt);
    const resultContextId = runtimeResult.contextId || boundaryContextId;

    // Fail closed on runtime failure
    if (!runtimeResult.ok) {
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: resultContextId,
        failedStage: runtimeResult.failedStage,
        error: runtimeResult.error,
        executionTimeMs,
      };
    }

    // ------------------------------------------------------------------------
    // Step 4: Handle Actions & Output Delivery Boundary
    // ------------------------------------------------------------------------
    switch (runtimeResult.status) {
      case 'ALLOW': {
        const deliverableText = runtimeResult.deliverableText ?? extracted.text;
        const deliveryPayload: DomDeliveryPayload = {
          deliverableText,
          action: 'ALLOW',
          targetElement: extracted.sourceElement,
          contextId: resultContextId,
          timestamp: this.fixedTimestamp ?? Date.now(),
        };

        let domDelivery: DomDeliveryResult;
        try {
          domDelivery = await this.applier.apply(deliveryPayload);
        } catch (err) {
          return {
            ok: false,
            status: 'ERROR',
            action: 'ALLOW',
            contextId: resultContextId,
            deliverableText,
            failedStage: 'SEND',
            error: {
              code: 'DOM_DELIVERY_EXCEPTION',
              message: err instanceof Error ? err.message : String(err),
            },
            executionTimeMs,
          };
        }

        if (!domDelivery.success) {
          return {
            ok: false,
            status: 'ERROR',
            action: 'ALLOW',
            contextId: resultContextId,
            deliverableText,
            failedStage: 'SEND',
            domDelivery,
            error: {
              code: 'DOM_DELIVERY_FAILED',
              message: domDelivery.error || 'DOM output applier failed to apply deliverable text',
            },
            executionTimeMs,
          };
        }

        return {
          ok: true,
          status: 'ALLOW',
          action: 'ALLOW',
          contextId: resultContextId,
          deliverableText,
          decision: runtimeResult.decision,
          risk: runtimeResult.risk,
          deliveryReceipt: runtimeResult.deliveryReceipt,
          domDelivery,
          executionTimeMs,
        };
      }

      case 'MASK': {
        const deliverableText = runtimeResult.deliverableText;
        if (!deliverableText) {
          return {
            ok: false,
            status: 'ERROR',
            action: 'MASK',
            contextId: resultContextId,
            failedStage: 'TRANSFORM',
            error: {
              code: 'MISSING_DELIVERABLE_TEXT',
              message: 'MASK action authorized but no deliverable text was provided',
            },
            executionTimeMs,
          };
        }

        const deliveryPayload: DomDeliveryPayload = {
          deliverableText,
          action: 'MASK',
          targetElement: extracted.sourceElement,
          contextId: resultContextId,
          timestamp: this.fixedTimestamp ?? Date.now(),
        };

        let domDelivery: DomDeliveryResult;
        try {
          domDelivery = await this.applier.apply(deliveryPayload);
        } catch (err) {
          return {
            ok: false,
            status: 'ERROR',
            action: 'MASK',
            contextId: resultContextId,
            deliverableText,
            failedStage: 'SEND',
            error: {
              code: 'DOM_DELIVERY_EXCEPTION',
              message: err instanceof Error ? err.message : String(err),
            },
            executionTimeMs,
          };
        }

        if (!domDelivery.success) {
          return {
            ok: false,
            status: 'ERROR',
            action: 'MASK',
            contextId: resultContextId,
            deliverableText,
            failedStage: 'SEND',
            domDelivery,
            error: {
              code: 'DOM_DELIVERY_FAILED',
              message: domDelivery.error || 'DOM output applier failed to apply deliverable text',
            },
            executionTimeMs,
          };
        }

        return {
          ok: true,
          status: 'MASK',
          action: 'MASK',
          contextId: resultContextId,
          deliverableText,
          decision: runtimeResult.decision,
          risk: runtimeResult.risk,
          transformation: runtimeResult.transformation,
          verification: runtimeResult.verification,
          deliveryReceipt: runtimeResult.deliveryReceipt,
          domDelivery,
          executionTimeMs,
        };
      }

      case 'WARN': {
        // Invariant: WARN transmission is held. Zero DOM application occurs.
        return {
          ok: true,
          status: 'WARN',
          action: 'WARN',
          contextId: resultContextId,
          deliverableText: runtimeResult.deliverableText,
          decision: runtimeResult.decision,
          risk: runtimeResult.risk,
          deliveryReceipt: runtimeResult.deliveryReceipt,
          executionTimeMs,
        };
      }

      case 'BLOCK': {
        // Invariant: BLOCK transmission is prohibited. Zero DOM application occurs.
        // deliverableText is strictly omitted.
        return {
          ok: true,
          status: 'BLOCK',
          action: 'BLOCK',
          contextId: resultContextId,
          deliverableText: undefined,
          decision: runtimeResult.decision,
          risk: runtimeResult.risk,
          deliveryReceipt: runtimeResult.deliveryReceipt,
          executionTimeMs,
        };
      }

      default: {
        return {
          ok: false,
          status: 'ERROR',
          action: 'ERROR',
          contextId: resultContextId,
          failedStage: runtimeResult.failedStage,
          error: runtimeResult.error,
          executionTimeMs,
        };
      }
    }
  }
}

/**
 * Factory for creating a DOM Runtime Boundary instance.
 */
export function createDomRuntimeBoundary(options: DomRuntimeBoundaryOptions): DomRuntimeBoundary {
  return new DomRuntimeBoundary(options);
}
