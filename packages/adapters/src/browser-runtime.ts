/**
 * @shield/adapters - Browser Adapter Runtime (M2.2)
 *
 * Implements the browser/content-script runtime orchestrating DOM target detection,
 * transaction interception (Enter / Paste), and safe handoff with DomRuntimeBoundary.
 */

import type { PlatformContext, ShieldRuntime } from '@shield/core';
import { createDomRuntimeBoundary, DomRuntimeBoundary } from './boundary';
import type { DomBoundaryExecutionResult, DomInputExtractor, DomOutputApplier } from './contracts';
import {
  isSupportedDomTarget,
  StandardDomInputExtractor,
  StandardDomOutputApplier,
  type SupportedDomElement,
} from './standard-dom';

/**
 * Minimal interface for event target with listener capabilities.
 */
export interface EventTargetLike {
  addEventListener(type: string, listener: (event: unknown) => void, options?: unknown): void;
  removeEventListener(type: string, listener: (event: unknown) => void, options?: unknown): void;
}

/**
 * Minimal keyboard/paste event representation.
 */
export interface InterceptedEvent {
  key?: string;
  shiftKey?: boolean;
  type?: string;
  target?: unknown;
  preventDefault?(): void;
  stopPropagation?(): void;
}

export interface BrowserAdapterRuntimeOptions {
  readonly boundary?: DomRuntimeBoundary;
  readonly runtime?: ShieldRuntime;
  readonly extractor?: DomInputExtractor;
  readonly applier?: DomOutputApplier;
  readonly defaultPlatformContext?: PlatformContext;
  readonly fixedTimestamp?: number;
  readonly onIntercept?: (result: DomBoundaryExecutionResult, element: SupportedDomElement) => void;
}

/**
 * Real browser-side adapter runtime coordinating DOM element monitoring,
 * transaction boundaries, and Shield policy enforcement.
 */
export class BrowserAdapterRuntime {
  private readonly boundary: DomRuntimeBoundary;
  private readonly extractor: DomInputExtractor;
  private readonly applier: DomOutputApplier;
  private readonly defaultPlatformContext?: PlatformContext;
  private readonly onIntercept?: (
    result: DomBoundaryExecutionResult,
    element: SupportedDomElement,
  ) => void;

  private attachedRoot?: EventTargetLike;
  private keydownListener?: (event: unknown) => void;
  private pasteListener?: (event: unknown) => void;
  private attached = false;

  constructor(options: BrowserAdapterRuntimeOptions = {}) {
    this.defaultPlatformContext = options.defaultPlatformContext;
    this.onIntercept = options.onIntercept;

    this.extractor =
      options.extractor ??
      new StandardDomInputExtractor({
        defaultPlatformContext: options.defaultPlatformContext,
      });

    this.applier = options.applier ?? new StandardDomOutputApplier();

    this.boundary =
      options.boundary ??
      createDomRuntimeBoundary({
        runtime: options.runtime,
        extractor: this.extractor,
        applier: this.applier,
        defaultPlatformContext: options.defaultPlatformContext,
        fixedTimestamp: options.fixedTimestamp,
      });
  }

  get underlyingBoundary(): DomRuntimeBoundary {
    return this.boundary;
  }

  isAttached(): boolean {
    return this.attached;
  }

  /**
   * Attach transaction listeners to the document/root element.
   * Intercepts Enter (submit) and Paste transactions without scanning every keystroke.
   */
  attach(root?: EventTargetLike): boolean {
    if (this.attached) {
      return true;
    }

    // Default to global document if available in browser context
    let targetRoot = root;
    if (!targetRoot && typeof document !== 'undefined') {
      targetRoot = document as unknown as EventTargetLike;
    }

    if (!targetRoot) {
      return false;
    }

    this.attachedRoot = targetRoot;

    // Meaningful Transaction 1: Enter keypress (Submit attempt)
    this.keydownListener = (event: unknown) => {
      const e = event as InterceptedEvent;
      if (e.key === 'Enter' && !e.shiftKey) {
        if (isSupportedDomTarget(e.target)) {
          void this.processElement(e.target, { event: e });
        }
      }
    };

    // Meaningful Transaction 2: Paste event
    this.pasteListener = (event: unknown) => {
      const e = event as InterceptedEvent;
      if (isSupportedDomTarget(e.target)) {
        void this.processElement(e.target, { event: e });
      }
    };

    targetRoot.addEventListener('keydown', this.keydownListener, true);
    targetRoot.addEventListener('paste', this.pasteListener, true);
    this.attached = true;
    return true;
  }

  /**
   * Detach all event listeners and clean up.
   */
  detach(): void {
    if (!this.attached || !this.attachedRoot) {
      return;
    }

    if (this.keydownListener) {
      this.attachedRoot.removeEventListener('keydown', this.keydownListener, true);
      this.keydownListener = undefined;
    }

    if (this.pasteListener) {
      this.attachedRoot.removeEventListener('paste', this.pasteListener, true);
      this.pasteListener = undefined;
    }

    this.attachedRoot = undefined;
    this.attached = false;
  }

  /**
   * Execute prompt evaluation and enforcement for a specific DOM element.
   */
  async processElement(
    element: SupportedDomElement,
    options: {
      url?: string;
      event?: InterceptedEvent;
    } = {},
  ): Promise<DomBoundaryExecutionResult> {
    const event = options.event;

    try {
      // 1. Verify element is supported
      if (!isSupportedDomTarget(element)) {
        if (event?.preventDefault) {
          event.preventDefault();
          event.stopPropagation?.();
        }
        return {
          ok: false,
          status: 'ERROR',
          action: 'ERROR',
          contextId: 'unsupported-target',
          failedStage: 'INPUT',
          error: {
            code: 'UNSUPPORTED_TARGET_ELEMENT',
            message: 'Target element is not a supported textarea or contenteditable element',
          },
          executionTimeMs: 0,
        };
      }

      // 2. Configure active element for standard extractor & applier
      if (this.extractor instanceof StandardDomInputExtractor) {
        this.extractor.setActiveElement(element);
      }
      if (this.applier instanceof StandardDomOutputApplier) {
        this.applier.setActiveElement(element);
      }

      // 3. Determine URL
      let url = options.url || this.defaultPlatformContext?.url;
      if (!url && typeof window !== 'undefined' && window.location?.href) {
        url = window.location.href;
      }
      if (!url) {
        url = 'https://unknown.ai';
      }

      // 4. Execute boundary
      const result = await this.boundary.execute({
        url,
        metadata: { targetElement: element },
      });

      // 5. Enforce Action on Transaction Event
      if (!result.ok || result.status === 'BLOCK' || result.status === 'WARN') {
        // Hold (WARN) or Prohibit (BLOCK) or Fail-Closed (ERROR)
        if (event?.preventDefault) {
          event.preventDefault();
          event.stopPropagation?.();
        }
      }

      // 6. Callback notification
      this.onIntercept?.(result, element);

      return result;
    } catch (err) {
      if (event?.preventDefault) {
        event.preventDefault();
        event.stopPropagation?.();
      }

      const errorResult: DomBoundaryExecutionResult = {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: 'runtime-exception',
        failedStage: 'INPUT',
        error: {
          code: 'ADAPTER_RUNTIME_FAILURE',
          message: err instanceof Error ? err.message : String(err),
        },
        executionTimeMs: 0,
      };

      this.onIntercept?.(errorResult, element);
      return errorResult;
    }
  }
}

/**
 * Factory helper for BrowserAdapterRuntime.
 */
export function createBrowserAdapterRuntime(
  options: BrowserAdapterRuntimeOptions = {},
): BrowserAdapterRuntime {
  return new BrowserAdapterRuntime(options);
}
