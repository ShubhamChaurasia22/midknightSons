/**
 * @shield/adapters - Base AI Platform Adapter (M2.3)
 *
 * Implements common platform adapter lifecycle, transaction boundary interception,
 * safe text extraction, verified DOM application, recursion protection, and fail-closed handling.
 */

import type { PlatformContext, ShieldRuntime } from '@shield/core';
import type { DomBoundaryExecutionResult } from '../contracts';
import type { AdapterCapabilities } from '../index';
import {
  type SupportedDomElement,
  extractTextFromElement,
  applyTextToElement,
} from '../standard-dom';
import {
  type EventTargetLike,
  type InterceptedEvent,
  BrowserAdapterRuntime,
  createBrowserAdapterRuntime,
} from '../browser-runtime';
import type { AiPlatformAdapter, AiPlatformId, PlatformComposerInfo } from './contracts';
import { detectPlatform } from './detector';

export interface BaseAdapterOptions {
  readonly runtime?: ShieldRuntime;
  readonly browserRuntime?: BrowserAdapterRuntime;
  readonly defaultPlatformContext?: PlatformContext;
  readonly fixedTimestamp?: number;
  readonly onIntercept?: (result: DomBoundaryExecutionResult, element: SupportedDomElement) => void;
}

/**
 * Safely query a DOM selector from a provided root or global document.
 */
export function queryDomElement(root: unknown, selector: string): SupportedDomElement | null {
  if (!root) {
    if (typeof document !== 'undefined' && typeof document.querySelector === 'function') {
      try {
        const el = document.querySelector(selector);
        if (el && typeof el === 'object') {
          return el as SupportedDomElement;
        }
      } catch {
        return null;
      }
    }
    return null;
  }

  const elObj = root as SupportedDomElement & {
    querySelector?(sel: string): unknown;
    matches?(sel: string): boolean;
  };

  // 1. Query descendants FIRST if querySelector is available (standard for document / container / root)
  if (typeof elObj.querySelector === 'function') {
    try {
      const el = elObj.querySelector(selector);
      if (el && typeof el === 'object') {
        return el as SupportedDomElement;
      }
    } catch {
      // ignore
    }
  }

  // 2. Check if element itself matches selector if matches() is available
  if (typeof elObj.matches === 'function') {
    try {
      if (elObj.matches(selector)) {
        return elObj;
      }
    } catch {
      // ignore
    }
  }

  return null;
}

/**
 * Base implementation of an AI Platform Adapter.
 */
export abstract class BaseAiPlatformAdapter implements AiPlatformAdapter {
  abstract readonly platformId: AiPlatformId;
  abstract readonly displayName: string;
  abstract readonly urlPatterns: readonly string[];

  readonly capabilities: AdapterCapabilities = {
    supportsStreaming: true,
    supportsFileInput: false,
    supportsPromptInterception: true,
  };

  protected readonly browserRuntime: BrowserAdapterRuntime;
  protected readonly defaultPlatformContext?: PlatformContext;
  protected readonly onInterceptCallback?: (
    result: DomBoundaryExecutionResult,
    element: SupportedDomElement,
  ) => void;

  protected attachedRoot?: EventTargetLike;
  protected keydownListener?: (event: unknown) => void;
  protected clickListener?: (event: unknown) => void;
  protected pasteListener?: (event: unknown) => void;
  protected attached = false;

  // Transaction safety & recursion prevention flags
  protected isMutating = false;
  protected isProcessing = false;
  protected lastVerifiedText: string | null = null;

  constructor(options: BaseAdapterOptions = {}) {
    this.defaultPlatformContext = options.defaultPlatformContext;
    this.onInterceptCallback = options.onIntercept;

    this.browserRuntime =
      options.browserRuntime ??
      createBrowserAdapterRuntime({
        runtime: options.runtime,
        defaultPlatformContext: options.defaultPlatformContext,
        fixedTimestamp: options.fixedTimestamp,
        onIntercept: (result, element) => {
          this.onInterceptCallback?.(result, element);
        },
      });
  }

  get underlyingBrowserRuntime(): BrowserAdapterRuntime {
    return this.browserRuntime;
  }

  matches(url: string): boolean {
    return detectPlatform(url) === this.platformId;
  }

  isAttached(): boolean {
    return this.attached;
  }

  abstract discoverComposer(root?: unknown): PlatformComposerInfo | null;

  isSupportedState(root?: unknown): boolean {
    return this.discoverComposer(root) !== null;
  }

  extractPrompt(composer: PlatformComposerInfo): string | null {
    if (!composer?.composerElement) {
      return null;
    }
    return extractTextFromElement(composer.composerElement);
  }

  applyVerifiedText(composer: PlatformComposerInfo, text: string): boolean {
    if (!composer?.composerElement) {
      return false;
    }

    // Set mutation flag to prevent Shield from intercepting its own synthetic events
    this.isMutating = true;
    try {
      const applied = applyTextToElement(composer.composerElement, text);
      if (applied) {
        this.lastVerifiedText = text;
      }
      return applied;
    } finally {
      this.isMutating = false;
    }
  }

  async attach(root?: EventTargetLike): Promise<boolean> {
    if (this.attached) {
      return true;
    }

    let targetRoot = root;
    if (!targetRoot && typeof document !== 'undefined') {
      targetRoot = document as unknown as EventTargetLike;
    }

    if (!targetRoot) {
      return false;
    }

    this.attachedRoot = targetRoot;

    // 1. Intercept Enter keydown on composer
    this.keydownListener = (event: unknown) => {
      const e = event as InterceptedEvent;
      // Allow multiline entry: ignore Shift+Enter
      if (e.key === 'Enter' && !e.shiftKey) {
        const composer = this.discoverComposer(targetRoot);
        // Intercept if target matches composer or composer is active
        if (composer) {
          void this.handleTransaction(e, composer);
        }
      }
    };

    // 2. Intercept Click on send button
    this.clickListener = (event: unknown) => {
      const e = event as InterceptedEvent;
      const composer = this.discoverComposer(targetRoot);
      if (composer?.sendButtonElement) {
        // If the click is on the send button
        if (
          e.target === composer.sendButtonElement ||
          (typeof (e.target as { closest?: unknown })?.closest === 'function' &&
            (e.target as { closest(sel: string): unknown }).closest(
              composer.sendButtonElement.tagName?.toLowerCase() ?? 'button',
            ) === composer.sendButtonElement)
        ) {
          void this.handleTransaction(e, composer);
        }
      }
    };

    // 3. Intercept Paste into composer
    this.pasteListener = (event: unknown) => {
      const e = event as InterceptedEvent;
      const composer = this.discoverComposer(targetRoot);
      if (composer && e.target === composer.composerElement) {
        void this.handleTransaction(e, composer);
      }
    };

    targetRoot.addEventListener('keydown', this.keydownListener, true);
    targetRoot.addEventListener('click', this.clickListener, true);
    targetRoot.addEventListener('paste', this.pasteListener, true);

    this.attached = true;
    return true;
  }

  async detach(): Promise<void> {
    if (!this.attached || !this.attachedRoot) {
      return;
    }

    if (this.keydownListener) {
      this.attachedRoot.removeEventListener('keydown', this.keydownListener, true);
      this.keydownListener = undefined;
    }

    if (this.clickListener) {
      this.attachedRoot.removeEventListener('click', this.clickListener, true);
      this.clickListener = undefined;
    }

    if (this.pasteListener) {
      this.attachedRoot.removeEventListener('paste', this.pasteListener, true);
      this.pasteListener = undefined;
    }

    this.attachedRoot = undefined;
    this.attached = false;
    this.isProcessing = false;
    this.isMutating = false;
    this.lastVerifiedText = null;
  }

  async handleTransaction(
    event: InterceptedEvent,
    composer?: PlatformComposerInfo,
  ): Promise<DomBoundaryExecutionResult> {
    // 1. Recursion guard: do not re-intercept Shield's own DOM mutations
    if (this.isMutating) {
      return {
        ok: true,
        status: 'ALLOW',
        action: 'ALLOW',
        contextId: 'shield-synthetic-mutation',
        executionTimeMs: 0,
      };
    }

    // 2. Duplicate interception guard: do not run parallel evaluations
    if (this.isProcessing) {
      event.preventDefault?.();
      event.stopPropagation?.();
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: 'duplicate-interception',
        failedStage: 'INPUT',
        error: {
          code: 'CONCURRENT_TRANSACTION_BLOCKED',
          message: 'Concurrent or duplicate transaction intercepted',
        },
        executionTimeMs: 0,
      };
    }

    // 3. Resolve active composer
    const activeComposer = composer ?? this.discoverComposer(this.attachedRoot);
    if (!activeComposer || !activeComposer.composerElement) {
      event.preventDefault?.();
      event.stopPropagation?.();
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: 'composer-not-found',
        failedStage: 'INPUT',
        error: {
          code: 'COMPOSER_NOT_FOUND',
          message: `Supported composer for ${this.displayName} not found or ambiguous`,
        },
        executionTimeMs: 0,
      };
    }

    const currentText = this.extractPrompt(activeComposer);

    // 4. Check if text is already verified and allowed for transmission
    if (this.lastVerifiedText !== null && currentText === this.lastVerifiedText) {
      // Clear verified text cache after allowing transmission
      this.lastVerifiedText = null;
      return {
        ok: true,
        status: 'ALLOW',
        action: 'ALLOW',
        contextId: 'already-verified-transaction',
        deliverableText: currentText,
        executionTimeMs: 0,
      };
    }

    // 5. Empty prompt fail-closed
    if (!currentText || currentText.trim().length === 0) {
      event.preventDefault?.();
      event.stopPropagation?.();
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: 'empty-prompt',
        failedStage: 'INPUT',
        error: {
          code: 'EMPTY_PROMPT',
          message: 'Composer contains empty prompt text',
        },
        executionTimeMs: 0,
      };
    }

    // 6. Execute through BrowserAdapterRuntime
    this.isProcessing = true;
    try {
      const result = await this.browserRuntime.processElement(activeComposer.composerElement, {
        event,
        url: this.defaultPlatformContext?.url,
      });

      // Handle decisions
      if (result.ok && result.status === 'ALLOW') {
        // Normal send continues cleanly
        this.lastVerifiedText = currentText;
      } else if (result.ok && result.status === 'MASK' && result.deliverableText) {
        // Hold original submission, apply verified transformed text
        event.preventDefault?.();
        event.stopPropagation?.();
        this.applyVerifiedText(activeComposer, result.deliverableText);
      } else {
        // WARN (hold), BLOCK (prevent), or ERROR (fail-closed)
        event.preventDefault?.();
        event.stopPropagation?.();
      }

      return result;
    } catch (err) {
      event.preventDefault?.();
      event.stopPropagation?.();
      return {
        ok: false,
        status: 'ERROR',
        action: 'ERROR',
        contextId: 'platform-adapter-exception',
        failedStage: 'INPUT',
        error: {
          code: 'PLATFORM_ADAPTER_ERROR',
          message: err instanceof Error ? err.message : String(err),
        },
        executionTimeMs: 0,
      };
    } finally {
      this.isProcessing = false;
    }
  }
}
