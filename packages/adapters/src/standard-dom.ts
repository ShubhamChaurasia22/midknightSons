/**
 * @shield/adapters - Standard DOM Extractor & Applier (M2.2)
 *
 * Implements standard web DOM element detection, text extraction, and output
 * delivery for textarea and contenteditable targets.
 *
 * Designed to be browser-ready and mock-friendly for headless verification.
 */

import type { PlatformContext } from '@shield/core';
import type {
  DomDeliveryPayload,
  DomDeliveryResult,
  DomExtractionContext,
  DomExtractedInput,
  DomInputExtractor,
  DomOutputApplier,
  DomTargetElement,
} from './contracts';

/**
 * Minimal duck-typed DOM element interface supported by Shield.
 * Compatible with standard HTMLTextAreaElement, HTMLInputElement, and HTMLElement.
 */
export interface SupportedDomElement {
  tagName?: string;
  id?: string;
  value?: string;
  innerText?: string;
  textContent?: string | null;
  isContentEditable?: boolean;
  getAttribute?(name: string): string | null;
  setAttribute?(name: string, value: string): void;
  dispatchEvent?(event: unknown): boolean;
  readOnly?: boolean;
  disabled?: boolean;
}

/**
 * Check if a candidate element is a supported text-entry target:
 * - textarea
 * - input[type="text" | "search" | "email" | "url"]
 * - element with isContentEditable or contenteditable attribute
 */
export function isSupportedDomTarget(element: unknown): element is SupportedDomElement {
  if (!element || typeof element !== 'object') {
    return false;
  }

  const el = element as SupportedDomElement;
  const tag = (el.tagName ?? '').toLowerCase();

  if (tag === 'textarea') {
    return true;
  }

  if (tag === 'input') {
    const inputType = (el.getAttribute?.('type') ?? 'text').toLowerCase();
    return ['text', 'search', 'email', 'url'].includes(inputType);
  }

  if (el.isContentEditable === true) {
    return true;
  }

  if (typeof el.getAttribute === 'function') {
    const contentEditableAttr = el.getAttribute('contenteditable');
    if (
      contentEditableAttr === 'true' ||
      contentEditableAttr === '' ||
      contentEditableAttr === 'plaintext-only'
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Inspect a supported DOM element and return its DomTargetElement descriptor.
 */
export function describeDomTarget(element: SupportedDomElement): DomTargetElement {
  const tag = (element.tagName ?? '').toLowerCase();
  let inputType: 'textarea' | 'contenteditable' | 'input' | 'custom' = 'custom';

  if (tag === 'textarea') {
    inputType = 'textarea';
  } else if (tag === 'input') {
    inputType = 'input';
  } else if (element.isContentEditable || element.getAttribute?.('contenteditable') !== null) {
    inputType = 'contenteditable';
  }

  return {
    elementId: element.id || undefined,
    tagName: tag || undefined,
    inputType,
  };
}

/**
 * Extract text from a supported DOM element safely.
 */
export function extractTextFromElement(element: SupportedDomElement): string {
  const tag = (element.tagName ?? '').toLowerCase();

  if (tag === 'textarea' || tag === 'input') {
    return typeof element.value === 'string' ? element.value : '';
  }

  if (typeof element.innerText === 'string') {
    return element.innerText;
  }

  if (typeof element.textContent === 'string') {
    return element.textContent;
  }

  return '';
}

/**
 * Apply deliverable text back to a supported DOM element safely.
 */
export function applyTextToElement(element: SupportedDomElement, text: string): boolean {
  if (element.readOnly || element.disabled) {
    return false;
  }

  const tag = (element.tagName ?? '').toLowerCase();

  if (tag === 'textarea' || tag === 'input') {
    element.value = text;
  } else {
    // Contenteditable
    if ('innerText' in element) {
      element.innerText = text;
    } else {
      element.textContent = text;
    }
  }

  // Dispatch synthetic input and change events if supported
  if (typeof element.dispatchEvent === 'function') {
    try {
      if (typeof Event !== 'undefined') {
        element.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
        if (tag === 'textarea' || tag === 'input') {
          element.dispatchEvent(new Event('change', { bubbles: true }));
        }
      }
    } catch {
      // Non-critical event dispatch error in headless environments
    }
  }

  return true;
}

export interface StandardExtractorOptions {
  readonly defaultPlatformContext?: PlatformContext;
  readonly targetElement?: SupportedDomElement;
  /**
   * If true (default), extraction fails closed on empty or whitespace-only input.
   */
  readonly failOnEmpty?: boolean;
}

/**
 * Standard DOM Input Extractor.
 * Implements DomInputExtractor for standard textarea and contenteditable elements.
 */
export class StandardDomInputExtractor implements DomInputExtractor {
  private activeElement?: SupportedDomElement;
  private readonly defaultPlatformContext?: PlatformContext;
  private readonly failOnEmpty: boolean;

  constructor(options: StandardExtractorOptions = {}) {
    this.activeElement = options.targetElement;
    this.defaultPlatformContext = options.defaultPlatformContext;
    this.failOnEmpty = options.failOnEmpty ?? true;
  }

  setActiveElement(element: SupportedDomElement | undefined): void {
    this.activeElement = element;
  }

  async extract(context: DomExtractionContext): Promise<DomExtractedInput> {
    const candidate: unknown = context.metadata?.targetElement ?? this.activeElement;

    if (!candidate) {
      throw new Error('No target DOM element available for extraction');
    }

    if (!isSupportedDomTarget(candidate)) {
      const tag = (candidate as { tagName?: string }).tagName ?? 'unknown';
      throw new Error(`Target element <${tag}> is not a supported text-entry element`);
    }

    const text = extractTextFromElement(candidate);

    if (this.failOnEmpty && (!text || text.trim().length === 0)) {
      throw new Error('Target DOM element contains empty or whitespace-only text');
    }

    const sourceElement = describeDomTarget(candidate);

    // Parse platform context from context.url
    let site = this.defaultPlatformContext?.site ?? 'unknown';
    let isAiSite = this.defaultPlatformContext?.isAiSite ?? false;

    if (context.url) {
      try {
        const parsed = new URL(context.url);
        site = parsed.hostname;
        isAiSite = /chatgpt|claude|gemini|openai|anthropic/i.test(site);
      } catch {
        // Keep defaults
      }
    }

    const platformContext: PlatformContext = {
      site,
      isAiSite,
      url: context.url || this.defaultPlatformContext?.url,
      platformId: context.platformId || this.defaultPlatformContext?.platformId,
    };

    return {
      text,
      platformContext,
      sourceElement,
      extractedAt: context.timestamp ?? Date.now(),
      metadata: context.metadata,
    };
  }
}

export interface StandardApplierOptions {
  readonly targetElement?: SupportedDomElement;
}

/**
 * Standard DOM Output Applier.
 * Implements DomOutputApplier for standard textarea and contenteditable elements.
 */
export class StandardDomOutputApplier implements DomOutputApplier {
  private activeElement?: SupportedDomElement;

  constructor(options: StandardApplierOptions = {}) {
    this.activeElement = options.targetElement;
  }

  setActiveElement(element: SupportedDomElement | undefined): void {
    this.activeElement = element;
  }

  async apply(payload: DomDeliveryPayload): Promise<DomDeliveryResult> {
    const candidate = this.activeElement;

    if (!candidate) {
      return {
        success: false,
        appliedText: '',
        targetElement: payload.targetElement,
        deliveredAt: payload.timestamp,
        error: 'No active DOM element available for delivery',
      };
    }

    const success = applyTextToElement(candidate, payload.deliverableText);

    if (!success) {
      return {
        success: false,
        appliedText: '',
        targetElement: payload.targetElement,
        deliveredAt: payload.timestamp,
        error: 'Target element is read-only or rejected delivery write',
      };
    }

    return {
      success: true,
      appliedText: payload.deliverableText,
      targetElement: payload.targetElement,
      deliveredAt: payload.timestamp,
    };
  }
}
