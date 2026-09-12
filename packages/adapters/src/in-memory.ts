/**
 * In-Memory Test Doubles for DOM Extractor and Applier (M2.1)
 *
 * Allows testing the DOM adapter boundary deterministically without
 * needing browser APIs, document, or window.
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

export interface InMemoryExtractorOptions {
  readonly defaultText?: string;
  readonly defaultPlatformContext?: PlatformContext;
  readonly defaultSourceElement?: DomTargetElement;
  readonly shouldThrow?: boolean;
  readonly errorMessage?: string;
}

/**
 * Deterministic in-memory DOM input extractor.
 */
export class InMemoryDomInputExtractor implements DomInputExtractor {
  private text: string;
  private platformContext: PlatformContext;
  private sourceElement?: DomTargetElement;
  private shouldThrow: boolean;
  private errorMessage: string;
  private extractionCount = 0;

  constructor(options: InMemoryExtractorOptions = {}) {
    this.text = options.defaultText ?? '';
    this.platformContext = options.defaultPlatformContext ?? {
      site: 'chatgpt.com',
      isAiSite: true,
      url: 'https://chatgpt.com',
    };
    this.sourceElement = options.defaultSourceElement ?? {
      elementId: 'prompt-textarea',
      tagName: 'textarea',
      inputType: 'textarea',
    };
    this.shouldThrow = options.shouldThrow ?? false;
    this.errorMessage = options.errorMessage ?? 'Simulated DOM extraction failure';
  }

  setText(newText: string): void {
    this.text = newText;
  }

  setPlatformContext(ctx: PlatformContext): void {
    this.platformContext = ctx;
  }

  setShouldThrow(shouldThrow: boolean, errorMessage?: string): void {
    this.shouldThrow = shouldThrow;
    if (errorMessage) {
      this.errorMessage = errorMessage;
    }
  }

  get extractionsCount(): number {
    return this.extractionCount;
  }

  async extract(context: DomExtractionContext): Promise<DomExtractedInput> {
    this.extractionCount++;

    if (this.shouldThrow) {
      throw new Error(this.errorMessage);
    }

    // Infer site from URL if provided and not explicitly specified
    let site = this.platformContext.site;
    let isAiSite = this.platformContext.isAiSite;
    try {
      if (context.url) {
        const parsed = new URL(context.url);
        site = parsed.hostname;
        isAiSite = /chatgpt|claude|gemini|openai|anthropic/i.test(site);
      }
    } catch {
      // Keep default if URL parsing fails
    }

    const platformContext: PlatformContext = {
      site,
      isAiSite,
      url: context.url || this.platformContext.url,
      platformId: context.platformId || this.platformContext.platformId,
    };

    return {
      text: this.text,
      platformContext,
      sourceElement: context.targetElement ?? this.sourceElement,
      extractedAt: context.timestamp ?? Date.now(),
      metadata: context.metadata,
    };
  }
}

export interface InMemoryApplierOptions {
  readonly shouldThrow?: boolean;
  readonly shouldFail?: boolean;
  readonly errorMessage?: string;
}

/**
 * Deterministic in-memory DOM output applier.
 */
export class InMemoryDomOutputApplier implements DomOutputApplier {
  private readonly appliedPayloads: DomDeliveryPayload[] = [];
  private shouldThrow: boolean;
  private shouldFail: boolean;
  private errorMessage: string;

  constructor(options: InMemoryApplierOptions = {}) {
    this.shouldThrow = options.shouldThrow ?? false;
    this.shouldFail = options.shouldFail ?? false;
    this.errorMessage = options.errorMessage ?? 'Simulated DOM delivery error';
  }

  setShouldThrow(shouldThrow: boolean, errorMessage?: string): void {
    this.shouldThrow = shouldThrow;
    if (errorMessage) {
      this.errorMessage = errorMessage;
    }
  }

  setShouldFail(shouldFail: boolean, errorMessage?: string): void {
    this.shouldFail = shouldFail;
    if (errorMessage) {
      this.errorMessage = errorMessage;
    }
  }

  get deliveries(): readonly DomDeliveryPayload[] {
    return this.appliedPayloads;
  }

  clear(): void {
    this.appliedPayloads.length = 0;
  }

  async apply(payload: DomDeliveryPayload): Promise<DomDeliveryResult> {
    if (this.shouldThrow) {
      throw new Error(this.errorMessage);
    }

    if (this.shouldFail) {
      return {
        success: false,
        appliedText: '',
        targetElement: payload.targetElement,
        deliveredAt: payload.timestamp,
        error: this.errorMessage,
      };
    }

    this.appliedPayloads.push({ ...payload });

    return {
      success: true,
      appliedText: payload.deliverableText,
      targetElement: payload.targetElement,
      deliveredAt: payload.timestamp,
    };
  }
}
