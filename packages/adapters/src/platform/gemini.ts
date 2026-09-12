/**
 * @shield/adapters - Gemini Platform Adapter (M2.3)
 *
 * Implements composer discovery, transaction interception, and verified text delivery
 * for Gemini (gemini.google.com).
 */

import { BaseAiPlatformAdapter, queryDomElement, type BaseAdapterOptions } from './base-adapter';
import type { AiPlatformId, PlatformComposerInfo } from './contracts';

export class GeminiAdapter extends BaseAiPlatformAdapter {
  readonly platformId: AiPlatformId = 'gemini';
  readonly displayName = 'Gemini';
  readonly urlPatterns = ['https://gemini.google.com/*'] as const;

  constructor(options: BaseAdapterOptions = {}) {
    super({
      ...options,
      defaultPlatformContext: {
        site: 'gemini.google.com',
        isAiSite: true,
        url: options.defaultPlatformContext?.url ?? 'https://gemini.google.com/',
        ...options.defaultPlatformContext,
      },
    });
  }

  discoverComposer(root?: unknown): PlatformComposerInfo | null {
    const composerSelectors = [
      'rich-textarea div[contenteditable="true"]',
      'div.ql-editor[contenteditable="true"]',
      'div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"][aria-label*="prompt"]',
      'textarea[aria-label*="prompt"]',
      'div[contenteditable="true"]',
    ];

    let composerElement = null;
    let selectorUsed = '';

    for (const selector of composerSelectors) {
      const el = queryDomElement(root, selector);
      if (el) {
        composerElement = el;
        selectorUsed = selector;
        break;
      }
    }

    if (!composerElement) {
      return null;
    }

    const tag = (composerElement.tagName ?? '').toLowerCase();
    const isContentEditable =
      composerElement.isContentEditable ||
      composerElement.getAttribute?.('contenteditable') === 'true' ||
      composerElement.getAttribute?.('contenteditable') === '';

    const inputType =
      tag === 'textarea' ? 'textarea' : isContentEditable ? 'contenteditable' : 'custom';

    const sendButtonSelectors = [
      'button.send-button',
      'button[aria-label*="Send message"]',
      'button[aria-label*="Send prompt"]',
      'button[aria-label*="Send"]',
    ];

    let sendButtonElement = undefined;
    for (const selector of sendButtonSelectors) {
      const btn = queryDomElement(root, selector);
      if (btn) {
        sendButtonElement = btn;
        break;
      }
    }

    return {
      composerElement,
      inputType,
      sendButtonElement,
      selectorUsed,
    };
  }
}
