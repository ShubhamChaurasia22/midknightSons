/**
 * @shield/adapters - Claude Platform Adapter (M2.3)
 *
 * Implements composer discovery, transaction interception, and verified text delivery
 * for Claude (claude.ai).
 */

import { BaseAiPlatformAdapter, queryDomElement, type BaseAdapterOptions } from './base-adapter';
import type { AiPlatformId, PlatformComposerInfo } from './contracts';

export class ClaudeAdapter extends BaseAiPlatformAdapter {
  readonly platformId: AiPlatformId = 'claude';
  readonly displayName = 'Claude';
  readonly urlPatterns = ['https://claude.ai/*'] as const;

  constructor(options: BaseAdapterOptions = {}) {
    super({
      ...options,
      defaultPlatformContext: {
        site: 'claude.ai',
        isAiSite: true,
        url: options.defaultPlatformContext?.url ?? 'https://claude.ai/',
        ...options.defaultPlatformContext,
      },
    });
  }

  discoverComposer(root?: unknown): PlatformComposerInfo | null {
    const composerSelectors = [
      'div[contenteditable="true"].ProseMirror',
      'div.ProseMirror[contenteditable="true"]',
      'div[contenteditable="true"][aria-label*="Write your prompt"]',
      'div[contenteditable="true"][data-placeholder]',
      'fieldset div[contenteditable="true"]',
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
      'button[aria-label*="Send Message"]',
      'button[aria-label*="Send message"]',
      'button[aria-label="Send"]',
      'button[aria-label*="Submit"]',
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
