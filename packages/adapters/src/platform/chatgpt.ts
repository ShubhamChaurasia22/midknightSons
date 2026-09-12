/**
 * @shield/adapters - ChatGPT Platform Adapter (M2.3)
 *
 * Implements composer discovery, transaction interception, and verified text delivery
 * for ChatGPT (chatgpt.com and chat.openai.com).
 */

import { BaseAiPlatformAdapter, queryDomElement, type BaseAdapterOptions } from './base-adapter';
import type { AiPlatformId, PlatformComposerInfo } from './contracts';

export class ChatGPTAdapter extends BaseAiPlatformAdapter {
  readonly platformId: AiPlatformId = 'chatgpt';
  readonly displayName = 'ChatGPT';
  readonly urlPatterns = ['https://chatgpt.com/*', 'https://chat.openai.com/*'] as const;

  constructor(options: BaseAdapterOptions = {}) {
    super({
      ...options,
      defaultPlatformContext: {
        site: 'chatgpt.com',
        isAiSite: true,
        url: options.defaultPlatformContext?.url ?? 'https://chatgpt.com/',
        ...options.defaultPlatformContext,
      },
    });
  }

  discoverComposer(root?: unknown): PlatformComposerInfo | null {
    const composerSelectors = [
      '#prompt-textarea',
      'div#prompt-textarea[contenteditable="true"]',
      'textarea[data-id="root"]',
      'div[contenteditable="true"][tabindex="0"]',
      'textarea#prompt-textarea',
      'textarea#mobile-composer-prompt',
      'textarea.wm-composer-textarea',
      'textarea[placeholder*="ChatGPT"]',
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
      'button[data-testid="send-button"]',
      'button[data-testid="fruitjuice-send-button"]',
      'button[aria-label*="Send"]',
      'button[aria-label="Send prompt"]',
      'button.wm-composer-submitButton',
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
