/**
 * Shield Chrome Extension — Content Script Entry Point
 *
 * Phase 0: Proves script loading and internal message communication.
 * Ready for future platform adapters without hard-coding any ChatGPT selectors.
 */

import { EXTENSION_NAME, createMessage, type ShieldMessage } from '@shield/shared';
import {
  InMemoryAdapterRegistry,
  createBrowserAdapterRuntime,
  detectPlatform,
  ChatGPTAdapter,
  ClaudeAdapter,
  GeminiAdapter,
} from '@shield/adapters';

console.log(`[${EXTENSION_NAME}] Content script loaded on ${window.location.hostname}`);

// Setup adapter registry and register supported AI platform adapters (M2.3)
const adapterRegistry = new InMemoryAdapterRegistry();
const chatGptAdapter = new ChatGPTAdapter();
const claudeAdapter = new ClaudeAdapter();
const geminiAdapter = new GeminiAdapter();

adapterRegistry.register(chatGptAdapter);
adapterRegistry.register(claudeAdapter);
adapterRegistry.register(geminiAdapter);

// Initialize Browser Adapter Runtime (M2.2)
const browserRuntime = createBrowserAdapterRuntime({
  defaultPlatformContext: {
    site: window.location.hostname,
    url: window.location.href,
    isAiSite: /chatgpt|claude|gemini|openai|anthropic/i.test(window.location.hostname),
  },
  onIntercept: (result) => {
    // Audit log high-level action only; never log raw prompt content or secrets
    console.log(
      `[${EXTENSION_NAME}] Evaluation complete: status=${result.status}, action=${result.action}`,
    );
  },
});

// Check if any registered platform adapter matches the current page
const platformId = detectPlatform(window.location.href);
const matchedAdapter = adapterRegistry.findAdapterForUrl(window.location.href);

if (matchedAdapter) {
  console.log(`[${EXTENSION_NAME}] Found adapter for current page: ${matchedAdapter.displayName}`);
  if (typeof document !== 'undefined') {
    void matchedAdapter.attach(document);
    console.log(`[${EXTENSION_NAME}] Attached ${matchedAdapter.displayName} platform adapter.`);
  }
} else {
  // Generic DOM adapter active or unsupported platform fails closed
  console.log(
    `[${EXTENSION_NAME}] No specific platform adapter for ${platformId}; attaching standard DOM runtime.`,
  );
  if (typeof document !== 'undefined') {
    browserRuntime.attach(document);
    console.log(`[${EXTENSION_NAME}] Standard DOM adapter runtime attached.`);
  }
}

// Test internal extension communication with service worker
async function verifyExtensionCommunication(): Promise<void> {
  try {
    const pingMessage = createMessage('PING', 'content', {
      url: window.location.href,
      origin: window.location.origin,
    });

    chrome.runtime.sendMessage(pingMessage, (response: ShieldMessage | undefined) => {
      if (chrome.runtime.lastError) {
        console.warn(
          `[${EXTENSION_NAME}] Background communication check deferred:`,
          chrome.runtime.lastError.message,
        );
        return;
      }

      if (response && response.type === 'PONG') {
        console.log(
          `[${EXTENSION_NAME}] Internal communication confirmed with background service worker.`,
        );
      }
    });
  } catch (err) {
    console.warn(`[${EXTENSION_NAME}] Content script runtime message error:`, err);
  }
}

// Run verification ping
verifyExtensionCommunication();
