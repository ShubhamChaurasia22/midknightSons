/**
 * Shield Chrome Extension — Content Script Entry Point
 *
 * Phase 0: Proves script loading and internal message communication.
 * Ready for future platform adapters without hard-coding any ChatGPT selectors.
 */

import { EXTENSION_NAME, createMessage, type ShieldMessage } from '@shield/shared';
import { InMemoryAdapterRegistry } from '@shield/adapters';

console.log(`[${EXTENSION_NAME}] Content script loaded on ${window.location.hostname}`);

// Setup adapter registry placeholder for Phase 0
const adapterRegistry = new InMemoryAdapterRegistry();

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

// Check if any registered adapter matches the current page (none registered in Phase 0)
const matchedAdapter = adapterRegistry.findAdapterForUrl(window.location.href);
if (matchedAdapter) {
  console.log(`[${EXTENSION_NAME}] Found adapter for current page: ${matchedAdapter.displayName}`);
} else {
  // Expected in Phase 0: No platform-specific adapters registered yet
  console.log(`[${EXTENSION_NAME}] Phase 0 initialized. No platform adapters active.`);
}

// Run verification ping
verifyExtensionCommunication();
