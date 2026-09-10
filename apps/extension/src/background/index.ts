/**
 * Shield Chrome Extension — Background Service Worker
 *
 * Manifest V3 Service Worker Entry Point.
 * Phase 0: Minimal lifecycle initialization and internal message routing.
 * No product business logic or detection engines are run here in Phase 0.
 */

import {
  EXTENSION_NAME,
  EXTENSION_VERSION,
  STORAGE_KEYS,
  createMessage,
  type ShieldMessage,
} from '@shield/shared';

// Initialize extension defaults upon installation or update
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log(`[${EXTENSION_NAME}] Service worker installed. Reason: ${details.reason}`);

  try {
    const existing = await chrome.storage.local.get([STORAGE_KEYS.ENABLED]);
    if (existing[STORAGE_KEYS.ENABLED] === undefined) {
      await chrome.storage.local.set({
        [STORAGE_KEYS.ENABLED]: true,
      });
      console.log(`[${EXTENSION_NAME}] Default configuration initialized.`);
    }
  } catch (error) {
    console.error(`[${EXTENSION_NAME}] Failed to initialize storage defaults:`, error);
  }
});

// Internal message dispatch listener
chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
  if (!message || typeof message !== 'object') {
    return false;
  }

  const shieldMsg = message as ShieldMessage;
  console.log(
    `[${EXTENSION_NAME}] Background received message: ${shieldMsg.type} from ${shieldMsg.sender}`,
  );

  switch (shieldMsg.type) {
    case 'PING': {
      const response = createMessage('PONG', 'background', {
        status: 'ok',
        version: EXTENSION_VERSION,
      });
      sendResponse(response);
      break;
    }

    case 'GET_STATUS': {
      chrome.storage.local.get([STORAGE_KEYS.ENABLED]).then((data) => {
        const isEnabled = data[STORAGE_KEYS.ENABLED] ?? true;
        sendResponse(
          createMessage('STATUS_RESPONSE', 'background', {
            version: EXTENSION_VERSION,
            enabled: isEnabled,
            milestone: 'Phase 0 — Repository Bootstrap',
          }),
        );
      });
      return true; // Keep channel open for async response
    }

    default:
      // Unknown message type; ignore or return unhandled
      break;
  }

  return true;
});
