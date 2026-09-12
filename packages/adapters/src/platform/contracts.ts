/**
 * @shield/adapters - AI Platform Adapter Contracts (M2.3)
 *
 * Defines contracts for AI platform-specific DOM integration (ChatGPT, Claude, Gemini)
 * adhering to strict separation between platform DOM quirks and @shield/core.
 */

import type { DomBoundaryExecutionResult } from '../contracts';
import type { PlatformAdapter } from '../index';
import type { SupportedDomElement } from '../standard-dom';
import type { InterceptedEvent } from '../browser-runtime';

export type AiPlatformId = 'chatgpt' | 'claude' | 'gemini';

export type DetectedPlatformId = AiPlatformId | 'unsupported';

export type ComposerInputType = 'textarea' | 'contenteditable' | 'input' | 'custom';

/**
 * Structural information about the discovered platform composer.
 */
export interface PlatformComposerInfo {
  readonly composerElement: SupportedDomElement;
  readonly inputType: ComposerInputType;
  readonly sendButtonElement?: SupportedDomElement;
  readonly containerElement?: SupportedDomElement;
  readonly selectorUsed?: string;
}

/**
 * Common contract for AI platform-specific adapters.
 */
export interface AiPlatformAdapter extends PlatformAdapter {
  readonly platformId: AiPlatformId;

  /**
   * Discover and validate the active composer element on the page.
   * Returns null if missing or in an unsupported state.
   */
  discoverComposer(root?: unknown): PlatformComposerInfo | null;

  /**
   * Safely extract the current user prompt text from the composer.
   */
  extractPrompt(composer: PlatformComposerInfo): string | null;

  /**
   * Safely apply verified transformed text back into the composer DOM.
   */
  applyVerifiedText(composer: PlatformComposerInfo, text: string): boolean;

  /**
   * Intercept and evaluate a meaningful platform transaction (Enter / Send button / Paste).
   */
  handleTransaction(
    event: InterceptedEvent,
    composer?: PlatformComposerInfo,
  ): Promise<DomBoundaryExecutionResult>;

  /**
   * Check if the current DOM state is supported.
   */
  isSupportedState(root?: unknown): boolean;
}
