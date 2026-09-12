/**
 * Test Suite — Milestone M2.3: AI Platform Adapter Integration
 *
 * Validates platform adapters for ChatGPT, Claude, and Gemini:
 * - Platform detection & fail-closed on unknown origins
 * - Composer discovery (textarea, contenteditable, ProseMirror, rich-textarea)
 * - Missing/ambiguous composer fail-closed
 * - ALLOW / MASK / WARN / BLOCK transaction enforcement
 * - Verification failure preventing send & DOM mutation
 * - Adapter runtime failure fail-closed
 * - No raw sensitive data in logs/results
 * - Duplicate interception & re-entrancy protection
 * - Listener attach/detach lifecycle
 * - Multiline drafting (Shift+Enter) preservation
 * - Prevention of recursive self-interception on Shield DOM mutations
 * - Architecture boundary (@shield/core free of DOM/platform imports)
 */

import { describe, it, expect, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  detectPlatform,
  isSupportedAiPlatform,
  ChatGPTAdapter,
  ClaudeAdapter,
  GeminiAdapter,
  type SupportedDomElement,
  type EventTargetLike,
  type InterceptedEvent,
  type DomBoundaryExecutionResult,
} from '../packages/adapters/src';
import {
  createShieldRuntime,
  type ShieldRuntime,
  type Verifier,
  type PolicyEvaluator,
  type DeterministicDeliveryEngine,
  type PipelineOrchestrator,
} from '../packages/core/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

// ============================================================================
// Headless DOM Mocks
// ============================================================================

function createMockElement(attrs: {
  tagName: string;
  id?: string;
  value?: string;
  innerText?: string;
  textContent?: string;
  isContentEditable?: boolean;
  attributes?: Record<string, string>;
}): SupportedDomElement {
  const attributes = attrs.attributes ?? {};
  if (attrs.id) attributes['id'] = attrs.id;
  return {
    tagName: attrs.tagName,
    id: attrs.id,
    value: attrs.value,
    innerText: attrs.innerText,
    textContent: attrs.textContent ?? attrs.innerText,
    isContentEditable: attrs.isContentEditable ?? false,
    getAttribute: (name: string) => attributes[name] ?? null,
    setAttribute: (name: string, val: string) => {
      attributes[name] = val;
    },
    dispatchEvent: vi.fn(),
  };
}

class MockDomRoot implements EventTargetLike {
  public elements: Map<string, SupportedDomElement> = new Map();
  public listeners: Record<string, ((event: unknown) => void)[]> = {};

  setElement(selector: string, element: SupportedDomElement): void {
    this.elements.set(selector, element);
  }

  removeElement(selector: string): void {
    this.elements.delete(selector);
  }

  querySelector(selector: string): SupportedDomElement | null {
    if (this.elements.has(selector)) {
      return this.elements.get(selector)!;
    }
    for (const [key, val] of this.elements.entries()) {
      if (key.includes(selector) || selector.includes(key)) {
        return val;
      }
    }
    return null;
  }

  addEventListener(type: string, listener: (event: unknown) => void): void {
    if (!this.listeners[type]) {
      this.listeners[type] = [];
    }
    this.listeners[type].push(listener);
  }

  removeEventListener(type: string, listener: (event: unknown) => void): void {
    if (!this.listeners[type]) return;
    this.listeners[type] = this.listeners[type].filter((l) => l !== listener);
  }

  dispatch(type: string, event: unknown): void {
    const list = this.listeners[type] || [];
    for (const l of list) {
      l(event);
    }
  }
}

function createMockEvent(options: {
  key?: string;
  shiftKey?: boolean;
  type?: string;
  target: SupportedDomElement;
}): InterceptedEvent & { prevented: boolean; stopped: boolean } {
  let prevented = false;
  let stopped = false;
  return {
    key: options.key,
    shiftKey: options.shiftKey,
    type: options.type,
    target: options.target,
    preventDefault: () => {
      prevented = true;
    },
    stopPropagation: () => {
      stopped = true;
    },
    get prevented() {
      return prevented;
    },
    get stopped() {
      return stopped;
    },
  };
}

// ============================================================================
// Test Suite
// ============================================================================

describe('Milestone M2.3 — AI Platform Adapter Integration', () => {
  // ==========================================================================
  // 1. Platform Detection
  // ==========================================================================
  describe('Platform Detection', () => {
    it('1. Detects ChatGPT hosts correctly', () => {
      expect(detectPlatform('https://chatgpt.com/c/12345')).toBe('chatgpt');
      expect(detectPlatform('https://chat.openai.com/')).toBe('chatgpt');
      expect(detectPlatform('chatgpt.com')).toBe('chatgpt');
      expect(detectPlatform('https://subdomain.chatgpt.com/')).toBe('chatgpt');
      expect(isSupportedAiPlatform('https://chatgpt.com')).toBe(true);
    });

    it('2. Detects Claude hosts correctly', () => {
      expect(detectPlatform('https://claude.ai/chat/new')).toBe('claude');
      expect(detectPlatform('claude.ai')).toBe('claude');
      expect(isSupportedAiPlatform('https://claude.ai')).toBe(true);
    });

    it('3. Detects Gemini hosts correctly', () => {
      expect(detectPlatform('https://gemini.google.com/app')).toBe('gemini');
      expect(detectPlatform('gemini.google.com')).toBe('gemini');
      expect(isSupportedAiPlatform('https://gemini.google.com')).toBe(true);
    });

    it('4. Unsupported hosts fail-closed', () => {
      expect(detectPlatform('https://example.com/')).toBe('unsupported');
      expect(detectPlatform('https://google.com/search')).toBe('unsupported');
      expect(detectPlatform('https://attacker.evil.com/')).toBe('unsupported');
      expect(detectPlatform('')).toBe('unsupported');
      expect(isSupportedAiPlatform('https://example.com')).toBe(false);
    });
  });

  // ==========================================================================
  // Platform Adapter Tests: ChatGPT, Claude, Gemini
  // ==========================================================================
  const platforms = [
    {
      name: 'ChatGPT',
      createAdapter: (opts = {}) => new ChatGPTAdapter(opts),
      createComposer: (text: string) =>
        createMockElement({
          tagName: 'TEXTAREA',
          id: 'prompt-textarea',
          value: text,
        }),
      selector: '#prompt-textarea',
      sendButtonSelector: 'button[data-testid="send-button"]',
      createSendButton: () =>
        createMockElement({
          tagName: 'BUTTON',
          attributes: { 'data-testid': 'send-button' },
        }),
    },
    {
      name: 'Claude',
      createAdapter: (opts = {}) => new ClaudeAdapter(opts),
      createComposer: (text: string) =>
        createMockElement({
          tagName: 'DIV',
          innerText: text,
          textContent: text,
          isContentEditable: true,
          attributes: { class: 'ProseMirror', contenteditable: 'true' },
        }),
      selector: 'div[contenteditable="true"].ProseMirror',
      sendButtonSelector: 'button[aria-label*="Send Message"]',
      createSendButton: () =>
        createMockElement({
          tagName: 'BUTTON',
          attributes: { 'aria-label': 'Send Message' },
        }),
    },
    {
      name: 'Gemini',
      createAdapter: (opts = {}) => new GeminiAdapter(opts),
      createComposer: (text: string) =>
        createMockElement({
          tagName: 'DIV',
          innerText: text,
          textContent: text,
          isContentEditable: true,
          attributes: { contenteditable: 'true', role: 'textbox' },
        }),
      selector: 'rich-textarea div[contenteditable="true"]',
      sendButtonSelector: 'button.send-button',
      createSendButton: () =>
        createMockElement({
          tagName: 'BUTTON',
          attributes: { class: 'send-button' },
        }),
    },
  ];

  for (const p of platforms) {
    describe(`${p.name} Adapter`, () => {
      it(`5. Composer discovered: detects composer and send button on ${p.name}`, () => {
        const root = new MockDomRoot();
        const composer = p.createComposer('Initial text');
        const sendBtn = p.createSendButton();

        root.setElement(p.selector, composer);
        root.setElement(p.sendButtonSelector, sendBtn);

        const adapter = p.createAdapter();
        const info = adapter.discoverComposer(root);

        expect(info).not.toBeNull();
        expect(info?.composerElement).toBe(composer);
        expect(info?.sendButtonElement).toBe(sendBtn);
        expect(adapter.isSupportedState(root)).toBe(true);
      });

      it(`6. Missing/ambiguous composer fails closed on ${p.name}`, async () => {
        const root = new MockDomRoot(); // empty root without composer
        const adapter = p.createAdapter();

        expect(adapter.discoverComposer(root)).toBeNull();
        expect(adapter.isSupportedState(root)).toBe(false);

        const fakeTarget = createMockElement({ tagName: 'DIV', innerText: 'Some text' });
        const event = createMockEvent({ key: 'Enter', target: fakeTarget });

        const result = await adapter.handleTransaction(event);

        expect(result.ok).toBe(false);
        expect(result.status).toBe('ERROR');
        expect(result.failedStage).toBe('INPUT');
        expect(result.error?.code).toBe('COMPOSER_NOT_FOUND');
        expect(event.prevented).toBe(true);
      });

      it(`7. ALLOW send: clean text allowed through without transaction cancellation on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const composer = p.createComposer('Explain recursion in computer science');
        root.setElement(p.selector, composer);

        const adapter = p.createAdapter();
        await adapter.attach(root);
        const event = createMockEvent({ key: 'Enter', target: composer });

        const result = await adapter.handleTransaction(event);

        expect(result.ok).toBe(true);
        expect(result.status).toBe('ALLOW');
        expect(result.action).toBe('ALLOW');
        expect(event.prevented).toBe(false); // Normal send allowed
      });

      it(`8. MASK send only after verification on ${p.name}`, async () => {
        const rawApiKey = 'sk-proj-12345678901234567890123456789012';
        const root = new MockDomRoot();
        const composer = p.createComposer(`My OpenAI Key is: ${rawApiKey}`);
        root.setElement(p.selector, composer);

        const maskPolicyEvaluator: PolicyEvaluator = {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask secret credential',
            triggeredRules: ['rule-mask-1'],
            allowOverride: false,
          })),
        };

        const shieldRuntime = createShieldRuntime({
          detectorRegistry: createDefaultDetectorRegistry(),
          policyEvaluator: maskPolicyEvaluator,
        });

        const adapter = p.createAdapter({ runtime: shieldRuntime });
        await adapter.attach(root);
        const event = createMockEvent({ key: 'Enter', target: composer });

        const result = await adapter.handleTransaction(event);

        expect(result.ok).toBe(true);
        expect(result.status).toBe('MASK');
        expect(result.action).toBe('MASK');
        expect(result.deliverableText).toBeDefined();
        expect(result.deliverableText).toContain('[REDACTED_API_KEY]');
        expect(result.deliverableText).not.toContain(rawApiKey);

        // Original event cancelled, composer updated with verified masked text
        expect(event.prevented).toBe(true);
        const textInComposer = composer.value ?? composer.innerText;
        expect(textInComposer).toBe(result.deliverableText);
      });

      it(`9. WARN blocks/holds send on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const originalText = 'Suspicious query payload';
        const composer = p.createComposer(originalText);
        root.setElement(p.selector, composer);

        const warnPolicyEvaluator: PolicyEvaluator = {
          evaluate: vi.fn(async () => ({
            action: 'WARN',
            reason: 'Hold suspicious prompt',
            triggeredRules: ['rule-warn-1'],
            allowOverride: true,
          })),
        };

        const shieldRuntime = createShieldRuntime({
          detectorRegistry: createDefaultDetectorRegistry(),
          policyEvaluator: warnPolicyEvaluator,
        });

        const adapter = p.createAdapter({ runtime: shieldRuntime });
        await adapter.attach(root);
        const event = createMockEvent({ key: 'Enter', target: composer });

        const result = await adapter.handleTransaction(event);

        expect(result.ok).toBe(true);
        expect(result.status).toBe('WARN');
        expect(result.action).toBe('WARN');
        expect(event.prevented).toBe(true); // Send held
        const currentText = composer.value ?? composer.innerText;
        expect(currentText).toBe(originalText); // DOM not mutated
      });

      it(`10. BLOCK prevents send on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const originalText = 'sk-proj-12345678901234567890123456789012';
        const composer = p.createComposer(originalText);
        root.setElement(p.selector, composer);

        const blockPolicyEvaluator: PolicyEvaluator = {
          evaluate: vi.fn(async () => ({
            action: 'BLOCK',
            reason: 'Prohibited leak',
            triggeredRules: ['rule-block-1'],
            allowOverride: false,
          })),
        };

        const shieldRuntime = createShieldRuntime({
          detectorRegistry: createDefaultDetectorRegistry(),
          policyEvaluator: blockPolicyEvaluator,
        });

        const adapter = p.createAdapter({ runtime: shieldRuntime });
        await adapter.attach(root);
        const event = createMockEvent({ key: 'Enter', target: composer });

        const result = await adapter.handleTransaction(event);

        expect(result.ok).toBe(true);
        expect(result.status).toBe('BLOCK');
        expect(result.action).toBe('BLOCK');
        expect(event.prevented).toBe(true); // Send blocked
        const currentText = composer.value ?? composer.innerText;
        expect(currentText).toBe(originalText); // DOM not mutated
      });

      it(`11. Verification failure prevents DOM mutation and send on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const originalText = 'sk-proj-12345678901234567890123456789012';
        const composer = p.createComposer(originalText);
        root.setElement(p.selector, composer);

        const failingVerifier: Verifier = {
          verify: vi.fn(async () => ({
            status: 'FAILED',
            verified: false,
            residualRisk: {
              score: 99,
              severity: 'CRITICAL',
              confidence: 1.0,
              factors: [],
              summary: 'Residual token detected',
              evaluationTimestamp: Date.now(),
            },
            leaksDetected: true,
            failedChecks: ['LEAK_CHECK'],
          })),
        };

        const shieldRuntime = createShieldRuntime({
          detectorRegistry: createDefaultDetectorRegistry(),
          verifier: failingVerifier,
        });

        const adapter = p.createAdapter({ runtime: shieldRuntime });
        await adapter.attach(root);
        const event = createMockEvent({ key: 'Enter', target: composer });

        const result = await adapter.handleTransaction(event);

        expect(result.ok).toBe(false);
        expect(result.status).toBe('ERROR');
        expect(event.prevented).toBe(true); // Send prevented
        const currentText = composer.value ?? composer.innerText;
        expect(currentText).toBe(originalText); // DOM NOT mutated
      });

      it(`12. Adapter runtime failure fails closed on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const composer = p.createComposer('Normal prompt');
        root.setElement(p.selector, composer);

        const explodingRuntime = {
          execute: vi.fn().mockRejectedValue(new Error('Fatal runtime crash')),
          deliveryEngine: {} as unknown as DeterministicDeliveryEngine,
          orchestrator: {} as unknown as PipelineOrchestrator,
        } as unknown as ShieldRuntime;

        const adapter = p.createAdapter({ runtime: explodingRuntime });
        await adapter.attach(root);
        const event = createMockEvent({ key: 'Enter', target: composer });

        const result = await adapter.handleTransaction(event);

        expect(result.ok).toBe(false);
        expect(result.status).toBe('ERROR');
        expect(event.prevented).toBe(true);
      });

      it(`13. No raw sensitive data in results or logs on ${p.name}`, async () => {
        const rawKey = 'sk-proj-12345678901234567890123456789012';
        const root = new MockDomRoot();
        const composer = p.createComposer(`API Key: ${rawKey}`);
        root.setElement(p.selector, composer);

        let interceptedResult: DomBoundaryExecutionResult | undefined;
        const adapter = p.createAdapter({
          onIntercept: (res: DomBoundaryExecutionResult) => {
            interceptedResult = res;
          },
        });
        await adapter.attach(root);

        const event = createMockEvent({ key: 'Enter', target: composer });
        const result = await adapter.handleTransaction(event);

        const serializedResult = JSON.stringify(result);
        expect(serializedResult).not.toContain(rawKey);

        if (interceptedResult) {
          const serializedIntercept = JSON.stringify(interceptedResult);
          expect(serializedIntercept).not.toContain(rawKey);
        }
      });

      it(`14. Duplicate interception protection on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const composer = p.createComposer('Valid prompt');
        root.setElement(p.selector, composer);

        const adapter = p.createAdapter();
        await adapter.attach(root);
        const event1 = createMockEvent({ key: 'Enter', target: composer });
        const event2 = createMockEvent({ key: 'Enter', target: composer });

        // First transaction executes
        const p1 = adapter.handleTransaction(event1);
        // Second concurrent transaction intercepted
        const r2 = await adapter.handleTransaction(event2);
        const r1 = await p1;

        expect(r1.ok).toBe(true);
        expect(r2.ok).toBe(false);
        expect(r2.error?.code).toBe('CONCURRENT_TRANSACTION_BLOCKED');
        expect(event2.prevented).toBe(true);
      });

      it(`15. Listener attach/detach behavior on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const adapter = p.createAdapter();

        expect(adapter.isAttached()).toBe(false);
        await adapter.attach(root);
        expect(adapter.isAttached()).toBe(true);
        expect(root.listeners['keydown']).toBeDefined();
        expect(root.listeners['click']).toBeDefined();
        expect(root.listeners['paste']).toBeDefined();

        await adapter.detach();
        expect(adapter.isAttached()).toBe(false);
        expect(root.listeners['keydown']).toHaveLength(0);
        expect(root.listeners['click']).toHaveLength(0);
        expect(root.listeners['paste']).toHaveLength(0);
      });

      it(`16. Multiline drafting preserved (Shift+Enter ignored) on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const composer = p.createComposer('Line 1');
        root.setElement(p.selector, composer);

        let intercepted = false;
        const adapter = p.createAdapter({
          onIntercept: () => {
            intercepted = true;
          },
        });

        await adapter.attach(root);

        const shiftEnterEvent = createMockEvent({
          key: 'Enter',
          shiftKey: true,
          type: 'keydown',
          target: composer,
        });

        root.dispatch('keydown', shiftEnterEvent);

        await new Promise((r) => setTimeout(r, 20));
        expect(intercepted).toBe(false);
        expect(shiftEnterEvent.prevented).toBe(false); // Shift+Enter allowed freely

        await adapter.detach();
      });

      it(`17. Shield DOM update does not recursively trigger another Shield transaction on ${p.name}`, async () => {
        const root = new MockDomRoot();
        const composer = p.createComposer('Draft text');
        root.setElement(p.selector, composer);

        const adapter = p.createAdapter();
        await adapter.attach(root);

        let recursiveResult: DomBoundaryExecutionResult | undefined;
        composer.dispatchEvent = vi.fn(() => {
          const event = createMockEvent({ type: 'input', target: composer });
          void adapter.handleTransaction(event).then((r) => {
            recursiveResult = r;
          });
          return true;
        });

        adapter.applyVerifiedText(
          { composerElement: composer, inputType: 'textarea' },
          'Transformed text',
        );

        await new Promise((r) => setTimeout(r, 10));
        expect(recursiveResult).toBeDefined();
        expect(recursiveResult?.ok).toBe(true);
        expect(recursiveResult?.contextId).toBe('shield-synthetic-mutation');
      });

      it(`18. Deterministic behavior on identical inputs on ${p.name}`, async () => {
        const fixedTimestamp = 1700000000000;
        const root = new MockDomRoot();
        const prompt = 'Deterministic platform test: Alice and Bob';
        const composer1 = p.createComposer(prompt);
        const composer2 = p.createComposer(prompt);

        root.setElement(p.selector, composer1);

        const adapter1 = p.createAdapter({ fixedTimestamp });
        const adapter2 = p.createAdapter({ fixedTimestamp });

        await adapter1.attach(root);
        await adapter2.attach(root);

        const event1 = createMockEvent({ key: 'Enter', target: composer1 });
        const event2 = createMockEvent({ key: 'Enter', target: composer2 });

        const r1 = await adapter1.handleTransaction(event1);
        const r2 = await adapter2.handleTransaction(event2);

        expect(r1.status).toBe(r2.status);
        expect(r1.action).toBe(r2.action);
        expect(r1.deliverableText).toBe(r2.deliverableText);
      });
    });
  }

  // ==========================================================================
  // 19. Send Button Click Interception
  // ==========================================================================
  describe('Send Button Click Interception', () => {
    it('intercepts click on send button for ChatGPT, Claude, and Gemini', async () => {
      for (const p of platforms) {
        const root = new MockDomRoot();
        const composer = p.createComposer('Submit via button');
        const sendBtn = p.createSendButton();

        root.setElement(p.selector, composer);
        root.setElement(p.sendButtonSelector, sendBtn);

        let intercepted = false;
        const adapter = p.createAdapter({
          onIntercept: () => {
            intercepted = true;
          },
        });

        await adapter.attach(root);

        const clickEvent = createMockEvent({
          type: 'click',
          target: sendBtn,
        });

        root.dispatch('click', clickEvent);

        await new Promise((r) => setTimeout(r, 20));
        expect(intercepted).toBe(true);

        await adapter.detach();
      }
    });
  });

  // ==========================================================================
  // 20. Normal Typing & Enter Interception Validation
  // ==========================================================================
  describe('Normal Typing & Enter Interception', () => {
    it('does not intercept or block ordinary typing characters like "hello shield"', async () => {
      for (const p of platforms) {
        const root = new MockDomRoot();
        const composer = p.createComposer('');
        root.setElement(p.selector, composer);

        let intercepted = false;
        const adapter = p.createAdapter({
          onIntercept: () => {
            intercepted = true;
          },
        });

        await adapter.attach(root);

        // Simulate typing "hello shield" key by key
        const phrase = 'hello shield';
        let accumulatedText = '';
        for (const char of phrase) {
          accumulatedText += char;
          const keyEvent = createMockEvent({
            key: char,
            target: composer,
          });

          root.dispatch('keydown', keyEvent);

          // Crucial: normal typing must NEVER be prevented or intercepted
          expect(keyEvent.prevented).toBe(false);
          expect(keyEvent.stopped).toBe(false);

          // Update composer value/text to reflect native input entry
          if ('value' in composer) {
            composer.value = accumulatedText;
          } else {
            composer.innerText = accumulatedText;
            composer.textContent = accumulatedText;
          }
        }

        // Verify Shield evaluation did not trigger on ordinary typing
        expect(intercepted).toBe(false);

        // Verify multiline Shift+Enter typing is also NOT intercepted
        const shiftEnterEvent = createMockEvent({
          key: 'Enter',
          shiftKey: true,
          target: composer,
        });
        root.dispatch('keydown', shiftEnterEvent);
        expect(shiftEnterEvent.prevented).toBe(false);
        expect(intercepted).toBe(false);

        // Now test submit with Enter (send interception)
        const enterSubmitEvent = createMockEvent({
          key: 'Enter',
          shiftKey: false,
          target: composer,
        });

        const result = await adapter.handleTransaction(enterSubmitEvent);
        expect(result.ok).toBe(true);
        expect(result.status).toBe('ALLOW');
        expect(result.action).toBe('ALLOW');
        // Clean prompt allows submit to proceed
        expect(enterSubmitEvent.prevented).toBe(false);

        await adapter.detach();
      }
    });
  });

  // ==========================================================================
  // 21. Architectural Isolation: @shield/core Free of DOM/Platform Imports
  // ==========================================================================
  describe('Architectural Boundary', () => {
    it('20. @shield/core has 0 DOM/browser or platform adapter imports', () => {
      const coreSrcDir = path.resolve(__dirname, '../packages/core/src');
      const files = fs.readdirSync(coreSrcDir).filter((f) => f.endsWith('.ts'));

      const forbiddenTokens = [
        'window.',
        'document.',
        'HTMLElement',
        'HTMLTextAreaElement',
        'HTMLInputElement',
        'chrome.',
        '@shield/adapters',
        'ChatGPT',
        'Claude',
        'Gemini',
      ];

      const violations: { file: string; token: string }[] = [];

      for (const file of files) {
        const content = fs.readFileSync(path.join(coreSrcDir, file), 'utf-8');
        for (const token of forbiddenTokens) {
          if (content.includes(token)) {
            violations.push({ file, token });
          }
        }
      }

      expect(violations).toHaveLength(0);
    });
  });
});
