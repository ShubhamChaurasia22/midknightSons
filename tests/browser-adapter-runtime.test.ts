/**
 * Test Suite — Milestone M2.2: Browser Adapter Runtime
 *
 * Validates the browser/content-script runtime orchestrating DOM target detection,
 * transaction interception (Enter / Paste), and safe handoff with DomRuntimeBoundary:
 *
 * 1. Textarea extraction
 * 2. Contenteditable extraction
 * 3. Empty input fail-closed
 * 4. Extraction failure
 * 5. ALLOW delivery
 * 6. MASK delivery only after successful verification
 * 7. WARN hold/no delivery
 * 8. BLOCK no delivery
 * 9. Verification failure no DOM mutation
 * 10. Adapter/runtime failure fail-closed
 * 11. No raw sensitive data in results/logs
 * 12. No DOM/browser imports in @shield/core
 * 13. Deterministic behavior where practical
 * 14. Preservation of all M1 tests
 */

import { describe, it, expect, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  createBrowserAdapterRuntime,
  isSupportedDomTarget,
  describeDomTarget,
  extractTextFromElement,
  type SupportedDomElement,
  type EventTargetLike,
  type InterceptedEvent,
  type DomBoundaryExecutionResult,
} from '../packages/adapters/src';
import {
  createShieldRuntime,
  type PlatformContext,
  type ShieldRuntime,
  type Verifier,
  type PolicyEvaluator,
  type DeterministicDeliveryEngine,
  type PipelineOrchestrator,
} from '../packages/core/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

// ============================================================================
// Headless Mock Helpers
// ============================================================================

function createMockTextarea(
  initialValue: string,
  options: Partial<SupportedDomElement> = {},
): SupportedDomElement {
  const attrs: Record<string, string> = { type: 'textarea' };
  return {
    tagName: 'TEXTAREA',
    id: options.id ?? 'mock-textarea',
    value: initialValue,
    getAttribute: (name: string) => attrs[name] ?? null,
    setAttribute: (name: string, val: string) => {
      attrs[name] = val;
    },
    dispatchEvent: vi.fn(),
    ...options,
  };
}

function createMockContentEditable(
  initialText: string,
  options: Partial<SupportedDomElement> = {},
): SupportedDomElement {
  const attrs: Record<string, string> = { contenteditable: 'true' };
  return {
    tagName: 'DIV',
    id: options.id ?? 'mock-contenteditable',
    innerText: initialText,
    textContent: initialText,
    isContentEditable: true,
    getAttribute: (name: string) => attrs[name] ?? null,
    setAttribute: (name: string, val: string) => {
      attrs[name] = val;
    },
    dispatchEvent: vi.fn(),
    ...options,
  };
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

class MockEventRoot implements EventTargetLike {
  public listeners: Record<string, ((event: unknown) => void)[]> = {};

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

describe('Milestone M2.2 — Browser Adapter Runtime', () => {
  const defaultPlatformContext: PlatformContext = {
    site: 'chatgpt.com',
    isAiSite: true,
    url: 'https://chatgpt.com/c/test-session',
  };

  const createRuntimeWithDetectors = (
    options: {
      runtime?: ShieldRuntime;
      fixedTimestamp?: number;
      onIntercept?: (result: DomBoundaryExecutionResult, element: SupportedDomElement) => void;
    } = {},
  ) => {
    const shieldRuntime =
      options.runtime ??
      createShieldRuntime({
        detectorRegistry: createDefaultDetectorRegistry(),
        defaultPlatformContext,
        fixedTimestamp: options.fixedTimestamp,
      });

    const browserRuntime = createBrowserAdapterRuntime({
      runtime: shieldRuntime,
      defaultPlatformContext,
      fixedTimestamp: options.fixedTimestamp,
      onIntercept: options.onIntercept,
    });

    return { browserRuntime, shieldRuntime };
  };

  // ==========================================================================
  // 1. Textarea Extraction
  // ==========================================================================
  it('1. Textarea extraction: correctly detects, extracts, and identifies textarea elements', async () => {
    const textarea = createMockTextarea('Draft prompt inside textarea');
    expect(isSupportedDomTarget(textarea)).toBe(true);

    const descriptor = describeDomTarget(textarea);
    expect(descriptor.inputType).toBe('textarea');
    expect(descriptor.tagName).toBe('textarea');
    expect(descriptor.elementId).toBe('mock-textarea');

    const extractedText = extractTextFromElement(textarea);
    expect(extractedText).toBe('Draft prompt inside textarea');

    const { browserRuntime } = createRuntimeWithDetectors();
    const result = await browserRuntime.processElement(textarea);

    expect(result.ok).toBe(true);
    expect(result.status).toBe('ALLOW');
    expect(result.action).toBe('ALLOW');
  });

  // ==========================================================================
  // 2. Contenteditable Extraction
  // ==========================================================================
  it('2. Contenteditable extraction: correctly detects, extracts, and identifies contenteditable elements', async () => {
    const contenteditable = createMockContentEditable('Content inside rich text editor div');
    expect(isSupportedDomTarget(contenteditable)).toBe(true);

    const descriptor = describeDomTarget(contenteditable);
    expect(descriptor.inputType).toBe('contenteditable');
    expect(descriptor.tagName).toBe('div');

    const extractedText = extractTextFromElement(contenteditable);
    expect(extractedText).toBe('Content inside rich text editor div');

    const { browserRuntime } = createRuntimeWithDetectors();
    const result = await browserRuntime.processElement(contenteditable);

    expect(result.ok).toBe(true);
    expect(result.status).toBe('ALLOW');
  });

  // ==========================================================================
  // 3. Empty Input Fail-Closed
  // ==========================================================================
  it('3. Empty input fail-closed: fails closed and prevents transaction on empty or whitespace prompt', async () => {
    const textarea = createMockTextarea('   ');
    const mockEvent = createMockEvent({ key: 'Enter', target: textarea });

    const { browserRuntime } = createRuntimeWithDetectors();
    const result = await browserRuntime.processElement(textarea, { event: mockEvent });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.action).toBe('ERROR');
    expect(result.failedStage).toBe('INPUT');
    expect(mockEvent.prevented).toBe(true);
    expect(textarea.value).toBe('   '); // Unmutated
  });

  // ==========================================================================
  // 4. Extraction Failure
  // ==========================================================================
  it('4. Extraction failure: fails closed if target element is unsupported or detached', async () => {
    const unsupportedEl: SupportedDomElement = {
      tagName: 'SPAN',
      id: 'static-label',
      innerText: 'Static non-editable text',
    };
    expect(isSupportedDomTarget(unsupportedEl)).toBe(false);

    const mockEvent = createMockEvent({ key: 'Enter', target: unsupportedEl });
    const { browserRuntime } = createRuntimeWithDetectors();
    const result = await browserRuntime.processElement(unsupportedEl, { event: mockEvent });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.failedStage).toBe('INPUT');
    expect(result.error?.code).toBe('UNSUPPORTED_TARGET_ELEMENT');
    expect(mockEvent.prevented).toBe(true);
  });

  // ==========================================================================
  // 5. ALLOW Delivery
  // ==========================================================================
  it('5. ALLOW delivery: benign prompt is delivered cleanly without transaction prevention', async () => {
    const textarea = createMockTextarea('How do I configure git branches?');
    const mockEvent = createMockEvent({ key: 'Enter', target: textarea });

    const { browserRuntime } = createRuntimeWithDetectors();
    const result = await browserRuntime.processElement(textarea, { event: mockEvent });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('ALLOW');
    expect(result.action).toBe('ALLOW');
    expect(mockEvent.prevented).toBe(false);
    expect(textarea.value).toBe('How do I configure git branches?');
  });

  // ==========================================================================
  // 6. MASK Delivery Only After Successful Verification
  // ==========================================================================
  it('6. MASK delivery: masks sensitive data and safely mutates target DOM element', async () => {
    const rawApiKey = 'sk-proj-12345678901234567890123456789012';
    const textarea = createMockTextarea(`Here is my OpenAI API key: ${rawApiKey}`);
    const mockEvent = createMockEvent({ key: 'Enter', target: textarea });

    const maskPolicyEvaluator: PolicyEvaluator = {
      evaluate: vi.fn(async () => ({
        action: 'MASK',
        reason: 'Mask sensitive credentials per policy',
        triggeredRules: ['mask-credential-rule'],
        allowOverride: false,
      })),
    };

    const shieldRuntime = createShieldRuntime({
      detectorRegistry: createDefaultDetectorRegistry(),
      policyEvaluator: maskPolicyEvaluator,
      defaultPlatformContext,
    });

    const browserRuntime = createBrowserAdapterRuntime({
      runtime: shieldRuntime,
      defaultPlatformContext,
    });

    const result = await browserRuntime.processElement(textarea, { event: mockEvent });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('MASK');
    expect(result.action).toBe('MASK');
    expect(result.deliverableText).toBeDefined();
    expect(result.deliverableText).not.toContain(rawApiKey);
    expect(result.deliverableText).toContain('[REDACTED_API_KEY]');

    // Element value is safely updated with verified masked text
    expect(textarea.value).toBe(result.deliverableText);
    expect(textarea.value).not.toContain(rawApiKey);
  });

  it('6b. MASK delivery to contenteditable element', async () => {
    const rawApiKey = 'sk-proj-12345678901234567890123456789012';
    const contenteditable = createMockContentEditable(`Key: ${rawApiKey}`);
    const mockEvent = createMockEvent({ key: 'Enter', target: contenteditable });

    const maskPolicyEvaluator: PolicyEvaluator = {
      evaluate: vi.fn(async () => ({
        action: 'MASK',
        reason: 'Mask sensitive credentials per policy',
        triggeredRules: ['mask-credential-rule'],
        allowOverride: false,
      })),
    };

    const shieldRuntime = createShieldRuntime({
      detectorRegistry: createDefaultDetectorRegistry(),
      policyEvaluator: maskPolicyEvaluator,
      defaultPlatformContext,
    });

    const browserRuntime = createBrowserAdapterRuntime({
      runtime: shieldRuntime,
      defaultPlatformContext,
    });

    const result = await browserRuntime.processElement(contenteditable, { event: mockEvent });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('MASK');
    expect(contenteditable.innerText).toContain('[REDACTED_API_KEY]');
    expect(contenteditable.innerText).not.toContain(rawApiKey);
  });

  // ==========================================================================
  // 7. WARN Hold / No Delivery
  // ==========================================================================
  it('7. WARN hold/no delivery: holds transaction and prevents DOM mutation', async () => {
    const warnPolicyEvaluator: PolicyEvaluator = {
      evaluate: vi.fn(async () => ({
        action: 'WARN',
        reason: 'Suspicious payload detected',
        triggeredRules: ['rule-warn-1'],
        allowOverride: true,
      })),
    };

    const shieldRuntime = createShieldRuntime({
      detectorRegistry: createDefaultDetectorRegistry(),
      policyEvaluator: warnPolicyEvaluator,
      defaultPlatformContext,
    });

    const browserRuntime = createBrowserAdapterRuntime({
      runtime: shieldRuntime,
      defaultPlatformContext,
    });

    const initialText = 'Email: alice@example.com';
    const textarea = createMockTextarea(initialText);
    const mockEvent = createMockEvent({ key: 'Enter', target: textarea });

    const result = await browserRuntime.processElement(textarea, { event: mockEvent });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('WARN');
    expect(result.action).toBe('WARN');
    expect(mockEvent.prevented).toBe(true); // Transaction held
    expect(textarea.value).toBe(initialText); // No mutation
  });

  // ==========================================================================
  // 8. BLOCK No Delivery
  // ==========================================================================
  it('8. BLOCK no delivery: cancels transaction and prohibits DOM transmission', async () => {
    const blockPolicyEvaluator: PolicyEvaluator = {
      evaluate: vi.fn(async () => ({
        action: 'BLOCK',
        reason: 'Critical leak prohibited',
        triggeredRules: ['rule-block-1'],
        allowOverride: false,
      })),
    };

    const shieldRuntime = createShieldRuntime({
      detectorRegistry: createDefaultDetectorRegistry(),
      policyEvaluator: blockPolicyEvaluator,
      defaultPlatformContext,
    });

    const browserRuntime = createBrowserAdapterRuntime({
      runtime: shieldRuntime,
      defaultPlatformContext,
    });

    const initialText = 'sk-proj-12345678901234567890123456789012';
    const textarea = createMockTextarea(initialText);
    const mockEvent = createMockEvent({ key: 'Enter', target: textarea });

    const result = await browserRuntime.processElement(textarea, { event: mockEvent });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('BLOCK');
    expect(result.action).toBe('BLOCK');
    expect(mockEvent.prevented).toBe(true); // Transmission blocked
    expect(textarea.value).toBe(initialText); // Original input not altered
  });

  // ==========================================================================
  // 9. Verification Failure No DOM Mutation
  // ==========================================================================
  it('9. Verification failure: fails closed and prevents DOM mutation if verifier rejects', async () => {
    const failingVerifier: Verifier = {
      verify: vi.fn(async () => ({
        status: 'FAILED',
        verified: false,
        residualRisk: {
          score: 90,
          severity: 'HIGH',
          confidence: 0.95,
          factors: [],
          summary: 'Residual token detected after transform',
          evaluationTimestamp: Date.now(),
        },
        leaksDetected: true,
        failedChecks: ['RESIDUAL_LEAK_CHECK'],
      })),
    };

    const shieldRuntime = createShieldRuntime({
      detectorRegistry: createDefaultDetectorRegistry(),
      verifier: failingVerifier,
      defaultPlatformContext,
    });

    const browserRuntime = createBrowserAdapterRuntime({
      runtime: shieldRuntime,
      defaultPlatformContext,
    });

    const initialText = 'sk-proj-12345678901234567890123456789012';
    const textarea = createMockTextarea(initialText);
    const mockEvent = createMockEvent({ key: 'Enter', target: textarea });

    const result = await browserRuntime.processElement(textarea, { event: mockEvent });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(mockEvent.prevented).toBe(true);
    expect(textarea.value).toBe(initialText); // MUST NOT mutate DOM
  });

  // ==========================================================================
  // 10. Adapter / Runtime Failure Fail-Closed
  // ==========================================================================
  it('10. Adapter/runtime failure: fails closed and prevents event on unexpected exception', async () => {
    const explodingRuntime = {
      execute: vi.fn().mockRejectedValue(new Error('Catastrophic failure in core runtime')),
      deliveryEngine: {} as unknown as DeterministicDeliveryEngine,
      orchestrator: {} as unknown as PipelineOrchestrator,
    } as unknown as ShieldRuntime;

    const browserRuntime = createBrowserAdapterRuntime({
      runtime: explodingRuntime,
      defaultPlatformContext,
    });

    const textarea = createMockTextarea('Normal text');
    const mockEvent = createMockEvent({ key: 'Enter', target: textarea });

    const result = await browserRuntime.processElement(textarea, { event: mockEvent });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(mockEvent.prevented).toBe(true);
    expect(textarea.value).toBe('Normal text');
  });

  // ==========================================================================
  // 11. No Raw Sensitive Data in Results/Logs
  // ==========================================================================
  it('11. No raw sensitive data: ensures no raw sensitive credentials leak into results or logs', async () => {
    const rawApiKey = 'sk-proj-12345678901234567890123456789012';
    const textarea = createMockTextarea(`Check this secret: ${rawApiKey}`);

    let interceptedResult: DomBoundaryExecutionResult | undefined;
    const { browserRuntime } = createRuntimeWithDetectors({
      onIntercept: (res) => {
        interceptedResult = res;
      },
    });

    const result = await browserRuntime.processElement(textarea);
    expect(result.ok).toBe(true);

    const serializedResult = JSON.stringify(result);
    expect(serializedResult).not.toContain(rawApiKey);

    expect(interceptedResult).toBeDefined();
    const serializedIntercept = JSON.stringify(interceptedResult);
    expect(serializedIntercept).not.toContain(rawApiKey);
  });

  // ==========================================================================
  // 12. No DOM / Browser Imports in @shield/core
  // ==========================================================================
  it('12. Architectural boundary: @shield/core has 0 DOM/browser imports or references', () => {
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

  // ==========================================================================
  // 13. Deterministic Behavior
  // ==========================================================================
  it('13. Deterministic behavior: repeated executions with fixed timestamp produce identical results', async () => {
    const fixedTimestamp = 1700000000000;
    const { browserRuntime } = createRuntimeWithDetectors({ fixedTimestamp });

    const prompt = 'Test deterministic run: sk-proj-12345678901234567890123456789012';
    const textarea1 = createMockTextarea(prompt);
    const textarea2 = createMockTextarea(prompt);

    const result1 = await browserRuntime.processElement(textarea1);
    const result2 = await browserRuntime.processElement(textarea2);

    expect(result1.status).toBe(result2.status);
    expect(result1.action).toBe(result2.action);
    expect(result1.deliverableText).toBe(result2.deliverableText);
    expect(textarea1.value).toBe(textarea2.value);
  });

  // ==========================================================================
  // Transaction Interception: Attach, Detach, Enter & Paste
  // ==========================================================================
  describe('Transaction Interception Model', () => {
    it('attaches to root and intercepts Enter keypress', async () => {
      const mockRoot = new MockEventRoot();
      let intercepted = false;

      const { browserRuntime } = createRuntimeWithDetectors({
        onIntercept: () => {
          intercepted = true;
        },
      });

      expect(browserRuntime.isAttached()).toBe(false);
      browserRuntime.attach(mockRoot);
      expect(browserRuntime.isAttached()).toBe(true);

      const textarea = createMockTextarea('Normal prompt');
      const enterEvent = createMockEvent({
        key: 'Enter',
        shiftKey: false,
        type: 'keydown',
        target: textarea,
      });

      mockRoot.dispatch('keydown', enterEvent);

      // Wait a tick for async processing
      await new Promise((r) => setTimeout(r, 20));
      expect(intercepted).toBe(true);

      browserRuntime.detach();
      expect(browserRuntime.isAttached()).toBe(false);
    });

    it('ignores Shift+Enter to allow multi-line text input', async () => {
      const mockRoot = new MockEventRoot();
      let intercepted = false;

      const { browserRuntime } = createRuntimeWithDetectors({
        onIntercept: () => {
          intercepted = true;
        },
      });

      browserRuntime.attach(mockRoot);

      const textarea = createMockTextarea('Multi-line typing');
      const shiftEnterEvent = createMockEvent({
        key: 'Enter',
        shiftKey: true,
        type: 'keydown',
        target: textarea,
      });

      mockRoot.dispatch('keydown', shiftEnterEvent);

      await new Promise((r) => setTimeout(r, 20));
      expect(intercepted).toBe(false);

      browserRuntime.detach();
    });

    it('intercepts Paste transactions on supported elements', async () => {
      const mockRoot = new MockEventRoot();
      let intercepted = false;

      const { browserRuntime } = createRuntimeWithDetectors({
        onIntercept: () => {
          intercepted = true;
        },
      });

      browserRuntime.attach(mockRoot);

      const textarea = createMockTextarea('Pasted text content');
      const pasteEvent = createMockEvent({
        type: 'paste',
        target: textarea,
      });

      mockRoot.dispatch('paste', pasteEvent);

      await new Promise((r) => setTimeout(r, 20));
      expect(intercepted).toBe(true);

      browserRuntime.detach();
    });
  });
});
