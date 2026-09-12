/**
 * Test Suite — Milestone M2.1: Shield Browser/DOM Adapter Contract & Runtime Boundary
 *
 * Validates the boundary between browser/DOM abstractions and the M1.9 ShieldRuntime:
 * - Adapter contract creation & dependency injection
 * - Valid input extraction & invalid/empty input handling
 * - Output delivery boundary & safe handoff
 * - ALLOW / WARN / MASK / BLOCK transmission invariants
 * - Fail-closed semantics on extractor, verifier, or applier failures
 * - Zero raw sensitive-value leakage
 * - Platform independence & boundary isolation
 */

import { describe, it, expect, vi } from 'vitest';
import {
  createDomRuntimeBoundary,
  DomRuntimeBoundary,
  InMemoryDomInputExtractor,
  InMemoryDomOutputApplier,
  type DomInputExtractor,
  type DomOutputApplier,
  type DomExtractionContext,
  type DomTargetElement,
} from '../packages/adapters/src';
import {
  createShieldRuntime,
  type PlatformContext,
  type ShieldRuntime,
  type DetectorEngine,
  type Verifier,
} from '../packages/core/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

describe('M2.1 — Shield Browser/DOM Adapter Contract & Runtime Boundary', () => {
  const defaultPlatformContext: PlatformContext = {
    site: 'chatgpt.com',
    isAiSite: true,
    url: 'https://chatgpt.com/c/test-chat',
  };

  const defaultTargetElement: DomTargetElement = {
    elementId: 'prompt-textarea',
    tagName: 'textarea',
    inputType: 'textarea',
  };

  const createBoundaryWithDetectors = (
    options: {
      extractor?: DomInputExtractor;
      applier?: DomOutputApplier;
      runtime?: ShieldRuntime;
      fixedTimestamp?: number;
    } = {},
  ) => {
    const extractor =
      options.extractor ??
      new InMemoryDomInputExtractor({
        defaultPlatformContext,
        defaultSourceElement: defaultTargetElement,
      });

    const applier = options.applier ?? new InMemoryDomOutputApplier();

    const runtime =
      options.runtime ??
      createShieldRuntime({
        detectorRegistry: createDefaultDetectorRegistry(),
        defaultPlatformContext,
        fixedTimestamp: options.fixedTimestamp,
      });

    const boundary = createDomRuntimeBoundary({
      runtime,
      extractor,
      applier,
      defaultPlatformContext,
      fixedTimestamp: options.fixedTimestamp,
    });

    return { boundary, extractor, applier, runtime };
  };

  // ==========================================================================
  // 1. Adapter Contract Creation & Structure
  // ==========================================================================
  it('1. Adapter contract creation: instantiates DomRuntimeBoundary with valid contracts', () => {
    const extractor = new InMemoryDomInputExtractor();
    const applier = new InMemoryDomOutputApplier();

    const boundary = createDomRuntimeBoundary({
      extractor,
      applier,
      defaultPlatformContext,
    });

    expect(boundary).toBeDefined();
    expect(boundary).toBeInstanceOf(DomRuntimeBoundary);
    expect(boundary.execute).toBeTypeOf('function');
    expect(boundary.underlyingRuntime).toBeDefined();
  });

  it('2. Adapter contract creation: throws if extractor or applier is missing', () => {
    const applier = new InMemoryDomOutputApplier();
    const extractor = new InMemoryDomInputExtractor();

    expect(() =>
      createDomRuntimeBoundary({
        extractor: null as unknown as DomInputExtractor,
        applier,
      }),
    ).toThrow(/DomInputExtractor/);

    expect(() =>
      createDomRuntimeBoundary({
        extractor,
        applier: null as unknown as DomOutputApplier,
      }),
    ).toThrow(/DomOutputApplier/);
  });

  // ==========================================================================
  // 2. Input Extraction Boundary
  // ==========================================================================
  it('3. Valid input extraction: extracts prompt text, platformContext, and target element', async () => {
    const rawText = 'Explain zero-knowledge proofs in simple terms.';
    const extractor = new InMemoryDomInputExtractor({
      defaultText: rawText,
      defaultPlatformContext,
      defaultSourceElement: defaultTargetElement,
    });
    const applier = new InMemoryDomOutputApplier();
    const { boundary } = createBoundaryWithDetectors({ extractor, applier });

    const context: DomExtractionContext = {
      url: 'https://chatgpt.com/c/test-chat',
      targetElement: defaultTargetElement,
    };

    const result = await boundary.execute(context);

    expect(result.ok).toBe(true);
    expect(result.status).toBe('ALLOW');
    expect(result.deliverableText).toBe(rawText);
    expect(extractor.extractionsCount).toBe(1);
    expect(applier.deliveries).toHaveLength(1);
    expect(applier.deliveries[0]?.deliverableText).toBe(rawText);
    expect(applier.deliveries[0]?.targetElement).toEqual(defaultTargetElement);
  });

  it('4. Empty / invalid input handling: fails closed if extraction context has no url', async () => {
    const { boundary, applier } = createBoundaryWithDetectors();

    const invalidContext = {
      url: null as unknown as string,
    };

    const result = await boundary.execute(invalidContext);

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.failedStage).toBe('INPUT');
    expect(result.error?.code).toBe('EXTRACTION_CONTEXT_INVALID');
    expect(applier.deliveries).toHaveLength(0);
  });

  it('5. Empty / invalid input handling: fails closed if extractor yields non-string text', async () => {
    const extractor: DomInputExtractor = {
      extract: async () => ({
        text: undefined as unknown as string,
        platformContext: defaultPlatformContext,
        extractedAt: 1000,
      }),
    };

    const { boundary, applier } = createBoundaryWithDetectors({ extractor });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.failedStage).toBe('INPUT');
    expect(result.error?.code).toBe('EXTRACTED_INPUT_INVALID');
    expect(applier.deliveries).toHaveLength(0);
  });

  it('6. Extractor exception: fails closed safely without crashing', async () => {
    const extractor = new InMemoryDomInputExtractor({
      shouldThrow: true,
      errorMessage: 'DOM node detached from active document tree',
    });
    const { boundary, applier } = createBoundaryWithDetectors({ extractor });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.failedStage).toBe('INPUT');
    expect(result.error?.code).toBe('EXTRACTION_FAILED');
    expect(result.error?.message).toContain('DOM node detached');
    expect(applier.deliveries).toHaveLength(0);
  });

  // ==========================================================================
  // 3. ALLOW Behavior & Delivery Handoff
  // ==========================================================================
  it('7. ALLOW behavior: original text reaches DOM applier and succeeds', async () => {
    const cleanPrompt = 'How does photosynthesis convert sunlight into chemical energy?';
    const extractor = new InMemoryDomInputExtractor({
      defaultText: cleanPrompt,
      defaultPlatformContext,
      defaultSourceElement: defaultTargetElement,
    });
    const applier = new InMemoryDomOutputApplier();
    const fixedTimestamp = 1726100000000;

    const { boundary } = createBoundaryWithDetectors({
      extractor,
      applier,
      fixedTimestamp,
    });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('ALLOW');
    expect(result.action).toBe('ALLOW');
    expect(result.deliverableText).toBe(cleanPrompt);
    expect(result.domDelivery?.success).toBe(true);
    expect(result.domDelivery?.appliedText).toBe(cleanPrompt);

    expect(applier.deliveries).toHaveLength(1);
    expect(applier.deliveries[0]?.action).toBe('ALLOW');
    expect(applier.deliveries[0]?.deliverableText).toBe(cleanPrompt);
    expect(applier.deliveries[0]?.targetElement).toEqual(defaultTargetElement);
  });

  // ==========================================================================
  // 4. WARN Behavior & Hold Invariant
  // ==========================================================================
  it('8. WARN behavior: transmission held, zero items delivered to DOM applier', async () => {
    // Medium risk entity triggers WARN in default policy
    const mediumRiskPrompt = 'Confidential client internal notes regarding upcoming merger.';
    const customDetector: DetectorEngine = {
      detect: async () => ({
        entities: [
          {
            id: 'det-med',
            detectorId: 'd-med',
            category: 'PRIVATE_DATA',
            severity: 'MEDIUM',
            confidence: 0.9,
            range: { startIndex: 0, endIndex: 12 },
            evidence: { tokenLength: 12, hasRawValue: false },
          },
        ],
        hasDetections: true,
        durationMs: 1,
      }),
    };

    const runtime = createShieldRuntime({
      detectorEngine: customDetector,
      defaultPlatformContext,
    });

    const extractor = new InMemoryDomInputExtractor({
      defaultText: mediumRiskPrompt,
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier();

    const { boundary } = createBoundaryWithDetectors({
      extractor,
      applier,
      runtime,
    });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('WARN');
    expect(result.action).toBe('WARN');
    expect(result.domDelivery).toBeUndefined();
    // Critical Invariant: Applier MUST NOT receive held content
    expect(applier.deliveries).toHaveLength(0);
  });

  // ==========================================================================
  // 5. MASK Behavior & Verified Replacement Delivery
  // ==========================================================================
  it('9. MASK behavior: transformed & verified text is delivered to DOM applier', async () => {
    const rawEmail = 'contact-security@example.com';
    const prompt = `Please email ${rawEmail} for authorization.`;

    const runtime = createShieldRuntime({
      detectorRegistry: createDefaultDetectorRegistry(),
      policyEvaluator: {
        evaluate: vi.fn(async () => ({
          action: 'MASK',
          reason: 'Mask sensitive PII per policy',
          triggeredRules: ['mask-pii-rule'],
          allowOverride: false,
        })),
      },
      defaultPlatformContext,
    });

    const extractor = new InMemoryDomInputExtractor({
      defaultText: prompt,
      defaultPlatformContext,
      defaultSourceElement: defaultTargetElement,
    });
    const applier = new InMemoryDomOutputApplier();

    const { boundary } = createBoundaryWithDetectors({
      extractor,
      applier,
      runtime,
    });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('MASK');
    expect(result.action).toBe('MASK');
    expect(result.deliverableText).toContain('[REDACTED_PII]');
    expect(result.deliverableText).not.toContain(rawEmail);

    expect(applier.deliveries).toHaveLength(1);
    expect(applier.deliveries[0]?.action).toBe('MASK');
    expect(applier.deliveries[0]?.deliverableText).toBe(result.deliverableText);
    expect(applier.deliveries[0]?.deliverableText).not.toContain(rawEmail);
    expect(result.domDelivery?.success).toBe(true);
  });

  // ==========================================================================
  // 6. BLOCK Behavior & Prohibited Transmission
  // ==========================================================================
  it('10. BLOCK behavior: transmission prohibited, zero items delivered to DOM applier', async () => {
    const rawApiKey = 'sk-proj-CRITICALSECRETTOKEN1234567890ABCDEF123456';
    const prompt = `My OpenAI secret is ${rawApiKey}.`;

    const extractor = new InMemoryDomInputExtractor({
      defaultText: prompt,
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier();

    const { boundary } = createBoundaryWithDetectors({ extractor, applier });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('BLOCK');
    expect(result.action).toBe('BLOCK');
    expect(result.deliverableText).toBeUndefined();
    expect(result.domDelivery).toBeUndefined();
    // Critical Invariant: Applier MUST NOT receive blocked content
    expect(applier.deliveries).toHaveLength(0);
  });

  // ==========================================================================
  // 7. Verification Failure Fail-Closed Semantics
  // ==========================================================================
  it('11. Verification failure: halts at VERIFY stage, prevents DOM delivery', async () => {
    const failingVerifier: Verifier = {
      verify: async () => ({
        status: 'FAILED',
        verified: false,
        residualRisk: {
          score: 100,
          severity: 'CRITICAL',
          confidence: 1.0,
          factors: [],
          summary: 'Simulated leak detected during verification check',
          evaluationTimestamp: 0,
        },
        leaksDetected: true,
        failedChecks: ['MOCK_RESIDUAL_LEAK'],
      }),
    };

    const runtime = createShieldRuntime({
      verifier: failingVerifier,
      policyEvaluator: {
        evaluate: vi.fn(async () => ({
          action: 'MASK',
          reason: 'Attempt masking',
          triggeredRules: ['rule-1'],
          allowOverride: false,
        })),
      },
      detectorEngine: {
        detect: async () => ({
          entities: [
            {
              id: 'd1',
              detectorId: 'det',
              category: 'SECRET',
              severity: 'HIGH',
              confidence: 0.95,
              range: { startIndex: 0, endIndex: 6 },
              evidence: { tokenLength: 6, hasRawValue: false },
            },
          ],
          hasDetections: true,
          durationMs: 1,
        }),
      },
      defaultPlatformContext,
    });

    const extractor = new InMemoryDomInputExtractor({
      defaultText: 'secret prompt text',
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier();

    const { boundary } = createBoundaryWithDetectors({
      extractor,
      applier,
      runtime,
    });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.failedStage).toBe('VERIFY');
    expect(applier.deliveries).toHaveLength(0);
  });

  // ==========================================================================
  // 8. DOM Output Applier Failure
  // ==========================================================================
  it('12. DOM applier failure: returns fail-closed ERROR result when applier fails', async () => {
    const extractor = new InMemoryDomInputExtractor({
      defaultText: 'Clean prompt to deliver',
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier({
      shouldFail: true,
      errorMessage: 'Simulated textarea write permission denied',
    });

    const { boundary } = createBoundaryWithDetectors({ extractor, applier });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.failedStage).toBe('SEND');
    expect(result.error?.code).toBe('DOM_DELIVERY_FAILED');
    expect(result.error?.message).toContain('textarea write permission denied');
    expect(applier.deliveries).toHaveLength(0);
  });

  it('13. DOM applier exception: returns fail-closed ERROR result when applier throws', async () => {
    const extractor = new InMemoryDomInputExtractor({
      defaultText: 'Clean prompt to deliver',
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier({
      shouldThrow: true,
      errorMessage: 'Unexpected DOM mutation exception during input event dispatch',
    });

    const { boundary } = createBoundaryWithDetectors({ extractor, applier });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(false);
    expect(result.status).toBe('ERROR');
    expect(result.failedStage).toBe('SEND');
    expect(result.error?.code).toBe('DOM_DELIVERY_EXCEPTION');
    expect(result.error?.message).toContain('Unexpected DOM mutation exception');
  });

  // ==========================================================================
  // 9. Zero Raw Sensitive-Value Leakage
  // ==========================================================================
  it('14. No raw sensitive-value leakage in boundary result or serialized output', async () => {
    const apiKey = 'sk-proj-CONFIDENTIALKEY1234567890ABCDEF123456';
    const email = 'target-user@secure-domain.org';
    const phone = '415-555-0199';
    const prompt = `Data: key=${apiKey}, email=${email}, phone=${phone}`;

    const extractor = new InMemoryDomInputExtractor({
      defaultText: prompt,
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier();

    const { boundary } = createBoundaryWithDetectors({ extractor, applier });

    const result = await boundary.execute({ url: 'https://chatgpt.com' });

    expect(result.ok).toBe(true);

    // If deliverableText is present (not blocked), ensure it does not leak secrets
    if (result.deliverableText) {
      expect(result.deliverableText).not.toContain(apiKey);
      expect(result.deliverableText).not.toContain(email);
      expect(result.deliverableText).not.toContain(phone);
    }

    // Serialized output must contain zero raw secrets
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(apiKey);
    expect(serialized).not.toContain(email);
    expect(serialized).not.toContain(phone);
  });

  // ==========================================================================
  // 10. Boundary Isolation & Headless Node Compatibility
  // ==========================================================================
  it('15. Core / browser boundary isolation: operates completely in headless Node environment', async () => {
    expect(typeof window).toBe('undefined');
    expect(typeof document).toBe('undefined');

    const extractor = new InMemoryDomInputExtractor({
      defaultText: 'Test headless isolation execution',
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier();

    const { boundary } = createBoundaryWithDetectors({ extractor, applier });
    const result = await boundary.execute({ url: 'https://claude.ai' });

    expect(result.ok).toBe(true);
    expect(result.status).toBe('ALLOW');
  });

  // ==========================================================================
  // 11. Determinism & Wall-Clock Independence
  // ==========================================================================
  it('16. Deterministic behavior: repeated identical executions produce identical outcomes', async () => {
    const fixedTimestamp = 1726200000000;
    const prompt = 'Determinism check across boundary execution.';

    const extractor1 = new InMemoryDomInputExtractor({
      defaultText: prompt,
      defaultPlatformContext,
    });
    const applier1 = new InMemoryDomOutputApplier();
    const { boundary: boundary1 } = createBoundaryWithDetectors({
      extractor: extractor1,
      applier: applier1,
      fixedTimestamp,
    });

    const extractor2 = new InMemoryDomInputExtractor({
      defaultText: prompt,
      defaultPlatformContext,
    });
    const applier2 = new InMemoryDomOutputApplier();
    const { boundary: boundary2 } = createBoundaryWithDetectors({
      extractor: extractor2,
      applier: applier2,
      fixedTimestamp,
    });

    const result1 = await boundary1.execute({ url: 'https://chatgpt.com' });
    const result2 = await boundary2.execute({ url: 'https://chatgpt.com' });

    expect(result1.status).toBe(result2.status);
    expect(result1.action).toBe(result2.action);
    expect(result1.deliverableText).toBe(result2.deliverableText);
    expect(result1.domDelivery?.deliveredAt).toBe(result2.domDelivery?.deliveredAt);
    expect(result1.domDelivery?.deliveredAt).toBe(fixedTimestamp);
  });

  // ==========================================================================
  // 12. Dependency Injection & M1.9 Regression
  // ==========================================================================
  it('17. Dependency injection & M1.9 regression: custom runtime is utilized and preserved', async () => {
    const customRuntime = createShieldRuntime({
      defaultPlatformContext,
    });

    const executeSpy = vi.spyOn(customRuntime, 'execute');

    const extractor = new InMemoryDomInputExtractor({
      defaultText: 'Spy check prompt',
      defaultPlatformContext,
    });
    const applier = new InMemoryDomOutputApplier();

    const boundary = createDomRuntimeBoundary({
      runtime: customRuntime,
      extractor,
      applier,
      defaultPlatformContext,
    });

    expect(boundary.underlyingRuntime).toBe(customRuntime);

    const result = await boundary.execute({ url: defaultPlatformContext.url! });

    expect(result.ok).toBe(true);
    expect(executeSpy).toHaveBeenCalledTimes(1);
    expect(executeSpy).toHaveBeenCalledWith('Spy check prompt', defaultPlatformContext);
  });
});
