import { describe, it, expect, vi } from 'vitest';
import {
  DeterministicDeliveryEngine,
  createDeliveryEngine,
  createSendEngine,
  InMemoryDeliverySink,
  type DeliverySink,
  type FinalDelivery,
  type PipelineContext,
  createPipelineOrchestrator,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultRiskEvaluator,
  createVerificationEngine,
  InMemorySender,
} from '../packages/core/src';

describe('M1.8 Shield Delivery Engine (Stage 9: SEND)', () => {
  const createMockContext = (overrides: Partial<PipelineContext> = {}): PipelineContext => ({
    id: overrides.id ?? 'ctx-test-123',
    timestamp: overrides.timestamp ?? 1726000000000,
    input: overrides.input ?? { text: 'Hello test input', platformId: 'generic' },
    normalized: overrides.normalized ?? {
      rawText: 'Hello test input',
      normalizedText: 'Hello test input',
      encoding: 'utf-8',
    },
    detections: overrides.detections,
    classification: overrides.classification,
    risk: overrides.risk ?? {
      score: 0,
      severity: 'NONE',
      confidence: 1.0,
      factors: [],
      summary: 'Clean input',
      evaluationTimestamp: 1726000000000,
    },
    policy: overrides.policy,
    transformation: overrides.transformation,
    verification: overrides.verification,
  });

  const createContextForText = (
    text: string,
    overrides: Partial<PipelineContext> = {},
  ): PipelineContext => ({
    id: overrides.id ?? 'ctx-test-123',
    timestamp: overrides.timestamp ?? 1726000000000,
    input: { text, platformId: 'generic' },
    normalized: { rawText: text, normalizedText: text, encoding: 'utf-8' },
    detections: overrides.detections,
    classification: overrides.classification,
    risk: overrides.risk ?? {
      score: 0,
      severity: 'NONE',
      confidence: 1.0,
      factors: [],
      summary: 'Clean input',
      evaluationTimestamp: 1726000000000,
    },
    policy: overrides.policy,
    transformation: overrides.transformation,
    verification: overrides.verification,
  });

  // ==========================================================================
  // 1. Basic Invariants & Instantiation
  // ==========================================================================
  describe('Basic Invariants & Instantiation', () => {
    it('instantiates DeterministicDeliveryEngine with default properties', () => {
      const engine = new DeterministicDeliveryEngine();
      expect(engine.id).toBe('shield-deterministic-delivery-engine');
      expect(engine.name).toBe('Shield Deterministic Delivery Engine');
      expect(engine.getReceipts()).toHaveLength(0);
      expect(engine.deliveries).toHaveLength(0);
    });

    it('factory createDeliveryEngine and alias createSendEngine work identically', () => {
      const engine1 = createDeliveryEngine();
      const engine2 = createSendEngine();
      expect(engine1).toBeInstanceOf(DeterministicDeliveryEngine);
      expect(engine2).toBeInstanceOf(DeterministicDeliveryEngine);
    });
  });

  // ==========================================================================
  // 2. Happy Path Delivery
  // ==========================================================================
  describe('Happy Path Delivery', () => {
    it('1. ALLOW delivery succeeds and records DELIVERED receipt', async () => {
      const engine = createDeliveryEngine();
      const text = 'Safe public query to AI';
      const context = createMockContext({
        normalized: { rawText: text, normalizedText: text, encoding: 'utf-8' },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: text,
        actionTaken: 'ALLOW',
        reason: 'No sensitive data detected',
      };

      await engine.send(delivery, context);

      expect(engine.deliveries).toHaveLength(1);
      expect(engine.deliveries[0]?.deliverableText).toBe(text);
      expect(engine.deliveries[0]?.actionTaken).toBe('ALLOW');

      const receipt = engine.getLastReceipt();
      expect(receipt).toBeDefined();
      expect(receipt?.status).toBe('DELIVERED');
      expect(receipt?.actionTaken).toBe('ALLOW');
      expect(receipt?.deliverableLength).toBe(text.length);
      expect(receipt?.contextId).toBe(context.id);
    });

    it('2. MASK delivery succeeds with verified transformation', async () => {
      const engine = createDeliveryEngine();
      const rawText = 'Contact: user@example.com';
      const maskedText = 'Contact: [REDACTED_PII]';

      const context = createMockContext({
        transformation: {
          originalText: rawText,
          transformedText: maskedText,
          isModified: true,
          transformationsApplied: [
            {
              entityId: 'det-1',
              type: 'MASK',
              originalRange: { startIndex: 9, endIndex: 25 },
              replacedRange: { startIndex: 9, endIndex: 25 },
              category: 'PII',
            },
          ],
        },
        verification: {
          status: 'SUCCESS',
          verified: true,
          residualRisk: {
            score: 0,
            severity: 'NONE',
            confidence: 1.0,
            factors: [],
            summary: 'Zero residual leaks',
            evaluationTimestamp: 1726000000000,
          },
          leaksDetected: false,
        },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: maskedText,
        actionTaken: 'MASK',
        reason: 'Sensitive PII masked',
      };

      await engine.send(delivery, context);

      expect(engine.deliveries).toHaveLength(1);
      expect(engine.deliveries[0]?.deliverableText).toBe(maskedText);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('DELIVERED');
      expect(receipt?.actionTaken).toBe('MASK');
      expect(receipt?.deliverableLength).toBe(maskedText.length);
    });

    it('3. sendSync executes synchronously and returns receipt', () => {
      const engine = createDeliveryEngine();
      const text = 'Immediate synchronous delivery';
      const context = createMockContext({
        normalized: { rawText: text, normalizedText: text, encoding: 'utf-8' },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: text,
        actionTaken: 'ALLOW',
      };

      const receipt = engine.sendSync(delivery, context);

      expect(receipt.status).toBe('DELIVERED');
      expect(receipt.actionTaken).toBe('ALLOW');
      expect(engine.deliveries).toHaveLength(1);
    });
  });

  // ==========================================================================
  // 3. Policy Invariants & Transmission Safety
  // ==========================================================================
  describe('Policy Invariants & Transmission Safety', () => {
    it('4. BLOCK delivery attempt throws error and records BLOCKED receipt', async () => {
      const engine = createDeliveryEngine();
      const context = createMockContext();

      const delivery: FinalDelivery = {
        canSend: false,
        actionTaken: 'BLOCK',
        reason: 'Prohibited credential detected',
      };

      await expect(engine.send(delivery, context)).rejects.toThrow(/Transmission prohibited/);

      // Sinks must NOT receive blocked delivery
      expect(engine.deliveries).toHaveLength(0);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('BLOCKED');
      expect(receipt?.actionTaken).toBe('BLOCK');
      expect(receipt?.reason).toBe('Prohibited credential detected');
    });

    it('5. WARN delivery attempt holds transmission and does not dispatch to sinks', async () => {
      const engine = createDeliveryEngine();
      const text = 'Internal project draft';
      const context = createMockContext();

      const delivery: FinalDelivery = {
        canSend: false,
        deliverableText: text,
        actionTaken: 'WARN',
        reason: 'Internal term detected, user confirmation required',
      };

      await engine.send(delivery, context);

      // Warning items must be held without dispatching to delivery sinks
      expect(engine.deliveries).toHaveLength(0);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('HELD');
      expect(receipt?.actionTaken).toBe('WARN');
      expect(receipt?.reason).toContain('Internal term detected');
    });

    it('6. canSend: false for non-WARN action throws and records BLOCKED receipt', async () => {
      const engine = createDeliveryEngine();
      const context = createMockContext();

      const delivery: FinalDelivery = {
        canSend: false,
        actionTaken: 'ALLOW', // Inconsistent: ALLOW but canSend: false
        reason: 'Transmission disallowed',
      };

      await expect(engine.send(delivery, context)).rejects.toThrow(/Transmission prohibited/);
      expect(engine.deliveries).toHaveLength(0);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('BLOCKED');
    });
  });

  // ==========================================================================
  // 4. Integrity & Tampering Checks
  // ==========================================================================
  describe('Integrity & Tampering Checks', () => {
    it('7. Missing deliverableText on ALLOW fails transmission', async () => {
      const engine = createDeliveryEngine();
      const context = createMockContext();

      const delivery: FinalDelivery = {
        canSend: true,
        actionTaken: 'ALLOW',
      };

      await expect(engine.send(delivery, context)).rejects.toThrow(/deliverableText is missing/);
      expect(engine.deliveries).toHaveLength(0);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('FAILED');
    });

    it('8. Unverified MASK deliverable fails transmission', async () => {
      const engine = createDeliveryEngine();
      const context = createMockContext({
        verification: {
          status: 'FAILED',
          verified: false,
          residualRisk: {
            score: 95,
            severity: 'CRITICAL',
            confidence: 1.0,
            factors: [],
            summary: 'Residual leak',
            evaluationTimestamp: 1726000000000,
          },
          leaksDetected: true,
        },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: 'Leaked sk-123456',
        actionTaken: 'MASK',
      };

      await expect(engine.send(delivery, context)).rejects.toThrow(/failed Stage 8 verification/);
      expect(engine.deliveries).toHaveLength(0);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('FAILED');
    });

    it('9. Tampered MASK deliverable (diverging from transformedText) fails transmission', async () => {
      const engine = createDeliveryEngine();
      const context = createMockContext({
        transformation: {
          originalText: 'Key: sk-123456',
          transformedText: 'Key: [REDACTED_API_KEY]',
          isModified: true,
          transformationsApplied: [],
        },
        verification: {
          status: 'SUCCESS',
          verified: true,
          residualRisk: {
            score: 0,
            severity: 'NONE',
            confidence: 1.0,
            factors: [],
            summary: 'Clean',
            evaluationTimestamp: 1726000000000,
          },
          leaksDetected: false,
        },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: 'Key: tampered-different-text',
        actionTaken: 'MASK',
      };

      await expect(engine.send(delivery, context)).rejects.toThrow(
        /diverges from verified transformedText/,
      );
      expect(engine.deliveries).toHaveLength(0);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('FAILED');
    });

    it('10. Tampered ALLOW deliverable (diverging from normalizedText) fails transmission', async () => {
      const engine = createDeliveryEngine();
      const context = createMockContext({
        normalized: {
          rawText: 'Original text',
          normalizedText: 'Original text',
          encoding: 'utf-8',
        },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: 'Altered different text',
        actionTaken: 'ALLOW',
      };

      await expect(engine.send(delivery, context)).rejects.toThrow(
        /diverges from normalized deliverable/,
      );
      expect(engine.deliveries).toHaveLength(0);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('FAILED');
    });
  });

  // ==========================================================================
  // 5. Custom Sinks & Multi-Sink Dispatch
  // ==========================================================================
  describe('Custom Sinks & Multi-Sink Dispatch', () => {
    it('11. Custom DeliverySink receives delivery and context', async () => {
      const customSink: DeliverySink = {
        id: 'custom-logger-sink',
        deliver: vi.fn(),
      };

      const engine = createDeliveryEngine({ sinks: [customSink] });
      const text = 'Hello custom sink';
      const context = createContextForText(text);

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: text,
        actionTaken: 'ALLOW',
      };

      await engine.send(delivery, context);

      expect(customSink.deliver).toHaveBeenCalledTimes(1);
      expect(customSink.deliver).toHaveBeenCalledWith(delivery, context);
      expect(engine.getSinkIds()).toContain('custom-logger-sink');
    });

    it('12. Multiple sinks are invoked in strict registration order', async () => {
      const executionOrder: string[] = [];

      const sink1: DeliverySink = {
        id: 'sink-first',
        deliver: async () => {
          executionOrder.push('first');
        },
      };

      const sink2: DeliverySink = {
        id: 'sink-second',
        deliver: async () => {
          executionOrder.push('second');
        },
      };

      const engine = createDeliveryEngine();
      engine.registerSink(sink1);
      engine.registerSink(sink2);

      const text = 'Order test';
      const context = createContextForText(text);
      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: text,
        actionTaken: 'ALLOW',
      };

      await engine.send(delivery, context);

      expect(executionOrder).toEqual(['first', 'second']);
    });

    it('13. Unregistering a sink prevents subsequent dispatch to it', async () => {
      const customSink = new InMemoryDeliverySink('removable-sink');
      const engine = createDeliveryEngine();

      engine.registerSink(customSink);
      expect(engine.getSinkIds()).toContain('removable-sink');

      const removed = engine.unregisterSink('removable-sink');
      expect(removed).toBe(true);
      expect(engine.getSinkIds()).not.toContain('removable-sink');

      const text = 'Test';
      const context = createContextForText(text);
      await engine.send({ canSend: true, deliverableText: text, actionTaken: 'ALLOW' }, context);

      expect(customSink.capturedDeliveries).toHaveLength(0);
    });

    it('14. Sink failure produces FAILED receipt and rethrows error', async () => {
      const failingSink: DeliverySink = {
        id: 'failing-sink',
        deliver: () => {
          throw new Error('Sink network timeout');
        },
      };

      const engine = createDeliveryEngine({ sinks: [failingSink] });
      const text = 'Test';
      const context = createContextForText(text);

      await expect(
        engine.send({ canSend: true, deliverableText: text, actionTaken: 'ALLOW' }, context),
      ).rejects.toThrow(/Sink network timeout/);

      const receipt = engine.getLastReceipt();
      expect(receipt?.status).toBe('FAILED');
      expect(receipt?.reason).toContain('Sink network timeout');
      expect(receipt?.sinkIds).toContain('failing-sink');
    });
  });

  // ==========================================================================
  // 6. Input Boundaries & Edge Cases
  // ==========================================================================
  describe('Input Boundaries & Edge Cases', () => {
    it('15. Empty string deliverable sends cleanly', async () => {
      const engine = createDeliveryEngine();
      const context = createMockContext({
        normalized: { rawText: '', normalizedText: '', encoding: 'utf-8' },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: '',
        actionTaken: 'ALLOW',
      };

      await engine.send(delivery, context);

      expect(engine.deliveries).toHaveLength(1);
      expect(engine.deliveries[0]?.deliverableText).toBe('');
      const receipt = engine.getLastReceipt();
      expect(receipt?.deliverableLength).toBe(0);
      expect(receipt?.status).toBe('DELIVERED');
    });

    it('16. Large text prompt (100KB) delivers without truncation', async () => {
      const engine = createDeliveryEngine();
      const largeText = 'A'.repeat(100_000);
      const context = createMockContext({
        normalized: { rawText: largeText, normalizedText: largeText, encoding: 'utf-8' },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: largeText,
        actionTaken: 'ALLOW',
      };

      await engine.send(delivery, context);

      expect(engine.deliveries[0]?.deliverableText?.length).toBe(100_000);
      const receipt = engine.getLastReceipt();
      expect(receipt?.deliverableLength).toBe(100_000);
    });

    it('17. Multiline, Unicode, emoji, and tab characters preserved intact', async () => {
      const engine = createDeliveryEngine();
      const specialText = 'Line 1\n\tLine 2 with 🛡️ Shield & 日本語';
      const context = createMockContext({
        normalized: { rawText: specialText, normalizedText: specialText, encoding: 'utf-8' },
      });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: specialText,
        actionTaken: 'ALLOW',
      };

      await engine.send(delivery, context);

      expect(engine.deliveries[0]?.deliverableText).toBe(specialText);
    });
  });

  // ==========================================================================
  // 7. Receipt History & Management
  // ==========================================================================
  describe('Receipt History & Management', () => {
    it('18. getReceipts and clearHistory function as expected', async () => {
      const engine = createDeliveryEngine();

      await engine.send(
        { canSend: true, deliverableText: 'D1', actionTaken: 'ALLOW' },
        createContextForText('D1'),
      );
      await engine.send(
        { canSend: true, deliverableText: 'D2', actionTaken: 'ALLOW' },
        createContextForText('D2'),
      );

      expect(engine.getReceipts()).toHaveLength(2);
      expect(engine.deliveries).toHaveLength(2);

      engine.clearHistory();

      expect(engine.getReceipts()).toHaveLength(0);
      expect(engine.deliveries).toHaveLength(0);
      expect(engine.getLastReceipt()).toBeUndefined();
    });

    it('19. maxHistorySize truncates oldest receipts', async () => {
      const engine = createDeliveryEngine({ maxHistorySize: 3 });

      for (let i = 1; i <= 5; i++) {
        await engine.send(
          { canSend: true, deliverableText: `D${i}`, actionTaken: 'ALLOW' },
          createContextForText(`D${i}`),
        );
      }

      expect(engine.getReceipts()).toHaveLength(3);
      // Last receipt corresponds to D5
      expect(engine.getLastReceipt()?.deliverableLength).toBe(2);
    });
  });

  // ==========================================================================
  // 8. Security & Non-Leakage
  // ==========================================================================
  describe('Security & Non-Leakage', () => {
    it('20. Raw secrets never appear in delivery receipts or reasons', async () => {
      const engine = createDeliveryEngine();
      const rawApiKey = 'sk-proj-SUPERSECRET1234567890';
      const context = createMockContext();

      const delivery: FinalDelivery = {
        canSend: false,
        actionTaken: 'BLOCK',
        reason: 'Blocked by Rule: API_KEY_CRITICAL', // Safe reason without raw secret
      };

      await expect(engine.send(delivery, context)).rejects.toThrow();

      const receipt = engine.getLastReceipt();
      expect(receipt).toBeDefined();

      const serializedReceipt = JSON.stringify(receipt);
      expect(serializedReceipt).not.toContain(rawApiKey);
      expect(serializedReceipt).not.toContain('SUPERSECRET');
    });

    it('21. Serialized delivery history contains zero raw sensitive values', async () => {
      const engine = createDeliveryEngine();
      const rawEmail = 'sensitive.ceo@corporation.internal';
      const maskedEmail = '[REDACTED_PII]';

      const context = createMockContext({
        transformation: {
          originalText: `Contact ${rawEmail}`,
          transformedText: `Contact ${maskedEmail}`,
          isModified: true,
          transformationsApplied: [],
        },
        verification: {
          status: 'SUCCESS',
          verified: true,
          residualRisk: {
            score: 0,
            severity: 'NONE',
            confidence: 1.0,
            factors: [],
            summary: 'Clean',
            evaluationTimestamp: 1726000000000,
          },
          leaksDetected: false,
        },
      });

      await engine.send(
        {
          canSend: true,
          deliverableText: `Contact ${maskedEmail}`,
          actionTaken: 'MASK',
          reason: 'PII masked per policy',
        },
        context,
      );

      const receipts = engine.getReceipts();
      const serializedReceipts = JSON.stringify(receipts);
      expect(serializedReceipts).not.toContain(rawEmail);

      const deliveries = engine.deliveries;
      const serializedDeliveries = JSON.stringify(deliveries);
      expect(serializedDeliveries).not.toContain(rawEmail);
      expect(serializedDeliveries).toContain(maskedEmail);
    });
  });

  // ==========================================================================
  // 9. Determinism
  // ==========================================================================
  describe('Determinism', () => {
    it('22. Identical delivery inputs produce identical receipts', () => {
      const engine1 = createDeliveryEngine();
      const engine2 = createDeliveryEngine();

      const context = createContextForText('Deterministic prompt', {
        id: 'stable-ctx-1',
        timestamp: 1726000000000,
      });
      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: 'Deterministic prompt',
        actionTaken: 'ALLOW',
      };

      const r1 = engine1.sendSync(delivery, context);
      const r2 = engine2.sendSync(delivery, context);

      expect(r1.status).toBe(r2.status);
      expect(r1.actionTaken).toBe(r2.actionTaken);
      expect(r1.timestamp).toBe(r2.timestamp);
      expect(r1.deliverableLength).toBe(r2.deliverableLength);
      expect(r1.contextId).toBe(r2.contextId);
    });

    it('23. Delivery decisions contain zero wall-clock time dependency', () => {
      const engine = createDeliveryEngine();
      const fixedTimestamp = 1600000000000;
      const context = createContextForText('Timestamp test', { timestamp: fixedTimestamp });

      const delivery: FinalDelivery = {
        canSend: true,
        deliverableText: 'Timestamp test',
        actionTaken: 'ALLOW',
      };

      const receipt = engine.sendSync(delivery, context);
      expect(receipt.timestamp).toBe(fixedTimestamp);
    });
  });

  // ==========================================================================
  // 10. Pipeline Orchestrator Integration
  // ==========================================================================
  describe('Pipeline Orchestrator Integration', () => {
    const createBaseInput = (rawText: string) => ({
      rawText,
      timestamp: 1726000000000,
      platformContext: {
        site: 'chatgpt.com',
        isAiSite: true,
        url: 'https://chatgpt.com/c/12345',
      },
      metadata: { requestId: 'req-001' },
    });

    it('24. Full pipeline integration with ALLOW: delivers clean text to delivery engine', async () => {
      const deliveryEngine = createDeliveryEngine();

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [],
            hasDetections: false,
            durationMs: 1,
          })),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'ALLOW',
            reason: 'Clean input allowed',
            triggeredRules: [],
            allowOverride: false,
          })),
        },
        transformer: {
          transform: vi.fn(async (norm) => ({
            originalText: norm.normalizedText,
            transformedText: norm.normalizedText,
            isModified: false,
            transformationsApplied: [],
          })),
        },
        verifier: createVerificationEngine(),
        sender: deliveryEngine,
      });

      const result = await orchestrator.process(createBaseInput('Public query for assistant'));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result');
      expect(result.value.status).toBe('ALLOW');

      expect(deliveryEngine.deliveries).toHaveLength(1);
      expect(deliveryEngine.deliveries[0]?.deliverableText).toBe('Public query for assistant');

      const receipt = deliveryEngine.getLastReceipt();
      expect(receipt?.status).toBe('DELIVERED');
      expect(receipt?.actionTaken).toBe('ALLOW');
    });

    it('25. Full pipeline integration with MASK: delivers masked text to delivery engine', async () => {
      const deliveryEngine = createDeliveryEngine();
      const rawSecret = 'sk-secret-token-12345';
      const prompt = `Key is ${rawSecret}`;
      const maskedPrompt = 'Key is [REDACTED_API_KEY]';

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [
              {
                id: 'det-1',
                detectorId: 'detector-key',
                category: 'API_KEY' as const,
                severity: 'CRITICAL' as const,
                confidence: 0.99,
                range: { startIndex: 7, endIndex: 7 + rawSecret.length },
                evidence: { tokenLength: rawSecret.length, hasRawValue: true },
                rawValue: rawSecret,
              },
            ],
            hasDetections: true,
            durationMs: 2,
          })),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask credentials',
            triggeredRules: ['rule-mask'],
            allowOverride: false,
          })),
        },
        transformer: {
          transform: vi.fn(async () => ({
            originalText: prompt,
            transformedText: maskedPrompt,
            isModified: true,
            transformationsApplied: [
              {
                entityId: 'det-1',
                type: 'MASK' as const,
                originalRange: { startIndex: 7, endIndex: 7 + rawSecret.length },
                replacedRange: { startIndex: 7, endIndex: 7 + '[REDACTED_API_KEY]'.length },
                category: 'API_KEY' as const,
              },
            ],
          })),
        },
        verifier: createVerificationEngine(),
        sender: deliveryEngine,
      });

      const result = await orchestrator.process(createBaseInput(prompt));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result');
      expect(result.value.status).toBe('MASK');

      expect(deliveryEngine.deliveries).toHaveLength(1);
      expect(deliveryEngine.deliveries[0]?.deliverableText).toBe(maskedPrompt);

      const receipt = deliveryEngine.getLastReceipt();
      expect(receipt?.status).toBe('DELIVERED');
      expect(receipt?.actionTaken).toBe('MASK');
    });

    it('26. Full pipeline integration with BLOCK: never delivers to delivery engine', async () => {
      const deliveryEngine = createDeliveryEngine();

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [],
            hasDetections: true,
            durationMs: 1,
          })),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'BLOCK',
            reason: 'Policy block',
            triggeredRules: ['rule-block'],
            allowOverride: false,
          })),
        },
        transformer: {
          transform: vi.fn(),
        },
        verifier: createVerificationEngine(),
        sender: deliveryEngine,
      });

      const result = await orchestrator.process(createBaseInput('Blocked prompt'));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result');
      expect(result.value.status).toBe('BLOCK');

      // BLOCK action must never invoke sender.send
      expect(deliveryEngine.deliveries).toHaveLength(0);
    });

    it('27. Full pipeline integration with WARN: never delivers automatically', async () => {
      const deliveryEngine = createDeliveryEngine();

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [],
            hasDetections: true,
            durationMs: 1,
          })),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'WARN',
            reason: 'Review required',
            triggeredRules: ['rule-warn'],
            allowOverride: true,
          })),
        },
        transformer: {
          transform: vi.fn(),
        },
        verifier: createVerificationEngine(),
        sender: deliveryEngine,
      });

      const result = await orchestrator.process(createBaseInput('Warning prompt'));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result');
      expect(result.value.status).toBe('WARN');

      // WARN action must never invoke sender.send automatically
      expect(deliveryEngine.deliveries).toHaveLength(0);
    });

    it('28. Failed verification in Stage 8 halts pipeline before Stage 9 SEND', async () => {
      const deliveryEngine = createDeliveryEngine();
      const brokenTransformer = {
        transform: vi.fn(async (norm) => ({
          originalText: norm.normalizedText,
          transformedText: 'Unchanged with sk-leak-key', // Failed redaction
          isModified: true,
          transformationsApplied: [
            {
              entityId: 'det-1',
              type: 'MASK' as const,
              originalRange: { startIndex: 15, endIndex: 26 },
              replacedRange: { startIndex: 15, endIndex: 26 },
              category: 'API_KEY' as const,
            },
          ],
        })),
      };

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [
              {
                id: 'det-1',
                detectorId: 'detector-test',
                category: 'API_KEY' as const,
                severity: 'CRITICAL' as const,
                confidence: 0.99,
                range: { startIndex: 15, endIndex: 26 },
                evidence: { tokenLength: 11, hasRawValue: true },
                rawValue: 'sk-leak-key',
              },
            ],
            hasDetections: true,
            durationMs: 2,
          })),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask key',
            triggeredRules: ['rule-mask'],
            allowOverride: false,
          })),
        },
        transformer: brokenTransformer,
        verifier: createVerificationEngine(),
        sender: deliveryEngine,
      });

      const result = await orchestrator.process(createBaseInput('Unchanged with sk-leak-key'));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result');
      expect(result.value.status).toBe('ERROR');
      if (result.value.status === 'ERROR') {
        expect(result.value.failedStage).toBe('VERIFY');
      }

      // SENDER MUST NEVER RECEIVE TRANSMISSION WHEN VERIFICATION FAILS
      expect(deliveryEngine.deliveries).toHaveLength(0);
    });

    it('29. Backward compatibility: existing InMemorySender continues to work', async () => {
      const memorySender = new InMemorySender();

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [],
            hasDetections: false,
            durationMs: 1,
          })),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'ALLOW',
            reason: 'Allowed',
            triggeredRules: [],
            allowOverride: false,
          })),
        },
        transformer: {
          transform: vi.fn(async (norm) => ({
            originalText: norm.normalizedText,
            transformedText: norm.normalizedText,
            isModified: false,
            transformationsApplied: [],
          })),
        },
        verifier: createVerificationEngine(),
        sender: memorySender,
      });

      const result = await orchestrator.process(createBaseInput('Test backward compat'));

      expect(result.ok).toBe(true);
      expect(memorySender.deliveries).toHaveLength(1);
    });
  });
});
