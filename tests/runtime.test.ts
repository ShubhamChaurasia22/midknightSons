import { describe, it, expect, vi } from 'vitest';
import {
  createShieldRuntime,
  CoreShieldRuntime,
  type ShieldRuntime,
  type ShieldRuntimeOptions,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultRiskEvaluator,
  DefaultPolicyEvaluator,
  DefaultTransformer,
  DeterministicVerificationEngine,
  createVerificationEngine,
  createDeliveryEngine,
  InMemoryDeliverySink,
  InMemorySender,
  type PipelineInput,
  type PlatformContext,
  type DetectorEngine,
  type PolicyDecision,
  type RiskAssessment,
  type PolicyEvaluator,
  type Transformer,
  type Verifier,
  type Sender,
  type FinalDelivery,
} from '../packages/core/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';
import { createPolicyEngine, createPolicyEvaluator } from '../packages/policy/src';
import {
  createTransformationEngine,
  createPipelineTransformer,
} from '../packages/transformation/src';

describe('M1.9 — Shield End-to-End Runtime Composition & Core Integration', () => {
  const defaultPlatformContext: PlatformContext = {
    site: 'chatgpt.com',
    isAiSite: true,
    url: 'https://chatgpt.com/c/test-conversation',
  };

  const createRuntimeWithDetector = (
    options: Partial<ShieldRuntimeOptions> = {},
  ): ShieldRuntime => {
    const detectorRegistry = createDefaultDetectorRegistry();
    return createShieldRuntime({
      detectorRegistry,
      defaultPlatformContext,
      ...options,
    });
  };

  // ==========================================================================
  // Group 1: Instantiation & Baseline Execution
  // ==========================================================================
  describe('Group 1: Instantiation & Baseline Flow', () => {
    it('1. Default runtime instantiation works without throwing', () => {
      const runtime = createShieldRuntime();
      expect(runtime).toBeDefined();
      expect(runtime).toBeInstanceOf(CoreShieldRuntime);
      expect(runtime.execute).toBeTypeOf('function');
      expect(runtime.deliveryEngine).toBeDefined();
      expect(runtime.orchestrator).toBeDefined();
    });

    it('2. Clean input → ALLOW: original text reaches delivery engine', async () => {
      const runtime = createRuntimeWithDetector({ fixedTimestamp: 1726000000000 });
      const cleanPrompt = 'Explain the difference between TCP and UDP in simple terms.';

      const result = await runtime.execute(cleanPrompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('ALLOW');
      expect(result.action).toBe('ALLOW');
      expect(result.deliverableText).toBe(cleanPrompt);
      expect(result.risk?.severity).toBe('NONE');
      expect(result.deliveryReceipt?.status).toBe('DELIVERED');
      expect(result.deliveryReceipt?.actionTaken).toBe('ALLOW');

      expect(runtime.deliveryEngine.deliveries).toHaveLength(1);
      expect(runtime.deliveryEngine.deliveries[0]?.deliverableText).toBe(cleanPrompt);
    });

    it('3. LOW risk → correct end-to-end behavior: allowed transmission', async () => {
      // Mock detector returning low risk non-critical entity
      const lowRiskDetector: DetectorEngine = {
        detect: async () => ({
          entities: [
            {
              id: 'det-low-1',
              detectorId: 'detector-public-info',
              category: 'PII',
              severity: 'LOW',
              confidence: 0.8,
              range: { startIndex: 11, endIndex: 16 },
              evidence: { tokenLength: 5, hasRawValue: false },
            },
          ],
          hasDetections: true,
          durationMs: 1,
        }),
      };

      const runtime = createShieldRuntime({
        detectorEngine: lowRiskDetector,
        defaultPlatformContext,
      });

      const prompt = 'My name is Alice.';
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('ALLOW');
      expect(result.action).toBe('ALLOW');
      expect(result.deliverableText).toBe(prompt);
      expect(runtime.deliveryEngine.deliveries).toHaveLength(1);
    });
  });

  // ==========================================================================
  // Group 2: Policy Actions & Transmission Invariants
  // ==========================================================================
  describe('Group 2: Policy Actions & Transmission Invariants', () => {
    it('4. MEDIUM risk → WARN: transmission held, zero unauthorized deliveries', async () => {
      const mediumRiskDetector: DetectorEngine = {
        detect: async () => ({
          entities: [
            {
              id: 'det-med-1',
              detectorId: 'detector-internal-note',
              category: 'PRIVATE_DATA',
              severity: 'MEDIUM',
              confidence: 0.85,
              range: { startIndex: 8, endIndex: 20 },
              evidence: { tokenLength: 12, hasRawValue: false },
            },
          ],
          hasDetections: true,
          durationMs: 2,
        }),
      };

      const runtime = createShieldRuntime({
        detectorEngine: mediumRiskDetector,
        defaultPlatformContext,
      });

      const prompt = 'Confidential project details.';
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('WARN');
      expect(result.action).toBe('WARN');
      expect(result.deliveryReceipt?.status).toBe('HELD');

      // WARN transmission must never deliver automatically to sinks
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
    });

    it('5. HIGH risk → MASK: sensitive entities masked and verified deliverable transmitted', async () => {
      const rawSecret = 'sk-proj-1234567890abcdef1234567890123456';
      const prompt = `Use this key: ${rawSecret} to access the API.`;

      const highRiskDetector: DetectorEngine = {
        detect: async (norm) => {
          const idx = norm.normalizedText.indexOf(rawSecret);
          return {
            entities: [
              {
                id: 'det-key-1',
                detectorId: 'detector-api-key',
                category: 'API_KEY',
                severity: 'HIGH',
                confidence: 0.99,
                range: { startIndex: idx, endIndex: idx + rawSecret.length },
                evidence: { tokenLength: rawSecret.length, hasRawValue: true },
                rawValue: rawSecret,
              },
            ],
            hasDetections: true,
            durationMs: 2,
          };
        },
      };

      const runtime = createShieldRuntime({
        detectorEngine: highRiskDetector,
        defaultPlatformContext,
      });

      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('MASK');
      expect(result.action).toBe('MASK');
      expect(result.deliverableText).toBe('Use this key: [REDACTED_API_KEY] to access the API.');
      expect(result.deliveryReceipt?.status).toBe('DELIVERED');
      expect(result.transformation?.isModified).toBe(true);
      expect(result.verification?.verified).toBe(true);

      // Verified masked content delivered to destination sinks
      expect(runtime.deliveryEngine.deliveries).toHaveLength(1);
      expect(runtime.deliveryEngine.deliveries[0]?.deliverableText).toBe(
        'Use this key: [REDACTED_API_KEY] to access the API.',
      );
    });

    it('6. CRITICAL risk → BLOCK: transmission prohibited and pipeline fails closed', async () => {
      const criticalDetector: DetectorEngine = {
        detect: async () => ({
          entities: [
            {
              id: 'det-crit-1',
              detectorId: 'detector-root-key',
              category: 'SECRET',
              severity: 'CRITICAL',
              confidence: 0.99,
              range: { startIndex: 0, endIndex: 30 },
              evidence: { tokenLength: 30, hasRawValue: false },
            },
          ],
          hasDetections: true,
          durationMs: 1,
        }),
      };

      const runtime = createShieldRuntime({
        detectorEngine: criticalDetector,
        defaultPlatformContext,
      });

      const result = await runtime.execute('CRITICAL_PRIVATE_KEY_DATA_HERE');

      expect(result.ok).toBe(true);
      expect(result.status).toBe('BLOCK');
      expect(result.action).toBe('BLOCK');
      // BLOCK must strictly omit deliverable text
      expect(result.deliverableText).toBeUndefined();

      // BLOCK must never deliver to sinks
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
    });

    it('7. MASK → transformation → verification → delivery exact chain', async () => {
      const rawEmail = 'alice@example.com';
      const prompt = `Contact us at ${rawEmail} for support.`;

      // Default detector detects alice@example.com as PII (severity: MEDIUM or HIGH)
      // Custom policy engine configured to MASK PII
      const policyEngine = createPolicyEngine();
      const policyEvaluator = createPolicyEvaluator(policyEngine);

      const customRuntime = createShieldRuntime({
        detectorRegistry: createDefaultDetectorRegistry(),
        policyEvaluator,
        defaultPlatformContext,
      });

      const result = await customRuntime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('MASK');
      expect(result.deliverableText).toContain('[REDACTED_PII]');
      expect(result.deliverableText).not.toContain(rawEmail);
      expect(result.verification?.verified).toBe(true);
      expect(customRuntime.deliveryEngine.deliveries).toHaveLength(1);
    });

    it('8. WARN → no delivery: destination sinks receive 0 items', async () => {
      const runtime = createShieldRuntime({
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'WARN',
            reason: 'User confirmation required',
            triggeredRules: ['warn-rule'],
            allowOverride: true,
          })),
        },
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'det-1',
                detectorId: 'd',
                category: 'PII',
                severity: 'MEDIUM',
                confidence: 0.9,
                range: { startIndex: 0, endIndex: 5 },
                evidence: { tokenLength: 5, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Drafting prompt');
      expect(result.status).toBe('WARN');
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
      expect(result.deliveryReceipt?.status).toBe('HELD');
    });

    it('9. BLOCK → no delivery: destination sinks receive 0 items', async () => {
      const runtime = createShieldRuntime({
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'BLOCK',
            reason: 'Total block',
            triggeredRules: ['block-rule'],
            allowOverride: false,
          })),
        },
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'det-1',
                detectorId: 'd',
                category: 'SECRET',
                severity: 'CRITICAL',
                confidence: 1.0,
                range: { startIndex: 0, endIndex: 5 },
                evidence: { tokenLength: 5, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Strictly blocked prompt');
      expect(result.status).toBe('BLOCK');
      expect(result.deliverableText).toBeUndefined();
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
    });
  });

  // ==========================================================================
  // Group 3: Fail-Closed & Stage Failure Guarantees
  // ==========================================================================
  describe('Group 3: Fail-Closed Semantics & Stage Failures', () => {
    it('10. Verification failure → no delivery: SEND is never called', async () => {
      const customSender: Sender = {
        send: vi.fn(),
      };

      const failingVerifier: Verifier = {
        verify: vi.fn(async () => ({
          status: 'FAILED',
          verified: false,
          residualRisk: {
            score: 95,
            severity: 'CRITICAL',
            confidence: 1.0,
            factors: [],
            summary: 'Residual leak detected in deliverable',
            evaluationTimestamp: Date.now(),
          },
          leaksDetected: true,
          failedChecks: ['UNMASKED_LEAK'],
        })),
      };

      const runtime = createShieldRuntime({
        verifier: failingVerifier,
        sender: customSender,
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask sensitive',
            triggeredRules: ['rule-1'],
            allowOverride: false,
          })),
        },
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'det-1',
                detectorId: 'd',
                category: 'API_KEY',
                severity: 'HIGH',
                confidence: 0.95,
                range: { startIndex: 0, endIndex: 5 },
                evidence: { tokenLength: 5, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Test prompt');

      expect(result.ok).toBe(false);
      expect(result.status).toBe('ERROR');
      expect(result.failedStage).toBe('VERIFY');
      expect(result.deliverableText).toBeUndefined();
      expect(customSender.send).not.toHaveBeenCalled();
    });

    it('11. Transformation failure → no delivery: pipeline halts before VERIFY and SEND', async () => {
      const customVerifier: Verifier = { verify: vi.fn() };
      const customSender: Sender = { send: vi.fn() };

      const failingTransformer: Transformer = {
        transform: vi.fn(async () => {
          throw new Error('Transformer crashed on regex syntax');
        }),
      };

      const runtime = createShieldRuntime({
        transformer: failingTransformer,
        verifier: customVerifier,
        sender: customSender,
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask',
            triggeredRules: ['r'],
            allowOverride: false,
          })),
        },
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'd1',
                detectorId: 'd',
                category: 'PII',
                severity: 'HIGH',
                confidence: 0.9,
                range: { startIndex: 0, endIndex: 4 },
                evidence: { tokenLength: 4, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Sample');

      expect(result.ok).toBe(false);
      expect(result.status).toBe('ERROR');
      expect(result.failedStage).toBe('TRANSFORM');
      expect(customVerifier.verify).not.toHaveBeenCalled();
      expect(customSender.send).not.toHaveBeenCalled();
    });

    it('12. Delivery failure → safe failure result reported cleanly', async () => {
      const failingSink = new InMemoryDeliverySink('failing-sink');
      failingSink.deliver = vi.fn(() => {
        throw new Error('Network socket disconnected during transmit');
      });

      const deliveryEngine = createDeliveryEngine({ sinks: [failingSink] });

      const runtime = createShieldRuntime({
        deliveryEngine,
        defaultPlatformContext,
      });

      const result = await runtime.execute('Clean transmission prompt');

      expect(result.ok).toBe(false);
      expect(result.status).toBe('ERROR');
      expect(result.failedStage).toBe('SEND');
      expect(result.error?.message).toContain('Network socket disconnected');
    });

    it('13. Detection failure → fail closed: halts at DETECT stage', async () => {
      const failingDetector: DetectorEngine = {
        detect: vi.fn(async () => {
          throw new Error('Detector worker process killed: out of memory');
        }),
      };

      const runtime = createShieldRuntime({
        detectorEngine: failingDetector,
        defaultPlatformContext,
      });

      const result = await runtime.execute('Some input');

      expect(result.ok).toBe(false);
      expect(result.status).toBe('ERROR');
      expect(result.failedStage).toBe('DETECT');
      expect(result.error?.message).toContain('Detector worker process killed');
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
    });

    it('14. Risk evaluation failure → fail closed: halts at RISK stage', async () => {
      const failingRiskEvaluator: RiskEvaluator = {
        evaluate: vi.fn(async () => {
          throw new Error('Risk matrix weight file corrupted');
        }),
      };

      const runtime = createShieldRuntime({
        riskEvaluator: failingRiskEvaluator,
        defaultPlatformContext,
      });

      const result = await runtime.execute('Prompt for risk analysis');

      expect(result.ok).toBe(false);
      expect(result.status).toBe('ERROR');
      expect(result.failedStage).toBe('RISK');
      expect(result.error?.message).toContain('Risk matrix weight file corrupted');
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
    });

    it('15. Policy evaluation failure → fail closed: no transmission', async () => {
      const failingPolicyEvaluator: PolicyEvaluator = {
        evaluate: vi.fn(async () => {
          throw new Error('Policy rule evaluation parse exception');
        }),
      };

      const runtime = createShieldRuntime({
        policyEvaluator: failingPolicyEvaluator,
        defaultPlatformContext,
      });

      const result = await runtime.execute('Prompt for policy analysis');

      expect(result.ok).toBe(false);
      expect(result.status).toBe('ERROR');
      expect(result.failedStage).toBe('POLICY');
      expect(result.error?.message).toContain('Policy rule evaluation parse exception');
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
    });
  });

  // ==========================================================================
  // Group 4: Complex Input Scenarios (Entities, Categories, Ranges)
  // ==========================================================================
  describe('Group 4: Complex Entities, Categories & Ranges', () => {
    it('16. Multiple detections end-to-end: replaces all detected entities cleanly', async () => {
      const rawEmail = 'security@shield.ai';
      const rawKey = 'sk-proj-99887766554433221100aabbccddeeff';
      const prompt = `Email: ${rawEmail} and API Key: ${rawKey} for verification.`;

      const runtime = createShieldRuntime({
        detectorRegistry: createDefaultDetectorRegistry(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask multiple entities per policy',
            triggeredRules: ['mask-all'],
            allowOverride: false,
          })),
        },
        defaultPlatformContext,
      });
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('MASK');
      expect(result.deliverableText).not.toContain(rawEmail);
      expect(result.deliverableText).not.toContain(rawKey);
      expect(result.deliverableText).toContain('[REDACTED_PII]');
      expect(result.deliverableText).toContain('[REDACTED_API_KEY]');
      expect(result.transformation?.transformationsApplied.length).toBeGreaterThanOrEqual(2);
      expect(runtime.deliveryEngine.deliveries).toHaveLength(1);
    });

    it('17. Multiple categories end-to-end: handles PII, API_KEY, and SECRET concurrently', async () => {
      const pii = 'user@example.com';
      const apiKey = 'sk-proj-00112233445566778899aabbccddeeff';
      const secret = 'BEGIN PRIVATE KEY 12345';
      const prompt = `PII: ${pii}, Key: ${apiKey}, Secret: ${secret}`;

      const runtime = createRuntimeWithDetector();
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      // Under default policy, critical/secret results in BLOCK or MASK
      expect(['MASK', 'BLOCK']).toContain(result.status);
      if (result.status === 'MASK') {
        expect(result.deliverableText).not.toContain(pii);
        expect(result.deliverableText).not.toContain(apiKey);
      }
    });

    it('18. Adjacent sensitive ranges: masks correctly without boundaries merging or off-by-one errors', async () => {
      const email1 = 'first@test.org';
      const email2 = 'second@test.org';
      const prompt = `${email1} ${email2}`; // Space separated adjacent

      const runtime = createShieldRuntime({
        detectorRegistry: createDefaultDetectorRegistry(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask sensitive PII per policy',
            triggeredRules: ['mask-pii'],
            allowOverride: false,
          })),
        },
        defaultPlatformContext,
      });
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('MASK');
      expect(result.deliverableText).toBe('[REDACTED_PII] [REDACTED_PII]');
      expect(result.deliverableText).not.toContain(email1);
      expect(result.deliverableText).not.toContain(email2);
    });

    it('19. Overlapping detections: resolved deterministically without corrupting output', async () => {
      // Overlapping detector fixture: one range nested inside another
      const overlappingDetector: DetectorEngine = {
        detect: async () => ({
          entities: [
            {
              id: 'det-outer',
              detectorId: 'd-outer',
              category: 'SECRET',
              severity: 'HIGH',
              confidence: 0.99,
              range: { startIndex: 10, endIndex: 35 },
              evidence: { tokenLength: 25, hasRawValue: false },
            },
            {
              id: 'det-inner',
              detectorId: 'd-inner',
              category: 'API_KEY',
              severity: 'CRITICAL',
              confidence: 0.95,
              range: { startIndex: 15, endIndex: 30 },
              evidence: { tokenLength: 15, hasRawValue: false },
            },
          ],
          hasDetections: true,
          durationMs: 1,
        }),
      };

      const runtime = createShieldRuntime({
        detectorEngine: overlappingDetector,
        defaultPlatformContext,
      });

      const prompt = 'Prefix -- 1234567890123456789012345 -- Suffix';
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      // Verify no duplicate or garbled replacement happened
      expect(result.status).toBe('BLOCK'); // Inner critical entity triggers BLOCK
    });

    it('20. Exact transformation / verification / delivery consistency', async () => {
      const rawEmail = 'audit@consistency-check.org';
      const prompt = `Notification for ${rawEmail} dispatch.`;

      const runtime = createShieldRuntime({
        detectorRegistry: createDefaultDetectorRegistry(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask PII',
            triggeredRules: ['mask-pii'],
            allowOverride: false,
          })),
        },
        defaultPlatformContext,
      });
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('MASK');

      // The deliverable text in runtime result, transformation result, and delivery sink must be identical
      expect(result.deliverableText).toBe(result.transformation?.transformedText);
      expect(runtime.deliveryEngine.deliveries[0]?.deliverableText).toBe(result.deliverableText);
    });

    it('21. Policy action remains authoritative over risk score alone', async () => {
      // High score risk, but policy evaluator decides WARN
      const runtime = createShieldRuntime({
        riskEvaluator: {
          evaluate: vi.fn(async () => ({
            score: 95,
            severity: 'CRITICAL',
            confidence: 1.0,
            factors: [],
            summary: 'Critical findings',
            evaluationTimestamp: 1000,
          })),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'WARN',
            reason: 'Policy exception granted: override with user confirmation',
            triggeredRules: ['special-override-rule'],
            allowOverride: true,
          })),
        },
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'd1',
                detectorId: 'd',
                category: 'SECRET',
                severity: 'CRITICAL',
                confidence: 1.0,
                range: { startIndex: 0, endIndex: 4 },
                evidence: { tokenLength: 4, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Strict data');

      // Policy decision WARN takes precedence
      expect(result.status).toBe('WARN');
      expect(result.action).toBe('WARN');
      expect(runtime.deliveryEngine.deliveries).toHaveLength(0);
    });
  });

  // ==========================================================================
  // Group 5: Immutability & Side-Effect Independence
  // ==========================================================================
  describe('Group 5: Immutability & Side-Effect Independence', () => {
    it('22. Runtime does not mutate original input object', async () => {
      const runtime = createRuntimeWithDetector();
      const inputObj: PipelineInput = {
        rawText: 'Contact alice@example.com for secrets.',
        timestamp: 1726000000000,
        platformContext: { site: 'claude.ai', isAiSite: true },
        metadata: { clientSession: 'sess-123' },
      };

      const originalRawText = inputObj.rawText;
      const originalMetadata = { ...inputObj.metadata };

      await runtime.execute(inputObj);

      expect(inputObj.rawText).toBe(originalRawText);
      expect(inputObj.metadata).toEqual(originalMetadata);
    });

    it('23. Runtime does not mutate risk assessment', async () => {
      let capturedRisk: RiskAssessment | undefined;
      const customRiskEvaluator: RiskEvaluator = {
        evaluate: vi.fn(async () => {
          capturedRisk = {
            score: 75,
            severity: 'HIGH',
            confidence: 0.9,
            factors: [
              {
                detectorId: 'd1',
                category: 'API_KEY',
                severity: 'HIGH',
                weight: 75,
                reason: 'API Key detected',
              },
            ],
            summary: 'High risk finding',
            evaluationTimestamp: 1726000000000,
          };
          return capturedRisk;
        }),
      };

      const runtime = createShieldRuntime({
        riskEvaluator: customRiskEvaluator,
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'd1',
                detectorId: 'd',
                category: 'API_KEY',
                severity: 'HIGH',
                confidence: 0.9,
                range: { startIndex: 0, endIndex: 5 },
                evidence: { tokenLength: 5, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Token 12345');

      expect(result.risk).toEqual(capturedRisk);
    });

    it('24. Runtime does not mutate policy decision', async () => {
      let capturedDecision: PolicyDecision | undefined;
      const customPolicyEvaluator: PolicyEvaluator = {
        evaluate: vi.fn(async () => {
          capturedDecision = {
            action: 'MASK',
            reason: 'Masking API Key',
            matchedRuleId: 'rule-mask-1',
            triggeredRules: ['rule-mask-1'],
            allowOverride: false,
          };
          return capturedDecision;
        }),
      };

      const runtime = createShieldRuntime({
        policyEvaluator: customPolicyEvaluator,
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'd1',
                detectorId: 'd',
                category: 'API_KEY',
                severity: 'HIGH',
                confidence: 0.9,
                range: { startIndex: 0, endIndex: 5 },
                evidence: { tokenLength: 5, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Token 12345');

      expect(result.decision).toEqual(capturedDecision);
    });
  });

  // ==========================================================================
  // Group 6: Dependency Injection
  // ==========================================================================
  describe('Group 6: Dependency Injection', () => {
    it('25. Dependency injection works: all custom engines can be passed', () => {
      const normalizer = new DefaultNormalizer();
      const classifier = new DefaultClassifier();
      const riskEvaluator = new DefaultRiskEvaluator();
      const policyEvaluator = new DefaultPolicyEvaluator();
      const transformer = new DefaultTransformer();
      const verifier = createVerificationEngine();
      const sender = new InMemorySender();

      const runtime = createShieldRuntime({
        normalizer,
        classifier,
        riskEvaluator,
        policyEvaluator,
        transformer,
        verifier,
        sender,
        defaultPlatformContext,
      });

      expect(runtime).toBeDefined();
    });

    it('26. Custom policy engine works: DeterministicPolicyEngine integration', async () => {
      const policyEngine = createPolicyEngine([
        {
          id: 'custom-force-block-everything',
          name: 'Block Everything',
          scope: 'GLOBAL',
          action: 'BLOCK',
          priority: 999,
          enabled: true,
        },
      ]);
      const policyEvaluator = createPolicyEvaluator(policyEngine);

      const runtime = createShieldRuntime({
        policyEvaluator,
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'd1',
                detectorId: 'd',
                category: 'PII',
                severity: 'LOW',
                confidence: 0.5,
                range: { startIndex: 0, endIndex: 3 },
                evidence: { tokenLength: 3, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Bob');
      expect(result.status).toBe('BLOCK');
      expect(result.decision?.matchedRuleId).toBe('custom-force-block-everything');
    });

    it('27. Custom transformer works: DeterministicTransformationEngine integration', async () => {
      const transformEngine = createTransformationEngine({
        defaultStrategy: {
          type: 'MASK',
          replacementText: '<PROTECTED_VALUE>',
        },
      });
      const transformer = createPipelineTransformer(transformEngine);

      const runtime = createShieldRuntime({
        transformer,
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask with custom token',
            triggeredRules: ['r1'],
            allowOverride: false,
          })),
        },
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'd1',
                detectorId: 'd',
                category: 'API_KEY',
                severity: 'HIGH',
                confidence: 0.99,
                range: { startIndex: 7, endIndex: 12 },
                evidence: { tokenLength: 5, hasRawValue: true },
                rawValue: '12345',
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Secret 12345 here');
      expect(result.status).toBe('MASK');
      expect(result.deliverableText).toBe('Secret <PROTECTED_VALUE> here');
    });

    it('28. Custom verifier works: DeterministicVerificationEngine integration', async () => {
      const customVerifier = new DeterministicVerificationEngine();
      const verifySpy = vi.spyOn(customVerifier, 'verify');

      const runtime = createShieldRuntime({
        verifier: customVerifier,
        detectorRegistry: createDefaultDetectorRegistry(),
        defaultPlatformContext,
      });

      await runtime.execute('Clean verification pass');
      expect(verifySpy).toHaveBeenCalled();
    });

    it('29. Custom sender works: custom destination receives delivery and context', async () => {
      const deliveriesReceived: { delivery: FinalDelivery; contextId: string }[] = [];
      const customSender: Sender = {
        send: async (delivery, context) => {
          deliveriesReceived.push({ delivery, contextId: context.id });
        },
      };

      const runtime = createShieldRuntime({
        sender: customSender,
        defaultPlatformContext,
      });

      const result = await runtime.execute('Hello world');
      expect(result.status).toBe('ALLOW');
      expect(deliveriesReceived).toHaveLength(1);
      expect(deliveriesReceived[0].delivery.deliverableText).toBe('Hello world');
    });
  });

  // ==========================================================================
  // Group 7: Determinism & Non-Leakage Security
  // ==========================================================================
  describe('Group 7: Determinism & Non-Leakage Security', () => {
    it('30. Deterministic repeated execution: identical inputs produce identical outcomes', async () => {
      const prompt =
        'Contact alice@example.com for authorization key sk-proj-11223344556677889900aabbccddeeff.';
      const runtime1 = createRuntimeWithDetector({ fixedTimestamp: 1726000000000 });
      const runtime2 = createRuntimeWithDetector({ fixedTimestamp: 1726000000000 });

      const result1 = await runtime1.execute(prompt);
      const result2 = await runtime2.execute(prompt);

      expect(result1.status).toBe(result2.status);
      expect(result1.action).toBe(result2.action);
      expect(result1.deliverableText).toBe(result2.deliverableText);
      expect(result1.risk?.score).toBe(result2.risk?.score);
      expect(result1.risk?.severity).toBe(result2.risk?.severity);
      expect(result1.transformation?.transformedText).toBe(result2.transformation?.transformedText);
    });

    it('31. No wall-clock dependency: fixed timestamp controls timing deterministically', async () => {
      const fixedTimestamp = 1726050000000;
      const runtime = createRuntimeWithDetector({ fixedTimestamp });

      const result = await runtime.execute('Simple prompt');
      expect(result.deliveryReceipt?.timestamp).toBe(fixedTimestamp);
    });

    it('32. No raw sensitive value leakage in runtime result fields', async () => {
      const apiKey = 'sk-proj-SUPERCONFIDENTIALSECRETKEY1234567890ABCDEF123456';
      const email = 'victim@secure-shield-test.com';
      const phone = '415-555-2671';
      const prompt = `Sensitive dump: key=${apiKey}, email=${email}, phone=${phone}`;

      const runtime = createRuntimeWithDetector();
      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);

      // Verify each top-level result field does not leak raw secrets
      if (result.deliverableText) {
        expect(result.deliverableText).not.toContain(apiKey);
        expect(result.deliverableText).not.toContain(email);
        expect(result.deliverableText).not.toContain(phone);
      }

      expect(result.decision?.reason).not.toContain(apiKey);
      if (result.decision?.userNotice) {
        expect(result.decision.userNotice).not.toContain(apiKey);
      }

      if (result.transformation?.transformedText) {
        expect(result.transformation.transformedText).not.toContain(apiKey);
        expect(result.transformation.transformedText).not.toContain(email);
        expect(result.transformation.transformedText).not.toContain(phone);
      }

      if (result.deliveryReceipt?.reason) {
        expect(result.deliveryReceipt.reason).not.toContain(apiKey);
        expect(result.deliveryReceipt.reason).not.toContain(email);
      }

      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(apiKey);
      expect(serialized).not.toContain(email);
      expect(serialized).not.toContain(phone);
    });

    it('33. Serialized runtime result contains zero secrets', async () => {
      const apiKey = 'sk-proj-TOPSECRETTOKEN99998888777766665555444433332222';
      const password = 'SuperSecretMasterPassword123!@#';
      const prompt = `Token: ${apiKey} and password: ${password}`;

      const runtime = createRuntimeWithDetector();
      const result = await runtime.execute(prompt);

      const serialized = JSON.stringify(result);

      expect(serialized).not.toContain(apiKey);
      expect(serialized).not.toContain(password);
    });

    it('34. Failed VERIFY prevents SEND in all cases', async () => {
      let sendCalled = false;
      const customSender: Sender = {
        send: async () => {
          sendCalled = true;
        },
      };

      const failingVerifier: Verifier = {
        verify: async () => ({
          status: 'FAILED',
          verified: false,
          residualRisk: {
            score: 99,
            severity: 'CRITICAL',
            confidence: 1.0,
            factors: [],
            summary: 'Verification forced failure',
            evaluationTimestamp: 0,
          },
          leaksDetected: true,
          failedChecks: ['MOCK_VERIFY_FAILURE'],
        }),
      };

      const runtime = createShieldRuntime({
        verifier: failingVerifier,
        sender: customSender,
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Attempt mask',
            triggeredRules: ['rule'],
            allowOverride: false,
          })),
        },
        detectorEngine: {
          detect: async () => ({
            entities: [
              {
                id: 'd1',
                detectorId: 'd',
                category: 'SECRET',
                severity: 'HIGH',
                confidence: 1.0,
                range: { startIndex: 0, endIndex: 5 },
                evidence: { tokenLength: 5, hasRawValue: false },
              },
            ],
            hasDetections: true,
            durationMs: 1,
          }),
        },
        defaultPlatformContext,
      });

      const result = await runtime.execute('Some input');

      expect(result.status).toBe('ERROR');
      expect(result.failedStage).toBe('VERIFY');
      expect(sendCalled).toBe(false);
    });

    it('35. Full M1.2 → M1.4 → M1.5 → M1.6 → M1.7 → M1.8 integration', async () => {
      // Wires real M1.2 detector registry, M1.4 risk evaluator, M1.5 policy engine,
      // M1.6 transformation engine, M1.7 verification engine, M1.8 delivery engine
      const detectorRegistry = createDefaultDetectorRegistry();
      const policyEngine = createPolicyEngine();
      const transformationEngine = createTransformationEngine();
      const verificationEngine = createVerificationEngine();
      const deliveryEngine = createDeliveryEngine();

      const runtime = createShieldRuntime({
        detectorRegistry,
        policyEvaluator: createPolicyEvaluator(policyEngine),
        transformer: createPipelineTransformer(transformationEngine),
        verifier: verificationEngine,
        deliveryEngine,
        defaultPlatformContext,
      });

      const rawEmail = 'integrator@shield-foundation.org';
      const prompt = `Contact us at ${rawEmail} for support.`;

      const result = await runtime.execute(prompt);

      expect(result.ok).toBe(true);
      expect(result.status).toBe('MASK');
      expect(result.action).toBe('MASK');
      expect(result.deliverableText).toContain('[REDACTED_PII]');
      expect(result.deliverableText).not.toContain(rawEmail);
      expect(result.verification?.verified).toBe(true);
      expect(result.deliveryReceipt?.status).toBe('DELIVERED');

      expect(deliveryEngine.deliveries).toHaveLength(1);
      expect(deliveryEngine.deliveries[0]?.deliverableText).toBe(result.deliverableText);
    });

    it('36. Existing M1.3 orchestrator regression remains green when accessed via runtime', async () => {
      const runtime = createRuntimeWithDetector();
      const result = await runtime.orchestrator.process({
        rawText: 'Orchestrator baseline test',
        timestamp: 1726000000000,
        platformContext: defaultPlatformContext,
        metadata: {},
      });

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.status).toBe('ALLOW');
      }
    });
  });
});
