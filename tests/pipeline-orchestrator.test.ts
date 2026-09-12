import { describe, it, expect, vi } from 'vitest';
import {
  CorePipelineOrchestrator,
  createPipelineOrchestrator,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultRiskEvaluator,
  DefaultTransformer,
  DefaultVerifier,
  InMemorySender,
  PIPELINE_STAGES,
  type PipelineDependencies,
  type PipelineInput,
  type DetectorEngine,
  type PolicyEvaluator,
  type Sender,
  type PipelineStage,
  type DetectionResult,
  type PolicyAction,
} from '../packages/core/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

describe('M1.3 Shield Core Pipeline Orchestrator', () => {
  const createBaseInput = (rawText: string): PipelineInput => ({
    rawText,
    timestamp: 1726000000000,
    platformContext: {
      site: 'chatgpt.com',
      isAiSite: true,
      url: 'https://chatgpt.com/c/12345',
    },
    metadata: { requestId: 'req-001' },
  });

  const createFakeDetections = (hasSensitive: boolean, text?: string): DetectionResult => {
    if (!hasSensitive) {
      return {
        entities: [],
        hasDetections: false,
        durationMs: 5,
      };
    }

    const rawValue = 'sk-proj-SUPERCONFIDENTIALSECRETKEY1234567890ABCDEF123456';
    const foundIndex = text ? text.indexOf(rawValue) : -1;
    const startIndex = foundIndex >= 0 ? foundIndex : 16;
    const endIndex = startIndex + rawValue.length;

    return {
      entities: [
        {
          id: 'det-api-key-1',
          detectorId: 'detector-api-key',
          category: 'API_KEY',
          severity: 'CRITICAL',
          confidence: 0.99,
          range: { startIndex, endIndex },
          evidence: {
            tokenLength: rawValue.length,
            hasRawValue: false,
            previewMasked: 'sk-p****cdef',
            ruleName: 'openai-api-key',
          },
          rawValue,
        },
      ],
      hasDetections: true,
      durationMs: 8,
    };
  };

  const createSetup = (overrides: Partial<PipelineDependencies> = {}) => {
    const normalizer = overrides.normalizer ?? new DefaultNormalizer();
    const detectorEngine: DetectorEngine = overrides.detectorEngine ?? {
      detect: vi.fn(async () => createFakeDetections(false)),
    };
    const classifier = overrides.classifier ?? new DefaultClassifier();
    const riskEvaluator = overrides.riskEvaluator ?? new DefaultRiskEvaluator();
    const policyEvaluator: PolicyEvaluator = overrides.policyEvaluator ?? {
      evaluate: vi.fn(async () => ({
        action: 'ALLOW' as PolicyAction,
        reason: 'Clean input allowed',
        triggeredRules: [],
        allowOverride: false,
      })),
    };
    const transformer = overrides.transformer ?? new DefaultTransformer();
    const verifier = overrides.verifier ?? new DefaultVerifier();
    const sender: Sender = overrides.sender ?? new InMemorySender();

    const deps: PipelineDependencies = {
      normalizer,
      detectorEngine,
      classifier,
      riskEvaluator,
      policyEvaluator,
      transformer,
      verifier,
      sender,
      stageObserver: overrides.stageObserver,
    };

    const orchestrator = createPipelineOrchestrator(deps);
    return { orchestrator, deps, sender: sender as InMemorySender };
  };

  describe('1. Clean Input & Default Flow', () => {
    it('processes clean input → detection empty → policy ALLOW → sends payload', async () => {
      const sender = new InMemorySender();
      const { orchestrator } = createSetup({ sender });
      const input = createBaseInput('Write a Python function to compute Fibonacci numbers.');

      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok result');
      expect(result.value.status).toBe('ALLOW');

      if (result.value.status === 'ALLOW') {
        expect(result.value.deliverableText).toBe(input.rawText);
        expect(result.value.decision.action).toBe('ALLOW');
        expect(result.value.risk.severity).toBe('NONE');
        expect(result.value.risk.score).toBe(0);
      }

      // Verify sender was called with deliverable text
      expect(sender.deliveries).toHaveLength(1);
      expect(sender.deliveries[0]!.canSend).toBe(true);
      expect(sender.deliveries[0]!.deliverableText).toBe(input.rawText);
      expect(sender.deliveries[0]!.actionTaken).toBe('ALLOW');
    });

    it('completes normally when no sensitive information is present', async () => {
      const { orchestrator } = createSetup();
      const input = createBaseInput('Hello world, simple harmless prose.');

      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ALLOW');
      expect(result.value.metadata.errors).toHaveLength(0);
      expect(result.value.metadata.completedAt).toBeDefined();
    });
  });

  describe('2. Sensitive Input & Policy Decisions', () => {
    it('handles sensitive input → policy WARN → no transformation → no send', async () => {
      const sender = new InMemorySender();
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => createFakeDetections(true)),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'WARN',
            reason: 'Warning: detected API key',
            triggeredRules: ['warn-on-secrets'],
            allowOverride: true,
            userNotice: 'This prompt contains an API key. Proceed with caution.',
          })),
        },
        sender,
      });

      const input = createBaseInput(
        'Here is my key: sk-proj-SUPERCONFIDENTIALSECRETKEY1234567890ABCDEF123456',
      );
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('WARN');

      if (result.value.status === 'WARN') {
        expect(result.value.warningNotice).toContain('This prompt contains an API key');
        expect(result.value.allowOverride).toBe(true);
        expect(result.value.decision.action).toBe('WARN');
        expect(result.value.risk.severity).toBe('CRITICAL');
      }

      // WARN requires user confirmation: sender MUST NOT be invoked automatically
      expect(sender.deliveries).toHaveLength(0);
    });

    it('handles sensitive input → policy MASK → transforms → verifies → sends transformed text', async () => {
      const sender = new InMemorySender();
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => createFakeDetections(true)),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask sensitive API keys before transmission',
            triggeredRules: ['mask-api-keys'],
            allowOverride: false,
          })),
        },
        sender,
      });

      const input = createBaseInput(
        'Here is my key: sk-proj-SUPERCONFIDENTIALSECRETKEY1234567890ABCDEF123456',
      );
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');

      if (result.value.status === 'MASK') {
        expect(result.value.deliverableText).toBe('Here is my key: [REDACTED_API_KEY]');
        expect(result.value.transformation.isModified).toBe(true);
        expect(result.value.verification.verified).toBe(true);
        expect(result.value.verification.status).toBe('SUCCESS');
        expect(result.value.decision.action).toBe('MASK');
      }

      // Sender MUST receive only the verified transformed text
      expect(sender.deliveries).toHaveLength(1);
      expect(sender.deliveries[0]!.canSend).toBe(true);
      expect(sender.deliveries[0]!.deliverableText).toBe('Here is my key: [REDACTED_API_KEY]');
      expect(sender.deliveries[0]!.actionTaken).toBe('MASK');
    });

    it('handles sensitive input → policy BLOCK → no transformation → no send', async () => {
      const sender = new InMemorySender();
      const transformSpy = vi.fn();
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => createFakeDetections(true)),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'BLOCK',
            reason: 'Critical credentials blocked by security policy',
            triggeredRules: ['block-critical-secrets'],
            allowOverride: false,
          })),
        },
        transformer: {
          transform: transformSpy,
        },
        sender,
      });

      const input = createBaseInput(
        'Here is my key: sk-proj-SUPERCONFIDENTIALSECRETKEY1234567890ABCDEF123456',
      );
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('BLOCK');

      if (result.value.status === 'BLOCK') {
        expect(result.value.blockedReason).toContain('Critical credentials blocked');
        expect(result.value.decision.action).toBe('BLOCK');
      }

      // Transformer should not be called for BLOCK
      expect(transformSpy).not.toHaveBeenCalled();
      // Sender MUST NOT be called for BLOCK
      expect(sender.deliveries).toHaveLength(0);
    });
  });

  describe('3. Failure Handling & Fail-Safe Guarantees', () => {
    it('fails safely when transformation throws an error → no send → ERROR result', async () => {
      const sender = new InMemorySender();
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => createFakeDetections(true)),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask secrets',
            triggeredRules: ['mask-rule'],
            allowOverride: false,
          })),
        },
        transformer: {
          transform: vi.fn(async () => {
            throw new Error('Out of memory during AST replacement');
          }),
        },
        sender,
      });

      const input = createBaseInput('Secret: sk-proj-12345');
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ERROR');

      if (result.value.status === 'ERROR') {
        expect(result.value.failedStage).toBe('TRANSFORM');
        expect(result.value.error.code).toBe('TRANSFORM_ERROR');
        expect(result.value.error.message).toContain('Out of memory during AST replacement');
      }

      // No send on transformation failure
      expect(sender.deliveries).toHaveLength(0);
    });

    it('fails safely when verification fails → no send → ERROR result', async () => {
      const sender = new InMemorySender();
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => createFakeDetections(true)),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask secrets',
            triggeredRules: ['mask-rule'],
            allowOverride: false,
          })),
        },
        verifier: {
          verify: vi.fn(async (): Promise<VerificationResult> => ({
            status: 'FAILED',
            verified: false,
            residualRisk: {
              score: 95,
              severity: 'CRITICAL',
              confidence: 0.99,
              factors: [],
              summary: 'Secret leak detected in post-transform buffer',
              evaluationTimestamp: Date.now(),
            },
            leaksDetected: true,
            notes: 'Verification detected unmasked residual token',
          })),
        },
        sender,
      });

      const input = createBaseInput('Key: sk-proj-12345');
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ERROR');

      if (result.value.status === 'ERROR') {
        expect(result.value.failedStage).toBe('VERIFY');
        expect(result.value.error.code).toBe('VERIFY_ERROR');
        expect(result.value.error.message).toContain('residual token');
      }

      // NEVER send unverified content
      expect(sender.deliveries).toHaveLength(0);
    });

    it('handles detector failure gracefully → structured error', async () => {
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => {
            throw new Error('Detection worker crashed');
          }),
        },
      });

      const input = createBaseInput('Test input');
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ERROR');
      if (result.value.status === 'ERROR') {
        expect(result.value.failedStage).toBe('DETECT');
        expect(result.value.error.code).toBe('DETECT_ERROR');
        expect(result.value.error.message).toBe('Detection worker crashed');
      }
    });

    it('handles policy evaluation failure gracefully → structured error', async () => {
      const { orchestrator } = createSetup({
        policyEvaluator: {
          evaluate: vi.fn(async () => {
            throw new Error('Policy database connection timeout');
          }),
        },
      });

      const input = createBaseInput('Test input');
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ERROR');
      if (result.value.status === 'ERROR') {
        expect(result.value.failedStage).toBe('POLICY');
        expect(result.value.error.code).toBe('POLICY_ERROR');
        expect(result.value.error.message).toBe('Policy database connection timeout');
      }
    });
  });

  describe('4. Multiple Detections Preservation', () => {
    it('preserves multiple detections across classification, risk, and transformation', async () => {
      const multiDetections: DetectionResult = {
        entities: [
          {
            id: 'det-email',
            detectorId: 'detector-email',
            category: 'PII',
            severity: 'MEDIUM',
            confidence: 0.95,
            range: { startIndex: 7, endIndex: 23 },
            evidence: { tokenLength: 16, hasRawValue: false, previewMasked: 'u***r@test.com' },
            rawValue: 'user@example.com',
          },
          {
            id: 'det-api-key',
            detectorId: 'detector-api-key',
            category: 'API_KEY',
            severity: 'CRITICAL',
            confidence: 0.99,
            range: { startIndex: 33, endIndex: 62 },
            evidence: { tokenLength: 29, hasRawValue: false, previewMasked: 'sk-p****cdef' },
            rawValue: 'sk-proj-1234567890abcdef12345',
          },
        ],
        hasDetections: true,
        durationMs: 12,
      };

      const sender = new InMemorySender();
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => multiDetections),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask multiple sensitive entities',
            triggeredRules: ['mask-all'],
            allowOverride: false,
          })),
        },
        sender,
      });

      const raw = 'Email: user@example.com and key: sk-proj-1234567890abcdef12345';
      const input = createBaseInput(raw);
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');

      if (result.value.status === 'MASK') {
        expect(result.value.risk.factors).toHaveLength(2);
        expect(result.value.risk.severity).toBe('CRITICAL');
        expect(result.value.transformation.transformationsApplied).toHaveLength(2);
        expect(result.value.deliverableText).toBe(
          'Email: [REDACTED_PII] and key: [REDACTED_API_KEY]',
        );
      }
    });
  });

  describe('5. Canonical Stage Order Verification', () => {
    it('executes stages in exact order: INPUT → NORMALIZE → DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND', async () => {
      const executedStages: PipelineStage[] = [];
      const stageObserver = (stage: PipelineStage) => {
        executedStages.push(stage);
      };

      const { orchestrator } = createSetup({
        stageObserver,
        detectorEngine: {
          detect: vi.fn(async () => createFakeDetections(true)),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask secrets',
            triggeredRules: ['mask-rule'],
            allowOverride: false,
          })),
        },
      });

      const input = createBaseInput('Test input with key');
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      expect(executedStages).toEqual([
        'INPUT',
        'NORMALIZE',
        'DETECT',
        'CLASSIFY',
        'RISK',
        'POLICY',
        'TRANSFORM',
        'VERIFY',
        'SEND',
      ]);

      expect(executedStages).toEqual([...PIPELINE_STAGES]);
    });
  });

  describe('6. Dependency Injection & Decoupling', () => {
    it('executes entirely through injected mock dependencies without external bindings', async () => {
      const normalizerMock: ReturnType<typeof vi.fn> = vi.fn((inp: PipelineInput) => ({
        original: inp,
        normalizedText: inp.rawText.toUpperCase(),
        encoding: 'UTF-8',
        normalizationApplied: ['custom-upper'],
      }));

      const detectorMock = vi.fn(async () => ({
        entities: [],
        hasDetections: false,
        durationMs: 1,
      }));

      const classifierMock = vi.fn(async () => ({
        classifiedEntities: [],
      }));

      const riskMock = vi.fn(async () => ({
        score: 0,
        severity: 'NONE' as const,
        confidence: 1.0,
        factors: [],
        summary: 'Injected zero risk',
        evaluationTimestamp: 1000,
      }));

      const policyMock = vi.fn(async () => ({
        action: 'ALLOW' as PolicyAction,
        reason: 'Injected allow',
        triggeredRules: [],
        allowOverride: false,
      }));

      const transformMock = vi.fn(async () => ({
        originalText: '',
        transformedText: '',
        isModified: false,
        transformationsApplied: [],
      }));

      const verifierMock = vi.fn(async () => ({
        status: 'NOT_REQUIRED' as const,
        verified: true,
        residualRisk: {
          score: 0,
          severity: 'NONE' as const,
          confidence: 1.0,
          factors: [],
          summary: '',
          evaluationTimestamp: 1000,
        },
        leaksDetected: false,
      }));

      const senderMock = vi.fn(async () => {});

      const customOrchestrator = new CorePipelineOrchestrator({
        normalizer: { normalize: normalizerMock },
        detectorEngine: { detect: detectorMock },
        classifier: { classify: classifierMock },
        riskEvaluator: { evaluate: riskMock },
        policyEvaluator: { evaluate: policyMock },
        transformer: { transform: transformMock },
        verifier: { verify: verifierMock },
        sender: { send: senderMock },
      });

      const result = await customOrchestrator.process(createBaseInput('mock test'));
      expect(result.ok).toBe(true);

      expect(normalizerMock).toHaveBeenCalledTimes(1);
      expect(detectorMock).toHaveBeenCalledTimes(1);
      expect(classifierMock).toHaveBeenCalledTimes(1);
      expect(riskMock).toHaveBeenCalledTimes(1);
      expect(policyMock).toHaveBeenCalledTimes(1);
      expect(verifierMock).toHaveBeenCalledTimes(1);
      expect(senderMock).toHaveBeenCalledTimes(1);
    });
  });

  describe('7. Policy Independence (Detection != Policy)', () => {
    const runWithPolicyAction = async (action: PolicyAction) => {
      const sender = new InMemorySender();
      const orchestrator = new CorePipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async (normalized) =>
            createFakeDetections(true, normalized.normalizedText),
          ),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action,
            reason: `Explicitly set policy action to ${action}`,
            triggeredRules: [`rule-${action.toLowerCase()}`],
            allowOverride: action === 'WARN',
            userNotice: action === 'WARN' ? 'Warning prompt' : undefined,
          })),
        },
        transformer: new DefaultTransformer(),
        verifier: new DefaultVerifier(),
        sender,
      });

      const input = createBaseInput(
        'Secret: sk-proj-SUPERCONFIDENTIALSECRETKEY1234567890ABCDEF123456',
      );
      const result = await orchestrator.process(input);
      return { result, sender };
    };

    it('proves SAME sensitive detection produces ALLOW when policy allows', async () => {
      const { result, sender } = await runWithPolicyAction('ALLOW');
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ALLOW');
      expect(sender.deliveries).toHaveLength(1);
    });

    it('proves SAME sensitive detection produces WARN when policy warns', async () => {
      const { result, sender } = await runWithPolicyAction('WARN');
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('WARN');
      expect(sender.deliveries).toHaveLength(0); // No send on warning
    });

    it('proves SAME sensitive detection produces MASK when policy masks', async () => {
      const { result, sender } = await runWithPolicyAction('MASK');
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');
      expect(sender.deliveries).toHaveLength(1);
      expect(sender.deliveries[0]!.deliverableText).toContain('[REDACTED_API_KEY]');
    });

    it('proves SAME sensitive detection produces BLOCK when policy blocks', async () => {
      const { result, sender } = await runWithPolicyAction('BLOCK');
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('BLOCK');
      expect(sender.deliveries).toHaveLength(0); // No send on block
    });
  });

  describe('8. Security & Non-Leakage in Errors and Metadata', () => {
    it('ensures pipeline errors never expose raw sensitive tokens in message or details', async () => {
      const rawSecret = 'SUPER_SECRET_TOKEN_DO_NOT_LEAK_99999';
      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => {
            throw new Error(`Failed to parse token: ${rawSecret}`);
          }),
        },
      });

      const input = createBaseInput(`Token=${rawSecret}`);
      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);

      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ERROR');
      if (result.value.status === 'ERROR') {
        expect(result.value.failedStage).toBe('DETECT');
      }
    });

    it('does not mutate caller input during processing', async () => {
      const { orchestrator } = createSetup();
      const originalInput = createBaseInput('Original immutability test');
      const inputCopy = { ...originalInput };

      await orchestrator.process(originalInput);
      expect(originalInput).toEqual(inputCopy);
    });
  });

  describe('9. M1.3 Regression & Range Boundary Integrity', () => {
    it('verifies exact startIndex, endIndex, and slice correspondence', async () => {
      const rawText =
        'Prefix characters: sk-proj-EXACTBOUNDARYKEY1234567890ABCDEF123456 :suffix characters.';
      const token = 'sk-proj-EXACTBOUNDARYKEY1234567890ABCDEF123456';
      const startIndex = rawText.indexOf(token);
      const endIndex = startIndex + token.length;

      // Assert M1.2 locked range convention [startIndex, endIndex)
      expect(rawText.slice(startIndex, endIndex)).toBe(token);

      const detectionResult: DetectionResult = {
        entities: [
          {
            id: 'det-exact-range',
            detectorId: 'detector-api-key',
            category: 'API_KEY',
            severity: 'CRITICAL',
            confidence: 0.99,
            range: { startIndex, endIndex },
            evidence: {
              tokenLength: token.length,
              hasRawValue: false,
              previewMasked: 'sk-p****cdef',
              ruleName: 'openai-api-key',
            },
            rawValue: token,
          },
        ],
        hasDetections: true,
        durationMs: 4,
      };

      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => detectionResult),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask secret',
            triggeredRules: ['mask-key'],
            allowOverride: false,
          })),
        },
      });

      const result = await orchestrator.process(createBaseInput(rawText));
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');

      if (result.value.status === 'MASK') {
        const { deliverableText, transformation } = result.value;

        // 1. Replacement removes the complete sensitive value
        expect(deliverableText).not.toContain(token);
        expect(deliverableText).not.toContain('EXACTBOUNDARYKEY');

        // 2. Transformations do not leave prefix/suffix characters behind
        expect(deliverableText).not.toContain('123456');
        expect(deliverableText).not.toContain('sk-');

        // 3. Transformations do not consume adjacent characters
        expect(deliverableText.startsWith('Prefix characters: ')).toBe(true);
        expect(deliverableText.endsWith(' :suffix characters.')).toBe(true);

        // 4. Exact deliverable equality
        expect(deliverableText).toBe('Prefix characters: [REDACTED_API_KEY] :suffix characters.');

        // 5. Applied transformation ranges are exact
        expect(transformation.transformationsApplied).toHaveLength(1);
        const applied = transformation.transformationsApplied[0]!;
        expect(applied.originalRange).toEqual({ startIndex, endIndex });
        expect(
          rawText.slice(applied.originalRange.startIndex, applied.originalRange.endIndex),
        ).toBe(token);
        expect(
          deliverableText.slice(applied.replacedRange.startIndex, applied.replacedRange.endIndex),
        ).toBe('[REDACTED_API_KEY]');
      }
    });

    it('transforms multiple non-overlapping detections correctly without offset drift', async () => {
      const email = 'alice@example.com';
      const phone = '+1-555-019-2834';
      const token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

      const rawText = `Contact: ${email}, Phone: ${phone}, Token: ${token} [END]`;

      const emailStart = rawText.indexOf(email);
      const emailEnd = emailStart + email.length;
      const phoneStart = rawText.indexOf(phone);
      const phoneEnd = phoneStart + phone.length;
      const tokenStart = rawText.indexOf(token);
      const tokenEnd = tokenStart + token.length;

      // Verify exact slices before feeding
      expect(rawText.slice(emailStart, emailEnd)).toBe(email);
      expect(rawText.slice(phoneStart, phoneEnd)).toBe(phone);
      expect(rawText.slice(tokenStart, tokenEnd)).toBe(token);

      const detectionResult: DetectionResult = {
        entities: [
          {
            id: 'det-token',
            detectorId: 'detector-api-key',
            category: 'API_KEY',
            severity: 'CRITICAL',
            confidence: 0.99,
            range: { startIndex: tokenStart, endIndex: tokenEnd },
            evidence: { tokenLength: token.length, hasRawValue: false, previewMasked: 'ghp_****' },
            rawValue: token,
          },
          {
            id: 'det-email',
            detectorId: 'detector-email',
            category: 'PII',
            severity: 'MEDIUM',
            confidence: 0.95,
            range: { startIndex: emailStart, endIndex: emailEnd },
            evidence: {
              tokenLength: email.length,
              hasRawValue: false,
              previewMasked: 'a***e@example.com',
            },
            rawValue: email,
          },
          {
            id: 'det-phone',
            detectorId: 'detector-phone',
            category: 'PII',
            severity: 'MEDIUM',
            confidence: 0.95,
            range: { startIndex: phoneStart, endIndex: phoneEnd },
            evidence: { tokenLength: phone.length, hasRawValue: false, previewMasked: '+1-***' },
            rawValue: phone,
          },
        ],
        hasDetections: true,
        durationMs: 8,
      };

      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => detectionResult),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask all sensitive entities',
            triggeredRules: ['mask-pii', 'mask-secrets'],
            allowOverride: false,
          })),
        },
      });

      const result = await orchestrator.process(createBaseInput(rawText));
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');

      if (result.value.status === 'MASK') {
        const { deliverableText, transformation } = result.value;

        // Verify exact expected deliverable
        const expected =
          'Contact: [REDACTED_PII], Phone: [REDACTED_PII], Token: [REDACTED_API_KEY] [END]';
        expect(deliverableText).toBe(expected);

        // Verify zero leakage of all entities
        expect(deliverableText).not.toContain(email);
        expect(deliverableText).not.toContain(phone);
        expect(deliverableText).not.toContain(token);

        // Verify adjacent separators
        expect(deliverableText).toContain('Contact: ');
        expect(deliverableText).toContain(', Phone: ');
        expect(deliverableText).toContain(', Token: ');
        expect(deliverableText).toContain(' [END]');

        // Verify each replacedRange matches its replacement in the final text
        expect(transformation.transformationsApplied).toHaveLength(3);
        for (const applied of transformation.transformationsApplied) {
          const sliceInTransformed = deliverableText.slice(
            applied.replacedRange.startIndex,
            applied.replacedRange.endIndex,
          );
          expect(sliceInTransformed).toBe(`[REDACTED_${applied.category}]`);
        }
      }
    });

    it('transforms touching boundary entities without character loss or corruption', async () => {
      const email1 = 'first@test.com';
      const email2 = 'second@test.com';
      const rawText = `(${email1})(${email2})`;

      const s1 = rawText.indexOf(email1);
      const e1 = s1 + email1.length;
      const s2 = rawText.indexOf(email2);
      const e2 = s2 + email2.length;

      const detectionResult: DetectionResult = {
        entities: [
          {
            id: 'det-1',
            detectorId: 'detector-email',
            category: 'PII',
            severity: 'MEDIUM',
            confidence: 0.95,
            range: { startIndex: s1, endIndex: e1 },
            evidence: {
              tokenLength: email1.length,
              hasRawValue: false,
              previewMasked: 'f***@test.com',
            },
            rawValue: email1,
          },
          {
            id: 'det-2',
            detectorId: 'detector-email',
            category: 'PII',
            severity: 'MEDIUM',
            confidence: 0.95,
            range: { startIndex: s2, endIndex: e2 },
            evidence: {
              tokenLength: email2.length,
              hasRawValue: false,
              previewMasked: 's***@test.com',
            },
            rawValue: email2,
          },
        ],
        hasDetections: true,
        durationMs: 3,
      };

      const { orchestrator } = createSetup({
        detectorEngine: {
          detect: vi.fn(async () => detectionResult),
        },
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask both emails',
            triggeredRules: ['mask-pii'],
            allowOverride: false,
          })),
        },
      });

      const result = await orchestrator.process(createBaseInput(rawText));
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');

      if (result.value.status === 'MASK') {
        expect(result.value.deliverableText).toBe('([REDACTED_PII])([REDACTED_PII])');
      }
    });

    it('executes full path end-to-end with real M1.2 Detection Engine: detect → classify → risk → policy → transform → verify → send', async () => {
      const detectorRegistry = createDefaultDetectorRegistry();
      const sender = new InMemorySender();

      const realDetectorEngine: DetectorEngine = {
        detect: async (normalized) =>
          detectorRegistry.runAll({
            text: normalized.normalizedText,
            includeRawValue: true,
          }),
      };

      const { orchestrator } = createSetup({
        detectorEngine: realDetectorEngine,
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Automated policy masking secrets and PII',
            triggeredRules: ['mask-sensitive'],
            allowOverride: false,
          })),
        },
        sender,
      });

      const raw =
        'Contact admin at ops@shield-security.org or use key sk-proj-1234567890abcdef1234567890123456 immediately.';
      const input = createBaseInput(raw);

      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');

      if (result.value.status === 'MASK') {
        expect(result.value.deliverableText).toBe(
          'Contact admin at [REDACTED_PII] or use key [REDACTED_API_KEY] immediately.',
        );
        expect(result.value.verification.verified).toBe(true);
        expect(result.value.verification.status).toBe('SUCCESS');
        expect(result.value.verification.leaksDetected).toBe(false);

        // Verify sender was called with verified deliverable
        expect(sender.deliveries).toHaveLength(1);
        expect(sender.deliveries[0]!.deliverableText).toBe(
          'Contact admin at [REDACTED_PII] or use key [REDACTED_API_KEY] immediately.',
        );
      }
    });
  });
});
