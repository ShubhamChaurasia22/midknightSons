import { describe, it, expect, vi } from 'vitest';
import {
  createTransformationEngine,
  createPipelineTransformer,
  createReverseTransformer,
  DeterministicTransformationEngine,
  type ReversibleMapping,
} from '../packages/transformation/src';
import {
  createPipelineOrchestrator,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultRiskEvaluator,
  DefaultVerifier,
  InMemorySender,
  type DetectionEntity,
  type PolicyDecision,
  type PipelineInput,
} from '../packages/core/src';
import { createPolicyEvaluator } from '../packages/policy/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

describe('M1.6 Shield Transformation Engine', () => {
  const createEntity = (overrides: Partial<DetectionEntity> = {}): DetectionEntity => ({
    id: overrides.id ?? 'det-1',
    detectorId: overrides.detectorId ?? 'detector-test',
    category: overrides.category ?? 'API_KEY',
    severity: overrides.severity ?? 'CRITICAL',
    confidence: overrides.confidence ?? 0.99,
    range: overrides.range ?? { startIndex: 0, endIndex: 10 },
    evidence: overrides.evidence ?? {
      tokenLength: 10,
      hasRawValue: false,
      previewMasked: 's***1',
    },
    rawValue: overrides.rawValue,
  });

  const createDecision = (overrides: Partial<PolicyDecision> = {}): PolicyDecision => ({
    action: overrides.action ?? 'MASK',
    reason: overrides.reason ?? 'Policy test reason',
    matchedRuleId: overrides.matchedRuleId ?? 'rule-test',
    triggeredRules: overrides.triggeredRules ?? ['rule-test'],
    allowOverride: overrides.allowOverride ?? false,
    userNotice: overrides.userNotice,
  });

  // ==========================================================================
  // 1. Policy Semantics: ALLOW
  // ==========================================================================
  describe('1. Policy ALLOW Semantics', () => {
    it('instantiates DeterministicTransformationEngine class directly', () => {
      const engine = new DeterministicTransformationEngine();
      expect(engine.id).toBe('shield-deterministic-transformer');
      expect(engine.supportedTypes).toContain('MASK');
    });

    it('preserves text unmodified with isModified: false when policy is ALLOW', () => {
      const engine = createTransformationEngine();
      const rawText = 'Clean text: hello world';
      const entity = createEntity({ range: { startIndex: 12, endIndex: 17 } });
      const decision = createDecision({ action: 'ALLOW' });

      const result = engine.transformWithDecision(rawText, [entity], decision);

      expect(result.originalText).toBe(rawText);
      expect(result.transformedText).toBe(rawText);
      expect(result.isModified).toBe(false);
      expect(result.transformationsApplied).toHaveLength(0);
    });
  });

  // ==========================================================================
  // 2. Policy Semantics: WARN
  // ==========================================================================
  describe('2. Policy WARN Semantics', () => {
    it('does NOT silently transform WARN decision; preserves text as-is', () => {
      const engine = createTransformationEngine();
      const rawText = 'Attention: internal document reference doc-999';
      const entity = createEntity({
        category: 'PRIVATE_DATA',
        range: { startIndex: 39, endIndex: 46 },
      });
      const decision = createDecision({ action: 'WARN', allowOverride: true });

      const result = engine.transformWithDecision(rawText, [entity], decision);

      expect(result.originalText).toBe(rawText);
      expect(result.transformedText).toBe(rawText);
      expect(result.isModified).toBe(false);
      expect(result.transformationsApplied).toHaveLength(0);
    });
  });

  // ==========================================================================
  // 3. Policy Semantics: BLOCK
  // ==========================================================================
  describe('3. Policy BLOCK Semantics', () => {
    it('does NOT transform BLOCK decision to make it sendable; preserves text as-is', () => {
      const engine = createTransformationEngine();
      const rawText = 'Private key: -----BEGIN RSA PRIVATE KEY-----';
      const entity = createEntity({
        category: 'SECRET',
        severity: 'CRITICAL',
        range: { startIndex: 13, endIndex: 44 },
      });
      const decision = createDecision({ action: 'BLOCK' });

      const result = engine.transformWithDecision(rawText, [entity], decision);

      expect(result.originalText).toBe(rawText);
      expect(result.transformedText).toBe(rawText);
      expect(result.isModified).toBe(false);
      expect(result.transformationsApplied).toHaveLength(0);
    });
  });

  // ==========================================================================
  // 4. Policy Semantics: MASK
  // ==========================================================================
  describe('4. Policy MASK Semantics', () => {
    it('transforms sensitive entities into safe replacements with isModified: true', () => {
      const engine = createTransformationEngine();
      const rawText = 'My key is sk-1234567890abcdef and secret is done';
      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex: 10, endIndex: 29 },
      });
      const decision = createDecision({ action: 'MASK' });

      const result = engine.transformWithDecision(rawText, [entity], decision);

      expect(result.originalText).toBe(rawText);
      expect(result.transformedText).toBe('My key is [REDACTED_API_KEY] and secret is done');
      expect(result.isModified).toBe(true);
      expect(result.transformationsApplied).toHaveLength(1);
    });
  });

  // ==========================================================================
  // 5. Strict Half-Open Range Convention [startIndex, endIndex)
  // ==========================================================================
  describe('5. Strict Half-Open Range Convention [startIndex, endIndex)', () => {
    it('strictly satisfies text.slice(startIndex, endIndex) on the original span', () => {
      const engine = createTransformationEngine();
      const rawText = 'Prefix target_token suffix';
      const startIndex = rawText.indexOf('target_token');
      const endIndex = startIndex + 'target_token'.length;

      expect(rawText.slice(startIndex, endIndex)).toBe('target_token');

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex, endIndex },
      });

      const result = engine.transformSync(rawText, [entity]);
      const applied = result.transformationsApplied[0]!;

      expect(applied.originalRange.startIndex).toBe(startIndex);
      expect(applied.originalRange.endIndex).toBe(endIndex);
      expect(rawText.slice(applied.originalRange.startIndex, applied.originalRange.endIndex)).toBe(
        'target_token',
      );
      expect(result.transformedText).toBe('Prefix [REDACTED_API_KEY] suffix');
    });
  });

  // ==========================================================================
  // 6. Exact replacedRange Mapping in Transformed Coordinates
  // ==========================================================================
  describe('6. Exact replacedRange Mapping in Transformed Coordinates', () => {
    it('maps replacedRange accurately such that transformedText.slice equals replacement', () => {
      const engine = createTransformationEngine();
      const rawText = 'Leading text before key: sk-secret-token-12345 and trailing text';
      const startIndex = rawText.indexOf('sk-secret-token-12345');
      const endIndex = startIndex + 'sk-secret-token-12345'.length;

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex, endIndex },
      });

      const result = engine.transformSync(rawText, [entity]);
      const applied = result.transformationsApplied[0]!;

      const replacedSlice = result.transformedText.slice(
        applied.replacedRange.startIndex,
        applied.replacedRange.endIndex,
      );

      expect(replacedSlice).toBe('[REDACTED_API_KEY]');
      expect(applied.replacedRange.startIndex).toBe(rawText.indexOf('sk-secret-token-12345'));
      expect(applied.replacedRange.endIndex).toBe(
        applied.replacedRange.startIndex + '[REDACTED_API_KEY]'.length,
      );
    });
  });

  // ==========================================================================
  // 7. Multiple Non-Overlapping Entities Without Offset Drift
  // ==========================================================================
  describe('7. Multiple Non-Overlapping Entities Without Offset Drift', () => {
    it('transforms multiple non-overlapping entities in forward pass without offset drift', () => {
      const engine = createTransformationEngine();
      const email = 'user@example.com';
      const key = 'sk-proj-SUPERLONGKEY1234567890ABCDEF';
      const phone = '555-123-4567';
      const rawText = `First email: ${email}, second key: ${key}, third phone: ${phone}. Final suffix.`;

      const sEmail = rawText.indexOf(email);
      const eEmail = sEmail + email.length;
      const sKey = rawText.indexOf(key);
      const eKey = sKey + key.length;
      const sPhone = rawText.indexOf(phone);
      const ePhone = sPhone + phone.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'ent-phone',
          category: 'PII',
          range: { startIndex: sPhone, endIndex: ePhone },
        }),
        createEntity({
          id: 'ent-email',
          category: 'PII',
          range: { startIndex: sEmail, endIndex: eEmail },
        }),
        createEntity({
          id: 'ent-key',
          category: 'API_KEY',
          range: { startIndex: sKey, endIndex: eKey },
        }),
      ];

      const result = engine.transformSync(rawText, entities);

      expect(result.transformedText).toBe(
        'First email: [REDACTED_PII], second key: [REDACTED_API_KEY], third phone: [REDACTED_PII]. Final suffix.',
      );
      expect(result.transformationsApplied).toHaveLength(3);

      for (const applied of result.transformationsApplied) {
        const extracted = result.transformedText.slice(
          applied.replacedRange.startIndex,
          applied.replacedRange.endIndex,
        );
        expect(extracted).toBe(`[REDACTED_${applied.category}]`);
      }
    });
  });

  // ==========================================================================
  // 8. Adjacent / Touching Boundary Entities
  // ==========================================================================
  describe('8. Adjacent / Touching Boundary Entities', () => {
    it('transforms touching boundary entities without character loss or corruption', () => {
      const engine = createTransformationEngine();
      const token1 = 'first_secret_123';
      const token2 = 'second_secret_456';
      const rawText = `[${token1}${token2}]`;

      const s1 = rawText.indexOf(token1);
      const e1 = s1 + token1.length;
      const s2 = rawText.indexOf(token2);
      const e2 = s2 + token2.length;

      // Ensure they touch exactly: e1 === s2
      expect(e1).toBe(s2);

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'det-1',
          category: 'API_KEY',
          range: { startIndex: s1, endIndex: e1 },
        }),
        createEntity({
          id: 'det-2',
          category: 'SECRET',
          range: { startIndex: s2, endIndex: e2 },
        }),
      ];

      const result = engine.transformSync(rawText, entities);

      expect(result.transformedText).toBe('[[REDACTED_API_KEY][REDACTED_SECRET]]');
      expect(result.transformationsApplied).toHaveLength(2);
      expect(result.transformationsApplied[0]!.replacedRange.endIndex).toBe(
        result.transformationsApplied[1]!.replacedRange.startIndex,
      );
    });
  });

  // ==========================================================================
  // 9. Overlapping Entities Deterministic Resolution
  // ==========================================================================
  describe('9. Overlapping Entities Deterministic Resolution', () => {
    it('resolves overlapping entities deterministically preferring higher severity', () => {
      const engine = createTransformationEngine();
      // "sk-proj-my-special-token" contains substring "special"
      const rawText = 'Credential is sk-proj-my-special-token in headers';
      const fullStart = rawText.indexOf('sk-proj-my-special-token');
      const fullEnd = fullStart + 'sk-proj-my-special-token'.length;
      const subStart = rawText.indexOf('special');
      const subEnd = subStart + 'special'.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'det-sub',
          category: 'PII',
          severity: 'LOW',
          confidence: 0.6,
          range: { startIndex: subStart, endIndex: subEnd },
        }),
        createEntity({
          id: 'det-full',
          category: 'API_KEY',
          severity: 'CRITICAL',
          confidence: 0.99,
          range: { startIndex: fullStart, endIndex: fullEnd },
        }),
      ];

      const result = engine.transformSync(rawText, entities);

      // Higher severity (CRITICAL API_KEY) should win over overlapping LOW PII
      expect(result.transformedText).toBe('Credential is [REDACTED_API_KEY] in headers');
      expect(result.transformationsApplied).toHaveLength(1);
      expect(result.transformationsApplied[0]!.entityId).toBe('det-full');
    });
  });

  // ==========================================================================
  // 10. Exact Duplicate Ranges Deduplication
  // ==========================================================================
  describe('10. Exact Duplicate Ranges Deduplication', () => {
    it('deduplicates entities with identical range choosing highest priority', () => {
      const engine = createTransformationEngine();
      const rawText = 'Found token secret12345 here';
      const startIndex = rawText.indexOf('secret12345');
      const endIndex = startIndex + 'secret12345'.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'det-low',
          category: 'PASSWORD',
          severity: 'LOW',
          confidence: 0.5,
          range: { startIndex, endIndex },
        }),
        createEntity({
          id: 'det-high',
          category: 'API_KEY',
          severity: 'HIGH',
          confidence: 0.95,
          range: { startIndex, endIndex },
        }),
      ];

      const result = engine.transformSync(rawText, entities);

      expect(result.transformedText).toBe('Found token [REDACTED_API_KEY] here');
      expect(result.transformationsApplied).toHaveLength(1);
      expect(result.transformationsApplied[0]!.entityId).toBe('det-high');
    });
  });

  // ==========================================================================
  // 11. Out-of-Bounds & Inverted Range Safety
  // ==========================================================================
  describe('11. Out-of-Bounds & Inverted Range Safety', () => {
    it('safely rejects invalid, inverted, and out-of-bounds ranges without crashing', () => {
      const engine = createTransformationEngine();
      const rawText = 'Valid text for safety check';

      const entities: DetectionEntity[] = [
        createEntity({ id: 'det-neg', range: { startIndex: -5, endIndex: 5 } }),
        createEntity({ id: 'det-oob', range: { startIndex: 10, endIndex: 9999 } }),
        createEntity({ id: 'det-inv', range: { startIndex: 15, endIndex: 5 } }),
        createEntity({ id: 'det-empty', range: { startIndex: 6, endIndex: 6 } }),
        createEntity({
          id: 'det-valid',
          category: 'PII',
          range: { startIndex: 0, endIndex: 5 }, // 'Valid'
        }),
      ];

      const result = engine.transformSync(rawText, entities);

      expect(result.transformedText).toBe('[REDACTED_PII] text for safety check');
      expect(result.transformationsApplied).toHaveLength(1);
      expect(result.transformationsApplied[0]!.entityId).toBe('det-valid');
    });
  });

  // ==========================================================================
  // 12. Strategy: REDACT (Category Placeholders & Custom Placeholders)
  // ==========================================================================
  describe('12. Strategy: REDACT', () => {
    it('uses category-specific REDACT placeholders by default and supports custom placeholders', () => {
      const engine = createTransformationEngine({
        customPlaceholders: {
          API_KEY: '<SAFE_API_KEY>',
        },
      });

      const rawText = 'Key sk-12345 and email test@example.com';
      const sKey = rawText.indexOf('sk-12345');
      const eKey = sKey + 'sk-12345'.length;
      const sEmail = rawText.indexOf('test@example.com');
      const eEmail = sEmail + 'test@example.com'.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'k1',
          category: 'API_KEY',
          range: { startIndex: sKey, endIndex: eKey },
        }),
        createEntity({
          id: 'e1',
          category: 'PII',
          range: { startIndex: sEmail, endIndex: eEmail },
        }),
      ];

      const result = engine.transformSync(rawText, entities);

      expect(result.transformedText).toBe('Key <SAFE_API_KEY> and email [REDACTED_PII]');
    });
  });

  // ==========================================================================
  // 13. Strategy: MASK with preserveLength: true
  // ==========================================================================
  describe('13. Strategy: MASK with preserveLength: true', () => {
    it('masks characters with asterisks matching exact original length', () => {
      const engine = createTransformationEngine({
        defaultStrategy: {
          type: 'MASK',
          maskChar: '*',
          preserveLength: true,
        },
      });

      const rawText = 'Secret: password123!';
      const token = 'password123!';
      const startIndex = rawText.indexOf(token);
      const endIndex = startIndex + token.length;

      const entity = createEntity({
        category: 'PASSWORD',
        range: { startIndex, endIndex },
      });

      const result = engine.transformSync(rawText, [entity]);

      expect(result.transformedText).toBe(`Secret: ${'*'.repeat(token.length)}`);
      expect(result.transformedText.length).toBe(rawText.length);
    });

    it('supports custom mask character such as bullet or X', () => {
      const engine = createTransformationEngine({
        defaultStrategy: {
          type: 'MASK',
          maskChar: 'X',
          preserveLength: true,
        },
      });

      const rawText = 'Code: 1234';
      const startIndex = rawText.indexOf('1234');
      const endIndex = startIndex + 4;

      const entity = createEntity({
        range: { startIndex, endIndex },
      });

      const result = engine.transformSync(rawText, [entity]);
      expect(result.transformedText).toBe('Code: XXXX');
    });
  });

  // ==========================================================================
  // 14. Strategy: REPLACE (Custom Fixed Replacement)
  // ==========================================================================
  describe('14. Strategy: REPLACE', () => {
    it('replaces target range with custom static replacement string', () => {
      const engine = createTransformationEngine({
        defaultStrategy: {
          type: 'REPLACE',
          replacementText: '[CONFIDENTIAL_TOKEN]',
        },
      });

      const rawText = 'Value is secret_token_data here';
      const startIndex = rawText.indexOf('secret_token_data');
      const endIndex = startIndex + 'secret_token_data'.length;

      const entity = createEntity({
        range: { startIndex, endIndex },
      });

      const result = engine.transformSync(rawText, [entity]);
      expect(result.transformedText).toBe('Value is [CONFIDENTIAL_TOKEN] here');
    });
  });

  // ==========================================================================
  // 15. Category-Specific Strategy Overrides
  // ==========================================================================
  describe('15. Category-Specific Strategy Overrides', () => {
    it('applies distinct strategies per category (e.g. MASK for PII, REDACT for API_KEY)', () => {
      const engine = createTransformationEngine({
        defaultStrategy: { type: 'REDACT' },
        categoryStrategies: {
          PII: { type: 'MASK', maskChar: '#', preserveLength: true },
          API_KEY: { type: 'REDACT', replacementText: '[REDACTED_KEY]' },
        },
      });

      const rawText = 'Email: bob@test.com and API: sk-12345';
      const sEmail = rawText.indexOf('bob@test.com');
      const eEmail = sEmail + 'bob@test.com'.length;
      const sKey = rawText.indexOf('sk-12345');
      const eKey = sKey + 'sk-12345'.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'ent-email',
          category: 'PII',
          range: { startIndex: sEmail, endIndex: eEmail },
        }),
        createEntity({
          id: 'ent-key',
          category: 'API_KEY',
          range: { startIndex: sKey, endIndex: eKey },
        }),
      ];

      const result = engine.transformSync(rawText, entities);

      expect(result.transformedText).toBe(
        `Email: ${'#'.repeat('bob@test.com'.length)} and API: [REDACTED_KEY]`,
      );
    });
  });

  // ==========================================================================
  // 16. Reversible Token Mapping & ReverseTransformer
  // ==========================================================================
  describe('16. Reversible Token Mapping & ReverseTransformer', () => {
    it('reverses authorized reversible placeholder tokens back to original values', async () => {
      const reverseTransformer = createReverseTransformer();

      const transformedText =
        'Hello [TOKEN_EMAIL_1], your session token is [TOKEN_SESSION_2]. Goodbye.';
      const mappings: ReversibleMapping[] = [
        {
          id: 'map-1',
          placeholder: '[TOKEN_EMAIL_1]',
          category: 'PII',
          originalValue: 'alice@wonderland.org',
          createdAt: Date.now(),
        },
        {
          id: 'map-2',
          placeholder: '[TOKEN_SESSION_2]',
          category: 'SECRET',
          originalValue: 'sess-xyz-987',
          createdAt: Date.now(),
        },
      ];

      const reversed = await reverseTransformer.reverse(transformedText, mappings);

      expect(reversed).toBe(
        'Hello alice@wonderland.org, your session token is sess-xyz-987. Goodbye.',
      );
    });
  });

  // ==========================================================================
  // 17. Security & Non-Leakage
  // ==========================================================================
  describe('17. Security & Non-Leakage', () => {
    it('never contains raw sensitive secrets or passwords in AppliedTransformation metadata or plan', () => {
      const engine = createTransformationEngine();
      const rawSecret = 'SUPER_SECRET_PASSWORD_12345!';
      const rawText = `User login: ${rawSecret} in auth header`;
      const startIndex = rawText.indexOf(rawSecret);
      const endIndex = startIndex + rawSecret.length;

      const entity = createEntity({
        category: 'PASSWORD',
        range: { startIndex, endIndex },
        rawValue: rawSecret,
      });

      const plan = engine.plan(rawText, [entity]);
      const planJson = JSON.stringify(plan);
      expect(planJson).not.toContain(rawSecret);

      const result = engine.transformSync(rawText, [entity]);
      const resultJson = JSON.stringify(result.transformationsApplied);
      expect(resultJson).not.toContain(rawSecret);

      // Transformed text must contain the redacted token, not the secret
      expect(result.transformedText).not.toContain(rawSecret);
      expect(result.transformedText).toContain('[REDACTED_PASSWORD]');
    });
  });

  // ==========================================================================
  // 18. Empty & Edge Case Input Handling
  // ==========================================================================
  describe('18. Empty & Edge Case Input Handling', () => {
    it('handles empty text, empty entities, and whitespace-only text safely', () => {
      const engine = createTransformationEngine();

      const r1 = engine.transformSync('', []);
      expect(r1.transformedText).toBe('');
      expect(r1.isModified).toBe(false);

      const r2 = engine.transformSync('   \n\t  ', []);
      expect(r2.transformedText).toBe('   \n\t  ');
      expect(r2.isModified).toBe(false);

      const r3 = engine.transformWithDecision(
        'Sample text',
        [],
        createDecision({ action: 'MASK' }),
      );
      expect(r3.transformedText).toBe('Sample text');
      expect(r3.isModified).toBe(false);
    });
  });

  // ==========================================================================
  // 19. Invariance: Transformation Does Not Mutate Inputs
  // ==========================================================================
  describe('19. Invariance: Transformation Does Not Mutate Inputs', () => {
    it('does not mutate input entities or policy decision', () => {
      const engine = createTransformationEngine();
      const rawText = 'Contact at contact@example.com for info';
      const entity = createEntity({
        range: { startIndex: 11, endIndex: 30 },
      });
      const decision = createDecision({ action: 'MASK' });

      const entityBefore = JSON.stringify(entity);
      const decisionBefore = JSON.stringify(decision);

      engine.transformWithDecision(rawText, [entity], decision);

      expect(JSON.stringify(entity)).toBe(entityBefore);
      expect(JSON.stringify(decision)).toBe(decisionBefore);
    });
  });

  // ==========================================================================
  // 20. Pure Determinism
  // ==========================================================================
  describe('20. Pure Determinism', () => {
    it('produces identical output given identical inputs across separate invocations', () => {
      const engine1 = createTransformationEngine();
      const engine2 = createTransformationEngine();

      const rawText = 'Key 1: sk-token-1234567, Key 2: sk-token-8901234';
      const entities = [
        createEntity({ id: 'k1', range: { startIndex: 7, endIndex: 23 } }),
        createEntity({ id: 'k2', range: { startIndex: 32, endIndex: 48 } }),
      ];

      const res1 = engine1.transformSync(rawText, entities);
      const res2 = engine2.transformSync(rawText, entities);

      expect(res1.transformedText).toBe(res2.transformedText);
      expect(res1.transformationsApplied).toEqual(res2.transformationsApplied);
      expect(res1.isModified).toBe(res2.isModified);
    });
  });

  // ==========================================================================
  // 21. Pipeline Orchestrator Integration via TransformationEngineAdapter
  // ==========================================================================
  describe('21. Pipeline Orchestrator Integration via TransformationEngineAdapter', () => {
    const createBaseInput = (rawText: string): PipelineInput => ({
      rawText,
      timestamp: 1726000000000,
      platformContext: {
        site: 'chatgpt.com',
        isAiSite: true,
      },
    });

    it('integrates cleanly into M1.3 orchestrator through createPipelineTransformer()', async () => {
      const sender = new InMemorySender();
      const transformer = createPipelineTransformer();

      const rawText = 'Authorization: sk-proj-SUPERCONFIDENTIALSECRETKEY123';
      const key = 'sk-proj-SUPERCONFIDENTIALSECRETKEY123';
      const startIndex = rawText.indexOf(key);
      const endIndex = startIndex + key.length;

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [
              createEntity({
                id: 'det-api',
                category: 'API_KEY',
                range: { startIndex, endIndex },
              }),
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
            reason: 'Mask API keys',
            triggeredRules: ['rule-mask-api'],
            allowOverride: false,
          })),
        },
        transformer,
        verifier: new DefaultVerifier(),
        sender,
      });

      const result = await orchestrator.process(createBaseInput(rawText));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result');

      expect(result.value.status).toBe('MASK');
      if (result.value.status === 'MASK') {
        expect(result.value.deliverableText).toBe('Authorization: [REDACTED_API_KEY]');
        expect(result.value.transformation.isModified).toBe(true);
        expect(result.value.transformation.transformationsApplied).toHaveLength(1);
      }

      expect(sender.deliveries).toHaveLength(1);
      expect(sender.deliveries[0]!.deliverableText).toBe('Authorization: [REDACTED_API_KEY]');
    });
  });

  // ==========================================================================
  // 22. Full Integration: Detect (M1.2) → Risk (M1.4) → Policy (M1.5) → Transform (M1.6)
  // ==========================================================================
  describe('22. Full Integration: Detect → Risk → Policy → Transform', () => {
    it('executes full pipeline with real M1.2 detectors, M1.4 risk, M1.5 policy, and M1.6 transformer', async () => {
      const registry = createDefaultDetectorRegistry();
      const realDetectorEngine = {
        detect: async (normalized: { normalizedText: string }) =>
          registry.runAll({
            text: normalized.normalizedText,
            includeRawValue: true,
          }),
      };
      const sender = new InMemorySender();

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: realDetectorEngine,
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: createPolicyEvaluator(),
        transformer: createPipelineTransformer(),
        verifier: new DefaultVerifier(),
        sender,
      });

      const rawText =
        'Contact support at contact@shieldsecurity.org or call +1-555-234-5678 regarding token sk-proj-1234567890abcdef1234567890abcdef';

      const result = await orchestrator.process({
        rawText,
        timestamp: Date.now(),
        platformContext: {
          site: 'chatgpt.com',
          isAiSite: true,
        },
      });

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');

      // The prompt contains critical API_KEY -> Default Policy decides BLOCK or MASK depending on rules
      // With M1.5 default rules: critical credential triggers BLOCK
      expect(['MASK', 'BLOCK']).toContain(result.value.status);

      if (result.value.status === 'MASK') {
        expect(result.value.transformation.isModified).toBe(true);
        expect(result.value.deliverableText).not.toContain('contact@shieldsecurity.org');
      } else if (result.value.status === 'BLOCK') {
        expect(result.value.blockedReason).toBeDefined();
        expect(sender.deliveries).toHaveLength(0);
      }
    });

    it('masks multiple PII and API keys when policy is explicitly configured to MASK all', async () => {
      const registry = createDefaultDetectorRegistry();
      const realDetectorEngine = {
        detect: async (normalized: { normalizedText: string }) =>
          registry.runAll({
            text: normalized.normalizedText,
            includeRawValue: true,
          }),
      };
      const sender = new InMemorySender();

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: realDetectorEngine,
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: {
          evaluate: vi.fn(async () => ({
            action: 'MASK',
            reason: 'Mask all detected findings',
            triggeredRules: ['mask-all'],
            allowOverride: false,
          })),
        },
        transformer: createPipelineTransformer(),
        verifier: new DefaultVerifier(),
        sender,
      });

      const rawText =
        'Email: alice@wonderland.org and key: sk-proj-1234567890abcdef1234567890abcdef';
      const result = await orchestrator.process({
        rawText,
        timestamp: Date.now(),
        platformContext: {
          site: 'chatgpt.com',
          isAiSite: true,
        },
      });

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');

      expect(result.value.status).toBe('MASK');
      if (result.value.status === 'MASK') {
        expect(result.value.deliverableText).toBe(
          'Email: [REDACTED_PII] and key: [REDACTED_API_KEY]',
        );
        expect(result.value.transformation.isModified).toBe(true);
        expect(result.value.transformation.transformationsApplied).toHaveLength(2);
      }

      expect(sender.deliveries).toHaveLength(1);
      expect(sender.deliveries[0]!.deliverableText).toBe(
        'Email: [REDACTED_PII] and key: [REDACTED_API_KEY]',
      );
    });
  });
});
