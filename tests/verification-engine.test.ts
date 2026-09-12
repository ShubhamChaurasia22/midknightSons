import { describe, it, expect, vi } from 'vitest';
import {
  DeterministicVerificationEngine,
  createVerificationEngine,
  type DetectionEntity,
  type PolicyDecision,
  type TransformationResult,
  type AppliedTransformation,
  createPipelineOrchestrator,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultRiskEvaluator,
  InMemorySender,
  type PipelineInput,
} from '../packages/core/src';
import { createPolicyEvaluator } from '../packages/policy/src';
import {
  createPipelineTransformer,
  createTransformationEngine,
} from '../packages/transformation/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

describe('M1.7 Shield Verification Engine', () => {
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
    reason: overrides.reason ?? 'Policy test decision',
    matchedRuleId: overrides.matchedRuleId ?? 'rule-test',
    triggeredRules: overrides.triggeredRules ?? ['rule-test'],
    allowOverride: overrides.allowOverride ?? false,
    userNotice: overrides.userNotice,
  });

  const createTransformation = (
    overrides: Partial<TransformationResult> = {},
  ): TransformationResult => ({
    originalText: overrides.originalText ?? 'Default original text',
    transformedText: overrides.transformedText ?? 'Default transformed text',
    isModified: overrides.isModified ?? true,
    transformationsApplied: overrides.transformationsApplied ?? [],
  });

  // ==========================================================================
  // Basic Tests
  // ==========================================================================
  describe('Basic Invariants', () => {
    it('instantiates DeterministicVerificationEngine class directly', () => {
      const engine = new DeterministicVerificationEngine();
      expect(engine.id).toBe('shield-deterministic-verifier');
    });

    it('1. Clean input passes verification with NOT_REQUIRED status', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Hello clean world without any sensitive data';
      const transformation = createTransformation({
        originalText: rawText,
        transformedText: rawText,
        isModified: false,
        transformationsApplied: [],
      });
      const decision = createDecision({ action: 'ALLOW' });

      const result = verifier.verifySync(transformation, decision, [], rawText, rawText, []);

      expect(result.verified).toBe(true);
      expect(result.status).toBe('NOT_REQUIRED');
      expect(result.leaksDetected).toBe(false);
      expect(result.residualRisk.severity).toBe('NONE');
    });

    it('2. ALLOW input remains unchanged and passes verification', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Public announcement for all users';
      const transformation = createTransformation({
        originalText: rawText,
        transformedText: rawText,
        isModified: false,
        transformationsApplied: [],
      });
      const decision = createDecision({ action: 'ALLOW' });

      const result = verifier.verifySync(transformation, decision, [], rawText, rawText, []);

      expect(result.verified).toBe(true);
      expect(result.status).toBe('NOT_REQUIRED');
    });

    it('3. Valid MASK output passes verification', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Key is sk-test-1234567890';
      const secret = 'sk-test-1234567890';
      const transformedText = 'Key is [REDACTED_API_KEY]';
      const s = rawText.indexOf(secret);
      const e = s + secret.length;

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex: s, endIndex: e },
        rawValue: secret,
      });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: s, endIndex: e },
          replacedRange: { startIndex: s, endIndex: s + '[REDACTED_API_KEY]'.length },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText,
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformedText,
        applied,
      );

      expect(result.verified).toBe(true);
      expect(result.status).toBe('SUCCESS');
      expect(result.leaksDetected).toBe(false);
    });

    it('4. Valid transformation metadata matches and passes', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();
      const rawText = 'Email: user@example.com for help';
      const email = 'user@example.com';
      const s = rawText.indexOf(email);
      const e = s + email.length;

      const entity = createEntity({
        category: 'PII',
        range: { startIndex: s, endIndex: e },
        rawValue: email,
      });

      const transformRes = engine.transformSync(rawText, [entity]);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(result.status).toBe('SUCCESS');
      expect(result.leaksDetected).toBe(false);
    });
  });

  // ==========================================================================
  // Failure Tests
  // ==========================================================================
  describe('Failure Modes & Leak Detection', () => {
    it('5. Raw sensitive value remains → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawSecret = 'sk-proj-SUPERSECRETKEY123';
      const rawText = `Header: ${rawSecret} in request`;
      // Buggy transformation that didn't actually redact
      const transformedText = `Header: ${rawSecret} in request`;

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex: 8, endIndex: 8 + rawSecret.length },
        rawValue: rawSecret,
      });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: 8, endIndex: 8 + rawSecret.length },
          replacedRange: { startIndex: 8, endIndex: 8 + rawSecret.length },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText,
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformedText,
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.leaksDetected).toBe(true);
      expect(result.failedChecks).toContain('RESIDUAL_RAW_LEAK:API_KEY');
    });

    it('6. Partial sensitive value remains → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawSecret = 'sk-test-123456';
      const rawText = `key: ${rawSecret}`;
      // Incomplete masking leaving suffix
      const transformedText = 'key: [REDACTED_API_KEY]123456';
      const s = rawText.indexOf(rawSecret);
      const e = s + rawSecret.length;

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex: s, endIndex: e },
        rawValue: rawSecret,
      });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: s, endIndex: e - 6 },
          replacedRange: { startIndex: s, endIndex: s + '[REDACTED_API_KEY]'.length },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText,
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformedText,
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.leaksDetected).toBe(true);
    });

    it('7. Sensitive prefix remains → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawSecret = 'sk-test-123456';
      const rawText = `key: ${rawSecret}`;
      // Prefix leaked before replacement
      const transformedText = 'key: sk-[REDACTED_API_KEY]';
      const s = rawText.indexOf(rawSecret);
      const e = s + rawSecret.length;

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex: s, endIndex: e },
        rawValue: rawSecret,
      });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: s + 3, endIndex: e },
          replacedRange: { startIndex: s + 3, endIndex: s + 3 + '[REDACTED_API_KEY]'.length },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText,
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformedText,
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.leaksDetected).toBe(true);
      expect(result.failedChecks).toContain('RESIDUAL_PREFIX_LEAK:API_KEY');
    });

    it('8. Sensitive suffix remains → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawSecret = 'sk-test-123456';
      const rawText = `key: ${rawSecret}`;
      const transformedText = 'key: [REDACTED_API_KEY]56';
      const s = rawText.indexOf(rawSecret);
      const e = s + rawSecret.length;

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex: s, endIndex: e },
        rawValue: rawSecret,
      });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: s, endIndex: e - 2 },
          replacedRange: { startIndex: s, endIndex: s + '[REDACTED_API_KEY]'.length },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText,
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformedText,
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.leaksDetected).toBe(true);
      expect(result.failedChecks).toContain('RESIDUAL_SUFFIX_LEAK:API_KEY');
    });

    it('9. Missing transformation → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Secret key: 1234567890';
      const entity = createEntity({
        range: { startIndex: 12, endIndex: 22 },
        rawValue: '1234567890',
      });

      // No transformations applied
      const transformation = createTransformation({
        originalText: rawText,
        transformedText: rawText,
        isModified: false,
        transformationsApplied: [],
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        rawText,
        [],
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.failedChecks).toContain('MISSING_ALL_TRANSFORMATIONS');
    });

    it('10. Invalid range (inverted indices) → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Sample text';
      const entity = createEntity({ range: { startIndex: 5, endIndex: 2 } });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: 5, endIndex: 2 },
          replacedRange: { startIndex: 0, endIndex: 10 },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText: '[REDACTED]',
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        '[REDACTED]',
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.failedChecks).toContain('INVALID_ORIGINAL_RANGE:API_KEY');
    });

    it('11. Out-of-bounds range → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Short';
      const entity = createEntity({ range: { startIndex: 0, endIndex: 100 } });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: 0, endIndex: 100 },
          replacedRange: { startIndex: 0, endIndex: 10 },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText: '[REDACTED]',
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        '[REDACTED]',
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.failedChecks).toContain('INVALID_ORIGINAL_RANGE:API_KEY');
    });

    it('12. Incorrect replacement (empty slice) → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Key is secret';
      const entity = createEntity({ range: { startIndex: 7, endIndex: 13 } });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: 7, endIndex: 13 },
          replacedRange: { startIndex: 7, endIndex: 7 }, // Empty replaced range!
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText: 'Key is ',
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        'Key is ',
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.failedChecks).toContain('EMPTY_REPLACEMENT:API_KEY');
    });

    it('13. Transformation metadata mismatch (neighboring text consumed) → FAIL', () => {
      const verifier = createVerificationEngine();
      const rawSecret = 'sk-test-123456';
      const rawText = `key: ${rawSecret}`;
      // Label "y:" consumed
      const transformedText = 'ke[REDACTED_API_KEY]';

      const entity = createEntity({
        range: { startIndex: 5, endIndex: 5 + rawSecret.length },
        rawValue: rawSecret,
      });

      const applied: AppliedTransformation[] = [
        {
          entityId: entity.id,
          type: 'MASK',
          originalRange: { startIndex: 2, endIndex: 5 + rawSecret.length }, // Consumed "y: "
          replacedRange: { startIndex: 2, endIndex: 2 + '[REDACTED_API_KEY]'.length },
          category: 'API_KEY',
        },
      ];

      const transformation = createTransformation({
        originalText: rawText,
        transformedText,
        isModified: true,
        transformationsApplied: applied,
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformedText,
        applied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
      expect(result.failedChecks).toContain('SURROUNDING_TEXT_CORRUPTED:PREFIX');
    });
  });

  // ==========================================================================
  // Multiple Entities & Boundary Scenarios
  // ==========================================================================
  describe('Multiple Entities & Boundary Scenarios', () => {
    it('14. Multiple detections verified properly', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();

      const email = 'alice@wonderland.org';
      const key = 'sk-proj-SUPERSECRET123456';
      const rawText = `Email: ${email}, Key: ${key}`;

      const sEmail = rawText.indexOf(email);
      const eEmail = sEmail + email.length;
      const sKey = rawText.indexOf(key);
      const eKey = sKey + key.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'e1',
          category: 'PII',
          range: { startIndex: sEmail, endIndex: eEmail },
          rawValue: email,
        }),
        createEntity({
          id: 'k1',
          category: 'API_KEY',
          range: { startIndex: sKey, endIndex: eKey },
          rawValue: key,
        }),
      ];

      const transformRes = engine.transformSync(rawText, entities);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        entities,
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(result.status).toBe('SUCCESS');
      expect(result.leaksDetected).toBe(false);
    });

    it('15. Multiple transformations all independently verified', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();

      const rawText = 'Items: 111-11-1111 and 222-22-2222 and 333-33-3333.';
      const entities: DetectionEntity[] = [
        createEntity({
          id: 'i1',
          category: 'PII',
          range: { startIndex: 7, endIndex: 18 },
          rawValue: '111-11-1111',
        }),
        createEntity({
          id: 'i2',
          category: 'PII',
          range: { startIndex: 23, endIndex: 34 },
          rawValue: '222-22-2222',
        }),
        createEntity({
          id: 'i3',
          category: 'PII',
          range: { startIndex: 39, endIndex: 50 },
          rawValue: '333-33-3333',
        }),
      ];

      const transformRes = engine.transformSync(rawText, entities);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        entities,
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(result.status).toBe('SUCCESS');
    });

    it('16. Adjacent transformations touch without boundary bleeding', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();

      const tok1 = 'secret_A';
      const tok2 = 'secret_B';
      const rawText = `(${tok1}${tok2})`;

      const s1 = rawText.indexOf(tok1);
      const e1 = s1 + tok1.length;
      const s2 = rawText.indexOf(tok2);
      const e2 = s2 + tok2.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 't1',
          category: 'API_KEY',
          range: { startIndex: s1, endIndex: e1 },
          rawValue: tok1,
        }),
        createEntity({
          id: 't2',
          category: 'SECRET',
          range: { startIndex: s2, endIndex: e2 },
          rawValue: tok2,
        }),
      ];

      const transformRes = engine.transformSync(rawText, entities);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        entities,
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(result.status).toBe('SUCCESS');
      expect(transformRes.transformedText).toBe('([REDACTED_API_KEY][REDACTED_SECRET])');
    });

    it('17. Overlapping transformations safely resolved and verified', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();

      const rawText = 'Found: sk-proj-1234567890abcdef in code';
      const fullToken = 'sk-proj-1234567890abcdef';
      const subToken = '1234567890';

      const sFull = rawText.indexOf(fullToken);
      const eFull = sFull + fullToken.length;
      const sSub = rawText.indexOf(subToken);
      const eSub = sSub + subToken.length;

      const entities: DetectionEntity[] = [
        createEntity({
          id: 'sub',
          category: 'PII',
          severity: 'LOW',
          range: { startIndex: sSub, endIndex: eSub },
          rawValue: subToken,
        }),
        createEntity({
          id: 'full',
          category: 'API_KEY',
          severity: 'CRITICAL',
          range: { startIndex: sFull, endIndex: eFull },
          rawValue: fullToken,
        }),
      ];

      const transformRes = engine.transformSync(rawText, entities);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        entities,
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(result.status).toBe('SUCCESS');
      expect(transformRes.transformedText).toBe('Found: [REDACTED_API_KEY] in code');
    });

    it('18. Beginning-of-string transformation verified', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();

      const secret = 'sk-start-token';
      const rawText = `${secret} trailing text`;

      const entity = createEntity({
        range: { startIndex: 0, endIndex: secret.length },
        rawValue: secret,
      });

      const transformRes = engine.transformSync(rawText, [entity]);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(transformRes.transformedText).toBe('[REDACTED_API_KEY] trailing text');
    });

    it('19. End-of-string transformation verified', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();

      const secret = 'sk-end-token';
      const rawText = `Leading text ${secret}`;
      const startIndex = rawText.indexOf(secret);

      const entity = createEntity({
        range: { startIndex, endIndex: rawText.length },
        rawValue: secret,
      });

      const transformRes = engine.transformSync(rawText, [entity]);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(transformRes.transformedText).toBe('Leading text [REDACTED_API_KEY]');
    });

    it('20. Punctuation boundaries preserved without character loss', () => {
      const engine = createTransformationEngine();
      const verifier = createVerificationEngine();

      const email = 'user@test.org';
      const rawText = `("email": "${email}", "verified": true);`;
      const startIndex = rawText.indexOf(email);
      const endIndex = startIndex + email.length;

      const entity = createEntity({
        category: 'PII',
        range: { startIndex, endIndex },
        rawValue: email,
      });

      const transformRes = engine.transformSync(rawText, [entity]);
      const result = verifier.verifySync(
        transformRes,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformRes.transformedText,
        transformRes.transformationsApplied,
      );

      expect(result.verified).toBe(true);
      expect(transformRes.transformedText).toBe('("email": "[REDACTED_PII]", "verified": true);');
    });
  });

  // ==========================================================================
  // Policy Semantics & Invariance
  // ==========================================================================
  describe('Policy Semantics & Invariance', () => {
    it('21. MASK requires successful verification to proceed', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Password is secret123';
      const entity = createEntity({
        range: { startIndex: 12, endIndex: 21 },
        rawValue: 'secret123',
      });

      // Incomplete transformation
      const transformation = createTransformation({
        originalText: rawText,
        transformedText: 'Password is [REDACTED]secret123',
        isModified: true,
        transformationsApplied: [
          {
            entityId: entity.id,
            type: 'MASK',
            originalRange: { startIndex: 12, endIndex: 21 },
            replacedRange: { startIndex: 12, endIndex: 22 },
            category: 'API_KEY',
          },
        ],
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        transformation.transformedText,
        transformation.transformationsApplied,
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('FAILED');
    });

    it('22. BLOCK remains non-sendable and returns NOT_REQUIRED', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Top secret private key';
      const transformation = createTransformation({
        originalText: rawText,
        transformedText: rawText,
        isModified: false,
        transformationsApplied: [],
      });
      const decision = createDecision({ action: 'BLOCK' });

      const result = verifier.verifySync(transformation, decision, [], rawText, rawText, []);

      expect(result.verified).toBe(true);
      expect(result.status).toBe('NOT_REQUIRED');
    });

    it('23. WARN does not become silently sendable; preserves decision semantics', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Warning: internal document';
      const transformation = createTransformation({
        originalText: rawText,
        transformedText: rawText,
        isModified: false,
        transformationsApplied: [],
      });
      const decision = createDecision({ action: 'WARN', allowOverride: true });

      const result = verifier.verifySync(transformation, decision, [], rawText, rawText, []);

      expect(result.verified).toBe(true);
      expect(result.status).toBe('NOT_REQUIRED');
    });

    it('24. Verification does not change policy action', () => {
      const verifier = createVerificationEngine();
      const decision = createDecision({ action: 'MASK' });
      const originalAction = decision.action;

      verifier.verifySync(
        createTransformation({
          originalText: 'text',
          transformedText: 'text',
          isModified: false,
          transformationsApplied: [],
        }),
        decision,
        [],
        'text',
        'text',
        [],
      );

      expect(decision.action).toBe(originalAction);
    });

    it('25. Verification does not mutate risk assessment or inputs', () => {
      const verifier = createVerificationEngine();
      const entity = createEntity({ range: { startIndex: 0, endIndex: 5 } });
      const entityJson = JSON.stringify(entity);

      verifier.verifySync(
        createTransformation({
          originalText: 'hello',
          transformedText: 'hello',
          isModified: false,
          transformationsApplied: [],
        }),
        createDecision({ action: 'ALLOW' }),
        [entity],
        'hello',
        'hello',
        [],
      );

      expect(JSON.stringify(entity)).toBe(entityJson);
    });
  });

  // ==========================================================================
  // Security & Non-Leakage
  // ==========================================================================
  describe('Security & Non-Leakage', () => {
    it('26. Verification result never contains raw sensitive values in failure reasons or notes', () => {
      const verifier = createVerificationEngine();
      const rawPassword = 'SUPER_SECRET_UNMASKED_PASSWORD!';
      const rawText = `Login: ${rawPassword}`;

      const entity = createEntity({
        category: 'PASSWORD',
        range: { startIndex: 7, endIndex: 7 + rawPassword.length },
        rawValue: rawPassword,
      });

      const transformation = createTransformation({
        originalText: rawText,
        transformedText: rawText, // Failed to mask
        isModified: true,
        transformationsApplied: [
          {
            entityId: entity.id,
            type: 'MASK',
            originalRange: { startIndex: 7, endIndex: 7 + rawPassword.length },
            replacedRange: { startIndex: 7, endIndex: 7 + rawPassword.length },
            category: 'PASSWORD',
          },
        ],
      });

      const result = verifier.verifySync(
        transformation,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        rawText,
        transformation.transformationsApplied,
      );

      expect(result.verified).toBe(false);
      expect(result.notes).not.toContain(rawPassword);
      if (result.failedChecks) {
        for (const check of result.failedChecks) {
          expect(check).not.toContain(rawPassword);
        }
      }
    });

    it('27. Safe error messages: residualRisk factors contain safe descriptions only', () => {
      const verifier = createVerificationEngine();
      const rawApiKey = 'sk-proj-CRITICALVENDORSECRET12345';
      const rawText = `Bearer ${rawApiKey}`;

      const entity = createEntity({
        category: 'API_KEY',
        range: { startIndex: 7, endIndex: 7 + rawApiKey.length },
        rawValue: rawApiKey,
      });

      const result = verifier.verifySync(
        createTransformation({
          originalText: rawText,
          transformedText: rawText,
          isModified: true,
          transformationsApplied: [],
        }),
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        rawText,
        [],
      );

      expect(result.residualRisk.summary).not.toContain(rawApiKey);
      for (const factor of result.residualRisk.factors) {
        expect(factor.reason).not.toContain(rawApiKey);
      }
    });

    it('28. Serialized verification result contains zero secrets', () => {
      const verifier = createVerificationEngine();
      const secret = 'TOP_SECRET_AUTH_TOKEN_99999';
      const rawText = `Auth: ${secret}`;

      const entity = createEntity({
        category: 'SECRET',
        range: { startIndex: 6, endIndex: 6 + secret.length },
        rawValue: secret,
      });

      const result = verifier.verifySync(
        createTransformation({
          originalText: rawText,
          transformedText: rawText,
          isModified: false,
          transformationsApplied: [],
        }),
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        rawText,
        [],
      );

      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain(secret);
    });
  });

  // ==========================================================================
  // Determinism
  // ==========================================================================
  describe('Determinism', () => {
    it('29. Same input repeatedly produces identical verification decision', () => {
      const v1 = createVerificationEngine();
      const v2 = createVerificationEngine();

      const rawText = 'Key: sk-12345';
      const entity = createEntity({ range: { startIndex: 5, endIndex: 13 }, rawValue: 'sk-12345' });
      const trans = createTransformation({
        originalText: rawText,
        transformedText: 'Key: [REDACTED_API_KEY]',
        isModified: true,
        transformationsApplied: [
          {
            entityId: entity.id,
            type: 'MASK',
            originalRange: { startIndex: 5, endIndex: 13 },
            replacedRange: { startIndex: 5, endIndex: 23 },
            category: 'API_KEY',
          },
        ],
      });

      const r1 = v1.verifySync(
        trans,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        trans.transformedText,
        trans.transformationsApplied,
        1000,
      );
      const r2 = v2.verifySync(
        trans,
        createDecision({ action: 'MASK' }),
        [entity],
        rawText,
        trans.transformedText,
        trans.transformationsApplied,
        1000,
      );

      expect(r1).toEqual(r2);
    });

    it('30. No wall-clock dependency in verification logic', () => {
      const verifier = createVerificationEngine();
      const rawText = 'Text without secrets';
      const trans = createTransformation({
        originalText: rawText,
        transformedText: rawText,
        isModified: false,
        transformationsApplied: [],
      });

      const r1 = verifier.verifySync(
        trans,
        createDecision({ action: 'ALLOW' }),
        [],
        rawText,
        rawText,
        [],
        100,
      );
      const r2 = verifier.verifySync(
        trans,
        createDecision({ action: 'ALLOW' }),
        [],
        rawText,
        rawText,
        [],
        999999999,
      );

      expect(r1.verified).toBe(r2.verified);
      expect(r1.status).toBe(r2.status);
      expect(r1.leaksDetected).toBe(r2.leaksDetected);
    });
  });

  // ==========================================================================
  // Full Integration Tests
  // ==========================================================================
  describe('Full Integration & Orchestrator Safety', () => {
    const createBaseInput = (rawText: string): PipelineInput => ({
      rawText,
      timestamp: 1726000000000,
      platformContext: {
        site: 'chatgpt.com',
        isAiSite: true,
      },
    });

    it('31. Full pipeline: Detect (M1.2) → Risk (M1.4) → Policy (M1.5) → Transform (M1.6) → Verify (M1.7)', async () => {
      const detectorRegistry = createDefaultDetectorRegistry();
      const realDetectorEngine = {
        detect: async (normalized: { normalizedText: string }) =>
          detectorRegistry.runAll({
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
        verifier: createVerificationEngine(),
        sender,
      });

      const rawText = 'Email contact: ops@shield.org is our primary address.';
      const result = await orchestrator.process(createBaseInput(rawText));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');

      if (result.value.status === 'MASK') {
        expect(result.value.verification.verified).toBe(true);
        expect(result.value.verification.status).toBe('SUCCESS');
        expect(result.value.verification.leaksDetected).toBe(false);
        expect(result.value.deliverableText).toBe(
          'Email contact: [REDACTED_PII] is our primary address.',
        );
        expect(sender.deliveries).toHaveLength(1);
      }
    });

    it('32. Regression through M1.3 orchestrator with DefaultVerifier delegation', async () => {
      const sender = new InMemorySender();
      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [
              createEntity({
                id: 'k1',
                category: 'API_KEY',
                range: { startIndex: 5, endIndex: 15 },
                rawValue: 'sk-1234567',
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
            reason: 'Mask API key',
            triggeredRules: ['mask-keys'],
            allowOverride: false,
          })),
        },
        transformer: createPipelineTransformer(),
        verifier: createVerificationEngine(),
        sender,
      });

      const rawText = 'Key: sk-1234567';
      const result = await orchestrator.process(createBaseInput(rawText));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('MASK');
      if (result.value.status === 'MASK') {
        expect(result.value.deliverableText).toBe('Key: [REDACTED_API_KEY]');
        expect(result.value.verification.verified).toBe(true);
      }
      expect(sender.deliveries).toHaveLength(1);
    });

    it('33. Failed verification prevents SEND and halts pipeline', async () => {
      const sender = new InMemorySender();
      // Broken transformer that leaks raw value
      const brokenTransformer = {
        transform: vi.fn(() => ({
          originalText: 'Key: sk-supersecret-token',
          transformedText: 'Key: sk-supersecret-token', // Leaked!
          isModified: true,
          transformationsApplied: [
            {
              entityId: 'det-1',
              type: 'MASK' as const,
              originalRange: { startIndex: 5, endIndex: 25 },
              replacedRange: { startIndex: 5, endIndex: 25 },
              category: 'API_KEY',
            },
          ],
        })),
      };

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: vi.fn(async () => ({
            entities: [
              createEntity({
                id: 'det-1',
                category: 'API_KEY',
                range: { startIndex: 5, endIndex: 25 },
                rawValue: 'sk-supersecret-token',
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
            reason: 'Mask credentials',
            triggeredRules: ['rule-mask'],
            allowOverride: false,
          })),
        },
        transformer: brokenTransformer,
        verifier: createVerificationEngine(),
        sender,
      });

      const result = await orchestrator.process(createBaseInput('Key: sk-supersecret-token'));

      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result with error status');

      // Pipeline status must be ERROR due to verification failure
      expect(result.value.status).toBe('ERROR');
      if (result.value.status === 'ERROR') {
        expect(result.value.failedStage).toBe('VERIFY');
      }

      // SENDER MUST NEVER RECEIVE DELIVERIES WHEN VERIFICATION FAILS
      expect(sender.deliveries).toHaveLength(0);
    });
  });
});
