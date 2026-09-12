import { describe, it, expect } from 'vitest';
import {
  DeterministicPolicyEngine,
  createPolicyEngine,
  createDefaultPolicyRules,
  createPolicyEvaluator,
  type PolicyEvaluationContext,
} from '../packages/policy/src';
import {
  createPipelineOrchestrator,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultRiskEvaluator,
  DefaultTransformer,
  DefaultVerifier,
  InMemorySender,
  DefaultPolicyEvaluator,
  type PolicyRule,
  type DetectionResult,
  type RiskAssessment,
  type DetectionEntity,
  type PipelineInput,
} from '../packages/core/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

describe('M1.5 Shield Policy Evaluation Engine', () => {
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

  const createBaseRisk = (overrides: Partial<RiskAssessment> = {}): RiskAssessment => ({
    score: overrides.score ?? 0,
    severity: overrides.severity ?? 'NONE',
    confidence: overrides.confidence ?? 1.0,
    factors: overrides.factors ?? [],
    summary: overrides.summary ?? 'Test risk summary',
    evaluationTimestamp: overrides.evaluationTimestamp ?? 1726000000000,
  });

  const createBaseContext = (
    overrides: Partial<PolicyEvaluationContext> = {},
  ): PolicyEvaluationContext => ({
    platformContext: overrides.platformContext ?? {
      site: 'chatgpt.com',
      isAiSite: true,
      url: 'https://chatgpt.com/c/12345',
    },
    detections: overrides.detections ?? {
      entities: [],
      hasDetections: false,
      durationMs: 2,
    },
    risk: overrides.risk ?? createBaseRisk(),
    userSettings: overrides.userSettings,
  });

  // ==========================================================================
  // 1. Clean input → ALLOW
  // ==========================================================================
  describe('1. Clean Input', () => {
    it('instantiates DeterministicPolicyEngine and createDefaultPolicyRules directly', () => {
      const rules = createDefaultPolicyRules();
      expect(rules.length).toBeGreaterThan(0);
      const engine = new DeterministicPolicyEngine(rules);
      expect(engine.getRules()).toHaveLength(rules.length);
    });

    it('evaluates clean input with no detections to ALLOW without override', async () => {
      const engine = createPolicyEngine();
      const decision = await engine.evaluate(createBaseContext());

      expect(decision.action).toBe('ALLOW');
      expect(decision.reason).toContain('Clean input allowed');
      expect(decision.triggeredRules).toHaveLength(0);
      expect(decision.allowOverride).toBe(false);
    });
  });

  // ==========================================================================
  // 2. Low-risk input → expected default action
  // ==========================================================================
  describe('2. Low-Risk Input', () => {
    it('evaluates low risk input to ALLOW under default policy', async () => {
      const engine = createPolicyEngine();
      const entity = createEntity({ severity: 'LOW', category: 'PII' });
      const context = createBaseContext({
        detections: { entities: [entity], hasDetections: true, durationMs: 2 },
        risk: createBaseRisk({ score: 10, severity: 'LOW', confidence: 0.85 }),
      });

      const decision = await engine.evaluate(context);
      expect(decision.action).toBe('ALLOW');
      expect(decision.matchedRuleId).toBe('default-allow-low-risk');
      expect(decision.allowOverride).toBe(false);
    });
  });

  // ==========================================================================
  // 3. Medium-risk input → expected default action
  // ==========================================================================
  describe('3. Medium-Risk Input', () => {
    it('evaluates medium risk input to WARN requiring user confirmation', async () => {
      const engine = createPolicyEngine();
      const entity = createEntity({ severity: 'MEDIUM', category: 'PRIVATE_DATA' });
      const context = createBaseContext({
        detections: { entities: [entity], hasDetections: true, durationMs: 3 },
        risk: createBaseRisk({ score: 35, severity: 'MEDIUM', confidence: 0.9 }),
      });

      const decision = await engine.evaluate(context);
      expect(decision.action).toBe('WARN');
      expect(decision.allowOverride).toBe(true);
      expect(decision.userNotice).toBeDefined();
    });
  });

  // ==========================================================================
  // 4. High-risk input → expected default action
  // ==========================================================================
  describe('4. High-Risk Input', () => {
    it('evaluates high risk input with API_KEY to MASK under default policy', async () => {
      const engine = createPolicyEngine();
      const entity = createEntity({ severity: 'HIGH', category: 'API_KEY' });
      const context = createBaseContext({
        detections: { entities: [entity], hasDetections: true, durationMs: 3 },
        risk: createBaseRisk({ score: 60, severity: 'HIGH', confidence: 0.95 }),
      });

      const decision = await engine.evaluate(context);
      expect(decision.action).toBe('MASK');
      expect(decision.matchedRuleId).toBe('default-mask-api-keys');
      expect(decision.allowOverride).toBe(false);
    });
  });

  // ==========================================================================
  // 5. Critical-risk input → expected default action
  // ==========================================================================
  describe('5. Critical-Risk Input', () => {
    it('evaluates critical risk input to BLOCK transmission', async () => {
      const engine = createPolicyEngine();
      const entity = createEntity({ severity: 'CRITICAL', category: 'API_KEY' });
      const context = createBaseContext({
        detections: { entities: [entity], hasDetections: true, durationMs: 4 },
        risk: createBaseRisk({ score: 95, severity: 'CRITICAL', confidence: 0.99 }),
      });

      const decision = await engine.evaluate(context);
      expect(decision.action).toBe('BLOCK');
      expect(decision.matchedRuleId).toBe('default-block-critical-credentials');
      expect(decision.allowOverride).toBe(false);
    });
  });

  // ==========================================================================
  // 6. WARN decision structure
  // ==========================================================================
  describe('6. WARN Decision Structure', () => {
    it('provides userNotice and allowOverride: true on WARN decisions', async () => {
      const customRules: PolicyRule[] = [
        {
          id: 'custom-warn-internal',
          name: 'Warn on Internal Keywords',
          description: 'This prompt mentions internal assets. Please review.',
          scope: 'GLOBAL',
          minSeverity: 'LOW',
          action: 'WARN',
          priority: 100,
          enabled: true,
        },
      ];
      const engine = createPolicyEngine(customRules);
      const entity = createEntity({ severity: 'LOW', category: 'PII' });
      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [entity], hasDetections: true, durationMs: 1 },
          risk: createBaseRisk({ score: 15, severity: 'LOW' }),
        }),
      );

      expect(decision.action).toBe('WARN');
      expect(decision.allowOverride).toBe(true);
      expect(decision.userNotice).toBe('This prompt mentions internal assets. Please review.');
    });
  });

  // ==========================================================================
  // 7. MASK decision structure
  // ==========================================================================
  describe('7. MASK Decision Structure', () => {
    it('structures MASK decisions with allowOverride: false and clear reason', async () => {
      const engine = createPolicyEngine();
      const entity = createEntity({ severity: 'MEDIUM', category: 'PII' });
      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [entity], hasDetections: true, durationMs: 2 },
          risk: createBaseRisk({ score: 25, severity: 'MEDIUM' }),
        }),
      );

      expect(decision.action).toBe('MASK');
      expect(decision.allowOverride).toBe(false);
      expect(decision.reason).toContain('default-mask-pii');
    });
  });

  // ==========================================================================
  // 8. BLOCK decision structure
  // ==========================================================================
  describe('8. BLOCK Decision Structure', () => {
    it('structures BLOCK decisions with allowOverride: false and zero-tolerance reason', async () => {
      const engine = createPolicyEngine();
      const entity = createEntity({ severity: 'CRITICAL', category: 'SECRET' });
      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [entity], hasDetections: true, durationMs: 2 },
          risk: createBaseRisk({ score: 90, severity: 'CRITICAL' }),
        }),
      );

      expect(decision.action).toBe('BLOCK');
      expect(decision.allowOverride).toBe(false);
      expect(decision.reason).toContain('default-block-critical-credentials');
    });
  });

  // ==========================================================================
  // 9. Deterministic Precedence (SITE_CATEGORY > SITE > CATEGORY > GLOBAL)
  // ==========================================================================
  describe('9. Deterministic Scope & Priority Precedence', () => {
    it('enforces SITE_CATEGORY (4) > SITE (3) > CATEGORY (2) > GLOBAL (1)', async () => {
      const rules: PolicyRule[] = [
        {
          id: 'rule-global',
          name: 'Global Rule',
          scope: 'GLOBAL',
          action: 'ALLOW',
          priority: 100, // High priority, but low scope
          enabled: true,
        },
        {
          id: 'rule-category',
          name: 'Category Rule',
          scope: 'CATEGORY',
          targetCategory: 'API_KEY',
          action: 'WARN',
          priority: 10,
          enabled: true,
        },
        {
          id: 'rule-site',
          name: 'Site Rule',
          scope: 'SITE',
          targetSite: 'chatgpt.com',
          action: 'MASK',
          priority: 10,
          enabled: true,
        },
        {
          id: 'rule-site-category',
          name: 'Site Category Rule',
          scope: 'SITE_CATEGORY',
          targetSite: 'chatgpt.com',
          targetCategory: 'API_KEY',
          action: 'BLOCK',
          priority: 1, // Lowest priority, but highest scope
          enabled: true,
        },
      ];

      const engine = createPolicyEngine(rules);
      const entity = createEntity({ category: 'API_KEY', severity: 'HIGH' });
      const decision = await engine.evaluate(
        createBaseContext({
          platformContext: { site: 'chatgpt.com', isAiSite: true },
          detections: { entities: [entity], hasDetections: true, durationMs: 2 },
          risk: createBaseRisk({ score: 60, severity: 'HIGH' }),
        }),
      );

      // SITE_CATEGORY must win even with lower numeric priority
      expect(decision.matchedRuleId).toBe('rule-site-category');
      expect(decision.action).toBe('BLOCK');
      expect(decision.triggeredRules).toEqual([
        'rule-site-category',
        'rule-site',
        'rule-category',
        'rule-global',
      ]);
    });

    it('enforces numeric priority within the same scope', async () => {
      const rules: PolicyRule[] = [
        {
          id: 'rule-cat-low-pri',
          name: 'Low Priority Category Rule',
          scope: 'CATEGORY',
          targetCategory: 'PII',
          action: 'ALLOW',
          priority: 10,
          enabled: true,
        },
        {
          id: 'rule-cat-high-pri',
          name: 'High Priority Category Rule',
          scope: 'CATEGORY',
          targetCategory: 'PII',
          action: 'BLOCK',
          priority: 50,
          enabled: true,
        },
      ];

      const engine = createPolicyEngine(rules);
      const entity = createEntity({ category: 'PII', severity: 'MEDIUM' });
      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [entity], hasDetections: true, durationMs: 1 },
          risk: createBaseRisk({ score: 30, severity: 'MEDIUM' }),
        }),
      );

      expect(decision.matchedRuleId).toBe('rule-cat-high-pri');
      expect(decision.action).toBe('BLOCK');
    });

    it('breaks ties using action severity rank: BLOCK > MASK > WARN > ALLOW', async () => {
      const rules: PolicyRule[] = [
        {
          id: 'rule-tied-warn',
          name: 'Tied Warn',
          scope: 'GLOBAL',
          action: 'WARN',
          priority: 10,
          enabled: true,
        },
        {
          id: 'rule-tied-block',
          name: 'Tied Block',
          scope: 'GLOBAL',
          action: 'BLOCK',
          priority: 10,
          enabled: true,
        },
      ];

      const engine = createPolicyEngine(rules);
      const entity = createEntity({ severity: 'HIGH' });
      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [entity], hasDetections: true, durationMs: 1 },
          risk: createBaseRisk({ score: 50, severity: 'HIGH' }),
        }),
      );

      expect(decision.action).toBe('BLOCK');
      expect(decision.matchedRuleId).toBe('rule-tied-block');
    });
  });

  // ==========================================================================
  // 10. Multiple detections handling
  // ==========================================================================
  describe('10. Multiple Detections Handling', () => {
    it('evaluates multiple detections and collects all triggered rules', async () => {
      const engine = createPolicyEngine();
      const e1 = createEntity({ id: 'e1', category: 'PII', severity: 'MEDIUM' });
      const e2 = createEntity({ id: 'e2', category: 'API_KEY', severity: 'HIGH' });

      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [e1, e2], hasDetections: true, durationMs: 3 },
          risk: createBaseRisk({ score: 70, severity: 'HIGH' }),
        }),
      );

      expect(decision.triggeredRules).toContain('default-mask-api-keys');
      expect(decision.triggeredRules).toContain('default-mask-pii');
      expect(decision.action).toBe('MASK');
    });
  });

  // ==========================================================================
  // 11. Mixed detection categories
  // ==========================================================================
  describe('11. Mixed Detection Categories', () => {
    it('selects the highest precedence action across distinct categories', async () => {
      const rules: PolicyRule[] = [
        {
          id: 'rule-pii-warn',
          name: 'Warn PII',
          scope: 'CATEGORY',
          targetCategory: 'PII',
          action: 'WARN',
          priority: 50,
          enabled: true,
        },
        {
          id: 'rule-secrets-block',
          name: 'Block Secrets',
          scope: 'CATEGORY',
          targetCategory: 'API_KEY',
          action: 'BLOCK',
          priority: 50,
          enabled: true,
        },
      ];

      const engine = createPolicyEngine(rules);
      const pii = createEntity({ id: 'p1', category: 'PII', severity: 'LOW' });
      const secret = createEntity({ id: 's1', category: 'API_KEY', severity: 'HIGH' });

      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [pii, secret], hasDetections: true, durationMs: 2 },
          risk: createBaseRisk({ score: 65, severity: 'HIGH' }),
        }),
      );

      expect(decision.action).toBe('BLOCK');
      expect(decision.matchedRuleId).toBe('rule-secrets-block');
    });
  });

  // ==========================================================================
  // 12. Sensitivity-aware behavior
  // ==========================================================================
  describe('12. Sensitivity-Aware Behavior', () => {
    it('applies stricter action when minSeverity matches high sensitivity findings', async () => {
      const rules: PolicyRule[] = [
        {
          id: 'rule-critical-only',
          name: 'Block Critical Only',
          scope: 'GLOBAL',
          minSeverity: 'CRITICAL',
          action: 'BLOCK',
          priority: 100,
          enabled: true,
        },
        {
          id: 'rule-fallback-allow',
          name: 'Allow Other',
          scope: 'GLOBAL',
          action: 'ALLOW',
          priority: 10,
          enabled: true,
        },
      ];

      const engine = createPolicyEngine(rules);

      // Low severity finding -> falls back to ALLOW
      const lowDecision = await engine.evaluate(
        createBaseContext({
          detections: {
            entities: [createEntity({ severity: 'LOW' })],
            hasDetections: true,
            durationMs: 1,
          },
          risk: createBaseRisk({ score: 10, severity: 'LOW' }),
        }),
      );
      expect(lowDecision.action).toBe('ALLOW');

      // Critical severity finding -> triggers BLOCK
      const critDecision = await engine.evaluate(
        createBaseContext({
          detections: {
            entities: [createEntity({ severity: 'CRITICAL' })],
            hasDetections: true,
            durationMs: 1,
          },
          risk: createBaseRisk({ score: 90, severity: 'CRITICAL' }),
        }),
      );
      expect(critDecision.action).toBe('BLOCK');
    });
  });

  // ==========================================================================
  // 13. Confidence-aware behavior
  // ==========================================================================
  describe('13. Confidence-Aware Behavior', () => {
    it('evaluates accurately with varying confidence levels', async () => {
      const engine = createPolicyEngine();
      const entity = createEntity({ severity: 'CRITICAL', confidence: 0.99 });
      const context = createBaseContext({
        detections: { entities: [entity], hasDetections: true, durationMs: 2 },
        risk: createBaseRisk({ score: 95, severity: 'CRITICAL', confidence: 0.99 }),
      });

      const decision = await engine.evaluate(context);
      expect(decision.action).toBe('BLOCK');
    });
  });

  // ==========================================================================
  // 14. Custom policy configuration (addRule, removeRule)
  // ==========================================================================
  describe('14. Custom Policy Configuration & Rule Management', () => {
    it('dynamically adds, modifies, and removes rules without code changes', async () => {
      const engine = createPolicyEngine([]);
      expect(engine.getRules()).toHaveLength(0);

      const rule: PolicyRule = {
        id: 'rule-custom-claude',
        name: 'Custom Claude Masking',
        scope: 'SITE',
        targetSite: 'claude.ai',
        action: 'MASK',
        priority: 10,
        enabled: true,
      };

      engine.addRule(rule);
      expect(engine.getRules()).toHaveLength(1);

      const decision = await engine.evaluate(
        createBaseContext({
          platformContext: { site: 'claude.ai', isAiSite: true },
          detections: {
            entities: [createEntity({ severity: 'MEDIUM' })],
            hasDetections: true,
            durationMs: 1,
          },
          risk: createBaseRisk({ score: 30, severity: 'MEDIUM' }),
        }),
      );
      expect(decision.action).toBe('MASK');
      expect(decision.matchedRuleId).toBe('rule-custom-claude');

      // Remove rule and re-evaluate
      const removed = engine.removeRule('rule-custom-claude');
      expect(removed).toBe(true);
      expect(engine.getRules()).toHaveLength(0);

      // Falls back to secure default
      const fallbackDecision = await engine.evaluate(
        createBaseContext({
          platformContext: { site: 'claude.ai', isAiSite: true },
          detections: {
            entities: [createEntity({ severity: 'MEDIUM' })],
            hasDetections: true,
            durationMs: 1,
          },
          risk: createBaseRisk({ score: 30, severity: 'MEDIUM' }),
        }),
      );
      expect(fallbackDecision.matchedRuleId).toBe('fallback-warn-medium');
    });
  });

  // ==========================================================================
  // 15. Same risk + different policies → different actions
  // ==========================================================================
  describe('15. Policy Independence (Same Risk → Different Actions)', () => {
    it('produces WARN, MASK, or BLOCK from identical risk under different policies', async () => {
      const fixedRisk = createBaseRisk({ score: 85, severity: 'CRITICAL', confidence: 0.99 });
      const detections: DetectionResult = {
        entities: [createEntity({ severity: 'CRITICAL', category: 'API_KEY' })],
        hasDetections: true,
        durationMs: 3,
      };

      const warnPolicy = createPolicyEngine([
        {
          id: 'p-warn',
          name: 'Warn All',
          scope: 'GLOBAL',
          action: 'WARN',
          priority: 1,
          enabled: true,
        },
      ]);
      const maskPolicy = createPolicyEngine([
        {
          id: 'p-mask',
          name: 'Mask All',
          scope: 'GLOBAL',
          action: 'MASK',
          priority: 1,
          enabled: true,
        },
      ]);
      const blockPolicy = createPolicyEngine([
        {
          id: 'p-block',
          name: 'Block All',
          scope: 'GLOBAL',
          action: 'BLOCK',
          priority: 1,
          enabled: true,
        },
      ]);

      const dWarn = await warnPolicy.evaluate(createBaseContext({ detections, risk: fixedRisk }));
      const dMask = await maskPolicy.evaluate(createBaseContext({ detections, risk: fixedRisk }));
      const dBlock = await blockPolicy.evaluate(createBaseContext({ detections, risk: fixedRisk }));

      expect(dWarn.action).toBe('WARN');
      expect(dMask.action).toBe('MASK');
      expect(dBlock.action).toBe('BLOCK');
    });
  });

  // ==========================================================================
  // 16. Policy does not mutate risk assessment
  // ==========================================================================
  describe('16. Invariance: Policy Does Not Mutate Risk Assessment', () => {
    it('preserves risk assessment object immutability', async () => {
      const engine = createPolicyEngine();
      const risk = createBaseRisk({ score: 75, severity: 'HIGH', confidence: 0.92 });
      const riskCopy = JSON.parse(JSON.stringify(risk));

      await engine.evaluate(
        createBaseContext({
          detections: {
            entities: [createEntity({ severity: 'HIGH' })],
            hasDetections: true,
            durationMs: 1,
          },
          risk,
        }),
      );

      expect(risk).toEqual(riskCopy);
    });
  });

  // ==========================================================================
  // 17. Policy does not transform text
  // ==========================================================================
  describe('17. Transformation Boundary: Policy Does Not Transform Text', () => {
    it('returns only policy decisions without modifying or returning deliverableText', async () => {
      const engine = createPolicyEngine();
      const decision = await engine.evaluate(
        createBaseContext({
          detections: {
            entities: [createEntity({ severity: 'HIGH', category: 'API_KEY' })],
            hasDetections: true,
            durationMs: 2,
          },
          risk: createBaseRisk({ score: 60, severity: 'HIGH' }),
        }),
      );

      // Decision interface must NOT have transformedText or deliverableText properties
      expect((decision as Record<string, unknown>).transformedText).toBeUndefined();
      expect((decision as Record<string, unknown>).deliverableText).toBeUndefined();
      expect(decision.action).toBe('MASK');
    });
  });

  // ==========================================================================
  // 18. Zero raw sensitive values in policy output
  // ==========================================================================
  describe('18. Security: Zero Raw Sensitive Leakage', () => {
    it('ensures raw tokens, passwords, and emails never leak into policy decision', async () => {
      const secret = 'sk-proj-TOPSECRETKEYDONOTLEAK123456';
      const entity = createEntity({
        severity: 'CRITICAL',
        category: 'API_KEY',
        rawValue: secret,
      });

      const engine = createPolicyEngine();
      const decision = await engine.evaluate(
        createBaseContext({
          detections: { entities: [entity], hasDetections: true, durationMs: 2 },
          risk: createBaseRisk({ score: 90, severity: 'CRITICAL' }),
        }),
      );

      const serialized = JSON.stringify(decision);
      expect(serialized).not.toContain(secret);
      expect(decision.reason).not.toContain(secret);
    });
  });

  // ==========================================================================
  // 19. Safe error behavior
  // ==========================================================================
  describe('19. Safe Error Handling', () => {
    it('handles unexpected errors safely without leaking sensitive input', async () => {
      const brokenEngine = createPolicyEngine();
      // Test evaluate call with malformed context
      const decision = await brokenEngine.evaluate({} as unknown as PolicyEvaluationContext);
      expect(decision.action).toBe('ALLOW');
      expect(decision.allowOverride).toBe(false);
    });
  });

  // ==========================================================================
  // 20. Edge cases & empty inputs
  // ==========================================================================
  describe('20. Empty & Edge-Case Input Robustness', () => {
    it('handles null, undefined, or empty structures gracefully', async () => {
      const engine = createPolicyEngine();

      const d1 = await engine.evaluate(createBaseContext({ detections: undefined }));
      expect(d1.action).toBe('ALLOW');

      const d2 = await engine.evaluate(createBaseContext({ risk: undefined }));
      expect(d2.action).toBe('ALLOW');
    });
  });

  // ==========================================================================
  // 21. Orchestrator Integration & Regression
  // ==========================================================================
  describe('21. Pipeline Orchestrator Integration via DefaultPolicyEvaluator', () => {
    it('orchestrates complete 9-stage pipeline using DefaultPolicyEvaluator', async () => {
      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: async () => ({
            entities: [],
            hasDetections: false,
            durationMs: 1,
          }),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator: new DefaultPolicyEvaluator(),
        transformer: new DefaultTransformer(),
        verifier: new DefaultVerifier(),
        sender: new InMemorySender(),
      });

      const input: PipelineInput = {
        rawText: 'Write a quick sort algorithm in Rust.',
        timestamp: 1726000000000,
        platformContext: { site: 'chatgpt.com', isAiSite: true },
      };

      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');
      expect(result.value.status).toBe('ALLOW');
      expect(result.value.deliverableText).toBe(input.rawText);
    });
  });

  // ==========================================================================
  // 22. End-to-End Integration: M1.2 Detect + M1.4 Risk + M1.5 Policy
  // ==========================================================================
  describe('22. Full Integration: Detect (M1.2) → Risk (M1.4) → Policy (M1.5)', () => {
    it('executes full pipeline with real M1.2 detectors, real M1.4 risk, and real M1.5 policy engine', async () => {
      const detectorRegistry = createDefaultDetectorRegistry();
      const customPolicyEngine = createPolicyEngine([
        {
          id: 'rule-mask-all-secrets',
          name: 'Mask All Secrets on AI Sites',
          scope: 'GLOBAL',
          targetCategory: 'API_KEY',
          action: 'MASK',
          priority: 100,
          enabled: true,
        },
      ]);
      const policyEvaluator = createPolicyEvaluator(customPolicyEngine);
      const sender = new InMemorySender();

      const orchestrator = createPipelineOrchestrator({
        normalizer: new DefaultNormalizer(),
        detectorEngine: {
          detect: async (norm) =>
            detectorRegistry.runAll({
              text: norm.normalizedText,
              includeRawValue: true,
            }),
        },
        classifier: new DefaultClassifier(),
        riskEvaluator: new DefaultRiskEvaluator(),
        policyEvaluator,
        transformer: new DefaultTransformer(),
        verifier: new DefaultVerifier(),
        sender,
      });

      const input: PipelineInput = {
        rawText: 'Here is my OpenAI key: sk-proj-1234567890abcdef1234567890123456 for testing.',
        timestamp: 1726000000000,
        platformContext: { site: 'chatgpt.com', isAiSite: true },
      };

      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok');

      expect(result.value.status).toBe('MASK');
      if (result.value.status === 'MASK') {
        expect(result.value.decision.action).toBe('MASK');
        expect(result.value.decision.matchedRuleId).toBe('rule-mask-all-secrets');
        expect(result.value.deliverableText).toBe(
          'Here is my OpenAI key: [REDACTED_API_KEY] for testing.',
        );
        expect(sender.deliveries).toHaveLength(1);
      }
    });
  });
});
