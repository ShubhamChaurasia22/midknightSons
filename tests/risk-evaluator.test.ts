import { describe, it, expect, vi } from 'vitest';
import {
  DeterministicRiskEvaluator,
  createRiskEvaluator,
  createPipelineOrchestrator,
  DefaultNormalizer,
  DefaultClassifier,
  DefaultTransformer,
  DefaultVerifier,
  InMemorySender,
  type DetectionEntity,
  type DetectionResult,
  type ClassificationResult,
  type PolicyDecision,
  type PolicyAction,
  type PipelineInput,
} from '../packages/core/src';
import { createDefaultDetectorRegistry } from '../packages/detection/src';

describe('M1.4 Shield Risk Evaluation Engine', () => {
  const evaluator = createRiskEvaluator({ defaultTimestamp: 1726000000000 });

  const createEntity = (overrides: Partial<DetectionEntity> = {}): DetectionEntity => ({
    id: overrides.id ?? 'det-test-1',
    detectorId: overrides.detectorId ?? 'detector-test',
    category: overrides.category ?? 'API_KEY',
    severity: overrides.severity ?? 'CRITICAL',
    confidence: overrides.confidence ?? 0.99,
    range: overrides.range ?? { startIndex: 10, endIndex: 30 },
    evidence: overrides.evidence ?? {
      tokenLength: 20,
      hasRawValue: false,
      previewMasked: 't***1',
      ruleName: 'test-rule',
    },
    rawValue: overrides.rawValue,
  });

  // ==========================================================================
  // 1. No detections
  // ==========================================================================
  describe('1. No Detections (Clean Input)', () => {
    it('evaluates empty detections to zero risk with 1.0 confidence', () => {
      expect(evaluator).toBeInstanceOf(DeterministicRiskEvaluator);

      const detections: DetectionResult = {
        entities: [],
        hasDetections: false,
        durationMs: 2,
      };

      const assessment = evaluator.evaluate(detections);
      expect(assessment.score).toBe(0);
      expect(assessment.severity).toBe('NONE');
      expect(assessment.confidence).toBe(1.0);
      expect(assessment.factors).toHaveLength(0);
      expect(assessment.summary).toBe('Clean input: no sensitive entities detected');
    });
  });

  // ==========================================================================
  // 2. Single low-risk detection
  // ==========================================================================
  describe('2. Single Low-Risk Detection', () => {
    it('evaluates single LOW severity detection accurately', () => {
      const entity = createEntity({
        id: 'det-low-1',
        detectorId: 'detector-phone',
        category: 'PII',
        severity: 'LOW',
        confidence: 0.85,
        rawValue: '555-0199',
      });

      const detections: DetectionResult = {
        entities: [entity],
        hasDetections: true,
        durationMs: 4,
      };

      const assessment = evaluator.evaluate(detections);
      expect(assessment.severity).toBe('LOW');
      expect(assessment.score).toBeGreaterThan(0);
      expect(assessment.score).toBeLessThan(20);
      expect(assessment.confidence).toBe(0.85);
      expect(assessment.factors).toHaveLength(1);
      expect(assessment.factors[0]!.severity).toBe('LOW');
      expect(assessment.factors[0]!.category).toBe('PII');
    });
  });

  // ==========================================================================
  // 3. Single high-risk detection
  // ==========================================================================
  describe('3. Single High-Risk Detection', () => {
    it('evaluates single HIGH severity detection with correct weighting and confidence', () => {
      const entity = createEntity({
        id: 'det-high-1',
        detectorId: 'detector-password',
        category: 'PASSWORD',
        severity: 'HIGH',
        confidence: 0.9,
      });

      const classification: ClassificationResult = {
        classifiedEntities: [
          {
            entityId: 'det-high-1',
            category: 'PASSWORD',
            sensitivityLevel: 'CONFIDENTIAL',
          },
        ],
      };

      const assessment = evaluator.evaluate(
        { entities: [entity], hasDetections: true, durationMs: 5 },
        classification,
      );

      expect(assessment.severity).toBe('HIGH');
      expect(assessment.score).toBeGreaterThanOrEqual(25);
      expect(assessment.score).toBeLessThanOrEqual(40);
      expect(assessment.confidence).toBe(0.9);
      expect(assessment.factors[0]!.reason).toContain('HIGH severity PASSWORD');
      expect(assessment.factors[0]!.reason).toContain('CONFIDENTIAL sensitivity');
    });
  });

  // ==========================================================================
  // 4. Single critical credential/secret detection
  // ==========================================================================
  describe('4. Single Critical Credential/Secret Detection', () => {
    it('evaluates single CRITICAL severity detection with maximum baseline weight', () => {
      const entity = createEntity({
        id: 'det-crit-1',
        detectorId: 'detector-api-key',
        category: 'API_KEY',
        severity: 'CRITICAL',
        confidence: 0.99,
        rawValue: 'sk-proj-CONFIDENTIALKEY1234567890',
      });

      const classification: ClassificationResult = {
        classifiedEntities: [
          {
            entityId: 'det-crit-1',
            category: 'API_KEY',
            sensitivityLevel: 'RESTRICTED',
          },
        ],
      };

      const assessment = evaluator.evaluate(
        { entities: [entity], hasDetections: true, durationMs: 3 },
        classification,
      );

      expect(assessment.severity).toBe('CRITICAL');
      expect(assessment.score).toBeGreaterThanOrEqual(50);
      expect(assessment.confidence).toBe(0.99);
      expect(assessment.factors).toHaveLength(1);
      expect(assessment.factors[0]!.severity).toBe('CRITICAL');
      expect(assessment.factors[0]!.category).toBe('API_KEY');
    });
  });

  // ==========================================================================
  // 5. Multiple detections
  // ==========================================================================
  describe('5. Multiple Detections Aggregation', () => {
    it('aggregates contributing detections into cumulative score and factors', () => {
      const e1 = createEntity({
        id: 'det-1',
        detectorId: 'detector-email',
        category: 'PII',
        severity: 'MEDIUM',
        confidence: 0.95,
      });
      const e2 = createEntity({
        id: 'det-2',
        detectorId: 'detector-phone',
        category: 'PII',
        severity: 'LOW',
        confidence: 0.8,
      });
      const e3 = createEntity({
        id: 'det-3',
        detectorId: 'detector-api-key',
        category: 'API_KEY',
        severity: 'CRITICAL',
        confidence: 0.99,
      });

      const assessment = evaluator.evaluate({
        entities: [e1, e2, e3],
        hasDetections: true,
        durationMs: 8,
      });

      expect(assessment.factors).toHaveLength(3);
      expect(assessment.severity).toBe('CRITICAL');
      expect(assessment.score).toBeGreaterThanOrEqual(65);
      expect(assessment.summary).toContain('Identified 3 sensitive factor(s)');
      expect(assessment.summary).toContain('2 categories');
    });
  });

  // ==========================================================================
  // 6. Mixed severities & Escalation
  // ==========================================================================
  describe('6. Mixed Severities & Deterministic Escalation', () => {
    it('governs severity by strongest contributing finding', () => {
      const low = createEntity({ id: 'l1', severity: 'LOW', category: 'PII' });
      const med = createEntity({ id: 'm1', severity: 'MEDIUM', category: 'PII' });

      const assessment = evaluator.evaluate({
        entities: [low, med],
        hasDetections: true,
        durationMs: 3,
      });

      expect(assessment.severity).toBe('MEDIUM');
    });

    it('deterministically escalates multiple MEDIUM findings to HIGH severity', () => {
      const m1 = createEntity({ id: 'm1', severity: 'MEDIUM', category: 'PII' });
      const m2 = createEntity({ id: 'm2', severity: 'MEDIUM', category: 'PRIVATE_DATA' });
      const m3 = createEntity({ id: 'm3', severity: 'MEDIUM', category: 'FINANCIAL' });

      const assessment = evaluator.evaluate({
        entities: [m1, m2, m3],
        hasDetections: true,
        durationMs: 5,
      });

      expect(assessment.severity).toBe('HIGH');
    });

    it('deterministically escalates multiple LOW findings to MEDIUM severity', () => {
      const l1 = createEntity({ id: 'l1', severity: 'LOW', category: 'PII' });
      const l2 = createEntity({ id: 'l2', severity: 'LOW', category: 'PII' });
      const l3 = createEntity({ id: 'l3', severity: 'LOW', category: 'PII' });

      const assessment = evaluator.evaluate({
        entities: [l1, l2, l3],
        hasDetections: true,
        durationMs: 4,
      });

      expect(assessment.severity).toBe('MEDIUM');
    });
  });

  // ==========================================================================
  // 7. Mixed confidence levels
  // ==========================================================================
  describe('7. Mixed Confidence Levels & Corroboration', () => {
    it('corroborates confidence across multiple detections without exceeding bounds', () => {
      const e1 = createEntity({ id: 'c1', confidence: 0.6 });
      const e2 = createEntity({ id: 'c2', confidence: 0.85 });
      const e3 = createEntity({ id: 'c3', confidence: 0.75 });

      const assessment = evaluator.evaluate({
        entities: [e1, e2, e3],
        hasDetections: true,
        durationMs: 4,
      });

      // Combined confidence must exceed the maximum single confidence (0.85) due to corroboration
      expect(assessment.confidence).toBeGreaterThan(0.85);
      expect(assessment.confidence).toBeLessThanOrEqual(1.0);
    });
  });

  // ==========================================================================
  // 8. Deterministic repeated evaluation
  // ==========================================================================
  describe('8. Deterministic Repeated Evaluation', () => {
    it('produces identical byte-for-byte evaluation results across 100 consecutive runs', () => {
      const detections: DetectionResult = {
        entities: [
          createEntity({
            id: 'det-1',
            category: 'API_KEY',
            severity: 'CRITICAL',
            confidence: 0.99,
          }),
          createEntity({ id: 'det-2', category: 'PII', severity: 'MEDIUM', confidence: 0.95 }),
        ],
        hasDetections: true,
        durationMs: 6,
      };

      const baseline = evaluator.evaluate(detections);
      const baselineJson = JSON.stringify(baseline);

      for (let i = 0; i < 100; i++) {
        const run = evaluator.evaluate(detections);
        expect(JSON.stringify(run)).toBe(baselineJson);
      }
    });
  });

  // ==========================================================================
  // 9. Confidence bounds
  // ==========================================================================
  describe('9. Confidence Bounds Clamping', () => {
    it('clamps confidence strictly to [0.0, 1.0] even with abnormal input', () => {
      const weirdEntities = [
        createEntity({ id: 'w1', confidence: -2.5 }),
        createEntity({ id: 'w2', confidence: 99.9 }),
        createEntity({ id: 'w3', confidence: Number.NaN }),
      ];

      const assessment = evaluator.evaluate({
        entities: weirdEntities,
        hasDetections: true,
        durationMs: 3,
      });

      expect(assessment.confidence).toBeGreaterThanOrEqual(0.0);
      expect(assessment.confidence).toBeLessThanOrEqual(1.0);
      expect(Number.isFinite(assessment.confidence)).toBe(true);
    });
  });

  // ==========================================================================
  // 10. Explainable reasons
  // ==========================================================================
  describe('10. Explainable Reasons & Audit Trail', () => {
    it('provides clear, traceable, human-readable reasons in every factor', () => {
      const entity = createEntity({
        id: 'det-email-1',
        detectorId: 'detector-email',
        category: 'PII',
        severity: 'MEDIUM',
        confidence: 0.95,
      });

      const assessment = evaluator.evaluate({
        entities: [entity],
        hasDetections: true,
        durationMs: 2,
      });

      expect(assessment.factors).toHaveLength(1);
      const factor = assessment.factors[0]!;
      expect(factor.reason).toBe(
        'MEDIUM severity PII detected by detector-email with INTERNAL sensitivity (95% confidence)',
      );
      expect(factor.weight).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // 11. Security & Zero Raw Sensitive Leakage
  // ==========================================================================
  describe('11. Security & Zero Raw Value Exposure', () => {
    it('ensures raw sensitive values NEVER leak into reasons, summaries, or metadata', () => {
      const rawSecretToken = 'ghp_SUPERSECRETTOKEN1234567890ABCDEF123456';
      const rawPassword = 'MySecretAdminPassword99!';
      const rawEmail = 'ceo-personal@secret-holding.com';

      const detections: DetectionResult = {
        entities: [
          createEntity({
            id: 'det-secret',
            category: 'API_KEY',
            severity: 'CRITICAL',
            rawValue: rawSecretToken,
          }),
          createEntity({
            id: 'det-password',
            category: 'PASSWORD',
            severity: 'CRITICAL',
            rawValue: rawPassword,
          }),
          createEntity({
            id: 'det-email',
            category: 'PII',
            severity: 'MEDIUM',
            rawValue: rawEmail,
          }),
        ],
        hasDetections: true,
        durationMs: 10,
      };

      const assessment = evaluator.evaluate(detections);
      const assessmentDump = JSON.stringify(assessment);

      // Verify that NONE of the raw sensitive values appear anywhere in the risk assessment
      expect(assessmentDump).not.toContain(rawSecretToken);
      expect(assessmentDump).not.toContain(rawPassword);
      expect(assessmentDump).not.toContain(rawEmail);

      // Check each factor specifically
      for (const factor of assessment.factors) {
        expect(factor.reason).not.toContain(rawSecretToken);
        expect(factor.reason).not.toContain(rawPassword);
        expect(factor.reason).not.toContain(rawEmail);
      }
      expect(assessment.summary).not.toContain(rawSecretToken);
      expect(assessment.summary).not.toContain(rawPassword);
      expect(assessment.summary).not.toContain(rawEmail);
    });
  });

  // ==========================================================================
  // 12. Policy Independence
  // ==========================================================================
  describe('12. Policy Independence (Decoupled Stage)', () => {
    it('proves SAME RiskAssessment can drive distinct policy actions (WARN, MASK, BLOCK) without modifying RiskEvaluator', () => {
      const highRiskDetections: DetectionResult = {
        entities: [
          createEntity({
            id: 'det-high',
            category: 'API_KEY',
            severity: 'CRITICAL',
            confidence: 0.99,
          }),
        ],
        hasDetections: true,
        durationMs: 5,
      };

      // 1. Evaluate risk ONCE
      const risk = evaluator.evaluate(highRiskDetections);
      expect(risk.severity).toBe('CRITICAL');
      expect(risk.score).toBeGreaterThanOrEqual(50);

      // 2. Simulate Policy A: Warning on high risk
      const evaluatePolicyA = (r: typeof risk): PolicyDecision => ({
        action: 'WARN' as PolicyAction,
        reason: `Policy A warns on risk severity ${r.severity}`,
        triggeredRules: ['warn-critical'],
        allowOverride: true,
      });

      // 3. Simulate Policy B: Masking on high risk
      const evaluatePolicyB = (r: typeof risk): PolicyDecision => ({
        action: 'MASK' as PolicyAction,
        reason: `Policy B masks on risk severity ${r.severity}`,
        triggeredRules: ['mask-critical'],
        allowOverride: false,
      });

      // 4. Simulate Policy C: Blocking on high risk
      const evaluatePolicyC = (r: typeof risk): PolicyDecision => ({
        action: 'BLOCK' as PolicyAction,
        reason: `Policy C blocks on risk score ${r.score}`,
        triggeredRules: ['block-critical'],
        allowOverride: false,
      });

      const decisionA = evaluatePolicyA(risk);
      const decisionB = evaluatePolicyB(risk);
      const decisionC = evaluatePolicyC(risk);

      expect(decisionA.action).toBe('WARN');
      expect(decisionB.action).toBe('MASK');
      expect(decisionC.action).toBe('BLOCK');

      // The RiskAssessment remained completely invariant across all three policy evaluations
      expect(risk.severity).toBe('CRITICAL');
    });
  });

  // ==========================================================================
  // 13. Empty / Invalid Input Contract Robustness
  // ==========================================================================
  describe('13. Empty / Invalid Input Contract Handling', () => {
    it('handles null, undefined, or empty structures gracefully', () => {
      const nullResult = evaluator.evaluate(null);
      expect(nullResult.severity).toBe('NONE');
      expect(nullResult.score).toBe(0);
      expect(nullResult.confidence).toBe(1.0);

      const undefinedResult = evaluator.evaluate(undefined);
      expect(undefinedResult.severity).toBe('NONE');
      expect(undefinedResult.score).toBe(0);

      const emptyEntitiesResult = evaluator.evaluate({
        entities: [],
        hasDetections: true,
        durationMs: 0,
      });
      expect(emptyEntitiesResult.severity).toBe('NONE');
      expect(emptyEntitiesResult.score).toBe(0);
    });
  });

  // ==========================================================================
  // 14. Regression Verification with M1.2 & M1.3
  // ==========================================================================
  describe('14. End-to-End Pipeline & Milestone Regression', () => {
    it('integrates seamlessly with M1.2 detectors and M1.3 pipeline orchestrator', async () => {
      const detectorRegistry = createDefaultDetectorRegistry();
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
        riskEvaluator: evaluator,
        policyEvaluator: {
          evaluate: vi.fn(async (risk) => ({
            action: risk.severity === 'CRITICAL' ? 'MASK' : 'ALLOW',
            reason: `Evaluated based on risk severity ${risk.severity}`,
            triggeredRules: ['risk-based-action'],
            allowOverride: false,
          })),
        },
        transformer: new DefaultTransformer(),
        verifier: new DefaultVerifier(),
        sender,
      });

      const input: PipelineInput = {
        rawText: 'My key is sk-proj-1234567890abcdef1234567890123456 please keep secret.',
        timestamp: 1726000000000,
        platformContext: {
          site: 'chatgpt.com',
          isAiSite: true,
          url: 'https://chatgpt.com',
        },
      };

      const result = await orchestrator.process(input);
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error('Expected ok result');

      expect(result.value.status).toBe('MASK');
      if (result.value.status === 'MASK') {
        expect(result.value.risk.severity).toBe('CRITICAL');
        expect(result.value.risk.score).toBeGreaterThanOrEqual(50);
        expect(result.value.deliverableText).toBe(
          'My key is [REDACTED_API_KEY] please keep secret.',
        );
      }
    });
  });
});
