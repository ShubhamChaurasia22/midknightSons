import { describe, it, expect } from 'vitest';
import type {
  PipelineStage,
  DetectionCategory,
  Severity,
  DetectionEntity,
  RiskAssessment,
  PolicyAction,
  PolicyScope,
  PolicyRule,
  PolicyDecision,
  TransformationResult,
  VerificationResult,
  PipelineResult,
} from '../packages/core/src';
import { PIPELINE_STAGES, POLICY_SCOPE_PRECEDENCE } from '../packages/core/src';

describe('M1.1 Shield Core Engine Domain Model', () => {
  describe('1. Canonical Pipeline Stages', () => {
    it('defines all 9 stages in canonical sequence', () => {
      const expected: readonly PipelineStage[] = [
        'INPUT',
        'NORMALIZE',
        'DETECT',
        'CLASSIFY',
        'RISK',
        'POLICY',
        'TRANSFORM',
        'VERIFY',
        'SEND',
      ];
      expect(PIPELINE_STAGES).toEqual(expected);
      expect(PIPELINE_STAGES).toHaveLength(9);
    });
  });

  describe('2. Detection Categories & Extensibility', () => {
    it('supports all initial canonical categories', () => {
      const knownCategories: DetectionCategory[] = [
        'PII',
        'CREDENTIAL',
        'API_KEY',
        'SECRET',
        'PASSWORD',
        'FINANCIAL',
        'PRIVATE_DATA',
        'UNKNOWN',
      ];
      expect(knownCategories).toHaveLength(8);
    });

    it('allows custom categories without engine changes', () => {
      const customCategory: DetectionCategory = 'CUSTOM_INTERNAL_PROJECT_CODE';
      const entity: DetectionEntity = {
        id: 'det-1',
        detectorId: 'custom-scanner',
        category: customCategory,
        severity: 'MEDIUM',
        confidence: 0.95,
        range: { startIndex: 0, endIndex: 10 },
        evidence: {
          tokenLength: 10,
          hasRawValue: false,
          ruleName: 'project-codename-rule',
        },
      };

      expect(entity.category).toBe('CUSTOM_INTERNAL_PROJECT_CODE');
      expect(entity.evidence.hasRawValue).toBe(false);
      expect(entity.rawValue).toBeUndefined();
    });
  });

  describe('3. Severity Independent from Policy Action', () => {
    it('allows CRITICAL severity to pair with MASK or WARN, not only BLOCK', () => {
      const criticalSeverity: Severity = 'CRITICAL';
      const maskAction: PolicyAction = 'MASK';
      const warnAction: PolicyAction = 'WARN';

      const decision1: PolicyDecision = {
        action: maskAction,
        reason: 'Critical API key detected, masking applied per enterprise policy',
        triggeredRules: ['rule-critical-mask'],
        allowOverride: false,
      };

      const decision2: PolicyDecision = {
        action: warnAction,
        reason: 'Critical confidential note detected, prompting user confirmation',
        triggeredRules: ['rule-critical-warn'],
        allowOverride: true,
        userNotice: 'Prompt contains critical internal project details. Proceed?',
      };

      expect(criticalSeverity).toBe('CRITICAL');
      expect(decision1.action).toBe('MASK');
      expect(decision2.action).toBe('WARN');
      expect(decision2.allowOverride).toBe(true);
    });
  });

  describe('4. Policy Scopes & Precedence', () => {
    it('supports all 4 scopes with correct hierarchical precedence', () => {
      const scopes: PolicyScope[] = ['GLOBAL', 'CATEGORY', 'SITE', 'SITE_CATEGORY'];
      expect(scopes).toHaveLength(4);

      expect(POLICY_SCOPE_PRECEDENCE.SITE_CATEGORY).toBeGreaterThan(POLICY_SCOPE_PRECEDENCE.SITE);
      expect(POLICY_SCOPE_PRECEDENCE.SITE).toBeGreaterThan(POLICY_SCOPE_PRECEDENCE.CATEGORY);
      expect(POLICY_SCOPE_PRECEDENCE.CATEGORY).toBeGreaterThan(POLICY_SCOPE_PRECEDENCE.GLOBAL);
    });

    it('represents scoped policy rules correctly', () => {
      const siteRule: PolicyRule = {
        id: 'rule-chatgpt-override',
        name: 'Block API keys on ChatGPT',
        scope: 'SITE_CATEGORY',
        targetSite: 'chatgpt.com',
        targetCategory: 'API_KEY',
        minSeverity: 'HIGH',
        action: 'BLOCK',
        priority: 10,
        enabled: true,
      };

      expect(siteRule.scope).toBe('SITE_CATEGORY');
      expect(siteRule.action).toBe('BLOCK');
      expect(siteRule.priority).toBe(10);
    });
  });

  describe('5. Deterministic Risk Model', () => {
    it('structures explainable risk scores and contributing factors', () => {
      const risk: RiskAssessment = {
        score: 85,
        severity: 'HIGH',
        confidence: 0.92,
        factors: [
          {
            detectorId: 'detector-api-key',
            category: 'API_KEY',
            severity: 'CRITICAL',
            weight: 60,
            reason: 'High-entropy secret token identified',
          },
          {
            detectorId: 'detector-email',
            category: 'PII',
            severity: 'MEDIUM',
            weight: 25,
            reason: 'Personal email address identified',
          },
        ],
        summary: 'Detected 1 critical API key and 1 personal email',
        evaluationTimestamp: 1726000000000,
      };

      expect(risk.score).toBe(85);
      expect(risk.severity).toBe('HIGH');
      expect(risk.factors).toHaveLength(2);
      expect(risk.factors[0]?.weight).toBe(60);
    });
  });

  describe('6. Transformation Model', () => {
    it('represents transformation results separately from policy', () => {
      const result: TransformationResult = {
        originalText: 'Send key sk-1234567890abcdef to user',
        transformedText: 'Send key [REDACTED_API_KEY] to user',
        isModified: true,
        transformationsApplied: [
          {
            entityId: 'ent-1',
            type: 'REDACT',
            originalRange: { startIndex: 9, endIndex: 31 },
            replacedRange: { startIndex: 9, endIndex: 27 },
            category: 'API_KEY',
          },
        ],
      };

      expect(result.isModified).toBe(true);
      expect(result.transformationsApplied[0]?.type).toBe('REDACT');
      expect(result.transformedText).toContain('[REDACTED_API_KEY]');
    });
  });

  describe('7. Verification Model', () => {
    it('distinguishes SUCCESS, FAILED, and NOT_REQUIRED states', () => {
      const successVerification: VerificationResult = {
        status: 'SUCCESS',
        verified: true,
        residualRisk: {
          score: 0,
          severity: 'NONE',
          confidence: 1.0,
          factors: [],
          summary: 'Zero residual sensitive entities found after transformation',
          evaluationTimestamp: 1726000000000,
        },
        leaksDetected: false,
      };

      const notRequiredVerification: VerificationResult = {
        status: 'NOT_REQUIRED',
        verified: true,
        residualRisk: {
          score: 0,
          severity: 'NONE',
          confidence: 1.0,
          factors: [],
          summary: 'Input allowed unchanged; no transformation required',
          evaluationTimestamp: 1726000000000,
        },
        leaksDetected: false,
      };

      const failedVerification: VerificationResult = {
        status: 'FAILED',
        verified: false,
        residualRisk: {
          score: 70,
          severity: 'HIGH',
          confidence: 0.85,
          factors: [
            {
              detectorId: 'post-check',
              category: 'SECRET',
              severity: 'HIGH',
              weight: 70,
              reason: 'Residual secret pattern still detected after replacement',
            },
          ],
          summary: 'Residual leak detected in output',
          evaluationTimestamp: 1726000000000,
        },
        leaksDetected: true,
        failedChecks: ['leak-detection-pass-failed'],
        notes: 'Residual pattern remained',
      };

      expect(successVerification.status).toBe('SUCCESS');
      expect(notRequiredVerification.status).toBe('NOT_REQUIRED');
      expect(failedVerification.status).toBe('FAILED');
      expect(failedVerification.leaksDetected).toBe(true);
    });
  });

  describe('8. Pipeline Result Discriminated Union', () => {
    const baseMetadata = {
      startedAt: 1000,
      completedAt: 1050,
      stageTimings: { INPUT: 2, NORMALIZE: 3, DETECT: 15, POLICY: 5, SEND: 2 },
      errors: [],
    };

    const emptyRisk: RiskAssessment = {
      score: 0,
      severity: 'NONE',
      confidence: 1.0,
      factors: [],
      summary: 'Clean input',
      evaluationTimestamp: 1000,
    };

    it('narrows ALLOW result safely', () => {
      const result: PipelineResult = {
        status: 'ALLOW',
        contextId: 'ctx-1',
        deliverableText: 'Hello AI assistant',
        decision: {
          action: 'ALLOW',
          reason: 'No sensitive data found',
          triggeredRules: [],
          allowOverride: false,
        },
        risk: emptyRisk,
        metadata: baseMetadata,
      };

      if (result.status === 'ALLOW') {
        expect(result.deliverableText).toBe('Hello AI assistant');
        expect(result.status).toBe('ALLOW');
      } else {
        throw new Error('Type narrowing failed');
      }
    });

    it('narrows WARN result safely with warningNotice', () => {
      const result: PipelineResult = {
        status: 'WARN',
        contextId: 'ctx-2',
        deliverableText: 'Confidential project update',
        warningNotice: 'Contains potential internal code names.',
        allowOverride: true,
        decision: {
          action: 'WARN',
          reason: 'Internal keyword triggered warning',
          triggeredRules: ['rule-internal-warn'],
          allowOverride: true,
        },
        risk: { ...emptyRisk, score: 40, severity: 'MEDIUM' },
        metadata: baseMetadata,
      };

      if (result.status === 'WARN') {
        expect(result.warningNotice).toBe('Contains potential internal code names.');
        expect(result.allowOverride).toBe(true);
      } else {
        throw new Error('Type narrowing failed');
      }
    });

    it('narrows MASK result safely with transformation and verification', () => {
      const result: PipelineResult = {
        status: 'MASK',
        contextId: 'ctx-3',
        deliverableText: 'Here is my email: [REDACTED_PII]',
        transformation: {
          originalText: 'Here is my email: user@test.com',
          transformedText: 'Here is my email: [REDACTED_PII]',
          isModified: true,
          transformationsApplied: [],
        },
        verification: {
          status: 'SUCCESS',
          verified: true,
          residualRisk: emptyRisk,
          leaksDetected: false,
        },
        decision: {
          action: 'MASK',
          reason: 'PII masked per user policy',
          triggeredRules: ['rule-mask-pii'],
          allowOverride: false,
        },
        risk: { ...emptyRisk, score: 30, severity: 'LOW' },
        metadata: baseMetadata,
      };

      if (result.status === 'MASK') {
        expect(result.transformation.isModified).toBe(true);
        expect(result.verification.status).toBe('SUCCESS');
      } else {
        throw new Error('Type narrowing failed');
      }
    });

    it('narrows BLOCK result safely with blockedReason', () => {
      const result: PipelineResult = {
        status: 'BLOCK',
        contextId: 'ctx-4',
        blockedReason: 'Transmission blocked: production private key detected.',
        decision: {
          action: 'BLOCK',
          reason: 'Zero-tolerance rule for private keys',
          triggeredRules: ['rule-block-private-key'],
          allowOverride: false,
        },
        risk: { ...emptyRisk, score: 99, severity: 'CRITICAL' },
        metadata: baseMetadata,
      };

      if (result.status === 'BLOCK') {
        expect(result.blockedReason).toContain('production private key');
      } else {
        throw new Error('Type narrowing failed');
      }
    });

    it('narrows ERROR result safely with failedStage', () => {
      const result: PipelineResult = {
        status: 'ERROR',
        contextId: 'ctx-5',
        failedStage: 'TRANSFORM',
        error: {
          code: 'TRANSFORMATION_TIMEOUT',
          message: 'Transformation timed out after 500ms',
        },
        metadata: {
          ...baseMetadata,
          errors: [
            {
              stage: 'TRANSFORM',
              code: 'TRANSFORMATION_TIMEOUT',
              message: 'Transformation timed out',
              recoverable: false,
            },
          ],
        },
      };

      if (result.status === 'ERROR') {
        expect(result.failedStage).toBe('TRANSFORM');
        expect(result.error.code).toBe('TRANSFORMATION_TIMEOUT');
      } else {
        throw new Error('Type narrowing failed');
      }
    });
  });
});
