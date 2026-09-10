/**
 * @shield/policy
 * Policy interfaces, scopes, actions, and evaluation contracts for Shield.
 *
 * NOTE: M1.1 contains domain contracts only.
 * Concrete policy evaluation engine is implemented in M1.3+.
 */

import type {
  DetectionResult,
  PlatformContext,
  PolicyAction,
  PolicyDecision,
  PolicyRule,
  PolicyScope,
  RiskAssessment,
} from '@shield/core';

export { PolicyAction, PolicyScope, PolicyRule, PolicyDecision };

export interface PolicyEvaluationContext {
  readonly platformContext: PlatformContext;
  readonly detections: DetectionResult;
  readonly risk?: RiskAssessment;
  readonly userSettings?: Readonly<Record<string, unknown>>;
}

export interface PolicyEngine {
  addRule(rule: PolicyRule): void;
  removeRule(ruleId: string): boolean;
  getRules(): readonly PolicyRule[];
  /**
   * Evaluate a given context against active rules to determine the action.
   */
  evaluate(context: PolicyEvaluationContext): Promise<PolicyDecision>;
}
