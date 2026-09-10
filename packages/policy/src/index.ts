/**
 * @shield/policy
 * Policy interfaces, scopes, actions, and evaluation contracts for Shield.
 *
 * NOTE: Phase 0 contains interface contracts only.
 * Concrete policy evaluation engine is implemented in M1+.
 */

import type { DetectionResult, PolicyAction, PolicyDecision } from '@shield/core';

export { PolicyAction };

export type PolicyScope = 'GLOBAL' | 'CATEGORY' | 'SITE' | 'SITE_AND_CATEGORY';

export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  scope: PolicyScope;
  targetSite?: string; // e.g. 'chatgpt.com', 'claude.ai', '*'
  targetCategory?: string; // e.g. 'PII', 'SECRET', '*'
  action: PolicyAction;
  enabled: boolean;
  priority: number;
}

export interface PolicyEvaluationContext {
  platformId: string;
  sourceUrl: string;
  detections: DetectionResult;
  userSettings?: Record<string, unknown>;
}

export interface PolicyEngine {
  addRule(rule: PolicyRule): void;
  removeRule(ruleId: string): boolean;
  getRules(): PolicyRule[];
  /**
   * Evaluate a given context against active rules to determine the action.
   */
  evaluate(context: PolicyEvaluationContext): Promise<PolicyDecision>;
}
