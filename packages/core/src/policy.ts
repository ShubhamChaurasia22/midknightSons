/**
 * Policy Domain Model
 *
 * Scopes, rules, actions, and decision contracts for the Shield policy layer.
 * Strictly separates policy decisions from detector logic.
 */

import type { DetectionCategory, Severity } from './detection';

export type PolicyAction = 'ALLOW' | 'WARN' | 'MASK' | 'BLOCK';

export type PolicyScope = 'GLOBAL' | 'CATEGORY' | 'SITE' | 'SITE_CATEGORY';

/**
 * Precedence hierarchy for scoping overrides:
 * SITE_CATEGORY (4) > SITE (3) > CATEGORY (2) > GLOBAL (1)
 */
export const POLICY_SCOPE_PRECEDENCE: Record<PolicyScope, number> = {
  SITE_CATEGORY: 4,
  SITE: 3,
  CATEGORY: 2,
  GLOBAL: 1,
} as const;

export interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  scope: PolicyScope;
  targetSite?: string; // e.g. 'chatgpt.com', 'claude.ai', '*'
  targetCategory?: DetectionCategory;
  minSeverity?: Severity;
  action: PolicyAction;
  priority: number; // Higher number takes precedence within same scope
  enabled: boolean;
}

export interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  matchedRuleId?: string;
  triggeredRules: readonly string[];
  allowOverride: boolean;
  userNotice?: string;
}
