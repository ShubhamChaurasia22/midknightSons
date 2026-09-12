/**
 * @shield/policy
 * Deterministic Policy Evaluation Engine, scopes, rules, and adapters for Shield.
 *
 * M1.5 owns the POLICY stage:
 * INPUT → NORMALIZE → DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND
 */

import {
  type DetectionCategory,
  type DetectionResult,
  type PlatformContext,
  type PolicyAction,
  type PolicyDecision,
  type PolicyRule,
  type PolicyScope,
  type RiskAssessment,
  type Severity,
  type ClassificationResult,
  type PipelineContext,
  type PolicyEvaluator,
  POLICY_SCOPE_PRECEDENCE,
  POLICY_ACTION_RANK,
  SEVERITY_RANK,
} from '@shield/core';

export {
  PolicyAction,
  PolicyScope,
  PolicyRule,
  PolicyDecision,
  POLICY_SCOPE_PRECEDENCE,
  POLICY_ACTION_RANK,
};

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

/**
 * Standard default rules providing baseline protection across AI sites.
 */
export function createDefaultPolicyRules(): PolicyRule[] {
  return [
    {
      id: 'default-block-critical-credentials',
      name: 'Block Critical Credentials & Secrets',
      description:
        'Zero-tolerance block on critical credentials, private keys, and high-entropy secrets',
      scope: 'GLOBAL',
      minSeverity: 'CRITICAL',
      action: 'BLOCK',
      priority: 100,
      enabled: true,
    },
    {
      id: 'default-mask-api-keys',
      name: 'Mask API Keys & Structured Tokens',
      description: 'Automatically mask detected vendor API keys and structured tokens before send',
      scope: 'GLOBAL',
      targetCategory: 'API_KEY',
      action: 'MASK',
      priority: 80,
      enabled: true,
    },
    {
      id: 'default-mask-pii',
      name: 'Mask Personally Identifiable Information',
      description: 'Mask emails, phone numbers, and PII before transmission',
      scope: 'GLOBAL',
      targetCategory: 'PII',
      minSeverity: 'MEDIUM',
      action: 'MASK',
      priority: 70,
      enabled: true,
    },
    {
      id: 'default-warn-medium-risk',
      name: 'Warn on Medium Risk Content',
      description: 'Require user confirmation for medium risk sensitive findings',
      scope: 'GLOBAL',
      minSeverity: 'MEDIUM',
      action: 'WARN',
      priority: 50,
      enabled: true,
    },
    {
      id: 'default-allow-low-risk',
      name: 'Allow Low Risk Content',
      description: 'Permit transmission of low severity informational patterns',
      scope: 'GLOBAL',
      minSeverity: 'LOW',
      action: 'ALLOW',
      priority: 10,
      enabled: true,
    },
  ];
}

/**
 * Deterministic Rule-Based Policy Engine
 *
 * Evaluates context against rules using strict precedence:
 * Scope Precedence: SITE_CATEGORY (4) > SITE (3) > CATEGORY (2) > GLOBAL (1)
 * Tiebreaker: Priority (descending) > Action Severity (BLOCK > MASK > WARN > ALLOW) > Rule ID
 */
export class DeterministicPolicyEngine implements PolicyEngine {
  private readonly rules = new Map<string, PolicyRule>();

  constructor(initialRules?: readonly PolicyRule[]) {
    const rulesToLoad = initialRules ?? createDefaultPolicyRules();
    for (const rule of rulesToLoad) {
      this.addRule(rule);
    }
  }

  addRule(rule: PolicyRule): void {
    this.rules.set(rule.id, { ...rule });
  }

  removeRule(ruleId: string): boolean {
    return this.rules.delete(ruleId);
  }

  getRules(): readonly PolicyRule[] {
    return Array.from(this.rules.values());
  }

  async evaluate(context: PolicyEvaluationContext): Promise<PolicyDecision> {
    // 1. Clean Input: No detections or NONE severity
    const detections = context.detections;
    const risk = context.risk;
    const isNoneSeverity = (risk?.severity as unknown as string) === 'NONE';

    if (
      !detections ||
      !detections.hasDetections ||
      !Array.isArray(detections.entities) ||
      detections.entities.length === 0 ||
      isNoneSeverity
    ) {
      return {
        action: 'ALLOW',
        reason: 'Clean input allowed: no sensitive entities detected',
        triggeredRules: [],
        allowOverride: false,
      };
    }

    const currentSite = (context.platformContext?.site ?? '').toLowerCase();
    const entities = detections.entities;
    const overallSeverity: Severity =
      risk?.severity && (risk.severity as unknown as string) !== 'NONE'
        ? (risk.severity as Severity)
        : 'LOW';

    // 2. Find all matching active rules
    const matchedRules: PolicyRule[] = [];

    for (const rule of this.rules.values()) {
      if (!rule.enabled) {
        continue;
      }

      if (this.isRuleMatch(rule, currentSite, entities, overallSeverity)) {
        matchedRules.push(rule);
      }
    }

    // 3. Deterministic Precedence Sorting
    matchedRules.sort((a, b) => {
      // 3a. Scope Precedence: SITE_CATEGORY (4) > SITE (3) > CATEGORY (2) > GLOBAL (1)
      const scopeDiff =
        (POLICY_SCOPE_PRECEDENCE[b.scope] ?? 0) - (POLICY_SCOPE_PRECEDENCE[a.scope] ?? 0);
      if (scopeDiff !== 0) {
        return scopeDiff;
      }

      // 3b. Priority within scope (higher number takes precedence)
      const priorityDiff = b.priority - a.priority;
      if (priorityDiff !== 0) {
        return priorityDiff;
      }

      // 3c. Action severity rank: BLOCK (4) > MASK (3) > WARN (2) > ALLOW (1)
      const actionDiff = (POLICY_ACTION_RANK[b.action] ?? 0) - (POLICY_ACTION_RANK[a.action] ?? 0);
      if (actionDiff !== 0) {
        return actionDiff;
      }

      // 3d. Stable deterministic tiebreaker: rule ID
      return a.id.localeCompare(b.id);
    });

    // 4. Construct Decision from winning rule or fallback
    if (matchedRules.length > 0) {
      const winningRule = matchedRules[0]!;
      const triggeredRules = matchedRules.map((r) => r.id);
      const isWarn = winningRule.action === 'WARN';

      const userNotice = isWarn
        ? (winningRule.description ??
          `Warning: Prompt contains sensitive ${winningRule.targetCategory ?? 'content'}. Proceed with caution.`)
        : undefined;

      const reason = `Policy rule '${winningRule.name}' (${winningRule.id}) triggered action ${winningRule.action} [scope: ${winningRule.scope}, priority: ${winningRule.priority}]`;

      return {
        action: winningRule.action,
        reason,
        matchedRuleId: winningRule.id,
        triggeredRules,
        allowOverride: isWarn,
        userNotice,
      };
    }

    // 5. Secure Fallback if no specific rule matched detected risk
    return this.createSecureFallbackDecision(overallSeverity, risk?.score ?? 0);
  }

  private isRuleMatch(
    rule: PolicyRule,
    currentSite: string,
    entities: readonly { category: DetectionCategory; severity: Severity }[],
    overallSeverity: Severity,
  ): boolean {
    // 1. Site check: if rule specifies targetSite, current site must match
    if (rule.targetSite) {
      const target = rule.targetSite.toLowerCase();
      if (target !== '*' && target !== currentSite) {
        return false;
      }
    } else if (rule.scope === 'SITE' || rule.scope === 'SITE_CATEGORY') {
      return false;
    }

    // 2. Category check: if rule specifies targetCategory, matching entities must be present
    if (rule.targetCategory) {
      const matchingEntities = entities.filter(
        (e) => rule.targetCategory === '*' || e.category === rule.targetCategory,
      );
      if (matchingEntities.length === 0) {
        return false;
      }

      // If minSeverity is also specified, at least one matching category entity must meet or exceed minSeverity
      if (rule.minSeverity) {
        const minRank = SEVERITY_RANK[rule.minSeverity] ?? 0;
        const meetsSeverity = matchingEntities.some(
          (e) => (SEVERITY_RANK[e.severity] ?? 0) >= minRank,
        );
        if (!meetsSeverity) {
          return false;
        }
      }
      return true;
    } else if (rule.scope === 'CATEGORY' || rule.scope === 'SITE_CATEGORY') {
      return false;
    }

    // 3. For rules without targetCategory (e.g. GLOBAL or SITE-only rules):
    // Check minSeverity against overall severity or any entity severity
    if (rule.minSeverity) {
      const minRank = SEVERITY_RANK[rule.minSeverity] ?? 0;
      const overallRank = SEVERITY_RANK[overallSeverity] ?? 0;
      const anyEntityMeets = entities.some((e) => (SEVERITY_RANK[e.severity] ?? 0) >= minRank);

      if (overallRank < minRank && !anyEntityMeets) {
        return false;
      }
    }

    return true;
  }

  private createSecureFallbackDecision(overallSeverity: Severity, score: number): PolicyDecision {
    switch (overallSeverity) {
      case 'CRITICAL':
        return {
          action: 'BLOCK',
          reason: `Default policy fallback: critical severity (score ${score}/100) blocked`,
          matchedRuleId: 'fallback-block-critical',
          triggeredRules: ['fallback-block-critical'],
          allowOverride: false,
        };
      case 'HIGH':
        return {
          action: 'MASK',
          reason: `Default policy fallback: high severity (score ${score}/100) masked`,
          matchedRuleId: 'fallback-mask-high',
          triggeredRules: ['fallback-mask-high'],
          allowOverride: false,
        };
      case 'MEDIUM':
        return {
          action: 'WARN',
          reason: `Default policy fallback: medium severity (score ${score}/100) requires confirmation`,
          matchedRuleId: 'fallback-warn-medium',
          triggeredRules: ['fallback-warn-medium'],
          allowOverride: true,
          userNotice:
            'This prompt contains sensitive information. Please review before proceeding.',
        };
      case 'LOW':
      default:
        return {
          action: 'ALLOW',
          reason: `Default policy fallback: low severity (score ${score}/100) allowed`,
          matchedRuleId: 'fallback-allow-low',
          triggeredRules: ['fallback-allow-low'],
          allowOverride: false,
        };
    }
  }
}

/**
 * Adapter allowing a PolicyEngine to be consumed as an orchestrator PolicyEvaluator stage
 */
export class PolicyEngineEvaluatorAdapter implements PolicyEvaluator {
  constructor(private readonly engine: PolicyEngine) {}

  async evaluate(
    risk: RiskAssessment,
    detections: DetectionResult,
    _classification: ClassificationResult,
    context: PipelineContext,
  ): Promise<PolicyDecision> {
    return this.engine.evaluate({
      platformContext: context.platformContext,
      detections,
      risk,
      userSettings: (context.platformContext as unknown as Record<string, unknown>)
        ?.userSettings as Record<string, unknown> | undefined,
    });
  }
}

/**
 * Factory for creating policy engines
 */
export function createPolicyEngine(rules?: readonly PolicyRule[]): DeterministicPolicyEngine {
  return new DeterministicPolicyEngine(rules);
}

/**
 * Factory for creating pipeline orchestrator policy evaluators
 */
export function createPolicyEvaluator(engine?: PolicyEngine): PolicyEvaluator {
  return new PolicyEngineEvaluatorAdapter(engine ?? createPolicyEngine());
}
