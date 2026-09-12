/**
 * Deterministic Risk Model & Evaluation Engine
 *
 * Provides typed, explainable risk assessments with traceable contributing factors.
 * Strictly avoids opaque or non-deterministic risk scores.
 * Completely decoupled from policy actions (ALLOW, WARN, MASK, BLOCK).
 */

import type {
  DetectionCategory,
  Severity,
  DetectionResult,
  ClassificationResult,
  SensitivityLevel,
} from './detection';
import type { PipelineContext } from './context';

export type RiskSeverity = Severity | 'NONE';

export interface RiskFactor {
  detectorId: string;
  category: DetectionCategory;
  severity: Severity;
  weight: number; // 0 to 100
  reason: string;
}

export interface RiskAssessment {
  score: number; // Normalized 0 to 100
  severity: RiskSeverity;
  confidence: number; // Normalized 0.0 to 1.0
  factors: readonly RiskFactor[];
  summary: string;
  evaluationTimestamp: number;
}

export interface RiskEvaluatorConfig {
  readonly severityWeights?: Readonly<Partial<Record<Severity, number>>>;
  readonly sensitivityMultipliers?: Readonly<Partial<Record<SensitivityLevel, number>>>;
  readonly categoryBonus?: number;
  readonly defaultTimestamp?: number;
}

export const SEVERITY_RANK: Readonly<Record<RiskSeverity, number>> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NONE: 0,
};

export const DEFAULT_SEVERITY_WEIGHTS: Readonly<Record<Severity, number>> = {
  CRITICAL: 50,
  HIGH: 30,
  MEDIUM: 15,
  LOW: 5,
};

export const DEFAULT_SENSITIVITY_MULTIPLIERS: Readonly<Record<SensitivityLevel, number>> = {
  RESTRICTED: 1.25,
  CONFIDENTIAL: 1.1,
  INTERNAL: 1.0,
  PUBLIC: 0.5,
};

/**
 * Deterministic Risk Evaluator
 *
 * Pure core engine for evaluating risk of detected entities.
 * Answers "How risky is the detected content and why?" without deciding policy actions.
 */
export class DeterministicRiskEvaluator {
  private readonly weights: Record<Severity, number>;
  private readonly multipliers: Record<SensitivityLevel, number>;
  private readonly categoryBonus: number;
  private readonly defaultTimestamp?: number;

  constructor(config?: RiskEvaluatorConfig) {
    this.weights = {
      ...DEFAULT_SEVERITY_WEIGHTS,
      ...config?.severityWeights,
    };
    this.multipliers = {
      ...DEFAULT_SENSITIVITY_MULTIPLIERS,
      ...config?.sensitivityMultipliers,
    };
    this.categoryBonus = config?.categoryBonus ?? 10;
    this.defaultTimestamp = config?.defaultTimestamp;
  }

  evaluate(
    detections?: DetectionResult | null,
    classification?: ClassificationResult | null,
    context?: PipelineContext | null,
  ): RiskAssessment {
    const timestamp =
      context?.timestamp ??
      context?.executionMetadata?.startedAt ??
      this.defaultTimestamp ??
      Date.now();

    // 1. Clean / Empty input validation
    if (
      !detections ||
      !detections.hasDetections ||
      !Array.isArray(detections.entities) ||
      detections.entities.length === 0
    ) {
      return {
        score: 0,
        severity: 'NONE',
        confidence: 1.0,
        factors: [],
        summary: 'Clean input: no sensitive entities detected',
        evaluationTimestamp: timestamp,
      };
    }

    const entities = detections.entities;
    const classifiedMap = new Map<string, SensitivityLevel>();
    if (classification && Array.isArray(classification.classifiedEntities)) {
      for (const c of classification.classifiedEntities) {
        classifiedMap.set(c.entityId, c.sensitivityLevel);
      }
    }

    let rawScoreSum = 0;
    let highestSeverity: Severity = 'LOW';
    let maxDetectorConfidence = 0;
    const distinctCategories = new Set<string>();
    const factors: RiskFactor[] = [];

    // 2. Evaluate individual factors
    for (const entity of entities) {
      const severity: Severity = entity.severity;
      const baseWeight = this.weights[severity] ?? 10;
      const sensitivity =
        classifiedMap.get(entity.id) ?? this.defaultSensitivityForSeverity(severity);
      const sensitivityMultiplier = this.multipliers[sensitivity] ?? 1.0;

      // Bound confidence cleanly between 0.0 and 1.0
      const clampedConfidence = Math.max(
        0,
        Math.min(1, Number.isFinite(entity.confidence) ? entity.confidence : 0.85),
      );
      if (clampedConfidence > maxDetectorConfidence) {
        maxDetectorConfidence = clampedConfidence;
      }

      // Track highest severity
      if (SEVERITY_RANK[severity] > SEVERITY_RANK[highestSeverity]) {
        highestSeverity = severity;
      }

      distinctCategories.add(entity.category);

      // Weight contribution
      const factorWeight = Math.min(
        100,
        Math.max(1, Math.round(baseWeight * sensitivityMultiplier * clampedConfidence)),
      );
      rawScoreSum += factorWeight;

      // Safe explainable reason (NEVER includes raw values, previews, or sensitive tokens)
      const confidencePercent = Math.round(clampedConfidence * 100);
      const reason = `${severity} severity ${entity.category} detected by ${entity.detectorId} with ${sensitivity} sensitivity (${confidencePercent}% confidence)`;

      factors.push({
        detectorId: entity.detectorId,
        category: entity.category,
        severity,
        weight: factorWeight,
        reason,
      });
    }

    // 3. Category diversity compounding
    if (distinctCategories.size > 1) {
      rawScoreSum += (distinctCategories.size - 1) * this.categoryBonus;
    }

    // 4. Severity escalation rules
    let finalSeverity: Severity = highestSeverity;
    if (highestSeverity === 'LOW' && entities.length >= 3) {
      finalSeverity = 'MEDIUM';
    } else if (
      highestSeverity === 'MEDIUM' &&
      (entities.length >= 3 || distinctCategories.size >= 2)
    ) {
      finalSeverity = 'HIGH';
    }

    // Final normalized score [0, 100]
    const finalScore = Math.min(100, Math.max(0, rawScoreSum));

    // 5. Corroborating confidence calculation strictly bounded in [0.0, 1.0]
    let finalConfidence = maxDetectorConfidence;
    if (entities.length > 1) {
      // Corroboration increases confidence asymptotically towards 1.0
      const corroborationFactor = 1 - 1 / (1 + 0.15 * (entities.length - 1));
      finalConfidence = maxDetectorConfidence + (1 - maxDetectorConfidence) * corroborationFactor;
    }
    // Round to 2 decimal places for deterministic precision and clamp
    finalConfidence = Math.min(1.0, Math.max(0.0, Math.round(finalConfidence * 100) / 100));

    // 6. Summary generation
    const categoryCount = distinctCategories.size;
    const categoryText = categoryCount === 1 ? '1 category' : `${categoryCount} categories`;
    const summary = `Identified ${entities.length} sensitive factor(s) across ${categoryText} with ${finalSeverity} overall severity (score ${finalScore}/100)`;

    return {
      score: finalScore,
      severity: finalSeverity,
      confidence: finalConfidence,
      factors,
      summary,
      evaluationTimestamp: timestamp,
    };
  }

  private defaultSensitivityForSeverity(severity: Severity): SensitivityLevel {
    switch (severity) {
      case 'CRITICAL':
        return 'RESTRICTED';
      case 'HIGH':
        return 'CONFIDENTIAL';
      case 'MEDIUM':
        return 'INTERNAL';
      case 'LOW':
        return 'PUBLIC';
    }
  }
}

/**
 * Factory for creating deterministic risk evaluators
 */
export function createRiskEvaluator(config?: RiskEvaluatorConfig): DeterministicRiskEvaluator {
  return new DeterministicRiskEvaluator(config);
}
