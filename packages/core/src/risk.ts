/**
 * Deterministic Risk Model
 *
 * Provides typed, explainable risk assessments with traceable contributing factors.
 * Strictly avoids opaque or non-deterministic risk scores.
 */

import type { DetectionCategory, Severity } from './detection';

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
