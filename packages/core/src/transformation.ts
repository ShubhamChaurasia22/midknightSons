/**
 * Transformation Domain Model
 *
 * Contracts for text masking, redaction, and replacement strategies.
 * Strictly decoupled from policy decisions.
 */

import type { DetectionCategory, TextRange } from './detection';

export type TransformationType = 'MASK' | 'REDACT' | 'REPLACE';

export interface TransformationStrategy {
  type: TransformationType;
  maskChar?: string; // Default: '*'
  replacementText?: string; // Default: '[REDACTED]' or entity-specific placeholder
  preserveLength?: boolean;
}

export interface TransformationStep {
  entityId: string;
  type: TransformationType;
  targetRange: TextRange;
  strategy: TransformationStrategy;
}

export interface AppliedTransformation {
  entityId: string;
  type: TransformationType;
  originalRange: TextRange;
  replacedRange: TextRange;
  category: DetectionCategory;
}

export interface TransformationPlan {
  steps: readonly TransformationStep[];
  totalEntities: number;
}

export interface TransformationResult {
  originalText: string;
  transformedText: string;
  isModified: boolean;
  transformationsApplied: readonly AppliedTransformation[];
}
