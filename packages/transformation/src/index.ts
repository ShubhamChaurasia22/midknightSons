/**
 * @shield/transformation
 * Transformation engine contracts and interfaces for Shield.
 *
 * NOTE: Phase 0 contains interface contracts only.
 * Transformation, masking, and redaction logic is implemented in M1+.
 */

import type { DetectionEntity } from '@shield/core';

export type TransformationType = 'mask' | 'redact' | 'replace' | 'temporary_map';

export interface TransformationMapping {
  id: string;
  originalValue: string;
  placeholder: string;
  category: string;
  createdAt: number;
  expiresAt?: number;
}

export interface TransformationStep {
  entityId: string;
  type: TransformationType;
  replacement: string;
}

export interface TransformationPlan {
  steps: TransformationStep[];
  totalModifications: number;
}

export interface TransformationResult {
  originalText: string;
  transformedText: string;
  isModified: boolean;
  mappings: TransformationMapping[];
}

export interface Transformer {
  readonly id: string;
  readonly name: string;
  readonly supportedTypes: TransformationType[];

  /**
   * Plan transformations based on detected entities.
   */
  plan(text: string, entities: DetectionEntity[]): TransformationPlan;

  /**
   * Apply transformations to the text.
   */
  transform(
    text: string,
    entities: DetectionEntity[],
    type: TransformationType,
  ): Promise<TransformationResult>;
}

export interface ReverseTransformer {
  /**
   * Resolve temporary mappings back to original values if authorized.
   */
  reverse(text: string, mappings: TransformationMapping[]): Promise<string>;
}
