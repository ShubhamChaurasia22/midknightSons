/**
 * @shield/transformation
 * Transformation engine contracts and interfaces for Shield.
 *
 * NOTE: M1.1 contains domain contracts only.
 * Transformation, masking, and redaction logic is implemented in M1.4+.
 */

import type {
  AppliedTransformation,
  DetectionEntity,
  TransformationPlan,
  TransformationResult,
  TransformationStrategy,
  TransformationType,
} from '@shield/core';

export type {
  AppliedTransformation,
  TransformationPlan,
  TransformationResult,
  TransformationStrategy,
  TransformationType,
};

export interface Transformer {
  readonly id: string;
  readonly name: string;
  readonly supportedTypes: readonly TransformationType[];

  /**
   * Plan transformations based on detected entities.
   */
  plan(text: string, entities: readonly DetectionEntity[]): TransformationPlan;

  /**
   * Apply planned transformations to the text.
   */
  transform(
    text: string,
    entities: readonly DetectionEntity[],
    strategy: TransformationStrategy,
  ): Promise<TransformationResult>;
}

export interface ReversibleMapping {
  readonly id: string;
  readonly placeholder: string;
  readonly category: string;
  readonly createdAt: number;
  readonly expiresAt?: number;
}

export interface ReverseTransformer {
  /**
   * Resolve temporary token mappings back to original values if authorized.
   */
  reverse(text: string, mappings: readonly ReversibleMapping[]): Promise<string>;
}
