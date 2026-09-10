/**
 * @shield/detection
 * Detector boundaries, interfaces, and registry contracts for Shield.
 *
 * NOTE: Phase 0 / M1.1 contains interface contracts only.
 * Concrete detectors are implemented in M1.2+.
 */

import type {
  DetectionCategory,
  DetectionEntity,
  DetectionResult,
  PlatformContext,
} from '@shield/core';

export type { DetectionCategory };

export interface DetectorContext {
  readonly text: string;
  readonly platformContext?: PlatformContext;
  readonly language?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface Detector<TConfig = Record<string, unknown>> {
  readonly id: string;
  readonly name: string;
  readonly category: DetectionCategory;
  readonly description: string;
  readonly enabled: boolean;

  /**
   * Run detection over the provided context.
   */
  detect(context: DetectorContext, config?: TConfig): Promise<readonly DetectionEntity[]>;
}

export interface DetectorRegistry {
  register(detector: Detector): void;
  unregister(detectorId: string): boolean;
  get(detectorId: string): Detector | undefined;
  getByCategory(category: DetectionCategory): readonly Detector[];
  getAll(): readonly Detector[];
  runAll(context: DetectorContext): Promise<DetectionResult>;
}
