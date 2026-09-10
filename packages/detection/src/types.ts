/**
 * @shield/detection
 * Types and contracts for the Shield detection engine.
 */

import type {
  DetectionCategory,
  DetectionEntity,
  DetectionResult,
  PlatformContext,
  Severity,
} from '@shield/core';

export type { DetectionCategory, DetectionEntity, DetectionResult, PlatformContext, Severity };

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
   * Guaranteed to be deterministic and side-effect free.
   */
  detect(context: DetectorContext, config?: TConfig): Promise<readonly DetectionEntity[]>;
}

export type OverlapResolutionStrategy = 'KEEP_ALL' | 'KEEP_HIGHEST_SEVERITY' | 'PREFER_SPECIFIC';

export interface DetectionRunOptions {
  readonly overlapStrategy?: OverlapResolutionStrategy;
  readonly deduplicateExact?: boolean;
  readonly includeRawValue?: boolean;
}

export interface DetectorRegistry {
  register(detector: Detector): void;
  unregister(detectorId: string): boolean;
  get(detectorId: string): Detector | undefined;
  getByCategory(category: DetectionCategory): readonly Detector[];
  getAll(): readonly Detector[];
  /**
   * Run all registered and enabled detectors on the given context.
   */
  runAll(context: DetectorContext, options?: DetectionRunOptions): Promise<DetectionResult>;
}
