/**
 * @shield/detection
 * Detector boundaries, interfaces, and registry contracts for Shield.
 *
 * NOTE: Phase 0 contains interface contracts only.
 * Concrete detectors (PII, secrets, API keys, credentials) are implemented in M1+.
 */

import type { DetectionEntity, DetectionResult } from '@shield/core';

export type DetectorCategory =
  'PII' | 'SECRET' | 'API_KEY' | 'CREDENTIAL' | 'PRIVATE_KEY' | 'CUSTOM';

export interface DetectorContext {
  text: string;
  sourceUrl?: string;
  platformId?: string;
  language?: string;
  metadata?: Record<string, unknown>;
}

export interface Detector<TConfig = Record<string, unknown>> {
  readonly id: string;
  readonly name: string;
  readonly category: DetectorCategory;
  readonly description: string;
  readonly enabled: boolean;

  /**
   * Run detection over the provided context.
   */
  detect(context: DetectorContext, config?: TConfig): Promise<DetectionEntity[]>;
}

export interface DetectorRegistry {
  register(detector: Detector): void;
  unregister(detectorId: string): boolean;
  get(detectorId: string): Detector | undefined;
  getByCategory(category: DetectorCategory): Detector[];
  getAll(): Detector[];
  runAll(context: DetectorContext): Promise<DetectionResult>;
}
