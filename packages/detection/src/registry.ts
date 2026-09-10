/**
 * Detector Registry Implementation
 *
 * Manages lifecycle, registration, retrieval, and coordinated execution
 * of deterministic detectors.
 */

import type { DetectionCategory, DetectionEntity, DetectionResult } from '@shield/core';
import type { DetectionRunOptions, Detector, DetectorContext, DetectorRegistry } from './types';
import { resolveOverlaps } from './utils/overlaps';
import { EmailDetector } from './detectors/email';
import { PhoneDetector } from './detectors/phone';
import { ApiKeyDetector } from './detectors/apiKey';
import { PasswordDetector } from './detectors/password';
import { GenericSecretDetector } from './detectors/genericSecret';

export class DefaultDetectorRegistry implements DetectorRegistry {
  private readonly detectors = new Map<string, Detector>();

  register(detector: Detector): void {
    this.detectors.set(detector.id, detector);
  }

  unregister(detectorId: string): boolean {
    return this.detectors.delete(detectorId);
  }

  get(detectorId: string): Detector | undefined {
    return this.detectors.get(detectorId);
  }

  getByCategory(category: DetectionCategory): readonly Detector[] {
    const matched: Detector[] = [];
    for (const detector of this.detectors.values()) {
      if (detector.category === category) {
        matched.push(detector);
      }
    }
    return matched;
  }

  getAll(): readonly Detector[] {
    return Array.from(this.detectors.values());
  }

  async runAll(
    context: DetectorContext,
    options: DetectionRunOptions = {},
  ): Promise<DetectionResult> {
    const startTime = Date.now();
    const enabledDetectors = Array.from(this.detectors.values()).filter((d) => d.enabled);

    // Execute detectors in parallel or sequence (they are deterministic and side-effect free)
    const detectorPromises = enabledDetectors.map((d) =>
      d.detect(context, { includeRawValue: options.includeRawValue }),
    );

    const detectorOutputs = await Promise.all(detectorPromises);
    const aggregated: DetectionEntity[] = [];

    for (const entities of detectorOutputs) {
      for (const entity of entities) {
        aggregated.push(entity);
      }
    }

    // Apply overlap and duplicate resolution
    const overlapStrategy = options.overlapStrategy ?? 'KEEP_HIGHEST_SEVERITY';
    const resolvedEntities = resolveOverlaps(aggregated, overlapStrategy);

    const durationMs = Math.max(0, Date.now() - startTime);

    return {
      entities: resolvedEntities,
      hasDetections: resolvedEntities.length > 0,
      durationMs,
    };
  }
}

/**
 * Factory helper creating a registry pre-populated with initial deterministic detectors.
 */
export function createDefaultDetectorRegistry(): DefaultDetectorRegistry {
  const registry = new DefaultDetectorRegistry();
  registry.register(new EmailDetector());
  registry.register(new PhoneDetector());
  registry.register(new ApiKeyDetector());
  registry.register(new PasswordDetector());
  registry.register(new GenericSecretDetector());
  return registry;
}
