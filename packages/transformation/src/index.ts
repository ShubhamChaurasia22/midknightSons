/**
 * @shield/transformation
 * Deterministic Transformation & Masking Engine for Shield (Stage 7).
 *
 * INPUT → NORMALIZE → DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND
 */

import type {
  AppliedTransformation,
  DetectionCategory,
  DetectionEntity,
  NormalizedInput,
  PipelineContext,
  PolicyDecision,
  Severity,
  TransformationPlan,
  TransformationResult,
  TransformationStep,
  TransformationStrategy,
  TransformationType,
  Transformer as PipelineTransformer,
  DetectionResult,
} from '@shield/core';

export type {
  AppliedTransformation,
  TransformationPlan,
  TransformationResult,
  TransformationStep,
  TransformationStrategy,
  TransformationType,
};

/**
 * Domain-level Transformer interface
 */
export interface Transformer {
  readonly id: string;
  readonly name: string;
  readonly supportedTypes: readonly TransformationType[];

  /**
   * Plan transformations based on detected entities.
   */
  plan(
    text: string,
    entities: readonly DetectionEntity[],
    strategy?: TransformationStrategy,
  ): TransformationPlan;

  /**
   * Apply planned transformations to the text.
   */
  transform(
    text: string,
    entities: readonly DetectionEntity[],
    strategy?: TransformationStrategy,
  ): Promise<TransformationResult>;
}

export interface ReversibleMapping {
  readonly id: string;
  readonly placeholder: string;
  readonly category: string;
  readonly originalValue?: string;
  readonly createdAt: number;
  readonly expiresAt?: number;
}

export interface ReverseTransformer {
  /**
   * Resolve temporary token mappings back to original values if authorized.
   */
  reverse(text: string, mappings: readonly ReversibleMapping[]): Promise<string>;
}

export interface TransformationEngineConfig {
  readonly defaultStrategy?: TransformationStrategy;
  readonly categoryStrategies?: Readonly<
    Partial<Record<DetectionCategory, TransformationStrategy>>
  >;
  readonly customPlaceholders?: Readonly<Partial<Record<DetectionCategory, string>>>;
}

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

/**
 * Deterministic Transformation Engine
 *
 * Implements Stage 7 (TRANSFORM) of the canonical Shield pipeline.
 * Replaces detected sensitive ranges with safe deterministic tokens or masks.
 */
export class DeterministicTransformationEngine implements Transformer {
  readonly id = 'shield-deterministic-transformer';
  readonly name = 'Shield Deterministic Transformation Engine';
  readonly supportedTypes: readonly TransformationType[] = ['MASK', 'REDACT', 'REPLACE'];

  private readonly defaultStrategy: TransformationStrategy;
  private readonly categoryStrategies: Readonly<
    Partial<Record<DetectionCategory, TransformationStrategy>>
  >;
  private readonly customPlaceholders: Readonly<Partial<Record<DetectionCategory, string>>>;

  constructor(config?: TransformationEngineConfig) {
    this.defaultStrategy = config?.defaultStrategy ?? {
      type: 'REDACT',
      maskChar: '*',
      preserveLength: false,
    };
    this.categoryStrategies = config?.categoryStrategies ?? {};
    this.customPlaceholders = config?.customPlaceholders ?? {};
  }

  /**
   * Plan transformations by validating ranges, resolving overlaps/duplicates,
   * and assigning deterministic strategies per entity.
   */
  plan(
    text: string,
    entities: readonly DetectionEntity[],
    overrideStrategy?: TransformationStrategy,
  ): TransformationPlan {
    const validEntities = this.resolveAndFilterEntities(text, entities);
    const steps: TransformationStep[] = validEntities.map((entity) => {
      const strategy = overrideStrategy ?? this.getStrategyForEntity(entity);
      return {
        entityId: entity.id,
        type: strategy.type,
        targetRange: { ...entity.range },
        strategy: { ...strategy },
      };
    });

    return {
      steps,
      totalEntities: steps.length,
    };
  }

  /**
   * Transform text synchronously based on detected entities.
   */
  transformSync(
    text: string,
    entities: readonly DetectionEntity[],
    overrideStrategy?: TransformationStrategy,
  ): TransformationResult {
    if (!entities || entities.length === 0 || text.length === 0) {
      return {
        originalText: text,
        transformedText: text,
        isModified: false,
        transformationsApplied: [],
      };
    }

    const plan = this.plan(text, entities, overrideStrategy);
    if (plan.steps.length === 0) {
      return {
        originalText: text,
        transformedText: text,
        isModified: false,
        transformationsApplied: [],
      };
    }

    // Entity lookup by ID for category mapping in applied metadata
    const entityMap = new Map<string, DetectionEntity>();
    for (const entity of entities) {
      entityMap.set(entity.id, entity);
    }

    const pieces: string[] = [];
    const transformationsApplied: AppliedTransformation[] = [];
    let lastOriginalIndex = 0;
    let currentTransformedIndex = 0;

    for (const step of plan.steps) {
      const entity = entityMap.get(step.entityId);
      const category: DetectionCategory = entity?.category ?? 'UNKNOWN';
      const { startIndex, endIndex } = step.targetRange;

      // 1. Append untouched prefix before this entity
      const prefix = text.slice(lastOriginalIndex, startIndex);
      pieces.push(prefix);
      currentTransformedIndex += prefix.length;

      // 2. Generate replacement text
      const originalSlice = text.slice(startIndex, endIndex);
      const replacement = this.renderReplacement(step.strategy, category, originalSlice);
      const replStart = currentTransformedIndex;
      pieces.push(replacement);
      currentTransformedIndex += replacement.length;
      const replEnd = currentTransformedIndex;

      // 3. Record applied transformation with exact transformed coordinates
      transformationsApplied.push({
        entityId: step.entityId,
        type: step.type,
        originalRange: { startIndex, endIndex },
        replacedRange: { startIndex: replStart, endIndex: replEnd },
        category,
      });

      lastOriginalIndex = endIndex;
    }

    // 4. Append untouched suffix after the last entity
    pieces.push(text.slice(lastOriginalIndex));
    const transformedText = pieces.join('');

    return {
      originalText: text,
      transformedText,
      isModified: transformedText !== text && transformationsApplied.length > 0,
      transformationsApplied,
    };
  }

  /**
   * Domain transform interface implementation (async)
   */
  async transform(
    text: string,
    entities: readonly DetectionEntity[],
    overrideStrategy?: TransformationStrategy,
  ): Promise<TransformationResult> {
    return this.transformSync(text, entities, overrideStrategy);
  }

  /**
   * Apply transformation conditioned on a PolicyDecision.
   * Only MASK actions result in transformation; ALLOW, WARN, and BLOCK preserve original text.
   */
  transformWithDecision(
    text: string,
    entities: readonly DetectionEntity[],
    decision: PolicyDecision,
    overrideStrategy?: TransformationStrategy,
  ): TransformationResult {
    // Transformation strictly respects the policy decision
    if (decision.action !== 'MASK') {
      return {
        originalText: text,
        transformedText: text,
        isModified: false,
        transformationsApplied: [],
      };
    }

    return this.transformSync(text, entities, overrideStrategy);
  }

  /**
   * Generates replacement string deterministically for an entity according to strategy
   */
  private renderReplacement(
    strategy: TransformationStrategy,
    category: DetectionCategory,
    originalSlice: string,
  ): string {
    switch (strategy.type) {
      case 'MASK': {
        const maskChar =
          strategy.maskChar && strategy.maskChar.length > 0 ? strategy.maskChar : '*';
        if (strategy.preserveLength) {
          return maskChar.repeat(originalSlice.length);
        }
        return strategy.replacementText ?? maskChar.repeat(8);
      }

      case 'REPLACE': {
        return strategy.replacementText ?? `[REPLACED_${category}]`;
      }

      case 'REDACT':
      default: {
        if (strategy.replacementText) {
          return strategy.replacementText;
        }
        const custom = this.customPlaceholders[category];
        if (custom) {
          return custom;
        }
        return `[REDACTED_${category}]`;
      }
    }
  }

  /**
   * Resolve strategy for a given entity, checking category overrides then default.
   */
  private getStrategyForEntity(entity: DetectionEntity): TransformationStrategy {
    const categoryStrategy = this.categoryStrategies[entity.category];
    if (categoryStrategy) {
      return categoryStrategy;
    }
    return this.defaultStrategy;
  }

  /**
   * Validate half-open ranges [startIndex, endIndex) and resolve overlaps & duplicates deterministically.
   */
  private resolveAndFilterEntities(
    text: string,
    entities: readonly DetectionEntity[],
  ): DetectionEntity[] {
    const textLen = text.length;

    // 1. Range validity check: 0 <= startIndex < endIndex <= text.length
    const valid = entities.filter((e) => {
      const { startIndex, endIndex } = e.range;
      return (
        Number.isInteger(startIndex) &&
        Number.isInteger(endIndex) &&
        startIndex >= 0 &&
        endIndex <= textLen &&
        startIndex < endIndex
      );
    });

    if (valid.length <= 1) {
      return valid;
    }

    // 2. Deduplicate exact identical ranges [startIndex, endIndex)
    const byExactRange = new Map<string, DetectionEntity>();
    for (const entity of valid) {
      const key = `${entity.range.startIndex}:${entity.range.endIndex}`;
      const existing = byExactRange.get(key);
      if (!existing || this.compareEntityPriority(entity, existing) > 0) {
        byExactRange.set(key, entity);
      }
    }

    const deduplicated = Array.from(byExactRange.values());
    if (deduplicated.length <= 1) {
      return deduplicated;
    }

    // 3. Sort by startIndex ascending, then length descending
    const sorted = [...deduplicated].sort((a, b) => {
      if (a.range.startIndex !== b.range.startIndex) {
        return a.range.startIndex - b.range.startIndex;
      }
      const lenA = a.range.endIndex - a.range.startIndex;
      const lenB = b.range.endIndex - b.range.startIndex;
      return lenB - lenA;
    });

    // 4. Deterministic overlap resolution
    // Two half-open ranges [s1, e1) and [s2, e2) overlap iff s1 < e2 && s2 < e1
    const accepted: DetectionEntity[] = [];

    for (const candidate of sorted) {
      const overlapIndex = accepted.findIndex(
        (existing) =>
          existing.range.startIndex < candidate.range.endIndex &&
          candidate.range.startIndex < existing.range.endIndex,
      );

      if (overlapIndex === -1) {
        accepted.push(candidate);
      } else {
        const existing = accepted[overlapIndex]!;
        if (this.compareEntityPriority(candidate, existing) > 0) {
          accepted[overlapIndex] = candidate;
        }
      }
    }

    // 5. Final sort by startIndex ascending
    return accepted.sort(
      (a, b) => a.range.startIndex - b.range.startIndex || a.range.endIndex - b.range.endIndex,
    );
  }

  /**
   * Deterministic priority comparison between two entities:
   * 1. Severity rank: CRITICAL > HIGH > MEDIUM > LOW
   * 2. Confidence: higher wins
   * 3. Span length: longer wins
   * 4. Tiebreaker: entity ID comparison
   */
  private compareEntityPriority(a: DetectionEntity, b: DetectionEntity): number {
    const sevDiff = (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0);
    if (sevDiff !== 0) {
      return sevDiff;
    }

    const confDiff = a.confidence - b.confidence;
    if (Math.abs(confDiff) > 0.0001) {
      return confDiff;
    }

    const lenA = a.range.endIndex - a.range.startIndex;
    const lenB = b.range.endIndex - b.range.startIndex;
    if (lenA !== lenB) {
      return lenA - lenB;
    }

    return a.id.localeCompare(b.id);
  }
}

/**
 * Deterministic Reverse Transformer
 *
 * Restores authorized reversible token mappings in transformed text.
 */
export class DeterministicReverseTransformer implements ReverseTransformer {
  async reverse(text: string, mappings: readonly ReversibleMapping[]): Promise<string> {
    if (!mappings || mappings.length === 0 || text.length === 0) {
      return text;
    }

    let result = text;
    for (const mapping of mappings) {
      if (mapping.placeholder && mapping.originalValue !== undefined) {
        result = result.split(mapping.placeholder).join(mapping.originalValue);
      }
    }
    return result;
  }
}

/**
 * Pipeline Adapter connecting DeterministicTransformationEngine to the M1.3 orchestrator.
 */
export class TransformationEngineAdapter implements PipelineTransformer {
  constructor(private readonly engine: DeterministicTransformationEngine) {}

  transform(
    normalized: NormalizedInput,
    decision: PolicyDecision,
    detections: DetectionResult,
    _context?: PipelineContext,
  ): TransformationResult {
    return this.engine.transformWithDecision(
      normalized.normalizedText,
      detections.entities,
      decision,
    );
  }
}

/**
 * Factory for creating transformation engines
 */
export function createTransformationEngine(
  config?: TransformationEngineConfig,
): DeterministicTransformationEngine {
  return new DeterministicTransformationEngine(config);
}

/**
 * Factory for creating pipeline orchestrator transformer stages
 */
export function createPipelineTransformer(
  engine?: DeterministicTransformationEngine,
): PipelineTransformer {
  return new TransformationEngineAdapter(engine ?? createTransformationEngine());
}

/**
 * Factory for creating reverse transformers
 */
export function createReverseTransformer(): DeterministicReverseTransformer {
  return new DeterministicReverseTransformer();
}
