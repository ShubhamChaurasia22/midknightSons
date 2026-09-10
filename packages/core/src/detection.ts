/**
 * Detection & Classification Domain Model
 *
 * Provides strongly typed contracts for discovered entities, categories,
 * severities, and safe evidence representations.
 */

// Extensible Category Model
export type KnownDetectionCategory =
  | 'PII'
  | 'CREDENTIAL'
  | 'API_KEY'
  | 'SECRET'
  | 'PASSWORD'
  | 'FINANCIAL'
  | 'PRIVATE_DATA'
  | 'UNKNOWN';

// Allows known string autocompletion while remaining fully extensible for custom categories
export type DetectionCategory = KnownDetectionCategory | (string & {});

// Severity: Independent from Policy Action (e.g. CRITICAL != BLOCK automatically)
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface TextRange {
  startIndex: number;
  endIndex: number;
}

/**
 * Safe metadata for discovered entities.
 * Designed to prevent accidental logging of raw sensitive credentials or PII.
 */
export interface DetectionEvidence {
  tokenLength: number;
  hasRawValue: boolean;
  ruleName?: string;
  previewMasked?: string;
  metadata?: Record<string, unknown>;
}

export interface DetectionEntity {
  id: string;
  detectorId: string;
  category: DetectionCategory;
  severity: Severity;
  confidence: number; // 0.0 to 1.0
  range: TextRange;
  evidence: DetectionEvidence;
  /**
   * Optional isolated raw value.
   * Loggers, analytics, and telemetry must NEVER consume this field.
   */
  rawValue?: string;
}

export interface DetectionResult {
  entities: readonly DetectionEntity[];
  hasDetections: boolean;
  durationMs: number;
}

// Classification
export type SensitivityLevel = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

export interface ClassificationEntity {
  entityId: string;
  category: DetectionCategory;
  subCategory?: string;
  sensitivityLevel: SensitivityLevel;
}

export interface ClassificationResult {
  classifiedEntities: readonly ClassificationEntity[];
}
