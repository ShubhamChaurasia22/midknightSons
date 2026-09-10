/**
 * Pipeline Context Domain Model
 *
 * Strongly typed execution context carrying state across the 9 pipeline stages.
 * Holds typed, intentional state without arbitrary application baggage.
 */

import type { PipelineStage } from './stages';
import type { DetectionResult, ClassificationResult } from './detection';
import type { RiskAssessment } from './risk';
import type { PolicyDecision } from './policy';
import type { TransformationResult } from './transformation';
import type { VerificationResult } from './verification';

export interface PlatformContext {
  site: string; // e.g. 'chatgpt.com', 'claude.ai'
  platformId?: string; // Optional platform identifier
  isAiSite: boolean;
  url?: string;
}

export interface PipelineInput {
  rawText: string;
  timestamp: number;
  platformContext: PlatformContext;
  metadata?: Readonly<Record<string, unknown>>;
}

export interface NormalizedInput {
  original: PipelineInput;
  normalizedText: string;
  encoding: string;
  normalizationApplied: readonly string[];
}

export interface PipelineStageError {
  stage: PipelineStage;
  code: string;
  message: string;
  recoverable: boolean;
}

export interface PipelineExecutionMetadata {
  startedAt: number;
  completedAt?: number;
  stageTimings: Partial<Record<PipelineStage, number>>;
  errors: readonly PipelineStageError[];
}

export interface PipelineContext {
  readonly id: string;
  readonly timestamp: number;
  currentStage: PipelineStage;
  readonly input: PipelineInput;
  normalized?: NormalizedInput;
  detections?: DetectionResult;
  classification?: ClassificationResult;
  risk?: RiskAssessment;
  policyDecision?: PolicyDecision;
  transformation?: TransformationResult;
  verification?: VerificationResult;
  readonly platformContext: PlatformContext;
  readonly executionMetadata: PipelineExecutionMetadata;
}
