/**
 * @shield/core
 * Foundational pipeline architecture and interfaces for Shield.
 *
 * Core Orchestration Pipeline:
 * INPUT -> NORMALIZE -> DETECT -> CLASSIFY -> RISK -> POLICY -> TRANSFORM -> VERIFY -> SEND
 */

import type { Result } from '@shield/shared';

// Pipeline Stages
export type PipelineStage =
  | 'INPUT'
  | 'NORMALIZE'
  | 'DETECT'
  | 'CLASSIFY'
  | 'RISK'
  | 'POLICY'
  | 'TRANSFORM'
  | 'VERIFY'
  | 'SEND';

// 1. Stage: INPUT
export interface PipelineInput {
  rawText: string;
  sourceUrl: string;
  platformId: string;
  metadata?: Record<string, unknown>;
  timestamp: number;
}

// 2. Stage: NORMALIZE
export interface NormalizedInput {
  original: PipelineInput;
  normalizedText: string;
  encoding: string;
  normalizationApplied: string[];
}

// 3. Stage: DETECT
export interface DetectionEntity {
  id: string;
  detectorId: string;
  category: string;
  startIndex: number;
  endIndex: number;
  matchText: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export interface DetectionResult {
  entities: DetectionEntity[];
  hasDetections: boolean;
  durationMs: number;
}

// 4. Stage: CLASSIFY
export interface ClassificationEntity {
  entityId: string;
  category: string;
  subCategory?: string;
  sensitivityLevel: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
}

export interface ClassificationResult {
  classifiedEntities: ClassificationEntity[];
}

// 5. Stage: RISK
export type RiskLevel = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface RiskAssessment {
  overallRisk: RiskLevel;
  riskScore: number; // 0 to 100
  factors: string[];
}

// 6. Stage: POLICY
export type PolicyAction = 'ALLOW' | 'WARN' | 'MASK' | 'BLOCK';

export interface PolicyDecision {
  action: PolicyAction;
  rulesTriggered: string[];
  userNotice?: string;
  allowOverride: boolean;
}

// 7. Stage: TRANSFORM
export interface TransformedOutput {
  originalText: string;
  transformedText: string;
  isModified: boolean;
  mappingsCount: number;
}

// 8. Stage: VERIFY
export interface VerificationResult {
  verified: boolean;
  residualRisk: RiskLevel;
  leaksDetected: boolean;
  notes?: string;
}

// 9. Stage: SEND
export interface FinalDelivery {
  canSend: boolean;
  deliverableText: string;
  actionTaken: PolicyAction;
}

// Pipeline Execution Context & Result
export interface PipelineContext {
  id: string;
  input: PipelineInput;
  normalized?: NormalizedInput;
  detections?: DetectionResult;
  classification?: ClassificationResult;
  risk?: RiskAssessment;
  policy?: PolicyDecision;
  transformed?: TransformedOutput;
  verification?: VerificationResult;
  currentStage: PipelineStage;
  startTime: number;
  endTime?: number;
}

export interface PipelineExecutionResult {
  contextId: string;
  success: boolean;
  action: PolicyAction;
  finalText: string;
  verificationPassed: boolean;
  totalDurationMs: number;
}

// Orchestrator Contract (Interface Placeholder)
export interface PipelineOrchestrator {
  /**
   * Execute the full 9-stage pipeline on given input.
   * Note: Implementations belong to Milestone M1+.
   */
  process(input: PipelineInput): Promise<Result<PipelineExecutionResult, Error>>;
}
