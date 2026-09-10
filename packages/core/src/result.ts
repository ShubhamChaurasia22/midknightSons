/**
 * Pipeline Result Domain Model
 *
 * Discriminated union representing the terminal outcomes of the Shield pipeline:
 * ALLOW | WARN | MASK | BLOCK | ERROR
 *
 * Provides complete structured information for future UI warning dialogs and blocking views.
 */

import type { PipelineStage } from './stages';
import type { RiskAssessment } from './risk';
import type { PolicyAction, PolicyDecision } from './policy';
import type { TransformationResult } from './transformation';
import type { VerificationResult } from './verification';
import type { PipelineExecutionMetadata } from './context';

export interface PipelineAllowResult {
  readonly status: 'ALLOW';
  readonly contextId: string;
  readonly deliverableText: string;
  readonly decision: PolicyDecision;
  readonly risk: RiskAssessment;
  readonly metadata: PipelineExecutionMetadata;
}

export interface PipelineWarnResult {
  readonly status: 'WARN';
  readonly contextId: string;
  readonly deliverableText: string;
  readonly warningNotice: string;
  readonly allowOverride: boolean;
  readonly decision: PolicyDecision;
  readonly risk: RiskAssessment;
  readonly metadata: PipelineExecutionMetadata;
}

export interface PipelineMaskResult {
  readonly status: 'MASK';
  readonly contextId: string;
  readonly deliverableText: string;
  readonly transformation: TransformationResult;
  readonly verification: VerificationResult;
  readonly decision: PolicyDecision;
  readonly risk: RiskAssessment;
  readonly metadata: PipelineExecutionMetadata;
}

export interface PipelineBlockResult {
  readonly status: 'BLOCK';
  readonly contextId: string;
  readonly blockedReason: string;
  readonly decision: PolicyDecision;
  readonly risk: RiskAssessment;
  readonly metadata: PipelineExecutionMetadata;
}

export interface PipelineErrorResult {
  readonly status: 'ERROR';
  readonly contextId: string;
  readonly failedStage: PipelineStage;
  readonly error: {
    code: string;
    message: string;
    details?: string;
  };
  readonly metadata: PipelineExecutionMetadata;
}

export type PipelineResult =
  | PipelineAllowResult
  | PipelineWarnResult
  | PipelineMaskResult
  | PipelineBlockResult
  | PipelineErrorResult;

export interface FinalDelivery {
  canSend: boolean;
  deliverableText?: string;
  actionTaken: PolicyAction | 'ERROR';
  reason?: string;
}
