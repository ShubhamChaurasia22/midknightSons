/**
 * Verification Domain Model
 *
 * Post-transformation integrity and leak detection contracts.
 * Distinguishes successful transformation from "not required".
 */

import type { RiskAssessment } from './risk';

export type VerificationStatus = 'SUCCESS' | 'FAILED' | 'NOT_REQUIRED';

export interface VerificationResult {
  status: VerificationStatus;
  verified: boolean;
  residualRisk: RiskAssessment;
  leaksDetected: boolean;
  failedChecks?: readonly string[];
  notes?: string;
}
