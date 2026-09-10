/**
 * Pipeline Orchestrator Contract
 */

import type { Result } from '@shield/shared';
import type { PipelineInput } from './context';
import type { PipelineResult } from './result';

export interface PipelineOrchestrator {
  /**
   * Execute the full 9-stage pipeline on given input.
   * Concrete orchestrator implementation belongs to M1.2+.
   */
  process(input: PipelineInput): Promise<Result<PipelineResult, Error>>;
}
