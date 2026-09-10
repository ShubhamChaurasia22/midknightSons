/**
 * Canonical 9-Stage Pipeline Sequence
 *
 * INPUT → NORMALIZE → DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND
 */

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

export const PIPELINE_STAGES: readonly PipelineStage[] = [
  'INPUT',
  'NORMALIZE',
  'DETECT',
  'CLASSIFY',
  'RISK',
  'POLICY',
  'TRANSFORM',
  'VERIFY',
  'SEND',
] as const;
