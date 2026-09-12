/**
 * Delivery Engine Domain Model & Deterministic Delivery Engine
 *
 * Stage 9 (SEND) of the canonical Shield pipeline:
 * DETECT → CLASSIFY → RISK → POLICY → TRANSFORM → VERIFY → SEND
 *
 * Safely receives verified deliverables from Stage 8 (VERIFY), enforces transmission invariants,
 * generates audit delivery receipts, and dispatches sanitized prompts to destination sinks.
 */

import type { FinalDelivery } from './result';
import type { PolicyAction } from './policy';
import type { PipelineContext } from './context';
import type { Sender } from './orchestrator';

export type DeliveryStatus = 'DELIVERED' | 'HELD' | 'BLOCKED' | 'FAILED';

export interface DeliveryReceipt {
  readonly deliveryId: string;
  readonly contextId: string;
  readonly status: DeliveryStatus;
  readonly actionTaken: PolicyAction | 'ERROR';
  readonly channelId: string;
  readonly timestamp: number;
  readonly deliverableLength?: number;
  readonly reason?: string;
  readonly sinkIds: readonly string[];
}

export interface DeliverySink {
  readonly id: string;
  deliver(delivery: FinalDelivery, context: PipelineContext): Promise<void> | void;
}

export class InMemoryDeliverySink implements DeliverySink {
  readonly id: string;
  readonly capturedDeliveries: FinalDelivery[] = [];

  constructor(id = 'in-memory-sink') {
    this.id = id;
  }

  deliver(delivery: FinalDelivery): void {
    this.capturedDeliveries.push({ ...delivery });
  }

  clear(): void {
    this.capturedDeliveries.length = 0;
  }
}

export interface DeliveryEngineOptions {
  readonly defaultChannelId?: string;
  readonly sinks?: readonly DeliverySink[];
  readonly enableReceiptHistory?: boolean;
  readonly maxHistorySize?: number;
}

/**
 * Deterministic Delivery Engine
 *
 * Terminal stage 9 executor enforcing transmission safety, sink dispatch, and audit receipts.
 */
export class DeterministicDeliveryEngine implements Sender {
  readonly id = 'shield-deterministic-delivery-engine';
  readonly name = 'Shield Deterministic Delivery Engine';

  private readonly defaultChannelId: string;
  private readonly sinks: DeliverySink[] = [];
  private readonly defaultCaptureSink: InMemoryDeliverySink;
  private readonly receipts: DeliveryReceipt[] = [];
  private readonly enableHistory: boolean;
  private readonly maxHistorySize: number;
  private sequence = 1;

  constructor(options: DeliveryEngineOptions = {}) {
    this.defaultChannelId = options.defaultChannelId ?? 'default-channel';
    this.enableHistory = options.enableReceiptHistory ?? true;
    this.maxHistorySize = options.maxHistorySize ?? 1000;

    // Built-in capture sink for inspectability and backward compatibility
    this.defaultCaptureSink = new InMemoryDeliverySink('default-capture-sink');
    this.sinks.push(this.defaultCaptureSink);

    if (options.sinks) {
      for (const sink of options.sinks) {
        this.registerSink(sink);
      }
    }
  }

  /**
   * Access to deliveries captured by the default in-memory sink.
   * Preserves backward compatibility with InMemorySender.deliveries.
   */
  get deliveries(): readonly FinalDelivery[] {
    return this.defaultCaptureSink.capturedDeliveries;
  }

  /**
   * Register a custom delivery sink destination.
   */
  registerSink(sink: DeliverySink): void {
    if (!this.sinks.some((s) => s.id === sink.id)) {
      this.sinks.push(sink);
    }
  }

  /**
   * Unregister a delivery sink by ID.
   */
  unregisterSink(sinkId: string): boolean {
    const idx = this.sinks.findIndex((s) => s.id === sinkId);
    if (idx !== -1) {
      this.sinks.splice(idx, 1);
      return true;
    }
    return false;
  }

  /**
   * Get all registered sink IDs.
   */
  getSinkIds(): readonly string[] {
    return this.sinks.map((s) => s.id);
  }

  /**
   * Asynchronous send implementation conforming to the orchestrator's Sender interface.
   */
  async send(delivery: FinalDelivery, context: PipelineContext): Promise<void> {
    const receipt = this.validateAndPrepare(delivery, context);

    if (receipt.status === 'BLOCKED') {
      this.recordReceipt(receipt);
      throw new Error(
        receipt.reason
          ? `Transmission prohibited: ${receipt.reason}`
          : 'Transmission prohibited: deliverable blocked by policy',
      );
    }

    if (receipt.status === 'FAILED') {
      this.recordReceipt(receipt);
      throw new Error(
        receipt.reason
          ? `Transmission prohibited: ${receipt.reason}`
          : 'Transmission prohibited: deliverable failed integrity check',
      );
    }

    if (receipt.status === 'HELD') {
      this.recordReceipt(receipt);
      // Warning flow is safely held without dispatching to destination sinks
      return;
    }

    // Status is DELIVERED: dispatch to all registered sinks
    const activeSinks = [...this.sinks];
    for (const sink of activeSinks) {
      try {
        await sink.deliver(delivery, context);
      } catch (err) {
        const errorReceipt: DeliveryReceipt = {
          deliveryId: receipt.deliveryId,
          contextId: receipt.contextId,
          status: 'FAILED',
          actionTaken: receipt.actionTaken,
          channelId: receipt.channelId,
          timestamp: receipt.timestamp,
          deliverableLength: receipt.deliverableLength,
          reason: `Delivery sink '${sink.id}' failed transmission: ${err instanceof Error ? err.message : 'Unknown error'}`,
          sinkIds: [sink.id],
        };
        this.recordReceipt(errorReceipt);
        throw err;
      }
    }

    this.recordReceipt(receipt);
  }

  /**
   * Synchronous send implementation for deterministic unit testing.
   */
  sendSync(delivery: FinalDelivery, context: PipelineContext): DeliveryReceipt {
    const receipt = this.validateAndPrepare(delivery, context);

    if (receipt.status === 'DELIVERED') {
      const activeSinks = [...this.sinks];
      for (const sink of activeSinks) {
        sink.deliver(delivery, context);
      }
    }

    this.recordReceipt(receipt);
    return receipt;
  }

  /**
   * Internal validation of transmission invariants before dispatching.
   */
  private validateAndPrepare(delivery: FinalDelivery, context: PipelineContext): DeliveryReceipt {
    const contextId = context.id ?? 'anonymous-context';
    const timestamp = context.timestamp ?? 0;
    const deliveryId = `${contextId}:del-${this.sequence++}`;
    const channelId = this.defaultChannelId;
    const sinkIds = this.sinks.map((s) => s.id);

    // 1. Invariant: Action is BLOCK
    if (
      delivery.actionTaken === 'BLOCK' ||
      (delivery.canSend === false && delivery.actionTaken !== 'WARN')
    ) {
      return {
        deliveryId,
        contextId,
        status: 'BLOCKED',
        actionTaken: 'BLOCK',
        channelId,
        timestamp,
        reason: delivery.reason || 'Transmission prohibited by BLOCK policy action',
        sinkIds,
      };
    }

    // 2. Invariant: Action is WARN
    if (delivery.actionTaken === 'WARN') {
      return {
        deliveryId,
        contextId,
        status: 'HELD',
        actionTaken: 'WARN',
        channelId,
        timestamp,
        deliverableLength: delivery.deliverableText?.length,
        reason: delivery.reason || 'Transmission held pending user review',
        sinkIds,
      };
    }

    // 3. Invariant: Missing deliverableText for deliverable actions (ALLOW, MASK)
    if (delivery.deliverableText === undefined || delivery.deliverableText === null) {
      return {
        deliveryId,
        contextId,
        status: 'FAILED',
        actionTaken: delivery.actionTaken,
        channelId,
        timestamp,
        reason: 'Transmission failed: deliverableText is missing',
        sinkIds,
      };
    }

    // 4. Invariant: MASK action requires verified context with zero leaks
    if (delivery.actionTaken === 'MASK') {
      if (context.verification && !context.verification.verified) {
        return {
          deliveryId,
          contextId,
          status: 'FAILED',
          actionTaken: 'MASK',
          channelId,
          timestamp,
          deliverableLength: delivery.deliverableText.length,
          reason: 'Transmission prohibited: deliverable failed Stage 8 verification',
          sinkIds,
        };
      }

      if (
        context.transformation &&
        delivery.deliverableText !== context.transformation.transformedText
      ) {
        return {
          deliveryId,
          contextId,
          status: 'FAILED',
          actionTaken: 'MASK',
          channelId,
          timestamp,
          deliverableLength: delivery.deliverableText.length,
          reason: 'Transmission prohibited: deliverableText diverges from verified transformedText',
          sinkIds,
        };
      }
    }

    // 5. Invariant: ALLOW action requires deliverableText matching normalized text
    if (delivery.actionTaken === 'ALLOW') {
      if (context.normalized && delivery.deliverableText !== context.normalized.normalizedText) {
        return {
          deliveryId,
          contextId,
          status: 'FAILED',
          actionTaken: 'ALLOW',
          channelId,
          timestamp,
          deliverableLength: delivery.deliverableText.length,
          reason: 'Transmission prohibited: deliverableText diverges from normalized deliverable',
          sinkIds,
        };
      }
    }

    // All invariants passed: deliverable is safe to transmit
    return {
      deliveryId,
      contextId,
      status: 'DELIVERED',
      actionTaken: delivery.actionTaken,
      channelId,
      timestamp,
      deliverableLength: delivery.deliverableText.length,
      sinkIds,
    };
  }

  private recordReceipt(receipt: DeliveryReceipt): void {
    if (!this.enableHistory) return;
    this.receipts.push(receipt);
    if (this.receipts.length > this.maxHistorySize) {
      this.receipts.shift();
    }
  }

  /**
   * Retrieve all recorded receipts in chronological order.
   */
  getReceipts(): readonly DeliveryReceipt[] {
    return [...this.receipts];
  }

  /**
   * Retrieve the most recent delivery receipt.
   */
  getLastReceipt(): DeliveryReceipt | undefined {
    return this.receipts[this.receipts.length - 1];
  }

  /**
   * Clear recorded receipts and captured deliveries.
   */
  clearHistory(): void {
    this.receipts.length = 0;
    this.defaultCaptureSink.clear();
  }
}

/**
 * Factory for creating deterministic delivery engines
 */
export function createDeliveryEngine(options?: DeliveryEngineOptions): DeterministicDeliveryEngine {
  return new DeterministicDeliveryEngine(options);
}

// Aliases for semantic clarity
export const createSendEngine = createDeliveryEngine;
export type DeterministicSendEngine = DeterministicDeliveryEngine;
