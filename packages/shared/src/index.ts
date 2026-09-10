/**
 * @shield/shared
 * Foundational shared types, constants, and utilities for the Shield monorepo.
 */

// Message Protocol Types
export type ShieldMessageType = 'PING' | 'PONG' | 'GET_STATUS' | 'STATUS_RESPONSE' | 'INITIALIZE';

export type MessageSender = 'popup' | 'background' | 'content' | 'options';

export interface ShieldMessage<T = unknown> {
  id: string;
  type: ShieldMessageType;
  payload?: T;
  timestamp: number;
  sender: MessageSender;
}

// Result Pattern
export type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

// Environment Types
export type ShieldEnvironment = 'development' | 'staging' | 'production';

// Extension & App Constants
export const EXTENSION_NAME = 'Shield';
export const EXTENSION_VERSION = '0.1.0';

export const STORAGE_KEYS = {
  ENABLED: 'shield:enabled',
  SETTINGS: 'shield:settings',
} as const;

// Utility functions
export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

export function createMessage<T>(
  type: ShieldMessageType,
  sender: MessageSender,
  payload?: T,
): ShieldMessage<T> {
  return {
    id: generateId(),
    type,
    payload,
    timestamp: Date.now(),
    sender,
  };
}
