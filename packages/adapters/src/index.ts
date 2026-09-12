/**
 * @shield/adapters
 * Platform adapter contracts and registry interfaces for Shield.
 *
 * NOTE: Phase 0 contains interface contracts only.
 * Isolated adapters for ChatGPT, Claude, and Gemini will be implemented
 * in later milestones without platform-specific DOM selectors here.
 */

export type PlatformId = 'chatgpt' | 'claude' | 'gemini' | 'generic';

export interface AdapterCapabilities {
  supportsStreaming: boolean;
  supportsFileInput: boolean;
  supportsPromptInterception: boolean;
}

export interface InputInterceptionResult {
  capturedText: string;
  sourceElementInfo?: {
    tagName: string;
    id?: string;
  };
  metadata?: Record<string, unknown>;
}

export interface PlatformAdapter {
  readonly platformId: PlatformId;
  readonly displayName: string;
  readonly urlPatterns: readonly string[];
  readonly capabilities: AdapterCapabilities;

  /**
   * Determine if the adapter applies to the given URL.
   */
  matches(url: string): boolean;

  /**
   * Attach hooks/listeners to the platform UI.
   */
  attach(root?: unknown): Promise<boolean>;

  /**
   * Detach all listeners and clean up.
   */
  detach(): Promise<void>;

  /**
   * Status check of adapter attachment.
   */
  isAttached(): boolean;
}

export interface PlatformAdapterRegistry {
  register(adapter: PlatformAdapter): void;
  unregister(platformId: PlatformId): boolean;
  get(platformId: PlatformId): PlatformAdapter | undefined;
  findAdapterForUrl(url: string): PlatformAdapter | undefined;
  getAll(): PlatformAdapter[];
}

/**
 * In-memory adapter registry placeholder for Phase 0.
 */
export class InMemoryAdapterRegistry implements PlatformAdapterRegistry {
  private readonly adapters = new Map<PlatformId, PlatformAdapter>();

  register(adapter: PlatformAdapter): void {
    this.adapters.set(adapter.platformId, adapter);
  }

  unregister(platformId: PlatformId): boolean {
    return this.adapters.delete(platformId);
  }

  get(platformId: PlatformId): PlatformAdapter | undefined {
    return this.adapters.get(platformId);
  }

  findAdapterForUrl(url: string): PlatformAdapter | undefined {
    for (const adapter of this.adapters.values()) {
      if (adapter.matches(url)) {
        return adapter;
      }
    }
    return undefined;
  }

  getAll(): PlatformAdapter[] {
    return Array.from(this.adapters.values());
  }
}

export * from './contracts';
export * from './in-memory';
export * from './boundary';
export * from './standard-dom';
export * from './browser-runtime';
export * from './platform';
