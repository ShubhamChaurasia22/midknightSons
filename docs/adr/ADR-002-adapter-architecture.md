# ADR-002: Isolated Platform Adapter Architecture

## Status

Accepted

## Context

Shield targets multiple generative AI platforms, initially including ChatGPT (OpenAI), Claude (Anthropic), and Gemini (Google). Each platform features distinct web UI frameworks, DOM hierarchies, dynamic mutation cycles, and submission keyboard events (such as Shift+Enter vs Enter, rich text div vs textarea).

Directly coupling DOM selectors and platform-specific quirks into the core security engine would result in fragile code, making maintenance difficult as platforms frequently update their web interfaces.

## Decision

We establish a dedicated `@shield/adapters` package that encapsulates all platform-specific DOM interaction, selectors, and event listeners behind a uniform interface:

```typescript
export interface PlatformAdapter {
  readonly platformId: PlatformId;
  readonly displayName: string;
  readonly urlPatterns: readonly string[];
  readonly capabilities: AdapterCapabilities;
  matches(url: string): boolean;
  attach(): Promise<boolean>;
  detach(): Promise<void>;
  isAttached(): boolean;
}
```

The core engine (`@shield/core`) and detection packages remain completely agnostic to platform DOM details.

## Consequences

- **Positive**: Platform changes and UI updates only require modifications within the specific adapter file; unit testing of the core pipeline is decoupled from browser DOM.
- **Negative**: Adds a layer of indirection and requires maintaining lifecycle hooks (`attach`/`detach`) across SPA route transitions.
