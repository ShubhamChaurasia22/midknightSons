# Shield System Architecture

This document describes the high-level architecture, subsystem boundaries, data flow, and design principles of the Shield platform.

---

## 1. Monorepo Structure

Shield is organized as a strict, multi-package workspace managed via `pnpm`:

```text
shield/
├── apps/
│   ├── extension/          # Manifest V3 browser extension
│   ├── website/            # Marketing and documentation web app
│   └── api/                # Minimal backend API service
└── packages/
    ├── shared/             # Shared types, messaging protocol, constants
    ├── core/               # 9-stage pipeline interfaces & orchestration contracts
    ├── detection/          # Detector contracts & registry
    ├── policy/             # Policy engine contracts, scopes, & actions
    ├── transformation/     # Masking & redaction contracts
    ├── adapters/           # Platform-agnostic adapter interfaces
    └── ui/                 # Reusable React UI component foundation
```

### Dependency Flow

```text
               apps/extension
                     │
      ┌──────────────┼──────────────┐
      ▼              ▼              ▼
packages/adapters packages/ui packages/core
      │                             │
      │              ┌──────────────┴──────────────┐
      │              ▼              ▼              ▼
      │     packages/detection packages/policy packages/transformation
      │              │              │              │
      └──────────────┴───────┬──────┴──────────────┘
                             ▼
                      packages/shared
```

Rules:

1. **`packages/shared`** has zero internal workspace dependencies.
2. **`packages/core`** defines pipeline contracts and depends only on `packages/shared`.
3. Specialized packages (`detection`, `policy`, `transformation`, `adapters`) depend on `core` and `shared`.
4. The core engine never imports platform-specific code or DOM selectors.

---

## 2. Extension Architecture (Manifest V3)

The extension separates execution across isolated contexts:

```text
┌──────────────────────────────────────────────┐
│ Content Script (Injected into AI Web Apps)   │
│ - Monitors prompt input lifecycle            │
│ - Uses isolated Platform Adapters            │
│ - Communicates via internal Chrome runtime   │
└──────────────────────┬───────────────────────┘
                       │ (ShieldMessage Protocol)
                       ▼
┌──────────────────────────────────────────────┐
│ Background Service Worker                    │
│ - Lifecycle management & state coordination  │
│ - chrome.storage.local persistence           │
│ - Coordinates future background pipelines    │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│ Extension UI (Popup & Settings Page)         │
│ - Built with React & @shield/ui              │
│ - Configuration toggles and status display   │
└──────────────────────────────────────────────┘
```

---

## 3. Core Engine Pipeline Concept

When active, user prompt interactions are evaluated through a 9-stage local pipeline:

```text
[1] INPUT
      │ (Raw prompt text & platform metadata)
      ▼
[2] NORMALIZE
      │ (Encoding canonicalization, whitespace normalization)
      ▼
[3] DETECT
      │ (Entity discovery: PII, credentials, API keys, custom patterns)
      ▼
[4] CLASSIFY
      │ (Categorization, confidence scores, sensitivity labeling)
      ▼
[5] RISK
      │ (Composite risk scoring: NONE, LOW, MEDIUM, HIGH, CRITICAL)
      ▼
[6] POLICY
      │ (Action resolution: ALLOW, WARN, MASK, BLOCK)
      ▼
[7] TRANSFORM
      │ (Redaction, pseudonymization, temporary token mapping)
      ▼
[8] VERIFY
      │ (Integrity check: zero residual sensitive leaks)
      ▼
[9] SEND / PROCEED
        (Deliver sanitized input to target AI web interface)
```

---

## 4. Platform Adapter Pattern

AI websites (ChatGPT, Claude, Gemini) have distinct DOM layouts, input mechanisms (contenteditables, textareas), and send triggers (Enter keys, Send buttons, voice inputs).

To insulate the security engine from layout churn:

- **`packages/adapters`** defines generic contracts (`PlatformAdapter`, `AdapterCapabilities`, `InputInterceptionResult`).
- Specific adapters attach to DOM elements without leaking platform specifics into the core engine.
- Platform adapters are loaded dynamically based on active URL patterns.

---

## 5. Current Implementation vs. Planned Milestones

| Subsystem                 | Phase 0 Status (Current)                                                           | Planned Milestone                 |
| :------------------------ | :--------------------------------------------------------------------------------- | :-------------------------------- |
| **Workspace & Tooling**   | **Implemented**: pnpm monorepo, strict TypeScript, Vitest, ESLint                  | Ongoing maintenance               |
| **Shared Contracts**      | **Implemented**: Messaging types, Result types, constants                          | Ongoing maintenance               |
| **UI Components**         | **Implemented**: Button, Toggle, Card, StatusBadge                                 | Expansion in M2+                  |
| **Extension Shell**       | **Implemented**: MV3 Manifest, Service Worker, Content Script, React Popup/Options | Enhanced in M1+                   |
| **Core Orchestrator**     | **Interface Only**: Types and pipeline contracts defined                           | **Milestone M1 (Core Engine)**    |
| **Detectors**             | **Interface Only**: Detector and Registry contracts                                | **Milestone M1 (Detectors)**      |
| **Policy Engine**         | **Interface Only**: Rules, Scopes, and Actions defined                             | **Milestone M1 (Policy Engine)**  |
| **Transformation Engine** | **Interface Only**: Masking, Redaction, Mapping contracts                          | **Milestone M1 (Transformation)** |
| **Platform Adapters**     | **Interface Only**: Adapter interfaces & in-memory registry                        | **Milestone M2 (Adapters)**       |
| **API Server**            | **Scaffold Only**: Native HTTP server with `/health` endpoint                      | Milestone M4+                     |
| **Website**               | **Scaffold Only**: Landing page with milestone roadmap                             | Milestone M3+                     |
