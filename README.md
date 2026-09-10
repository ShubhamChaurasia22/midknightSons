# Shield

Shield is a privacy and security browser extension designed to protect sensitive information when interacting with AI platforms such as ChatGPT, Claude, and Gemini.

## Status

**Phase 0 — Repository Bootstrap**

This milestone establishes a clean, production-oriented monorepo foundation, workspace package boundaries, type contracts, and application scaffolds. Core security pipelines, PII/secret detectors, masking algorithms, and platform adapters are scheduled for subsequent milestones (M1+).

## Repository Structure

```text
shield/
├── apps/
│   ├── extension/          # Chrome Extension (Manifest V3, Vite + React)
│   ├── website/            # Landing page scaffold (Vite + React)
│   └── api/                # Minimal Node.js / TypeScript API server
│
├── packages/
│   ├── shared/             # Common types, message envelopes, and utilities
│   ├── core/               # 9-stage pipeline interfaces & orchestration contracts
│   ├── detection/          # Detector interfaces and registry
│   ├── policy/             # Policy engine rules, scopes, and actions
│   ├── transformation/     # Masking, redaction, and replacement contracts
│   ├── adapters/           # Platform adapter abstractions (ChatGPT, Claude, Gemini)
│   └── ui/                 # Reusable UI component library (Button, Toggle, Card, StatusBadge)
│
├── tests/                  # Root smoke and integration tests
├── docs/                   # Architecture, Security, Privacy, and ADR documentation
├── package.json
├── pnpm-workspace.yaml
├── tsconfig.base.json
└── tsconfig.json
```

## Getting Started

### Prerequisites

- Node.js >= 20.0.0
- pnpm >= 9.0.0

### Installation

```bash
pnpm install
```

### Development

```bash
# Run extension development server
pnpm dev

# Run website development server (port 3000)
pnpm dev:website

# Run API local server (port 3001)
pnpm dev:api
```

### Building

```bash
# Build all packages and applications in topological order
pnpm build

# Build extension only
pnpm build:extension

# Build website only
pnpm build:website

# Build API only
pnpm build:api
```

## Loading the Extension in Chrome

1. Build the extension distribution:
   ```bash
   pnpm build:extension
   ```
2. Open Google Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** via the toggle in the top right.
4. Click **Load unpacked**.
5. Select the `apps/extension/dist` directory.
6. The Shield extension will appear in your extension bar with popup UI and background worker running.

## Testing & Quality

```bash
# Run test suite
pnpm test

# Type check all packages and applications
pnpm typecheck

# Lint workspace
pnpm lint

# Format check
pnpm format
```
