# Shield Security Principles & Baseline

This document outlines the core security model and engineering guidelines for the Shield codebase.

---

## 1. Local-First Processing

Shield is built on the principle that sensitive prompt data should **never leave the user's browser** unnecessarily:

- Detection, classification, risk scoring, policy evaluation, and transformation are performed client-side on-device.
- Shield does not send user prompt text or detected sensitive entities to backend servers for analysis.
- Off-device network requests must never occur during prompt evaluation without explicit user opt-in and consent.

---

## 2. Least Privilege

The Chrome extension requests only the minimum set of permissions required for its current functionality:

- **Phase 0 Permissions**: The extension requests only `storage` to persist user preferences locally.
- Future permissions (such as `activeTab` or host permissions) will be introduced incrementally and solely when required for specific platform adapter integration.
- Wildcard permissions (`<all_urls>`) must be avoided.

---

## 3. Zero Secrets in Extension Code

Browser extensions execute within an environment that can be inspected, decompiled, and modified by the end user or external tools:

- **No private API keys, master passwords, database credentials, or production signing secrets** may be committed to this repository or packaged into extension build artifacts.
- The `.gitignore` file enforces exclusion of local `.env` files.
- CI and build scripts verify that no credential environment variables are embedded into bundle distributions.

---

## 4. Strict Message Validation

Communication between the Content Script, Background Service Worker, and Extension UI uses Chrome's internal messaging APIs:

- Every message must adhere to the typed `ShieldMessage` schema defined in `@shield/shared`.
- Senders and message payload types must be validated prior to processing.
- The background service worker must not execute arbitrary code or evaluate unvalidated strings received from content scripts.

---

## 5. Prohibition of Sensitive Data Logging

To prevent accidental data leakage into browser console logs or debug outputs:

- Raw prompt text, detected PII, credentials, and original values must **never** be written to `console.log`, `console.info`, or error logs.
- Logging utilities must sanitize or redact text before emitting log events.

---

## 6. Vulnerability Disclosure

If you discover a security vulnerability or potential data leak in Shield, please report it via the project's designated security contact or private issue tracker. Do not report security vulnerabilities in public pull requests.

_(Note: Shield is in early development. No third-party audits, compliance certifications, or guarantees are claimed in Phase 0.)_
