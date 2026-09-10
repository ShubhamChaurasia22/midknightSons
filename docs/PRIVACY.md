# Shield Privacy Policy & Architectural Intent

This document describes the privacy posture and architectural design principles of Shield.

> [!NOTE]
> This document details technical design intent during Phase 0 bootstrap and is not a formal legal document.

---

## 1. Architectural Intent: Privacy by Design

Shield's fundamental purpose is to empower users to preserve their privacy while taking advantage of modern generative AI web applications. To achieve this:

1. **Client-Side Execution**: Prompt analysis, entity detection, and masking algorithms operate locally within the user's browser runtime.
2. **Zero Prompt Collection**: Shield does not transmit, store, or sell user prompts, chat history, or detected PII to remote servers.
3. **Local Storage Only**: User preferences (such as enabling/disabling protection or custom rule lists) are stored exclusively in `chrome.storage.local`.

---

## 2. Telemetry and Analytics in Phase 0

- **Telemetry Collection**: **NONE**.
- There are no third-party analytics trackers (such as Google Analytics, Mixpanel, or PostHog) embedded in the extension, website, or backend scaffold.
- No network requests are made on extension load, prompt evaluation, or page navigation.

---

## 3. Data Flow Overview

```text
User Types Prompt ──> Local Shield Content Script
                                │
                                ▼
                      Local Core Pipeline
                      (On-Device Inspection)
                                │
                        [Policy Decision]
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
        Mask / Redact                        Proceed / Block
             │                                     │
             ▼                                     ▼
   Sanitized Prompt                            Action Taken
```

At no point in this workflow does the user's prompt transit external Shield servers.

---

## 4. Unfinished & Future Consideration Areas

The following privacy-related mechanisms are scheduled for future milestones and are **not yet implemented**:

- [ ] Reversible token vault encryption for temporary mapping
- [ ] Enterprise opt-in telemetry and centralized policy management
- [ ] Export and complete erasure of local rule preferences
