# ADR-001: Local-First Processing Architecture

## Status

Accepted

## Context

Shield protects users against unintentional disclosure of sensitive information (PII, credentials, proprietary secrets) when sending prompts to AI websites. A critical architectural choice is whether prompt inspection and transformation occur on a remote backend service or locally within the browser extension runtime.

Sending prompt data to an intermediary cloud service introduces significant latency, introduces a single point of failure, creates high operational costs, and ironically contradicts the core privacy promise of the product by introducing a third party into sensitive data transit.

## Decision

All prompt detection, risk assessment, policy evaluation, and transformation will be performed **locally within the client browser environment**.

No prompt text or sensitive entities will be transmitted off-device for processing during normal operation.

## Consequences

- **Positive**: Zero latency overhead from external roundtrips; guarantees user privacy and data sovereignty; minimizes backend infrastructure costs.
- **Negative**: Detection models and rule engines must be lightweight enough to run within browser memory limits and CPU constraints without degrading browser responsiveness.
