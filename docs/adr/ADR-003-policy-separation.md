# ADR-003: Separation of Detection, Policy, and Transformation Concerns

## Status

Accepted

## Context

A privacy and data protection pipeline involves discovering what is present in text (Detection), deciding what action should be taken under configured rules (Policy), and mutating the text or blocking the transmission (Transformation).

Conflating these concerns into a monolithic engine creates tight coupling where changing a policy rule (e.g. from BLOCK to MASK) forces rewriting detector code or transformation logic.

## Decision

We decouple the pipeline into three strictly separated packages:

1. **`@shield/detection`**: Purely responsible for finding and identifying entities (e.g. discovering that string `X` is an API key with 95% confidence). Has no opinion on whether it should be blocked or masked.
2. **`@shield/policy`**: Responsible for determining actions (`ALLOW`, `WARN`, `MASK`, `BLOCK`) given the context, site, user rules, and detected entity types.
3. **`@shield/transformation`**: Responsible for taking the text and detected entities and applying masking, redaction, or placeholder replacements according to the policy directive.

Orchestration is coordinated exclusively by `@shield/core`.

## Consequences

- **Positive**: Detectors, policies, and transformation strategies can be developed, tested, optimized, and swapped independently.
- **Negative**: Requires passing structured state contexts (`PipelineContext`) across package boundaries.
