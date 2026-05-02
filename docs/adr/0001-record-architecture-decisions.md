# 0001 — Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-04-26

## Context

The project carries non-obvious decisions: a custom container format, a
four-state grammar with prohibited engineering vocabulary, a deliberate
refusal to operate hosted accounts, an "absence is the signal" UX
principle. New contributors and future maintainers cannot infer these from
the code alone, and a stale README cannot be relied on to capture them.

## Decision

We record architectural decisions as ADRs in `docs/adr/`, following the
Michael Nygard format. Each ADR is immutable once accepted; we supersede
rather than edit.

## Consequences

- Every load-bearing decision has a discoverable record.
- Reviewers can demand an ADR amendment instead of accepting drift.
- Context (the *why*) survives team rotation.
- Mild overhead per decision; trivial relative to the cost of relitigating.
