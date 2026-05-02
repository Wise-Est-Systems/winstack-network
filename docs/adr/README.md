# Architecture Decision Records

ADRs are short, immutable records of decisions that shape the system. Each
captures the context at decision time, the alternatives considered, and the
consequences accepted. They are not living documentation — once accepted,
an ADR is not edited. To change direction, supersede it with a new ADR.

Format: [Michael Nygard](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions).

## Index

- [0001 — Record architecture decisions](0001-record-architecture-decisions.md)
- [0002 — Four-state grammar](0002-four-state-grammar.md)
- [0003 — Custom .win container format](0003-win-container-format.md)
- [0004 — Witnesses bring their own keys](0004-witnesses-bring-their-own-keys.md)
- [0005 — WASM as the canonical receiver](0005-wasm-as-canonical-receiver.md)

## Conventions

- Filename: `NNNN-short-kebab-title.md` where `NNNN` is the next sequential
  four-digit number.
- Status: `Proposed` → `Accepted` → (later) `Superseded by NNNN`.
- One decision per ADR. Multiple decisions = multiple ADRs.
- Keep them short. If an ADR is over two screens, split it.
