# Security policy

## Reporting a vulnerability

Do **not** open a public issue. Use one of:

- **GitHub Security Advisories** — preferred. Open a private advisory at
  <https://github.com/Wise-Est-Systems/winstack-network/security/advisories/new>.
- **Email** — `security@truth.systems` (PGP-encrypted preferred; see below).

Include enough information to reproduce the issue: version or commit SHA,
platform, a minimal `.win` or proof bundle if relevant, and a short
description of the impact.

We will:

1. Acknowledge receipt within **two business days**.
2. Assign a severity using CVSS v3.1 and a triage owner within **five business
   days**.
3. Provide a remediation plan, expected fix window, and disclosure timeline.

## Disclosure window

Default coordinated-disclosure window is **90 days** from the initial report.
We will request an extension if (and only if) a fix demands more time, and
we will communicate the new date in writing. Reporters may publish at the
end of the agreed window.

## Scope

In scope:

- The verifier (`crates/verifier`, `crates/verifier-wasm`)
- The `.win` container and proof-bundle parsers (`crates/win-format`, `crates/canon-types`)
- The cryptographic primitives (`crates/crypto`)
- The `win` CLI binary
- The desktop app (`desktop`)
- The browser verifier (`window/verify.html`, `public/index.html`)
- The window API (`crates/window-api`) when used per documented configuration

Out of scope:

- Issues that require physical access to a device the attacker controls
- Issues that require an already-compromised witness key (key compromise is
  a documented failure mode — see `spec/grammar.md` § 5b)
- Misuse of the local CLI by the operator running it
- Third-party services not maintained by this project

## Threat model summary

The verifier MUST be safe against:

- Adversarial `.win` containers — including malformed, oversized, or
  algorithmically pathological inputs. The verifier never panics on user
  input; it returns `Dying` or `Unrecognized` instead.
- Adversarial proof bundles — signature forgeries, hash mismatches, time
  downgrade attacks, replayed predecessors, cycle attempts in lineage.
- Wire format attacks — protocol-version downgrade, oversized fields,
  ambiguous parsing.

See `crates/registry-core/tests/integration.rs` for the regression suite.

## Cryptographic agility

Today's primitives:

- SHA-256 for content hashing
- Ed25519 for object, time, and policy signatures
- RFC 3161 timestamps anchored via TSA chains using RSA / ECDSA-P256 / ECDSA-P384

Algorithm migration is tracked in `docs/adr/` (see `0006-algorithm-agility.md`
when it lands). Files signed under deprecated algorithms enter the
**Faded** annotation state per `spec/grammar.md` § 5b.

## PGP key

Available on request via `security@truth.systems`. Fingerprint published in
release notes for each major version.
