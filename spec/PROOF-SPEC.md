# Winstack Proof Specification

**Protocol version:** V1
**Status:** Active

---

## 1. Proof bundle structure

A proof bundle is a self-contained JSON document. It includes everything needed to verify an object offline, without any server or node state.

```
ProofBundle {
  object:                   SealedObject
  creator_identity:         IdentityRecord
  module_registration:      ModuleRegistration
  time_authority_identity:  IdentityRecord
  policy_evaluator_identity: IdentityRecord
  predecessor_time_event:   ChainedTimeEvent | null
  parent_objects:           SealedObject[]
  parent_proofs:            ProofBundle[]
}
```

## 2. SealedObject

```
SealedObject {
  object_id:            UUID v4
  object_class:         "Native" | "AiGenerated" | "SealedImport"
  payload_hash:         string (SHA-256 hex, 64 chars)
  artifact_size_bytes:  u64
  parent_ids:           UUID[]
  origin:               OriginRecord
  time_event:           ChainedTimeEvent
  policy_proof:         PolicyProof
  ai_generation:        AiGenerationRecord | null
  import_declaration:   ImportDeclaration | null
  object_signature:     string (Ed25519 hex, 128 chars)
  protocol:             "V1"
}
```

## 3. Field meanings

| Field | Meaning |
|---|---|
| `object_id` | Unique identifier for this sealed object |
| `object_class` | How this object was born: natively, by AI, or imported |
| `payload_hash` | SHA-256 of the exact artifact bytes at seal time |
| `artifact_size_bytes` | Byte count of the original artifact |
| `parent_ids` | Objects this object was derived from |
| `origin` | Who created it, with what module, under what time authority |
| `time_event` | Signed, chained timestamp of when sealing occurred |
| `policy_proof` | Signed proof that the policy evaluator permitted this birth |
| `object_signature` | Creator's Ed25519 signature over the object envelope |
| `protocol` | Always "V1" for this version |

## 4. Hashing rules

- **Algorithm:** SHA-256
- **Encoding:** lowercase hexadecimal, 64 characters
- **Input:** exact raw bytes of the artifact, no transformation
- **Determinism:** same bytes always produce the same hash

Payload hash computation:
```
payload_hash = hex(SHA-256(artifact_bytes))
```

Time chain predecessor hash:
```
predecessor_hash = hex(SHA-256(canonical_json(predecessor_event)))
```

## 5. Signature rules

- **Algorithm:** Ed25519
- **Encoding:** lowercase hexadecimal, 128 characters
- **Signing input:** canonical JSON (serde_json default serialization) of the payload struct, encoded as UTF-8 bytes
- **Key format:** 32-byte Ed25519 keys, hex-encoded as 64 characters

### Object signature payload

Signed by the creator identity key:

```
{
  "object_id":          UUID,
  "object_class":       ObjectClass,
  "payload_hash":       string,
  "artifact_size_bytes": u64,
  "parent_ids":         UUID[],
  "protocol":           "V1"
}
```

### Time event signature payload

Signed by the time authority key:

```
{
  "time_event_id":                UUID,
  "timestamp":                    string (RFC 3339),
  "time_authority_identity_id":   UUID,
  "predecessor_event_id":         UUID | null,
  "predecessor_hash":             string | null,
  "payload_hash":                 string
}
```

### Policy proof signature payload

Signed by the policy evaluator key:

```
{
  "policy_proof_id":          UUID,
  "decision":                 "Permit" | "Deny",
  "policy_version":           u64,
  "context_hash":             string,
  "evaluator_identity_id":    UUID,
  "evaluated_at":             string (RFC 3339)
}
```

## 6. Verification steps

Given: artifact bytes + proof bundle JSON

1. **Payload hash** — Compute `SHA-256(artifact_bytes)`. Must match `object.payload_hash`. If not: TAMPERED.

2. **Object signature** — Verify `object.object_signature` against the creator identity public key using the object signature payload. If invalid: INVALID.

3. **Creator identity** — `creator_identity.status` must be `Active`. Creator `identity_id` must match `origin.creator_identity_id`. Session identities cannot create Native or AiGenerated objects.

4. **Module registration** — `module_registration.module_id` must match `origin.module_identity_id`. Module kind must match object class (Import for SealedImport, AiGeneration for AiGenerated).

5. **Time signature** — Verify `time_event.signature` against the time authority identity public key using the time event signature payload. If invalid: INVALID.

6. **Time chain** — If non-genesis: `predecessor_time_event` must be present. Its `time_event_id` must match `time_event.predecessor_event_id`. The SHA-256 of its canonical JSON must match `time_event.predecessor_hash`. If missing or mismatched: INVALID.

7. **Policy proof** — `policy_proof.decision` must be `Permit`. Verify `policy_proof.signature` against the policy evaluator identity public key. If not Permit or signature invalid: INVALID.

8. **Origin consistency** — `origin.object_id` must match `object.object_id`. Creator, module, and time authority IDs in origin must match the corresponding records in the bundle.

9. **AI generation record** — If `object_class` is `AiGenerated`: `ai_generation` must be present. Its `object_id` must match. Its `output_hash` must match `SHA-256(artifact_bytes)`.

10. **Import declaration** — If `object_class` is `SealedImport`: `import_declaration` must be present.

11. **Lineage** — For each parent in `parent_ids`: parent must exist in `parent_objects`. Parent timestamp must be strictly before child timestamp. No self-cycles.

## 7. Result states

| State | Meaning |
|---|---|
| `VERIFIED` | All checks pass. The artifact is authentic and untampered. |
| `TAMPERED` | The payload hash does not match. The file has been modified. |
| `INVALID` | The proof structure or signatures are broken. The seal cannot be trusted. |

## 8. Trust classes

| Object class | Trust class | Meaning |
|---|---|---|
| `Native` | NATIVE | Born on this node through the sealing pipeline |
| `AiGenerated` | NATIVE | AI output sealed through the generation pipeline |
| `SealedImport` | FOREIGN | External artifact imported under a signed declaration. Never becomes native. |

## 9. Time source and RFC 3161 anchoring

| Value | Meaning |
|---|---|
| `Local` | Timestamp from the local system clock. Not externally anchored. |
| `External` | Timestamp anchored by an RFC 3161 Timestamp Authority. Independently verifiable. |

### ChainedTimeEvent extended fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `time_source` | `"Local"` or `"External"` | `"Local"` | How the timestamp was obtained |
| `rfc3161_token` | string (base64) or null | null | Raw RFC 3161 TimeStampResp, base64-encoded |
| `anchored_time` | string or null | null | GeneralizedTime from the TSA token (e.g. `"20260405120000Z"`) |

All fields are optional with defaults for backward compatibility. Old proofs without these fields deserialize as `Local` with no token.

### RFC 3161 flow

At seal time (optional):
1. Compute the SHA-256 hash of the artifact bytes
2. Build an RFC 3161 TimeStampReq with that hash
3. POST the request to a TSA URL with `Content-Type: application/timestamp-query`
4. Parse the TimeStampResp and extract the message hash + GeneralizedTime
5. Confirm the returned hash matches the payload hash
6. Store the full response as `rfc3161_token` (base64), the time as `anchored_time`, and set `time_source` to `External`

At verify time:
- If `time_source` is `External` and `rfc3161_token` is present: decode the token, parse TSTInfo, verify the message hash matches `payload_hash`
- If `time_source` is `External` and `rfc3161_token` is missing: `TsaTokenMissing` failure
- If `time_source` is `Local`: no TSA verification needed

### Configuration

External time anchoring is opt-in. Use `--tsa-url <URL>` with `winstack prove`:

```bash
winstack prove document.pdf --tsa-url https://freetsa.org/tsr
```

If the TSA is unreachable or rejects the request, sealing falls back to `Local` time with a warning.

### Limitations

The current implementation verifies that the TSA token contains the correct payload hash. Full CMS signature verification of the TSA's signing certificate chain is not yet implemented. The raw token is preserved for external audit tools that can perform full chain validation.

## 10. Protocol version

All records carry `"protocol": "V1"`. This spec describes V1 exclusively. Future versions will use a different protocol string and may change field layouts or verification rules.

## 11. Proof chaining

Proofs can optionally form a chain to track artifact version history.

### ProofChain structure

```
ProofChain {
  lineage_id:                UUID    — stable identifier for this artifact lineage
  predecessor_proof_id:      UUID?   — object_id of the previous proof (null for origin)
  predecessor_payload_hash:  string? — payload_hash of the previous proof (null for origin)
}
```

The `proof_chain` field is optional on `SealedObject`. If absent, the proof is standalone. All chain fields are included in the object signature payload via `#[serde(skip_serializing_if = "Option::is_none")]`, ensuring backward compatibility — old proofs without chain fields verify identically.

### Chain types

| Type | predecessor_proof_id | Meaning |
|---|---|---|
| Standalone | field absent | Not part of any chain |
| Origin | `null` | First proof in a lineage |
| Successor | present | Extends a previous proof |

### Verification rules

- If `predecessor_proof_id` is present but `predecessor_payload_hash` is absent: `ChainPredecessorMissing` → INVALID
- Tampering with any chain field (lineage_id, predecessor_proof_id, predecessor_payload_hash) invalidates the object signature → INVALID
- Standalone proofs with no `proof_chain` field remain valid (backward compatible)
- The verifier validates chain structure within a single proof. Full chain walk (loading and verifying predecessor bundles) is the caller's responsibility.

### CLI usage

```bash
# Create origin proof (standalone or first in chain)
winstack prove document.pdf

# Create successor proof linked to a prior version
winstack prove document-v2.pdf --from document.pdf.proof.json
```

The `--from` flag extracts the predecessor's `object_id`, `payload_hash`, and `lineage_id` (or derives lineage from the predecessor's own `object_id` if it has no chain).

### Limitations

- This does not prove absolute first creation in the world
- It proves continuity from a chosen origin
- Chain integrity depends on the creator holding the same keys
- No cross-chain linking or merging
