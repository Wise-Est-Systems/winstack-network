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

1b. **Artifact size** — `artifact_bytes.len()` must match `object.artifact_size_bytes`. If not: INVALID.

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
| `TAMPERED` | The payload hash does not match. The file content was changed after sealing. |
| `INVALID` | The proof structure or signatures are broken. The seal cannot be trusted. |
| `DAMAGED` | The .win container itself is structurally broken — bad header, truncated data, missing proof section, or corrupt packaging. This is not a content change; the package never unpacked successfully. |

**TAMPERED vs DAMAGED:** TAMPERED means the .win container opened correctly but the file inside does not match its proof. DAMAGED means the container itself could not be opened — the file may have been corrupted in transit, partially downloaded, or the .win format is invalid. A damaged file cannot be verified at all.

## 8. Trust classes

| Object class | Trust class | Meaning |
|---|---|---|
| `Native` | NATIVE | Born on this node through the sealing pipeline |
| `AiGenerated` | NATIVE | AI output sealed through the generation pipeline |
| `SealedImport` | FOREIGN | External artifact imported under a signed declaration. Never becomes native. |

## 9. What time means

Every proof contains a timestamp. That timestamp comes from one of two sources, and the source determines how much you can trust it.

### Local time

The timestamp came from the creator's device clock.

- Useful as a local record of when sealing happened.
- Not proof of global time. The device clock can be wrong, manually set, or intentionally backdated.
- If two people disagree about who sealed first, a local timestamp does not settle it.
- Displayed as: **"Local — from the creator's device clock"**

### Anchored time

The timestamp was obtained from an external RFC 3161 Timestamp Authority (TSA).

- Stronger than local time — an independent server confirmed the hash existed at that moment.
- The TSA response is stored in the proof and can be verified independently.
- Still depends on trusting the specific TSA. It is not absolute universal time.
- Displayed as: **"Anchored — externally timestamped (RFC 3161)"**

### When time matters

- If you need to prove that a file existed before a specific date, use anchored time (`--tsa-url`).
- If you just need a record for yourself, local time is fine.
- Do not rely on local timestamps for legal disputes about priority or first creation.

### Time source values

| Value | Meaning |
|---|---|
| `Local` | From the creator's device clock. Not externally anchored. |
| `External` | Anchored by an RFC 3161 Timestamp Authority. Independently verifiable. |

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

## 12. .win container format

A `.win` file packages the original file and its proof into a single container.

### Binary layout

```
[4 bytes]   magic: WIN\x01
[4 bytes]   filename length (u32 little-endian)
[N bytes]   filename (UTF-8, no path separators, max 4096 bytes)
[8 bytes]   file length (u64 little-endian)
[M bytes]   original file bytes (raw, uncompressed)
[rest]      proof JSON (UTF-8, everything from here to EOF)
```

### Rules

- Zero external dependencies (no ZIP, no compression library)
- Filename sanitized: path separators stripped, null bytes rejected, length capped
- File length bounds-checked with overflow protection
- Proof is the ProofBundle JSON, identical to standalone `.proof.json`
- Any tool that can read the binary layout can extract and verify

### CLI

```bash
winstack seal document.pdf              # creates document.pdf.win
winstack verify document.pdf.win        # VERIFIED / TAMPERED / INVALID
winstack open document.pdf.win          # extracts document.pdf
winstack verify file --proof file.proof.json  # legacy sidecar support
```

### Security

- Path traversal: sanitized on both pack and unpack
- Integer overflow on file length: checked arithmetic, returns error
- Null bytes in filename: rejected
- Filename length > 4096: rejected

### Limitation

The `.win` file contains the original file bytes. Unlike a standalone `.proof.json` (which only stores the hash), sharing a `.win` shares the file content itself.

## 13. Session authentication

Write endpoints (`/prove`, `/seal`) require a Bearer token in the Authorization header. The token is generated randomly (32 bytes, hex-encoded) per session and injected into the desktop app's webview on launch.

Read endpoints (`/verify`, `/check`, `/objects/:id`, `/objects/:id/export`) require no token.

## 14. Local key storage

Private keys are stored in `.winstack/node.json` as hex-encoded Ed25519 secret bytes.

### Permissions

| Path | Permissions | Contains |
|---|---|---|
| `.winstack/` | 0700 (owner only) | All node state |
| `.winstack/node.json` | 0600 (owner read/write) | Private keys (creator, time authority, policy evaluator) |
| `.winstack/graph.db` | 0600 (owner read/write) | SQLite lineage DAG — which files were sealed and when |
| `.winstack/store_data/` | inherited from parent | Sealed object metadata and artifact copies |

Permissions are set on creation. On every startup, the CLI and desktop app check permissions and repair them if they have drifted (e.g. after a backup restore or manual copy). If repair fails, a warning is printed with the exact chmod command needed.

### What is protected

- Other users on the same machine cannot read your keys or seal history.
- Default umask-created files (0644) are automatically tightened to 0600/0700.

### What is NOT protected

- **Keys are not encrypted on disk.** Anyone with root access, disk access (e.g. booting from USB, reading a backup), or malware running as your user can read `node.json` and impersonate your identity.
- **No OS keychain integration.** The keys are not stored in macOS Keychain, Windows Credential Manager, or Linux secret-service. This means they are not protected by biometrics or system-level encryption.
- **graph.db is not encrypted.** Anyone with read access to `graph.db` can see which files you sealed and when — but not the file contents (only object IDs, hashes, timestamps, and class metadata).
- **Stolen keys cannot be revoked.** If someone copies your `node.json`, there is currently no way to mark that key as compromised. Proofs signed by the stolen key remain valid.

### Practical guidance

- Do not share your `.winstack/` directory.
- Do not commit `node.json` to version control (it is gitignored by default).
- Enable FileVault (macOS), BitLocker (Windows), or LUKS (Linux) for disk encryption — this protects keys at rest when the machine is off.
- If you suspect key compromise, generate a new node (`rm -rf .winstack && winstack seal <file>`) and re-seal important files.

## 15. What the system proves

- A specific file existed at a specific time (local device clock, or anchored via RFC 3161)
- It has not been modified since it was sealed
- It was signed by a specific cryptographic key
- It may be part of a verifiable version chain

## 16. What the system does NOT prove

- That the file content is true or accurate
- The real-world identity of the key holder
- That this is the first copy in the world
- That a local timestamp is globally authoritative — local time comes from the device clock and can be wrong or backdated. Only anchored timestamps (RFC 3161) are independently verifiable, and even those depend on trusting the specific TSA.
- That a compromised key's past proofs are invalid

## 17. What trust means

The system proves that a specific key signed a specific file. It does not prove who controls that key.

Trust is a local decision. You choose which keys you trust by adding them to your local trust list (`~/.winstack/trusted_keys.json`).

### Trust status

| Status | Meaning |
|---|---|
| **Trusted key** | This key is in your local trust list. You chose to trust it. |
| **Untrusted key** | Valid proof, but you have not marked this key as trusted. |

### What trust does NOT mean

- **Trusted key does not mean the file content is true.** It means you recognize the signer.
- **Untrusted key does not mean the proof is invalid.** The proof is cryptographically valid regardless of trust.
- **Trust is local only.** Your trust list is yours. It does not affect anyone else's verification.
- **Removing a key from your trust list does not invalidate past proofs.** It only changes how they are labeled on your machine.

### CLI commands

```bash
winstack trust add <pubkey> --label "My main key"
winstack trust remove <pubkey>
winstack trust list
```

### How trust is displayed

- CLI: `trust     Trusted key (label)` or `trust     Untrusted key`
- Desktop/browser details panel: Key shown as truncated hex
- Trust status shown only when a proof is VERIFIED — TAMPERED/INVALID/DAMAGED results do not show trust because the proof itself is not valid
