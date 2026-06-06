# Be a witness

A short guide for anyone — a person, an organization, an AI lab — who
wants to start naming files. Five minutes from "never heard of
WIN" to "you've named your first file."

## What being a witness means

A witness is whoever signs a name tag. The signature on the tag is the
witness saying *"I saw this file at this moment, unchanged."* Receivers
of the file can recognize the witness offline, without contacting any
third party — including us. That last property is the whole point.

Three things follow from that:

1. **Witnesses hold their own keys.** We do not store them. We do not
   have a way to recover them. If the key is gone, the witness can't
   sign new files; previously-signed files keep working.
2. **Witnesses do not need an account.** No signup, no email
   verification, no us-in-the-loop. Witnesses are a key, not a
   profile.
3. **Witnesses can speak about their key.** If a witness's key is
   stolen, retired, or the witness disowns a previous signature,
   they publish a *witness notice* — a small signed statement —
   that verifiers will pick up.

## Generate your witness key

```bash
# Install the CLI (one-time)
cargo install --git https://github.com/Wise-Est-Systems/winstack-network win

# Initialize your witness identity. Keys live in ~/.wise/ on Linux/macOS,
# %APPDATA%\Wise\ on Windows. Permissions are restricted to your user.
win seal /dev/null   # or any file; this also bootstraps the key on first run
```

After the first `win seal`, your witness key exists at:

| Platform | Path                                          |
|----------|-----------------------------------------------|
| macOS    | `~/Library/Application Support/Wise/`     |
| Linux    | `~/.wise/`                                |
| Windows  | `%APPDATA%\Wise\`                         |

The directory is `0700` (owner-only) and contains:

- `node.json` — your witness key + auxiliary signing keys (time
  authority, policy evaluator). Mode `0600`.
- `store_data/` — content-addressed store of objects you've named.
- `graph.db` — SQLite lineage index.

## Back up your key

Treat `node.json` like a private key file. Two recommendations:

1. **Copy it to a hardware-encrypted USB drive** that lives in a
   physical safe. The same way you'd back up an SSH key.
2. **Print the hex** of the secret keys (visible inside `node.json`)
   on paper, double-sealed in a tamper-evident envelope. For the
   "lawyer's safe deposit box" scenario.

A witness who loses the key cannot un-name a file, cannot publish
notices about old signatures (the heir-witness mechanism is for
*planned* rotation, not lost-key recovery), and cannot continue
naming under the same identity. New files require a new witness
identity.

## Name your first file

```bash
win seal report.pdf

# Output:
#   Won           report.pdf
#   →  report.win
#   Share URL     https://truth.systems/v/<hash>
#   (run `win publish report.win` to make the URL resolve)
```

The `.win` is a single portable container holding the file plus its
name tag. Hand it to anyone — email, Slack, USB drive, whatever — and
they can recognize it offline.

## Make the share URL resolve

Sealing produces a `.win`. Publishing makes the URL `truth.systems/v/<hash>`
return a name tag.

```bash
win publish report.win
# Default: writes public/v/<hash>.json relative to the current dir.
# Use --to <path> to write to a different deploy root.
```

After publishing, the recipient does not need the `.win`. They need
*the file* and *the URL*. Verification happens entirely in their
browser; we just serve the static name tag.

## Choose a publishing path

| Path                                  | Best for                              | Tradeoff                              |
|---------------------------------------|---------------------------------------|---------------------------------------|
| **Push to your own static host**      | Witnesses with infrastructure         | You keep control; you carry the cost  |
| **Push to a shared `truth.systems` mirror** | Individuals; first-time witnesses | Convenient; fewer guarantees          |
| **Bundle as `.win` only, no URL**     | Air-gapped or paranoid contexts       | Survives without DNS; no link to share |

The recipient's verifier cares only about the bytes of the name tag.
Where you serve them from is a deployment choice.

## Publish a witness notice

When something happens to your key, publish a notice. It's a small
JSON document, signed with the same key (or your designated heir
key), placed at `https://<your-domain>/.well-known/win/notices.json`.

Three notice types — see [`docs/adr/`](adr/) for the upcoming ADR on
the format:

- **Dissolution** — *"I will not sign new files after [date]."* Old
  signatures continue to verify; verifiers display the witness as
  *Orphaned* alongside Alive.
- **Renunciation** — *"I disown file [hash], or all signatures before
  [date]."* Old signatures still cryptographically verify; verifiers
  display them as *Disowned.*
- **Compromise** — *"My key was no longer mine after [date]."*
  Signatures dated before the compromise remain trustworthy;
  signatures dated after are flagged.

A witness who never publishes notices is the common case. If
something goes wrong, you write one signed JSON file. That's the
whole protocol.

## Rotate your key (planned, not panicked)

For graceful succession — a new device, a colleague taking over the
witness role at an org, a planned algorithm migration:

```bash
# Sketch — `win delegate` lands in a future release.
# Until then: generate a new key, sign a delegation JSON with the
# previous key, distribute alongside future name tags. The verifier
# walks the delegation chain so old name tags continue to verify
# and new ones are recognized as the same witness.
```

Delegation chains are documented in `crates/canon-types`'s
`KeyDelegation`. Verification is implemented; the CLI surface is
on the roadmap.

## What we don't do

Repeating, because it matters:

- We don't hold your key.
- We don't run an account system.
- We don't store your published name tags (unless you push them to
  the shared mirror; even then, that's content-addressed static
  hosting, not a database of users).
- We can't recover anything for you.

This is the contract. It makes WIN a tool you *use*, not a
service you *depend on.* If we vanished tomorrow, every name tag
ever made would still verify — because verification is just bytes
plus the open WASM verifier and an open spec.

## Common questions

**Q: Can multiple devices share one witness?**
Yes — copy `node.json` to each device. Both devices can sign as the
same witness. Treat the file like an SSH key: secure transport, never
in plaintext on shared infrastructure.

**Q: Can an organization be a witness?**
Yes. The witness key is held by whoever the organization designates
(an HSM, a CI/CD pipeline, a designated person). For
high-stakes uses, threshold signing (2-of-3, etc.) is on the
post-Phase-0 roadmap — talk to us if you need it sooner.

**Q: Can I make my AI model a witness?**
Yes — that's the entire point. Hold the key inside the model's
serving infrastructure, sign every output as it streams. Recipients
get a name tag identifying *which model* wrote the bytes.

**Q: What if my witness gets sued?**
Out of scope for the protocol. Witnesses speak for themselves.
WIN does not represent or insure them.

**Q: How do I tell people I'm a witness?**
Publish your public key on a place they trust (your domain, your
verified social profile, a press release). Recipients see the public
key on every name tag and decide for themselves whether to trust it.
We do not maintain a "verified witness" list — that would be us
running an account system in disguise.
