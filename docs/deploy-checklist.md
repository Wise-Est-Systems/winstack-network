# Deploy Checklist

Step-by-step for taking `winstack.dev` from green-on-CI to live. Run
through this once for the initial deploy; subsequent deploys are
single-command (`vercel --prod`).

## Prerequisites

- [ ] Vercel CLI installed: `npm i -g vercel`
- [ ] Logged in: `vercel login`
- [ ] Project linked: `vercel link` (creates `.vercel/`, gitignored)
- [ ] DNS access for `winstack.dev` (or accept the `*.vercel.app`
      subdomain for the first deploy)
- [ ] CI green on `main`: `cargo fmt --all --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo test --workspace`, `./scripts/build-wasm.sh`

## Pre-deploy verification

Run locally first. Catches the obvious break before you ship it.

```bash
# 1. Build the WASM artifacts deterministically.
./scripts/build-wasm.sh

# 2. Confirm the deploy directory has everything it needs.
ls public/                        # → index.html, wasm/, v/
ls public/wasm/                   # → verifier_wasm.js, verifier_wasm_bg.wasm, *.d.ts

# 3. Serve locally to sanity-check.
python3 -m http.server -d public 8000
# Visit:  http://localhost:8000           (homepage flow)
#         http://localhost:8000/v/<hash>  (URL flow — requires the
#                                          static rewrite, so use
#                                          /v.html?hash=… as the
#                                          fallback or test on Vercel)
```

The static `python -m http.server` does not honor `vercel.json`
rewrites — `/v/<hash>` will 404 locally. That's fine; the rewrite is
verified post-deploy in step 5 below.

## The deploy

```bash
# 4. Preview deploy (gets a *.vercel.app URL; safe to share for review).
vercel

# 5. Verify the preview before promoting:
curl -sI https://<preview>.vercel.app/                        # 200, content-type text/html
curl -sI https://<preview>.vercel.app/wasm/verifier_wasm.js   # 200, content-type application/javascript
curl -sI https://<preview>.vercel.app/wasm/verifier_wasm_bg.wasm  # 200, content-type application/wasm
# Manual: open in browser, drop a sealed .win, confirm Alive renders.

# 6. Promote to production.
vercel --prod
```

## Domain (one-time)

```bash
# In the Vercel dashboard:
#   Settings → Domains → Add → winstack.dev
# Add the recommended A / CNAME records at your DNS provider.
# Wait for the green check (usually < 5 minutes).
```

## Publishing a name tag to the live deploy

Two paths.

### Path A — manual one-shot (Phase 0 only)

```bash
# Locally:
winstack win demo.pdf
winstack publish demo.win --to public

# Commit the new public/v/<hash>.json and redeploy.
git add public/v/<hash>.json
git commit -m "name-tag: publish demo.pdf hash <abbrev>"
vercel --prod
```

This is fine for the demo video and one-off marketing pages. **Do not
do this for user-published name tags** — committing publication
artifacts to source is wrong scaling.

### Path B — content-addressed publishing (post-Phase 0)

The right long-term path. Two options, decide before Phase 1 outreach:

1. **Vercel Blob / S3** — `winstack publish` uploads directly to a
   bucket, the bucket is served at `winstack.dev/v/`. Witness retains
   the artifact; we don't.
2. **Witness-hosted** — the witness publishes their own
   `<witness-domain>/.well-known/winstack/notices.json` plus per-hash
   files; `winstack.dev/v/<hash>` is just a UI shell that fetches from
   the witness's URL (encoded in the share link).

Option 2 is more aligned with P9 (witnesses bring their own keys and
their own infra) but takes longer to build. Pick after the first
anchor user lands.

## Smoke tests (post-deploy)

Run these after every production deploy. Should be a CI job eventually.

- [ ] `https://winstack.dev/` loads, shows "Is it alive?", drop zone visible
- [ ] WASM module loads (open devtools → Network → filter `wasm`; see 200, < 1.5 MB)
- [ ] Drop a known-Alive `.win` from the gallery → renders **Alive**, witness key visible
- [ ] Drop a known-Wounded `.win` from the gallery → renders **Wounded**, original/file hashes shown
- [ ] Drop a known-Dying `.win` (truncated) → renders **Dying**
- [ ] `https://winstack.dev/v/<known-hash>` resolves → shows preview, drop zone awaits the file
- [ ] Drop the matching file at the URL → renders **Alive**
- [ ] Drop a different file at the URL → renders **Wounded**
- [ ] CSP / security headers present:
      `curl -sI https://winstack.dev/ | grep -iE 'x-content-type-options|x-frame-options|referrer-policy'`
- [ ] Mobile (Safari iOS) loads and recognizes — drop equivalent uses the file picker

## Rollback

```bash
# In the Vercel dashboard:
#   Deployments → previous good deploy → "Promote to Production"
# Or via CLI:
vercel promote <deployment-url> --scope <org>
```

Static deploys roll back atomically — no client-side state to migrate.

## Things that go wrong

| Symptom                              | Likely cause                                    | Fix                                                    |
|--------------------------------------|-------------------------------------------------|--------------------------------------------------------|
| `/v/<hash>` 404s                     | Rewrite rule not registered on this domain      | Re-deploy; check `vercel.json` was included            |
| WASM 404                             | `public/wasm/` empty in deploy                  | Re-run `./scripts/build-wasm.sh`; commit / redeploy    |
| WASM 200 but page errors             | wasm-bindgen JS / .wasm version mismatch        | Reinstall matching wasm-bindgen-cli; rebuild           |
| URL flow loads, file drop hangs      | Browser missing Ed25519 in SubtleCrypto         | (Should not happen post-WASM rewrite — file a bug)     |
| Alive renders but no preview shown   | `public/v/<hash>.json` missing                  | Run `winstack publish <file>.win` and redeploy         |
| TLS warning on first load            | DNS not yet propagated                          | Wait 5–15 minutes; verify in dashboard                 |
