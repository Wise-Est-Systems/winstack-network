# proofs

Plain-English intro page: *what is a `.win` file*, what the three results mean, and what it does not prove.

Static HTML, deployed as a separate Vercel project from the verifier.

## Live

- **Public:** https://proofs-one.vercel.app
- **Eventual home:** `proofs.systems` (domain not yet registered)

## Deploy

This directory is its own Vercel project. From the repo root:

```sh
cd proofs
vercel        # preview
vercel --prod # promote to production
```

## Structure

```
proofs/
├── public/
│   └── index.html   ← the page (single file, no build step)
├── vercel.json      ← Vercel config: outputDirectory + headers
└── README.md        ← this file
```

## What this page is

A plain-English explainer aimed at someone arriving cold. Written to be understandable in under 15 seconds. Sections in order:

1. **What is a .win file?** — one paragraph
2. **What WIN is** — the protocol in plain English
3. **The three results** — Verified, Tampered, Invalid
4. **What a .win does not prove** — honest disclaimers
5. **Try it** — link to the verifier at truth.systems

## What this page is *not*

Not a sales page. Not an AI-exoneration product page. Not gated behind any account. Not behind any paywall.
