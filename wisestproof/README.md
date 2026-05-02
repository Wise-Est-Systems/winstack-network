# wisestproof.com

Front-end for Wise.Est Proof — the AI-exoneration product.

Sender side of the protocol. Free verifier lives at winstack.dev.

## Deploy

Separate Vercel project from the parent winstack.dev deploy. From this directory:

```sh
vercel link        # link to a new Vercel project (not the winstack-network one)
vercel --prod      # deploy
```

Then point `wisestproof.com` and `www.wisestproof.com` at the new project in the Vercel dashboard.

## What still needs wiring before launch

1. **Stripe Checkout links** — replace `href="#"` on the two `<a class="cta" data-stripe="...">` buttons in `public/index.html` with real Stripe Checkout URLs.
2. **Public sealing endpoint** — the success URL of each Stripe Checkout needs to land on a `/seal` page that takes the file drop, posts to the public `window-api` instance, and returns the `.win`. Not built yet; tracked as a separate task.
3. **Witness key** — generate the Wise.Est Systems Ed25519 witness key, pin its public key in this site's trust section once minted, and load the private key into the sealing host's secret store.

Everything else (copy, layout, branding) is shipped.
