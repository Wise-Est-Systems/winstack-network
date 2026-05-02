# 60-Second Demo Script

Phase 0 finish line: a 60-second video that makes the AI-lab pitch
undeniable. Read in one take, no narration during the recording —
overlay text added in post.

## Pre-roll setup (do once, before recording)

- Clean macOS desktop, dark mode, no clutter, system font visible.
- Browser: Chrome at 100% zoom; private window; bookmarks bar hidden.
- Terminal: full-screen, monospace 16pt, dark theme matching the brand.
- Build the WASM artifacts once: `./scripts/build-wasm.sh`.
- Run `./scripts/build-gallery.sh` to produce the four sample states.
- Have `report.pdf` (any 1-page PDF, ~50KB) ready on the desktop.

## The shot list (60 seconds total)

| Time     | Frame                                  | What's on screen                                                                  | Overlay text                                  |
|----------|----------------------------------------|-----------------------------------------------------------------------------------|-----------------------------------------------|
| 0:00–0:06 | Terminal                              | `$ wise win report.pdf` runs; outputs `Won` + share URL                    | "Win a file."                                |
| 0:07–0:12 | Terminal + macOS Finder               | Show `report.win` appearing next to the original                              | "The name tag travels with the file."         |
| 0:13–0:20 | Terminal                              | `$ wise publish report.win` — outputs the resolvable URL                  | "Publish the name tag."                       |
| 0:21–0:27 | Mac Mail or Slack                     | Drag `report.pdf` into a draft, paste the URL into the message body, send         | "Share the file. Share the URL."              |
| 0:28–0:35 | Other browser window (recipient view) | Click the URL: `truth.systems/v/<hash>`; preview shows witness + birthday          | "Anyone can recognize it. No account."        |
| 0:36–0:46 | Recipient view                        | Drag `report.pdf` into the drop zone; recognizer turns green: **Alive**           | "Alive. Witnessed by you. Born today."        |
| 0:47–0:53 | Recipient view (second take)          | Drop a tampered copy of the file; recognizer goes blue-grey: **Wounded**          | "Change the file — it stops being alive."     |
| 0:54–1:00 | Static end card                       | Wordmark + `truth.systems` + `Files that prove themselves.`                         | —                                             |

## Tone notes

- No music in the cut for the first version. Add later if needed.
- Cursor shown but no clicks audible; type slowly enough to read.
- Camera does not move; everything happens within fixed crops.
- The four states each get exactly one shot in the public deck. This
  cut shows two — Alive and Wounded — because they're the load-bearing
  emotional moments. Unrecognized and Dying are footnotes, not shots.

## What this video is for

- The AI-lab pitch deck (single embedded clip on the title slide).
- The README "Try it now" section (auto-play loop, muted).
- The `truth.systems` homepage above the fold.
- Twitter/threads launch post when an anchor user goes live.

## What this video is NOT

- A product walkthrough. No menus, no settings, no sub-features.
- A technical explanation. The words "cryptographic", "signature",
  "hash", "proof" do not appear on screen.
- A pitch for adoption. The video shows the act, not the argument.

## Recording checklist

- [ ] Wallpaper: solid `#0F0F12` (matches brand surface)
- [ ] Menu bar hidden
- [ ] Mic muted (recorded speech is added in post if needed)
- [ ] Two browser profiles open: "witness" and "receiver" — different colors
- [ ] Local Vercel deploy URL in clipboard for fallback if public DNS fails
- [ ] Tested run-through completed once before the take

## Post

- Export 1080p H.264 at 30fps, ≤ 8 MB.
- Provide a 720p variant for embed in `truth.systems`.
- Caption file: `.vtt` for accessibility, even though there's no audio.
- Upload to a CDN-backed location (not just GitHub LFS).
