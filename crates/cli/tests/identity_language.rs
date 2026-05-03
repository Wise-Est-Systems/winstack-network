//! Regression: living docs and surfaces must NOT claim that all .win
//! files are automatically signed by Wise.Est Systems. This test grep-
//! audits the repo at compile-test time and fails if any forbidden
//! phrase reappears in non-historical files.
//!
//! Historical artifacts (CHANGELOG.md, docs/adr/*) are exempt — ADR
//! doctrine is immutable; CHANGELOG records past states.

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// Files we audit. Living docs and surfaces only — no immutable history.
fn audited_files() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut out = vec![
        root.join("README.md"),
        root.join("ROADMAP.md"),
        root.join("SECURITY.md"),
        root.join("CONTRIBUTING.md"),
        root.join("public/index.html"),
        root.join("proofs/public/index.html"),
        root.join("window/verify.html"),
        root.join("docs/architecture.md"),
        root.join("docs/witness-onboarding.md"),
        root.join("docs/demo-script.md"),
        root.join("docs/deploy-checklist.md"),
        root.join("spec/grammar.md"),
        root.join("spec/PROOF-SPEC.md"),
    ];
    out.retain(|p| p.exists());
    out
}

/// Phrases that would *positively assert* Wise.Est Systems signs files
/// by default. Each is a distinctive fragment from one of the original
/// false claims; none would appear in legitimate negation or
/// disclaimer phrasing (we don't disclaim by quoting these forms).
///
/// To avoid catching disclaimer/quotation context (e.g. proofs page
/// saying *"if you see a result that claims X, it is true only if…"*),
/// these are tight present-tense assertions, not loose keyword matches.
const FORBIDDEN: &[&str] = &[
    "We sign your seal with our",
    "Our public key is pinned in the verifier and published",
    "The witness, today, is Wise.Est Systems",
    "every .win is signed by Wise",
    "Wise.Est Systems automatically signs",
    "Wise.Est Systems signs your file",
    "all .win files are signed by Wise.Est",
];

#[test]
fn living_docs_dont_falsely_claim_central_wise_est_signing() {
    let mut violations: Vec<(PathBuf, &'static str, usize, String)> = Vec::new();

    for path in audited_files() {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let lower = content.to_lowercase();
        for phrase in FORBIDDEN {
            let needle = phrase.to_lowercase();
            if let Some(byte_idx) = lower.find(&needle) {
                let line_no = content[..byte_idx].lines().count() + 1;
                let line = content.lines().nth(line_no - 1).unwrap_or("").trim();
                violations.push((path.clone(), phrase, line_no, line.to_string()));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = String::from(
            "\nFORBIDDEN identity-claim phrases found in living docs:\n\n\
             A .win is signed by whichever key sealed it (typically a key\n\
             generated on the user's own machine). There is no central\n\
             Wise.Est Systems witness key. The verifier may surface a\n\
             signer as 'Official' ONLY if the receiver has explicitly\n\
             added the fingerprint to a local trusted list.\n\n\
             Offending occurrences:\n",
        );
        for (path, phrase, line, text) in &violations {
            msg.push_str(&format!(
                "  {}:{}\n    phrase: {:?}\n    text:   {}\n\n",
                path.display(),
                line,
                phrase,
                text
            ));
        }
        panic!("{}", msg);
    }
}

#[test]
fn proofs_explainer_actually_includes_the_corrective_disclaimer() {
    // The proofs.systems explainer SHOULD say something like
    // "There is no central Wise.Est Systems signing key" or equivalent.
    // This is the inverse of the regression test: catch silent removal.
    let path = workspace_root().join("proofs/public/index.html");
    let content = fs::read_to_string(&path).expect("proofs page exists");
    let needles = [
        "no central Wise.Est Systems",
        "did not automatically sign",
    ];
    let found = needles.iter().any(|n| content.contains(n));
    assert!(
        found,
        "proofs.systems must include explicit 'no central key' disclaimer; \
         none of these phrases were found: {:?}",
        needles
    );
}

// ─────────────────────────────────────────────────────────────────────
// Trust-class UI regression — the verifier surfaces in public/index.html
// and window/verify.html must render trust class clearly so that
// Verified+Unknown can never be mistaken for Verified+Official.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn browser_verifier_surfaces_all_four_trust_classes() {
    let content = fs::read_to_string(workspace_root().join("public/index.html"))
        .expect("public/index.html exists");
    for class in ["Official", "Named", "Local", "Unknown"] {
        assert!(
            content.contains(class),
            "public/index.html must surface the {:?} trust class label",
            class
        );
    }
    // Plain-language line for each class must be present.
    let lines = [
        "Signed by an official trusted key you recognize.",
        "Signed by a named key you saved.",
        "Signed by this device's local key.",
        "Signed by a key not currently trusted or named.",
    ];
    for line in lines {
        assert!(
            content.contains(line),
            "public/index.html missing trust-class line: {:?}",
            line
        );
    }
}

#[test]
fn desktop_verifier_surfaces_all_four_trust_classes() {
    let content = fs::read_to_string(workspace_root().join("window/verify.html"))
        .expect("window/verify.html exists");
    for class in ["Official", "Named", "Local", "Unknown"] {
        assert!(
            content.contains(class),
            "window/verify.html must surface the {:?} trust class label",
            class
        );
    }
}

#[test]
fn verifier_surfaces_warn_when_verified_is_paired_with_unknown_signer() {
    // The crucial UX rule: Verified + Unknown must never read as
    // Verified + Official. There must be a string warning the user
    // that bytes-match-but-signer-not-trusted.
    let pages = [
        ("public/index.html", "browser verifier"),
        ("window/verify.html", "desktop verifier"),
    ];
    for (rel, label) in pages {
        let content = fs::read_to_string(workspace_root().join(rel))
            .expect(rel);
        // We accept any of these phrasings.
        let candidates = [
            "The bytes match. The signer is not trusted by you yet.",
            "not trusted by you yet",
            "verifiedUnknown",
        ];
        let found = candidates.iter().any(|s| content.contains(s));
        assert!(
            found,
            "{} ({}): missing the Verified+Unknown disambiguation message; \
             tried: {:?}",
            label, rel, candidates
        );
    }
}

#[test]
fn verifier_does_not_promote_unknown_to_official() {
    // Sanity: no JS path that maps Unknown → Official by default.
    // The only way to elevate to Official is an explicit fingerprint
    // match against the local trusted-key list. We grep for any
    // suspicious automatic mapping.
    let pages = ["public/index.html", "window/verify.html"];
    let forbidden = [
        // Auto-promotion patterns that would silently grant Official
        "identity_class:'Official'",
        "identity_class: 'Official'",
        "identity_class=\"Official\"",
        "default = 'Official'",
        "|| 'Official'",
        "|| \"Official\"",
    ];
    for rel in pages {
        let content = fs::read_to_string(workspace_root().join(rel)).expect(rel);
        for f in forbidden {
            assert!(
                !content.contains(f),
                "{}: contains suspicious auto-promotion pattern {:?}",
                rel,
                f
            );
        }
    }
}

#[test]
fn verifier_response_struct_carries_identity_class() {
    // Sanity that the wire format actually includes the field. If
    // someone removes it from window-api the desktop UI would silently
    // fall back to Unknown — caught here at compile-time-of-test.
    let content = fs::read_to_string(
        workspace_root().join("crates/window-api/src/lib.rs"),
    )
    .expect("window-api lib");
    assert!(
        content.contains("pub identity_class: String,"),
        "VerifyResponse must carry identity_class field"
    );
    assert!(
        content.contains("pub identity_explainer: String,"),
        "VerifyResponse must carry identity_explainer field"
    );
}
