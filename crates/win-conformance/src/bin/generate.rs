//! One-time generator for the frozen conformance vectors.
//!
//! Run with `cargo run -p win-conformance --bin win-conformance-generate`.
//! It writes `vectors/*.win` and `vectors/vectors.json`, then self-checks that
//! every frozen artifact reproduces its declared expectation before exiting.

use uuid::Uuid;
use win_conformance::{run_all, vectors_dir, Expectation, Manifest, Vector};
use win_transition::{
    assert_identity, govern, open_win, seal_win, Authority, Authorizer, Executor as _,
    FilesystemExecutor, GovernRequest, Persistence, PortableProof, Recorder, RequestedAction,
    Transition, TransitionPublicKeys,
};
use wise_crypto::{sha256_hex, KeyPair};

struct Ctx {
    proposer: Uuid,
    authorizer: Authorizer,
    executor: FilesystemExecutor,
    recorder: Recorder,
}

impl Ctx {
    fn new() -> Self {
        Self {
            proposer: Uuid::new_v4(),
            authorizer: Authorizer::new(Uuid::new_v4(), KeyPair::generate()),
            executor: FilesystemExecutor::new(Uuid::new_v4(), KeyPair::generate()),
            recorder: Recorder::new(Uuid::new_v4(), KeyPair::generate()),
        }
    }
    fn keys(&self, policy_pk: Option<String>) -> TransitionPublicKeys {
        TransitionPublicKeys::new(
            self.recorder.public_key_hex(),
            self.authorizer.public_key_hex(),
            self.executor.public_key_hex(),
            policy_pk,
        )
    }
}

fn tmp_target(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("winconf-{}-{tag}", Uuid::new_v4()))
        .to_string_lossy()
        .into_owned()
}

/// Run an accepted local-write transition over `source`, returning the sealed
/// transition and the content it carried (the proposed summary).
fn accepted(ctx: &Ctx, source: &[u8]) -> (Transition, Vec<u8>) {
    let subject = format!("sha256:{}", sha256_hex(source));
    let summary = win_transition::proposers::propose_summary(source);
    let grant = ctx.authorizer.issue_grant(Authority::LocalWrite, &subject);
    let action = RequestedAction::new(
        "create_file",
        &subject,
        tmp_target("out.txt"),
        Authority::LocalWrite,
    );
    let t = govern(
        GovernRequest {
            proposer_identity_id: ctx.proposer,
            proposer_model: None,
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject,
            action,
            grant,
            authorizer_public_key: ctx.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: summary.as_bytes(),
        },
        &ctx.executor,
        &ctx.recorder,
    );
    (t, summary.into_bytes())
}

fn seal(t: Transition, keys: TransitionPublicKeys, name: &str, content: &[u8]) -> Vec<u8> {
    seal_win(&PortableProof::new(t, keys), name, content)
}

fn main() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).expect("create vectors dir");

    let mut vectors: Vec<Vector> = Vec::new();
    let mut write = |id: &str, description: &str, bytes: &[u8], expect: Expectation| {
        let file = format!("{id}.win");
        std::fs::write(dir.join(&file), bytes).expect("write fixture");
        vectors.push(Vector {
            id: id.to_string(),
            description: description.to_string(),
            file,
            expect,
        });
    };

    let text = b"This Agreement binds Party A and Party B.\nDelivery within 30 days.\n";
    let jpeg = {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        v.extend_from_slice(b"JFIF\0\x01\x01\x00\x00\x01\x00\x01");
        v.extend_from_slice(&[0x00, 0x00, 0xFF, 0xD9]);
        v
    };

    // 1. Accepted text summary.
    {
        let ctx = Ctx::new();
        let (t, content) = accepted(&ctx, text);
        let bytes = seal(t, ctx.keys(None), "accepted.win", &content);
        write(
            "accepted-text-summary",
            "Text document summarized under a LocalWrite grant; executes and verifies.",
            &bytes,
            Expectation {
                readable: true,
                container_structure_valid: Some(true),
                content_integrity: Some("Valid".into()),
                transition_valid: Some(true),
                outcome: Some("executed".into()),
                refusal_reason: None,
                all_checks_pass: Some(true),
                authorizer_identity: Some("not_established".into()),
                ..Default::default()
            },
        );
    }

    // 2. Accepted object description (binary input handled honestly).
    {
        let ctx = Ctx::new();
        let (t, content) = accepted(&ctx, &jpeg);
        let bytes = seal(t, ctx.keys(None), "object.win", &content);
        write(
            "accepted-object-description",
            "A JPEG yields an honest object description (type/size/identity), executes, verifies.",
            &bytes,
            Expectation {
                readable: true,
                container_structure_valid: Some(true),
                content_integrity: Some("Valid".into()),
                transition_valid: Some(true),
                outcome: Some("executed".into()),
                all_checks_pass: Some(true),
                ..Default::default()
            },
        );
    }

    // 3. Refused publish (scope exceeded).
    {
        let ctx = Ctx::new();
        let subject = format!("sha256:{}", sha256_hex(text));
        let grant = ctx.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action = RequestedAction::new(
            "publish",
            &subject,
            "https://example.com/publish",
            Authority::ExternalPublish,
        );
        let t = govern(
            GovernRequest {
                proposer_identity_id: ctx.proposer,
                proposer_model: None,
                prior_state_id: None,
                subject_content_id: subject,
                action,
                grant,
                authorizer_public_key: ctx.authorizer.public_key_hex(),
                policy: None,
                policy_evaluator_public_key: None,
                content: b"",
            },
            &ctx.executor,
            &ctx.recorder,
        );
        let bytes = seal(t, ctx.keys(None), "refusal.win", b"");
        write(
            "refused-publish-scope",
            "Publish requested under a LocalWrite-only grant: refused, no side effect, verifies.",
            &bytes,
            Expectation {
                readable: true,
                container_structure_valid: Some(true),
                content_integrity: Some("NotApplicable".into()),
                transition_valid: Some(true),
                outcome: Some("refused".into()),
                refusal_reason: Some("AuthorizationScopeExceeded".into()),
                all_checks_pass: Some(true),
                ..Default::default()
            },
        );
    }

    // 4. Refused by policy deny.
    {
        let ctx = Ctx::new();
        let policy_key = KeyPair::generate();
        let policy_pk = policy_key.public_key_hex();
        let evaluator = policy_core::PolicyEvaluator::new(Uuid::new_v4(), policy_key);
        let deny = evaluator.deny(&sha256_hex(b"ctx"));
        let subject = format!("sha256:{}", sha256_hex(text));
        let grant = ctx.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action = RequestedAction::new(
            "create_file",
            &subject,
            tmp_target("denied.txt"),
            Authority::LocalWrite,
        );
        let t = govern(
            GovernRequest {
                proposer_identity_id: ctx.proposer,
                proposer_model: None,
                prior_state_id: None,
                subject_content_id: subject,
                action,
                grant,
                authorizer_public_key: ctx.authorizer.public_key_hex(),
                policy: Some(deny),
                policy_evaluator_public_key: Some(policy_pk.clone()),
                content: b"",
            },
            &ctx.executor,
            &ctx.recorder,
        );
        let bytes = seal(t, ctx.keys(Some(policy_pk)), "policy-deny.win", b"");
        write(
            "refused-policy-deny",
            "A Deny policy proof refuses the action; the refusal record still verifies.",
            &bytes,
            Expectation {
                readable: true,
                transition_valid: Some(true),
                outcome: Some("refused".into()),
                refusal_reason: Some("PolicyDenied".into()),
                all_checks_pass: Some(true),
                ..Default::default()
            },
        );
    }

    // 5. Refused self-approval (proposer == authorizer).
    {
        let ctx = Ctx::new();
        let subject = format!("sha256:{}", sha256_hex(text));
        let grant = ctx.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action = RequestedAction::new(
            "create_file",
            &subject,
            tmp_target("self.txt"),
            Authority::LocalWrite,
        );
        let t = govern(
            GovernRequest {
                proposer_identity_id: ctx.authorizer.identity_id(),
                proposer_model: None,
                prior_state_id: None,
                subject_content_id: subject,
                action,
                grant,
                authorizer_public_key: ctx.authorizer.public_key_hex(),
                policy: None,
                policy_evaluator_public_key: None,
                content: b"",
            },
            &ctx.executor,
            &ctx.recorder,
        );
        let bytes = seal(t, ctx.keys(None), "self-approval.win", b"");
        write(
            "refused-self-approval",
            "Proposer identity equals authorizer identity: refused (AI is never the authority).",
            &bytes,
            Expectation {
                readable: true,
                transition_valid: Some(true),
                outcome: Some("refused".into()),
                refusal_reason: Some("SelfApproval".into()),
                all_checks_pass: Some(true),
                ..Default::default()
            },
        );
    }

    // 6. Refused subject mismatch.
    {
        let ctx = Ctx::new();
        let subject = format!("sha256:{}", sha256_hex(text));
        let other = format!("sha256:{}", sha256_hex(b"a different subject"));
        let grant = ctx.authorizer.issue_grant(Authority::LocalWrite, &other);
        let action = RequestedAction::new(
            "create_file",
            &subject,
            tmp_target("mismatch.txt"),
            Authority::LocalWrite,
        );
        let t = govern(
            GovernRequest {
                proposer_identity_id: ctx.proposer,
                proposer_model: None,
                prior_state_id: None,
                subject_content_id: subject,
                action,
                grant,
                authorizer_public_key: ctx.authorizer.public_key_hex(),
                policy: None,
                policy_evaluator_public_key: None,
                content: b"",
            },
            &ctx.executor,
            &ctx.recorder,
        );
        let bytes = seal(t, ctx.keys(None), "subject-mismatch.win", b"");
        write(
            "refused-subject-mismatch",
            "The grant is bound to a different subject than the action targets: refused.",
            &bytes,
            Expectation {
                readable: true,
                transition_valid: Some(true),
                outcome: Some("refused".into()),
                refusal_reason: Some("SubjectMismatch".into()),
                all_checks_pass: Some(true),
                ..Default::default()
            },
        );
    }

    // 7. Tampered content (valid record, altered carried bytes).
    {
        let ctx = Ctx::new();
        let (t, content) = accepted(&ctx, text);
        let mut bytes = seal(t, ctx.keys(None), "tampered.win", &content);
        let idx = bytes
            .windows(content.len())
            .position(|w| w == content.as_slice())
            .expect("content present");
        bytes[idx] ^= 0xFF;
        write(
            "tampered-content",
            "Carried content byte flipped after sealing: content integrity MISMATCH, record still signed.",
            &bytes,
            Expectation {
                readable: true,
                container_structure_valid: Some(true),
                content_integrity: Some("Mismatch".into()),
                transition_valid: Some(true),
                outcome: Some("executed".into()),
                all_checks_pass: Some(false),
                ..Default::default()
            },
        );
    }

    // 8. Forged recorder signature.
    {
        let ctx = Ctx::new();
        let (mut t, content) = accepted(&ctx, text);
        t.signature = "00".repeat(64);
        let bytes = seal(t, ctx.keys(None), "forged-sig.win", &content);
        write(
            "forged-recorder-signature",
            "Recorder signature replaced: the sealed record fails signature verification.",
            &bytes,
            Expectation {
                readable: true,
                container_structure_valid: Some(true),
                transition_valid: Some(false),
                all_checks_pass: Some(false),
                ..Default::default()
            },
        );
    }

    // 9. Wrong embedded recorder key.
    {
        let ctx = Ctx::new();
        let (t, content) = accepted(&ctx, text);
        let attacker = KeyPair::generate();
        let forged_keys = TransitionPublicKeys::new(
            attacker.public_key_hex(),
            ctx.authorizer.public_key_hex(),
            ctx.executor.public_key_hex(),
            None,
        );
        let bytes = seal(t, forged_keys, "wrong-key.win", &content);
        write(
            "wrong-embedded-recorder-key",
            "Artifact names an attacker's recorder key: signature does not verify under it.",
            &bytes,
            Expectation {
                readable: true,
                transition_valid: Some(false),
                all_checks_pass: Some(false),
                ..Default::default()
            },
        );
    }

    // 10. Container damage (truncation).
    {
        let ctx = Ctx::new();
        let (t, content) = accepted(&ctx, text);
        let bytes = seal(t, ctx.keys(None), "damaged.win", &content);
        let truncated = bytes[..bytes.len() / 2].to_vec();
        // sanity: it really is unreadable
        assert!(open_win(&truncated).is_err(), "truncated must be unreadable");
        write(
            "container-damaged",
            "Container truncated mid-stream: reported as damage, not as a forged proof.",
            &truncated,
            Expectation {
                readable: false,
                error_contains: Some("container".into()),
                ..Default::default()
            },
        );
    }

    // 11. Self-asserted identity (verified with no trust list → CLAIMED).
    {
        // Authorizer whose key we retain so we can self-assert for it.
        let secret = KeyPair::generate().secret_key_bytes();
        let authorizer = Authorizer::new(Uuid::new_v4(), KeyPair::from_secret_bytes(&secret));
        let executor = FilesystemExecutor::new(Uuid::new_v4(), KeyPair::generate());
        let recorder = Recorder::new(Uuid::new_v4(), KeyPair::generate());
        let content = win_transition::proposers::propose_summary(text);
        let subject = format!("sha256:{}", sha256_hex(text));
        let grant = authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action = RequestedAction::new(
            "create_file",
            &subject,
            tmp_target("id.txt"),
            Authority::LocalWrite,
        );
        let t = govern(
            GovernRequest {
                proposer_identity_id: Uuid::new_v4(),
                proposer_model: None,
                prior_state_id: None,
                subject_content_id: subject,
                action,
                grant,
                authorizer_public_key: authorizer.public_key_hex(),
                policy: None,
                policy_evaluator_public_key: None,
                content: content.as_bytes(),
            },
            &executor,
            &recorder,
        );
        let ident = assert_identity(
            &KeyPair::from_secret_bytes(&secret),
            Some("Acme Ops".to_string()),
            Some("acme.co".to_string()),
            Persistence::Persistent,
        );
        let keys = TransitionPublicKeys::new(
            recorder.public_key_hex(),
            authorizer.public_key_hex(),
            executor.public_key_hex(),
            None,
        );
        let bytes = seal_win(
            &PortableProof::new(t, keys).with_identities(vec![ident]),
            "identity.win",
            content.as_bytes(),
        );
        write(
            "identity-self-asserted",
            "Authorizer carries a self-signed name claim; with no trust list it reads CLAIMED.",
            &bytes,
            Expectation {
                readable: true,
                transition_valid: Some(true),
                outcome: Some("executed".into()),
                all_checks_pass: Some(true),
                authorizer_identity: Some("self_asserted".into()),
                ..Default::default()
            },
        );
    }

    // Write the manifest.
    let manifest = Manifest {
        protocol: win_transition::PROTOCOL.to_string(),
        artifact_format: win_transition::ARTIFACT_FORMAT.to_string(),
        vectors,
    };
    let json = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    std::fs::write(dir.join("vectors.json"), json).expect("write manifest");

    // Self-check: every frozen fixture must reproduce its declared expectation.
    let results = run_all(&dir);
    let failed: Vec<_> = results.iter().filter(|r| !r.pass).collect();
    println!("generated {} vectors in {}", manifest.vectors.len(), dir.display());
    if failed.is_empty() {
        println!("self-check: all {} vectors match their declared expectations", results.len());
    } else {
        for f in &failed {
            eprintln!("SELF-CHECK FAIL {}: {}", f.id, f.detail);
        }
        std::process::exit(1);
    }
}
