//! W.I.N. SDK walkthrough — the public developer interface, step by step.
//!
//! Run: `cargo run -p win-transition --example sdk`
//!
//! This shows how another program uses `win-transition` to run a governed state
//! transition WITHOUT the desktop app. It covers the full lifecycle —
//!
//!   propose → authorize → verify → execute | refuse → record → seal → verify
//!
//! and it implements a *custom* executor to prove the executor interface is a
//! real, documented extension point (§10–11 of the protocol directive).
//!
//! The API deliberately makes the unsafe shortcut hard: there is no single call
//! that proposes, self-approves, executes and records in one step. Authority is
//! always a separately-issued, separately-keyed grant.

use std::cell::RefCell;

use uuid::Uuid;
use win_transition::{
    govern, seal_win, verify_authorization, verify_win, Authority, AuthorizationGrant, Authorizer,
    ExecResult, ExecutionReceipt, Executor, FilesystemExecutor, GovernRequest, PortableProof,
    Recorder, RefusalCode, RequestedAction, Refusal, TransitionOutcome, TransitionPublicKeys,
};
use wise_crypto::{sha256_hex, KeyPair};

fn main() {
    // ── Roles ────────────────────────────────────────────────────────────
    // Each role holds its own key. Proposer only suggests; authorizer alone
    // grants; executor alone acts; recorder alone seals.
    let proposer_id = Uuid::new_v4();
    let authorizer = Authorizer::new(Uuid::new_v4(), KeyPair::generate());
    let executor = FilesystemExecutor::new(Uuid::new_v4(), KeyPair::generate());
    let recorder = Recorder::new(Uuid::new_v4(), KeyPair::generate());

    // ── 1. PROPOSE ───────────────────────────────────────────────────────
    // A proposer computes a change and describes the action it requires. Note
    // the proposer supplies NO authority — only a request.
    let source = b"A short source document to be summarized.";
    let subject = format!("sha256:{}", sha256_hex(source));
    let summary = win_transition::proposers::propose_summary(source);
    let action = RequestedAction::new(
        "create_file",
        &subject,
        std::env::temp_dir().join("sdk-summary.txt").to_string_lossy(),
        Authority::LocalWrite,
    );
    println!("1. proposed action `{}` requiring {:?}", action.verb, action.required_authority);

    // ── 2. AUTHORIZE ─────────────────────────────────────────────────────
    // A *different* party issues a scoped, signed grant bound to this subject.
    let grant: AuthorizationGrant = authorizer.issue_grant(Authority::LocalWrite, &subject);
    println!("2. authorized: scoped grant for {:?}", grant.granted_authority);

    // ── 3. VERIFY (the grant is authentic) ───────────────────────────────
    // Anyone can check the grant's signature with the authorizer's public key.
    verify_authorization(&grant, &authorizer.public_key_hex()).expect("grant must verify");
    println!("3. verified: grant signature is valid");

    // ── 4. EXECUTE | REFUSE  and  5. RECORD ──────────────────────────────
    // `govern` is the safe orchestrator: it re-verifies the grant, enforces the
    // role separations (proposer≠authorizer, executor≠authorizer), evaluates any
    // policy, lets the executor act or refuse, and records the sealed transition.
    let transition = govern(
        GovernRequest {
            proposer_identity_id: proposer_id,
            proposer_model: None,
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: summary.as_bytes(),
        },
        &executor,
        &recorder,
    );
    println!("4-5. executed & recorded: outcome = {}", if transition.was_executed() { "EXECUTED" } else { "REFUSED" });

    // ── 6. SEAL to a portable .win ───────────────────────────────────────
    let keys = TransitionPublicKeys::new(
        recorder.public_key_hex(),
        authorizer.public_key_hex(),
        executor.public_key_hex(),
        None,
    );
    let win_bytes = seal_win(&PortableProof::new(transition, keys), "sdk.win", summary.as_bytes());
    println!("6. sealed: {} byte .win artifact", win_bytes.len());

    // ── 7. INDEPENDENTLY VERIFY (bytes alone) ────────────────────────────
    let v = verify_win(&win_bytes).expect("artifact opens");
    println!("7. independent verify: all_checks_pass = {}", v.all_checks_pass());
    assert!(v.all_checks_pass());

    // ── Custom executor: implement the Executor trait for a non-filesystem sink.
    custom_executor_demo(&authorizer, &recorder);

    // ── Refusal path: an over-scoped action is refused and sealed. ───────
    refusal_demo(proposer_id, &authorizer, &executor, &recorder);

    println!("\nSDK walkthrough complete.");
}

/// An executor that stores content in memory instead of on disk. Implementing
/// `Executor` is all it takes to add a new, narrowly-bounded action sink.
struct InMemoryExecutor {
    identity_id: Uuid,
    key: KeyPair,
    store: RefCell<Vec<(String, Vec<u8>)>>,
}

impl InMemoryExecutor {
    fn new() -> Self {
        Self {
            identity_id: Uuid::new_v4(),
            key: KeyPair::generate(),
            store: RefCell::new(Vec::new()),
        }
    }
}

impl Executor for InMemoryExecutor {
    fn identity_id(&self) -> Uuid {
        self.identity_id
    }
    fn public_key_hex(&self) -> String {
        self.key.public_key_hex()
    }
    fn bound_authority(&self) -> Authority {
        Authority::LocalWrite
    }
    fn settle(
        &self,
        action: &RequestedAction,
        grant: &AuthorizationGrant,
        content: &[u8],
        precheck: Result<(), RefusalCode>,
    ) -> TransitionOutcome {
        // Honor upstream governance decisions and enforce our own scope.
        let refuse = |reason| {
            TransitionOutcome::Refused(Refusal {
                refusal_id: Uuid::new_v4(),
                requested_verb: action.verb.clone(),
                requested_authority: action.required_authority,
                permitted_authority: grant.granted_authority,
                reason,
                side_effect_occurred: false,
                recorded: true,
                refused_by_identity_id: self.identity_id,
                refused_at: "1970-01-01T00:00:00+00:00".to_string(),
                signature: self.key.sign_bytes(b"refusal"),
            })
        };
        if let Err(r) = precheck {
            return refuse(r);
        }
        if action.subject_content_id != grant.subject_content_id {
            return refuse(RefusalCode::SubjectMismatch);
        }
        if !grant.granted_authority.covers(action.required_authority) {
            return refuse(RefusalCode::AuthorizationScopeExceeded);
        }
        // Perform the bounded side effect: store in memory.
        self.store
            .borrow_mut()
            .push((action.target.clone(), content.to_vec()));
        let cid = format!("sha256:{}", sha256_hex(content));
        TransitionOutcome::Executed(ExecutionReceipt {
            receipt_id: Uuid::new_v4(),
            requested_verb: action.verb.clone(),
            actual_verb: "store_in_memory".to_string(),
            destination: action.target.clone(),
            output_content_id: Some(cid),
            result: ExecResult::Completed,
            side_effect_occurred: true,
            error: None,
            executor_identity_id: self.identity_id,
            executed_at: "1970-01-01T00:00:00+00:00".to_string(),
            signature: self.key.sign_bytes(b"receipt"),
        })
    }
}

fn custom_executor_demo(authorizer: &Authorizer, recorder: &Recorder) {
    let exec = InMemoryExecutor::new();
    let content = b"stored, not written to disk";
    let subject = format!("sha256:{}", sha256_hex(content));
    let grant = authorizer.issue_grant(Authority::LocalWrite, &subject);
    let action = RequestedAction::new("create_file", &subject, "mem://slot", Authority::LocalWrite);
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
            content,
        },
        &exec,
        recorder,
    );
    println!(
        "custom executor: outcome = {}, in-memory items = {}",
        if t.was_executed() { "EXECUTED" } else { "REFUSED" },
        exec.store.borrow().len()
    );
}

fn refusal_demo(
    proposer_id: Uuid,
    authorizer: &Authorizer,
    executor: &FilesystemExecutor,
    recorder: &Recorder,
) {
    let content = b"secret";
    let subject = format!("sha256:{}", sha256_hex(content));
    let grant = authorizer.issue_grant(Authority::LocalWrite, &subject); // local only
    let action = RequestedAction::new("publish", &subject, "https://x/y", Authority::ExternalPublish);
    let t = govern(
        GovernRequest {
            proposer_identity_id: proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject,
            action,
            grant,
            authorizer_public_key: authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"",
        },
        executor,
        recorder,
    );
    match &t.outcome {
        TransitionOutcome::Refused(r) => {
            println!("refusal path: REFUSED — {:?}, side effect = {}", r.reason, r.side_effect_occurred);
        }
        TransitionOutcome::Executed(_) => panic!("publish must be refused"),
    }
}
