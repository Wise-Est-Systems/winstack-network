//! winopen — double-click a .win, see the file inside
//!
//! Always opens the file. Shows a warning if tampered or invalid.
//! No window. No server. No UI beyond the file itself.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        std::process::exit(2);
    }

    let path = std::path::Path::new(&args[1]);
    if !path.exists() {
        std::process::exit(2);
    }

    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => std::process::exit(2),
    };

    let (name, artifact, proof_json) = match win_format::unpack(&raw) {
        Ok(v) => v,
        Err(e) => {
            dialog("Damaged", &format!("This .win file is damaged and cannot be opened.\n\n{}", e));
            std::process::exit(3);
        }
    };

    let bundle: canon_types::ProofBundle = match serde_json::from_str(&proof_json) {
        Ok(b) => b,
        Err(e) => {
            dialog("Damaged", &format!("This .win file is damaged.\n\n{}", e));
            std::process::exit(3);
        }
    };

    // Check verification status
    let file_hash = winstack_crypto::sha256_hex(&artifact);
    let tampered = file_hash != bundle.object.payload_hash;
    let invalid = if !tampered {
        let vr = verifier::verify_from_proof_bundle(&bundle, &artifact);
        vr.status != canon_types::VerificationStatus::Verified
    } else {
        false
    };

    // Always extract and open the file
    let tmp_dir = std::env::temp_dir().join("winstack-open");
    let _ = std::fs::create_dir_all(&tmp_dir);
    let out_path = tmp_dir.join(&name);
    if std::fs::write(&out_path, &artifact).is_err() {
        std::process::exit(2);
    }

    // Open the file first so it appears immediately
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&out_path).status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", &out_path.to_string_lossy()])
            .status();
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(&out_path).status();
    }

    // Then show warning if something is wrong
    if tampered {
        dialog("Tampered", "This file has been modified since it was sealed.\nThe content does not match the original proof.");
    } else if invalid {
        dialog("Invalid Proof", "The proof in this file could not be verified.\nThe seal may be broken.");
    }
}

fn dialog(title: &str, message: &str) {
    #[cfg(target_os = "macos")]
    {
        let escaped = message.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "display dialog \"{}\" with title \"Winstack — {}\" buttons {{\"OK\"}} default button \"OK\" with icon caution",
            escaped, title
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .status();
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("Winstack — {}: {}", title, message);
    }
}
