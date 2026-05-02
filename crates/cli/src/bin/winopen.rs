//! winopen — double-click a .win, see the file inside
//!
//! Always opens the file. Shows a notice if the file is tampered or invalid.
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
            dialog("Invalid", &format!("I can't read this win tag.\n\n{}", e));
            std::process::exit(3);
        },
    };

    let bundle: canon_types::ProofBundle = match serde_json::from_str(&proof_json) {
        Ok(b) => b,
        Err(e) => {
            dialog("Invalid", &format!("I can't read this win tag.\n\n{}", e));
            std::process::exit(3);
        },
    };

    // Determine state — the file's win tag returns one of three things:
    // Verified, Tampered, or Invalid.
    let file_hash = winstack_crypto::sha256_hex(&artifact);
    let status = if file_hash != bundle.object.payload_hash {
        canon_types::VerificationStatus::Tampered
    } else {
        verifier::verify_from_proof_bundle(&bundle, &artifact).status
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
        let _ = std::process::Command::new("xdg-open")
            .arg(&out_path)
            .status();
    }

    // Then show a notice if the file isn't verified
    match status {
        canon_types::VerificationStatus::Verified => {},
        canon_types::VerificationStatus::Tampered => {
            dialog(
                "Tampered",
                "This file was sealed once. It has been changed since.\nThe original is gone.",
            );
        },
        canon_types::VerificationStatus::Invalid => {
            dialog("Invalid", "Invalid. We can't verify this file.");
        },
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
