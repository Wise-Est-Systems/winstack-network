//! W.I.N. conformance runner.
//!
//! Reads the frozen manifest + fixtures and checks the current verifier against
//! every declared expectation.
//!
//!   cargo run -p win-conformance --bin win-conformance            # human table
//!   cargo run -p win-conformance --bin win-conformance -- --json  # machine JSON
//!
//! Exit code is non-zero if any vector fails.

use win_conformance::{load_manifest, run_all, vectors_dir};

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    let dir = vectors_dir();
    let results = run_all(&dir);
    let pass = results.iter().filter(|r| r.pass).count();
    let fail = results.len() - pass;

    if json {
        let items: Vec<String> = results
            .iter()
            .map(|r| {
                format!(
                    "    {{\"id\": {:?}, \"pass\": {}, \"detail\": {:?}}}",
                    r.id, r.pass, r.detail
                )
            })
            .collect();
        println!("{{");
        println!("  \"total\": {}, \"pass\": {pass}, \"fail\": {fail},", results.len());
        println!("  \"results\": [\n{}\n  ]", items.join(",\n"));
        println!("}}");
    } else {
        let protocol = load_manifest(&dir)
            .map(|m| m.protocol)
            .unwrap_or_else(|_| "unknown".to_string());
        println!("W.I.N. conformance — protocol {protocol}");
        println!("vectors: {}\n", dir.display());
        for r in &results {
            let mark = if r.pass { "PASS" } else { "FAIL" };
            println!("  {mark}  {}", r.id);
            if !r.pass {
                println!("        {}", r.detail);
            }
        }
        println!("\nsummary: {pass} pass, {fail} fail, {} total", results.len());
    }

    if fail > 0 {
        std::process::exit(1);
    }
}
