//! `soroban-fuzz` CLI.
//!
//! Modeled on the `cargo-fuzz` workflow: you don't hand this binary a
//! contract at runtime (Rust has no stable ABI for that); instead you
//! write a small `FuzzContract` adapter + a `fn main()` fuzz target (see
//! `examples/token-contract/src/bin/fuzz_token.rs`), and this CLI helps
//! you scaffold that target and inspect/replay saved failure reports.
//!
//! Usage:
//!   soroban-fuzz init <name>        Scaffold a new fuzz target crate
//!   soroban-fuzz report <path.json> Pretty-print a saved FuzzReport

use soroban_fuzz_core::FuzzReport;
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => {
            let Some(name) = args.get(2) else {
                eprintln!("usage: soroban-fuzz init <target-name>");
                return ExitCode::FAILURE;
            };
            init_target(name);
            ExitCode::SUCCESS
        }
        Some("report") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: soroban-fuzz report <path-to-report.json>");
                return ExitCode::FAILURE;
            };
            match print_report(path) {
                Ok(clean) => {
                    if clean {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("error reading report: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!(
                "soroban-fuzz - property-based fuzzing for Soroban contracts\n\n\
                 Commands:\n  \
                 init <name>          Scaffold a new fuzz target\n  \
                 report <path.json>   Pretty-print a saved fuzz report\n\n\
                 To actually run a campaign, write a fuzz target (see `init`)\n\
                 and run it with `cargo run --release --bin <name>`."
            );
            ExitCode::FAILURE
        }
    }
}

fn print_report(path: &str) -> std::io::Result<bool> {
    let data = fs::read_to_string(path)?;
    let report: FuzzReport = serde_json::from_str(&data).expect("invalid report JSON");
    println!("iterations run: {}", report.iterations_run);
    println!("failures: {}", report.failures.len());
    for (i, f) in report.failures.iter().enumerate() {
        println!("\n--- failure #{} (seed {}) ---", i + 1, f.seed);
        println!("{:?}", f.kind);
        for call in &f.repro {
            println!("  {}({:?})", call.function, call.args);
        }
    }
    Ok(report.is_clean())
}

fn init_target(name: &str) {
    let dir = format!("fuzz_targets/{name}");
    fs::create_dir_all(&dir).expect("failed to create target dir");
    let contents = format!(
        r#"//! Fuzz target scaffold for `{name}`.
//! 1. Implement `FuzzContract` for your contract (or an adapter wrapping
//!    a real `soroban_sdk::Env`-backed contract - see docs/INTEGRATION.md).
//! 2. Register the invariants that must hold after every call.
//! 3. `cargo run --release --bin {name}`

use soroban_fuzz_core::{{FuzzConfig, FuzzRunner}};

fn main() {{
    let config = FuzzConfig::default();
    // let entry_points = YourContract::default().entry_points();
    // let runner = FuzzRunner::<YourContract>::new(config)
    //     .with_invariant(Box::new(FnInvariant::new("...", |c| {{ ... }})));
    // let report = runner.run(&entry_points);
    println!("edit {{}} to wire up your contract", file!());
}}
"#,
        name = name
    );
    fs::write(format!("{dir}/main.rs"), contents).expect("failed to write scaffold");
    println!("Scaffolded fuzz target at {dir}/main.rs — wire up your contract's FuzzContract impl and add it as a [[bin]] in Cargo.toml.");
}
