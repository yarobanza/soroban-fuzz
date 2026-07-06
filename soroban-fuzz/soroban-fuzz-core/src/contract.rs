use crate::value::{SorobanValue, ValueKind};
use serde::{Deserialize, Serialize};

/// Describes one callable entry point on the contract-under-test, so the
/// generator can produce well-typed arguments instead of blind bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub name: String,
    pub arg_kinds: Vec<ValueKind>,
}

impl EntryPoint {
    pub fn new(name: impl Into<String>, arg_kinds: Vec<ValueKind>) -> Self {
        Self {
            name: name.into(),
            arg_kinds,
        }
    }
}

/// Outcome of a single call. `Trap` represents a Rust panic / host-env
/// trap (the Soroban equivalent of a wasm `unreachable`), which the runner
/// always treats as a finding unless the entry point is explicitly
/// allow-listed to panic (e.g. an `assert!` guarding auth).
#[derive(Debug, Clone)]
pub enum CallOutcome {
    Ok(SorobanValue),
    /// Contract explicitly rejected the call (e.g. `panic_with_error!` for
    /// auth/validation) - expected, not a finding, unless the harness marks
    /// this entry point as "should never reject" for the given args.
    Rejected(String),
}

/// Implement this over your contract's real dispatch (via `soroban-sdk`'s
/// test `Env`, or directly over your contract struct if you're testing
/// pure logic). See `docs/INTEGRATION.md` for wiring a real Soroban
/// contract wasm/native build in.
pub trait FuzzContract {
    /// Fresh instance for each fuzz run (fresh storage state).
    fn new_instance() -> Self
    where
        Self: Sized;

    fn entry_points(&self) -> Vec<EntryPoint>;

    /// Dispatch a call. Implementations should NOT catch panics themselves;
    /// the runner wraps every call in `catch_unwind`.
    fn call(&mut self, function: &str, args: &[SorobanValue]) -> CallOutcome;
}

/// A named invariant checked against contract state after every call.
/// Return `Err(reason)` when broken.
pub trait Invariant<C> {
    fn name(&self) -> &str;
    fn check(&self, contract: &C) -> Result<(), String>;
}

/// Convenience constructor for closure-based invariants.
pub struct FnInvariant<C> {
    name: String,
    f: Box<dyn Fn(&C) -> Result<(), String>>,
}

impl<C> FnInvariant<C> {
    pub fn new(name: impl Into<String>, f: impl Fn(&C) -> Result<(), String> + 'static) -> Self {
        Self {
            name: name.into(),
            f: Box::new(f),
        }
    }
}

impl<C> Invariant<C> for FnInvariant<C> {
    fn name(&self) -> &str {
        &self.name
    }
    fn check(&self, contract: &C) -> Result<(), String> {
        (self.f)(contract)
    }
}
