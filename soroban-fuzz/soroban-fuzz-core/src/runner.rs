use crate::contract::{CallOutcome, EntryPoint, FuzzContract, Invariant};
use crate::value::SorobanValue;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::panic::{self, AssertUnwindSafe};

#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub iterations: u64,
    pub min_calls_per_run: usize,
    pub max_calls_per_run: usize,
    pub max_depth: u8,
    pub seed: Option<u64>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            iterations: 10_000,
            min_calls_per_run: 1,
            max_calls_per_run: 8,
            max_depth: 4,
            seed: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedCall {
    pub function: String,
    pub args: Vec<SorobanValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureKind {
    Panic { message: String },
    InvariantBroken { invariant: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub kind: FailureKind,
    /// Minimal (shrunk) call sequence that still reproduces the failure.
    pub repro: Vec<RecordedCall>,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzReport {
    pub iterations_run: u64,
    pub failures: Vec<Failure>,
}

impl FuzzReport {
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }
}

pub struct FuzzRunner<'a, C: FuzzContract> {
    invariants: Vec<Box<dyn Invariant<C> + 'a>>,
    config: FuzzConfig,
}

impl<'a, C: FuzzContract> FuzzRunner<'a, C> {
    pub fn new(config: FuzzConfig) -> Self {
        Self {
            invariants: Vec::new(),
            config,
        }
    }

    pub fn with_invariant(mut self, inv: Box<dyn Invariant<C> + 'a>) -> Self {
        self.invariants.push(inv);
        self
    }

    /// Run one call sequence against a fresh contract instance, returning
    /// the first failure encountered (if any).
    fn execute_sequence(
        &self,
        calls: &[RecordedCall],
    ) -> Result<C, (C, FailureKind)> {
        let mut contract = C::new_instance();
        for call in calls {
            let result = panic::catch_unwind(AssertUnwindSafe(|| {
                contract.call(&call.function, &call.args)
            }));
            match result {
                Ok(CallOutcome::Ok(_)) | Ok(CallOutcome::Rejected(_)) => {}
                Err(payload) => {
                    let message = panic_message(&payload);
                    return Err((contract, FailureKind::Panic { message }));
                }
            }
            for inv in &self.invariants {
                if let Err(reason) = inv.check(&contract) {
                    return Err((
                        contract,
                        FailureKind::InvariantBroken {
                            invariant: inv.name().to_string(),
                            reason,
                        },
                    ));
                }
            }
        }
        Ok(contract)
    }

    /// Remove calls from the sequence one at a time (front, back, then
    /// middle-out) while the failure still reproduces. This is a simple
    /// delta-debugging pass, not full ddmin, but it's usually enough to
    /// turn an 8-call sequence into the 1-2 calls that actually matter.
    fn shrink(&self, calls: Vec<RecordedCall>) -> Vec<RecordedCall> {
        let mut current = calls;
        let mut changed = true;
        while changed && current.len() > 1 {
            changed = false;
            let mut i = 0;
            while i < current.len() {
                let mut candidate = current.clone();
                candidate.remove(i);
                if !candidate.is_empty() && self.execute_sequence(&candidate).is_err() {
                    current = candidate;
                    changed = true;
                    // don't advance i; sequence shifted left
                } else {
                    i += 1;
                }
            }
        }
        current
    }

    pub fn run(&self, entry_points: &[EntryPoint]) -> FuzzReport {
        // Every caught panic still prints via the default hook otherwise,
        // which drowns the report in backtraces for expected findings.
        // Findings are reported (with their message) in the FuzzReport
        // itself, so the default hook's stderr output is redundant here.
        let previous_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let report = self.run_inner(entry_points);
        panic::set_hook(previous_hook);
        report
    }

    fn run_inner(&self, entry_points: &[EntryPoint]) -> FuzzReport {
        let seed = self.config.seed.unwrap_or_else(|| rand::thread_rng().gen());
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut failures = Vec::new();
        let mut iterations_run = 0u64;

        for _ in 0..self.config.iterations {
            iterations_run += 1;
            let n_calls = rng.gen_range(self.config.min_calls_per_run..=self.config.max_calls_per_run);
            let calls: Vec<RecordedCall> = (0..n_calls)
                .map(|_| {
                    let ep = &entry_points[rng.gen_range(0..entry_points.len())];
                    let args = ep
                        .arg_kinds
                        .iter()
                        .map(|k| SorobanValue::arbitrary(&mut rng, k, self.config.max_depth))
                        .collect();
                    RecordedCall {
                        function: ep.name.clone(),
                        args,
                    }
                })
                .collect();

            if let Err((_contract, kind)) = self.execute_sequence(&calls) {
                let repro = self.shrink(calls);
                failures.push(Failure { kind, repro, seed });
                // Stop at first class of failure per run to keep reports
                // readable; keep going to look for *different* bugs.
                if failures.len() >= 50 {
                    break;
                }
            }
        }

        FuzzReport {
            iterations_run,
            failures,
        }
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}
