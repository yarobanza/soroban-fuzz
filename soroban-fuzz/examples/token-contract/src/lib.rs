//! A deliberately simplified stand-in for a Soroban token contract's core
//! logic (mint / transfer / burn over an in-memory balance map), used to
//! demonstrate `soroban-fuzz` end to end.
//!
//! This is NOT wired to a real `soroban_sdk::Env` — see
//! `docs/INTEGRATION.md` in the repo root for how to adapt a real contract
//! (built against `soroban-sdk`, invoked through its test `Env`) into the
//! `FuzzContract` trait. Keeping the example dependency-free means the
//! whole crate builds with plain `cargo build`, no wasm target required,
//! so reviewers can run it in one command.
//!
//! It contains one intentionally injected bug (see `transfer`) so that
//! running the fuzzer against it produces a real, reproducible finding
//! instead of a "trust me it works" claim.

use soroban_fuzz_core::{CallOutcome, EntryPoint, FuzzContract, SorobanValue, ValueKind};
use std::collections::HashMap;

#[derive(Default)]
pub struct SimpleToken {
    pub balances: HashMap<String, u128>,
    pub total_supply: u128,
}

impl SimpleToken {
    fn addr(v: &SorobanValue) -> String {
        match v {
            SorobanValue::Address(s) => s.clone(),
            other => format!("{other:?}"),
        }
    }
    fn amount(v: &SorobanValue) -> u128 {
        match v {
            SorobanValue::U128(n) => *n,
            other => panic!("expected U128 amount, got {other:?}"),
        }
    }

    fn mint(&mut self, to: &str, amount: u128) -> Result<(), &'static str> {
        let bal = *self.balances.get(to).unwrap_or(&0);
        let new_bal = bal.checked_add(amount).ok_or("mint overflow")?;
        let new_supply = self
            .total_supply
            .checked_add(amount)
            .ok_or("mint overflow")?;
        self.balances.insert(to.to_string(), new_bal);
        self.total_supply = new_supply;
        Ok(())
    }

    fn transfer(&mut self, from: &str, to: &str, amount: u128) -> Result<(), &'static str> {
        let from_bal = *self.balances.get(from).unwrap_or(&0);
        if from_bal < amount {
            return Err("insufficient balance");
        }
        let to_bal = *self.balances.get(to).unwrap_or(&0);
        self.balances.insert(from.to_string(), from_bal - amount);

        // BUG (injected on purpose): the recipient's balance is read
        // *before* the sender's debit above is applied. This is invisible
        // for from != to. But on a self-transfer (from == to, which a
        // small reused address pool makes easy to sample) the recipient
        // read and the sender write hit the same key: the credit below
        // overwrites the debit with the *pre-debit* balance plus `amount`,
        // so the account gains `amount` for free instead of being a no-op.
        // No panic, no overflow - just a silently broken
        // "sum(balances) == total_supply" invariant, which is exactly the
        // class of bug that only a state-invariant check (not a panic
        // check) can catch, and that hand-written unit tests (which
        // rarely think to test "transfer to yourself") tend to miss.
        self.balances.insert(to.to_string(), to_bal + amount);
        Ok(())
    }

    fn burn(&mut self, from: &str, amount: u128) -> Result<(), &'static str> {
        let from_bal = *self.balances.get(from).unwrap_or(&0);
        if from_bal < amount {
            return Err("insufficient balance");
        }
        self.balances.insert(from.to_string(), from_bal - amount);
        self.total_supply = self
            .total_supply
            .checked_sub(amount)
            .expect("total_supply underflow");
        Ok(())
    }

    /// The property the fuzzer checks after every call.
    pub fn sum_balances_matches_supply(&self) -> Result<(), String> {
        let sum: u128 = self.balances.values().fold(0u128, |a, b| a.wrapping_add(*b));
        if sum == self.total_supply {
            Ok(())
        } else {
            Err(format!(
                "sum(balances) = {sum} != total_supply = {}",
                self.total_supply
            ))
        }
    }
}

impl FuzzContract for SimpleToken {
    fn new_instance() -> Self {
        SimpleToken::default()
    }

    fn entry_points(&self) -> Vec<EntryPoint> {
        vec![
            EntryPoint::new("mint", vec![ValueKind::Address, ValueKind::U128]),
            EntryPoint::new(
                "transfer",
                vec![ValueKind::Address, ValueKind::Address, ValueKind::U128],
            ),
            EntryPoint::new("burn", vec![ValueKind::Address, ValueKind::U128]),
        ]
    }

    fn call(&mut self, function: &str, args: &[SorobanValue]) -> CallOutcome {
        match function {
            "mint" => {
                let to = Self::addr(&args[0]);
                let amount = Self::amount(&args[1]);
                match self.mint(&to, amount) {
                    Ok(()) => CallOutcome::Ok(SorobanValue::Void),
                    Err(e) => CallOutcome::Rejected(e.to_string()),
                }
            }
            "transfer" => {
                let from = Self::addr(&args[0]);
                let to = Self::addr(&args[1]);
                let amount = Self::amount(&args[2]);
                match self.transfer(&from, &to, amount) {
                    Ok(()) => CallOutcome::Ok(SorobanValue::Void),
                    Err(e) => CallOutcome::Rejected(e.to_string()),
                }
            }
            "burn" => {
                let from = Self::addr(&args[0]);
                let amount = Self::amount(&args[1]);
                match self.burn(&from, amount) {
                    Ok(()) => CallOutcome::Ok(SorobanValue::Void),
                    Err(e) => CallOutcome::Rejected(e.to_string()),
                }
            }
            other => panic!("unknown entry point: {other}"),
        }
    }
}
