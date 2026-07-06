//! A value model that mirrors the shape of Soroban's `Val` type space
//! (Void, Bool, U32/I32/U64/I64/U128/I128, Symbol, Bytes, String, Vec, Map,
//! Address) closely enough that generated `SorobanValue`s can be losslessly
//! converted into real `soroban_sdk::Val`s inside a contract-under-test's
//! adapter (see `docs/INTEGRATION.md`).
//!
//! Keeping this crate free of a hard `soroban-sdk` dependency means the
//! fuzzing engine itself has no wasm-target / host-env requirements and can
//! run as a plain native binary; the adapter layer you write for your own
//! contract is what bridges into a real `Env`.

use rand::Rng;
use serde::{Deserialize, Serialize};

/// The kind of value an entry-point argument expects. Used to drive
/// *typed* generation instead of blind byte-soup fuzzing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueKind {
    Bool,
    U32,
    I32,
    U64,
    I64,
    U128,
    I128,
    /// Soroban symbols: <=32 chars, [A-Za-z0-9_]
    Symbol,
    Bytes { max_len: usize },
    StringVal { max_len: usize },
    Address,
    Vec(Box<ValueKind>, usize), // element kind, max length
    Map(Box<ValueKind>, Box<ValueKind>, usize), // key kind, val kind, max entries
    /// One of a fixed set of kinds is chosen uniformly at random each time
    /// (useful for "any Val" style parameters).
    OneOf(Vec<ValueKind>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SorobanValue {
    Void,
    Bool(bool),
    U32(u32),
    I32(i32),
    U64(u64),
    I64(i64),
    U128(u128),
    I128(i128),
    Symbol(String),
    Bytes(Vec<u8>),
    StringVal(String),
    Address(String),
    Vec(Vec<SorobanValue>),
    Map(Vec<(SorobanValue, SorobanValue)>),
}

const SYMBOL_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

impl SorobanValue {
    /// Generate a random value matching `kind`, recursing up to `depth`
    /// levels for nested Vec/Map kinds (protects against stack overflow on
    /// adversarial nested-kind specs).
    pub fn arbitrary<R: Rng + ?Sized>(rng: &mut R, kind: &ValueKind, depth: u8) -> SorobanValue {
        match kind {
            ValueKind::Bool => SorobanValue::Bool(rng.gen()),
            ValueKind::U32 => SorobanValue::U32(gen_biased_u32(rng)),
            ValueKind::I32 => SorobanValue::I32(gen_biased_i32(rng)),
            ValueKind::U64 => SorobanValue::U64(gen_biased_u64(rng)),
            ValueKind::I64 => SorobanValue::I64(gen_biased_i64(rng)),
            ValueKind::U128 => SorobanValue::U128(gen_biased_u128(rng)),
            ValueKind::I128 => SorobanValue::I128(gen_biased_i128(rng)),
            ValueKind::Symbol => {
                let len = rng.gen_range(1..=32);
                let s: String = (0..len)
                    .map(|_| SYMBOL_ALPHABET[rng.gen_range(0..SYMBOL_ALPHABET.len())] as char)
                    .collect();
                SorobanValue::Symbol(s)
            }
            ValueKind::Bytes { max_len } => {
                let len = rng.gen_range(0..=*max_len.max(&1));
                SorobanValue::Bytes((0..len).map(|_| rng.gen()).collect())
            }
            ValueKind::StringVal { max_len } => {
                let len = rng.gen_range(0..=*max_len.max(&1));
                let s: String = (0..len)
                    .map(|_| (rng.gen_range(0x20u8..0x7e) as char))
                    .collect();
                SorobanValue::StringVal(s)
            }
            ValueKind::Address => {
                // Small fixed pool of "actors" rather than a fresh random
                // string each call: interesting sequences need the *same*
                // address to reappear across calls (e.g. mint to X, then
                // transfer into X), which a huge address space would make
                // effectively impossible to sample. Actor-based fuzzers
                // (Trident, Echidna) make the same choice for that reason.
                const POOL_SIZE: u32 = 4;
                let idx = rng.gen_range(0..POOL_SIZE);
                SorobanValue::Address(format!("ADDR_{idx}"))
            }
            ValueKind::Vec(elem_kind, max_len) => {
                if depth == 0 {
                    return SorobanValue::Vec(vec![]);
                }
                let len = rng.gen_range(0..=*max_len);
                SorobanValue::Vec(
                    (0..len)
                        .map(|_| SorobanValue::arbitrary(rng, elem_kind, depth - 1))
                        .collect(),
                )
            }
            ValueKind::Map(key_kind, val_kind, max_entries) => {
                if depth == 0 {
                    return SorobanValue::Map(vec![]);
                }
                let len = rng.gen_range(0..=*max_entries);
                SorobanValue::Map(
                    (0..len)
                        .map(|_| {
                            (
                                SorobanValue::arbitrary(rng, key_kind, depth - 1),
                                SorobanValue::arbitrary(rng, val_kind, depth - 1),
                            )
                        })
                        .collect(),
                )
            }
            ValueKind::OneOf(kinds) => {
                let idx = rng.gen_range(0..kinds.len());
                SorobanValue::arbitrary(rng, &kinds[idx], depth)
            }
        }
    }
}

/// Numeric generation is biased toward edge values (0, 1, MAX, MAX-1,
/// negative-adjacent boundaries) because that's where overflow / off-by-one
/// bugs live, with the remainder uniformly random across the full range.
fn gen_biased_u32<R: Rng + ?Sized>(rng: &mut R) -> u32 {
    if rng.gen_bool(0.3) {
        *[0, 1, u32::MAX, u32::MAX - 1, u32::MAX / 2]
            .get(rng.gen_range(0..5))
            .unwrap()
    } else {
        rng.gen()
    }
}
fn gen_biased_i32<R: Rng + ?Sized>(rng: &mut R) -> i32 {
    if rng.gen_bool(0.3) {
        *[0, 1, -1, i32::MAX, i32::MIN, i32::MIN + 1]
            .get(rng.gen_range(0..6))
            .unwrap()
    } else {
        rng.gen()
    }
}
fn gen_biased_u64<R: Rng + ?Sized>(rng: &mut R) -> u64 {
    if rng.gen_bool(0.3) {
        *[0, 1, u64::MAX, u64::MAX - 1, u64::MAX / 2]
            .get(rng.gen_range(0..5))
            .unwrap()
    } else {
        rng.gen()
    }
}
fn gen_biased_i64<R: Rng + ?Sized>(rng: &mut R) -> i64 {
    if rng.gen_bool(0.3) {
        *[0, 1, -1, i64::MAX, i64::MIN, i64::MIN + 1]
            .get(rng.gen_range(0..6))
            .unwrap()
    } else {
        rng.gen()
    }
}
fn gen_biased_u128<R: Rng + ?Sized>(rng: &mut R) -> u128 {
    if rng.gen_bool(0.3) {
        *[0, 1, u128::MAX, u128::MAX - 1, u128::MAX / 2]
            .get(rng.gen_range(0..5))
            .unwrap()
    } else {
        (rng.gen::<u64>() as u128) << 64 | rng.gen::<u64>() as u128
    }
}
fn gen_biased_i128<R: Rng + ?Sized>(rng: &mut R) -> i128 {
    if rng.gen_bool(0.3) {
        *[0, 1, -1, i128::MAX, i128::MIN]
            .get(rng.gen_range(0..5))
            .unwrap()
    } else {
        (rng.gen::<i64>() as i128) << 64 | rng.gen::<u64>() as i128
    }
}
