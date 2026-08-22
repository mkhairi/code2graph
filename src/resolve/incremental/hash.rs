// SPDX-License-Identifier: Apache-2.0

//! Deterministic hash containers for internal resolution state.
//!
//! Incremental resolution keys its hot maps by crate-private identities
//! (`PendingRefId`, symbol paths, owner strings) that never come from an
//! untrusted caller, so the standard library's SipHash-based `RandomState`
//! buys nothing here and dominates the resolve profile. `FxBuildHasher` is
//! both faster and *seed-free*, which additionally makes iteration order
//! reproducible across runs — a property the resolver's determinism
//! invariant wants anyway.

/// A `std` hash map using the fixed, seed-free Fx hasher.
pub(crate) type HashMap<K, V> = std::collections::HashMap<K, V, rustc_hash::FxBuildHasher>;

/// A `std` hash set using the fixed, seed-free Fx hasher.
pub(crate) type HashSet<T> = std::collections::HashSet<T, rustc_hash::FxBuildHasher>;
