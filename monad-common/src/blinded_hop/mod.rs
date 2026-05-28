//! Low-level blinded-hop helpers.
//!
//! This module targets MONAD's secp256k1 transport identity model. Blinding is
//! applied directly in secp256k1 scalar/group space, so there is no longer any
//! need for the old Ed25519/X25519 compatibility bridge or its rejection
//! sampling.

mod math;
mod path;
mod payload;
mod types;

pub use path::{build_blinded_hop_descriptor, build_path};
pub use types::{
    BlindedHopDescriptor, BlindedHopError, BlindedHopMessage, CleartextHop, Path, PathHop,
    PathHopMode, PathNode,
};

#[cfg(test)]
mod tests;
