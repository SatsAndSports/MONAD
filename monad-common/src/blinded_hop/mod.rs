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

use crate::secp_identity::SecpTransportKeypair;
use payload::decrypt_blinded_hop_for_intro;

use self::math::{derive_tweaked_responder_secret_key, untweak_pubkey};

pub use path::{build_blinded_hop_descriptor, build_path};
pub use types::{
    BlindedHopDescriptor, BlindedHopError, BlindedHopMessage, CleartextHop, Path, PathHop,
    PathHopMode, PathNode, ResolvedBlindedHop,
};

pub fn resolve_blinded_hop_for_intro(
    intro_identity: &SecpTransportKeypair,
    descriptor: &BlindedHopDescriptor,
) -> Result<ResolvedBlindedHop, BlindedHopError> {
    let plaintext = decrypt_blinded_hop_for_intro(intro_identity, &descriptor.message)?;
    let next_hop_real_pubkey =
        untweak_pubkey(descriptor.tweaked_pubkey, &plaintext.next_hop_tweak)?;
    Ok(ResolvedBlindedHop {
        next_hop_addr: plaintext.next_hop_addr,
        next_hop_real_pubkey,
        tweak: plaintext.next_hop_tweak.raw_bytes(),
    })
}

pub fn derive_tweaked_responder_secret(
    identity: &SecpTransportKeypair,
    tweak: [u8; 32],
) -> Result<[u8; 32], BlindedHopError> {
    derive_tweaked_responder_secret_key(identity, tweak)
}

#[cfg(test)]
mod tests;
