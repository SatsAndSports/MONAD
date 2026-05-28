use super::math::derive_tweaked_hop_identity;
use super::payload::encrypt_blinded_hop_for_intro;
use super::types::{
    BlindedHopDescriptor, BlindedHopError, BlindedHopPlaintext, CleartextHop, Path, PathHop,
    PathHopMode, PathNode,
};

pub fn build_blinded_hop_descriptor(
    intro_pubkey: [u8; 33],
    next_hop_addr: &str,
    hidden_hop_identity: &crate::secp_identity::SecpTransportKeypair,
) -> Result<BlindedHopDescriptor, BlindedHopError> {
    let tweaked = derive_tweaked_hop_identity(hidden_hop_identity)?;
    let message = encrypt_blinded_hop_for_intro(
        intro_pubkey,
        &BlindedHopPlaintext {
            next_hop_addr: next_hop_addr.to_owned(),
            next_hop_tweak: tweaked.tweak,
        },
    )?;

    Ok(BlindedHopDescriptor {
        tweaked_pubkey: tweaked.tweaked_pubkey,
        message,
    })
}

pub fn build_path(hops: &[PathHop<'_>]) -> Result<Path, BlindedHopError> {
    if hops.is_empty() {
        return Err(BlindedHopError::InvalidPath(
            "path requires at least one real hop",
        ));
    }
    if hops[0].mode != PathHopMode::Cleartext {
        return Err(BlindedHopError::InvalidPath(
            "first path hop must be cleartext",
        ));
    }

    let mut path = Vec::with_capacity(hops.len());
    for (i, hop) in hops.iter().enumerate() {
        match hop.mode {
            PathHopMode::Cleartext => path.push(PathNode::Cleartext(CleartextHop {
                addr: hop.addr.to_owned(),
                pubkey: hop.identity.pubkey(),
            })),
            PathHopMode::Blinded => {
                let predecessor = &hops[i - 1];
                path.push(PathNode::Blinded(build_blinded_hop_descriptor(
                    predecessor.identity.pubkey().to_compressed_bytes(),
                    hop.addr,
                    hop.identity,
                )?));
            }
        }
    }

    Ok(Path { hops: path })
}
