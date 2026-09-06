use super::payload::encrypt_blinded_hop_for_intro;
use super::types::{
    BlindedHopDescriptor, BlindedHopError, BlindedHopPlaintext, CleartextHop, HopTweak, Path,
    PathHop, PathHopMode, PathNode,
};

pub fn build_blinded_hop_descriptor(
    intro_pubkey: [u8; 33],
    next_hop_addr: &str,
    hidden_hop_pubkey: crate::secp_identity::Secp256k1Pubkey,
) -> Result<BlindedHopDescriptor, BlindedHopError> {
    loop {
        let tweak = HopTweak::generate()?;
        match build_blinded_hop_descriptor_with_tweak(
            intro_pubkey,
            next_hop_addr,
            hidden_hop_pubkey,
            tweak,
        ) {
            Ok(descriptor) => return Ok(descriptor),
            Err(BlindedHopError::InvalidTweak) => continue,
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn build_blinded_hop_descriptor_with_tweak(
    intro_pubkey: [u8; 33],
    next_hop_addr: &str,
    hidden_hop_pubkey: crate::secp_identity::Secp256k1Pubkey,
    tweak: HopTweak,
) -> Result<BlindedHopDescriptor, BlindedHopError> {
    let (tweaked_pubkey, l_prime_y_is_odd) =
        super::math::tweak_pubkey_with_parity(hidden_hop_pubkey, &tweak)?;
    let message = encrypt_blinded_hop_for_intro(
        intro_pubkey,
        &BlindedHopPlaintext {
            next_hop_addr: next_hop_addr.to_owned(),
            next_hop_tweak: tweak,
            l_prime_y_is_odd,
        },
    )?;

    Ok(BlindedHopDescriptor {
        tweaked_pubkey,
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
                pubkey: hop.pubkey,
            })),
            PathHopMode::Blinded => {
                let predecessor = &hops[i - 1];
                path.push(PathNode::Blinded(build_blinded_hop_descriptor(
                    predecessor.pubkey.to_compressed_bytes(),
                    hop.addr,
                    hop.pubkey,
                )?));
            }
        }
    }

    Ok(Path { hops: path })
}
