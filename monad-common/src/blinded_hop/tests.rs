use super::math::{
    derive_even_tweaked_secret_key, derive_tweaked_hop_identity, derive_tweaked_hop_public,
    pubkey_from_secret_bytes, tweak_pubkey, untweak_pubkey,
};
use super::payload::{
    decode_blinded_hop_plaintext, decrypt_blinded_hop_for_intro, encode_blinded_hop_plaintext,
    encrypt_blinded_hop_for_intro,
};
use super::types::HopTweak;
use super::*;
use crate::noise_secp256k1;
use crate::secp_identity::SecpTransportKeypair;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use sha2::{Digest, Sha512};

const SAMPLE_COUNT: usize = 64;

fn sample_secret_bytes(label: &[u8], i: u32) -> [u8; 32] {
    let mut attempt = 0u32;
    loop {
        let mut hasher = Sha512::new();
        hasher.update(label);
        hasher.update(i.to_le_bytes());
        hasher.update(attempt.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        if SecpTransportKeypair::from_secret_bytes(&out).is_ok() {
            return out;
        }
        attempt = attempt.wrapping_add(1);
    }
}

fn sample_identity(i: u32) -> SecpTransportKeypair {
    SecpTransportKeypair::from_secret_bytes(&sample_secret_bytes(b"monad-secp-hop-key", i)).unwrap()
}

fn sample_scalar(bytes: [u8; 32]) -> k256::Scalar {
    let scalar = Option::<k256::Scalar>::from(k256::Scalar::from_repr(bytes.into())).unwrap();
    assert!(!bool::from(scalar.is_zero()));
    scalar
}

fn assert_descriptor_matches_hidden_hop(
    descriptor: &BlindedHopDescriptor,
    intro_identity: &SecpTransportKeypair,
    hidden_identity: &SecpTransportKeypair,
    expected_next_hop_addr: &str,
) {
    let plaintext = decrypt_blinded_hop_for_intro(intro_identity, &descriptor.message).unwrap();
    assert_eq!(plaintext.next_hop_addr, expected_next_hop_addr);

    let recovered_hidden =
        untweak_pubkey(descriptor.tweaked_pubkey, &plaintext.next_hop_tweak).unwrap();
    assert_eq!(recovered_hidden, hidden_identity.pubkey());

    let tweaked =
        derive_tweaked_hop_public(hidden_identity.pubkey(), &plaintext.next_hop_tweak).unwrap();
    assert_eq!(descriptor.tweaked_pubkey, tweaked.tweaked_pubkey);
}

#[test]
fn test_resolve_blinded_hop_for_intro_roundtrip() {
    let intro_identity = sample_identity(0);
    let hidden_identity = sample_identity(1);
    let descriptor = build_blinded_hop_descriptor(
        intro_identity.pubkey().to_compressed_bytes(),
        "10.1.2.3:9050",
        &hidden_identity,
    )
    .unwrap();

    let resolved = resolve_blinded_hop_for_intro(&intro_identity, &descriptor).unwrap();
    assert_eq!(resolved.next_hop_addr, "10.1.2.3:9050");
    assert_eq!(resolved.next_hop_real_pubkey, hidden_identity.pubkey());

    let plaintext = decrypt_blinded_hop_for_intro(&intro_identity, &descriptor.message).unwrap();
    assert_eq!(resolved.tweak, plaintext.next_hop_tweak.raw_bytes());
}

#[test]
fn test_derive_tweaked_responder_secret_matches_descriptor_pubkey() {
    let intro_identity = sample_identity(0);
    let hidden_identity = sample_identity(1);
    let descriptor = build_blinded_hop_descriptor(
        intro_identity.pubkey().to_compressed_bytes(),
        "10.1.2.3:9050",
        &hidden_identity,
    )
    .unwrap();

    let resolved = resolve_blinded_hop_for_intro(&intro_identity, &descriptor).unwrap();
    let responder_secret =
        derive_tweaked_responder_secret(&hidden_identity, resolved.tweak).unwrap();
    let derived_pubkey = pubkey_from_secret_bytes(&responder_secret).unwrap();
    assert_eq!(derived_pubkey, descriptor.tweaked_pubkey);
}

#[test]
fn test_odd_candidate_uses_adjusted_tweak_for_even_representative() {
    let identity = sample_identity(0);
    let base_scalar = sample_scalar(identity.normalized_secret_bytes());

    let (original_tweak, candidate_scalar) = loop {
        let tweak = HopTweak::generate().unwrap();
        let candidate_scalar = base_scalar + tweak.scalar().unwrap();
        let candidate_secret_key = match SecretKey::from_slice(&candidate_scalar.to_bytes()) {
            Ok(secret_key) => secret_key,
            Err(_) => continue,
        };
        if candidate_secret_key
            .public_key()
            .to_encoded_point(true)
            .as_bytes()[0]
            != 0x02
        {
            break (tweak, candidate_scalar);
        }
    };

    let adjusted_scalar = -candidate_scalar;
    let adjusted_tweak_bytes: [u8; 32] = (adjusted_scalar - base_scalar).to_bytes().into();
    let adjusted_tweak = HopTweak::from_bytes(adjusted_tweak_bytes);
    let recomputed_scalar = base_scalar + adjusted_tweak.scalar().unwrap();
    assert_eq!(recomputed_scalar, adjusted_scalar);

    let derived_secret = derive_tweaked_responder_secret(&identity, adjusted_tweak_bytes).unwrap();
    assert_eq!(derived_secret, <[u8; 32]>::from(adjusted_scalar.to_bytes()));

    let tweaked_pubkey = tweak_pubkey(identity.pubkey(), &adjusted_tweak).unwrap();
    assert_eq!(tweaked_pubkey.to_compressed_bytes()[0], 0x02);
    assert_eq!(
        tweaked_pubkey,
        pubkey_from_secret_bytes(&derived_secret).unwrap(),
    );

    let original_pubkey = tweak_pubkey(identity.pubkey(), &original_tweak).unwrap();
    assert_eq!(original_pubkey, tweaked_pubkey);
}

#[test]
fn test_tweak_pubkey_differs_from_original() {
    let identity = sample_identity(0);
    let tweak = derive_even_tweaked_secret_key(&identity).unwrap().0;
    let tweaked = tweak_pubkey(identity.pubkey(), &tweak).unwrap();

    assert_ne!(tweaked, identity.pubkey());
}

#[test]
fn test_tweak_secret_matches_tweaked_pubkey_over_many_samples() {
    for i in 0..SAMPLE_COUNT as u32 {
        let identity = sample_identity(i);
        let (tweak, tweaked_secret, tweaked_pubkey) =
            derive_even_tweaked_secret_key(&identity).unwrap();

        assert_eq!(
            pubkey_from_secret_bytes(&tweaked_secret).unwrap(),
            tweaked_pubkey,
            "sample {i}"
        );
        assert_eq!(
            tweak_pubkey(identity.pubkey(), &tweak).unwrap(),
            tweaked_pubkey,
            "sample {i}"
        );
    }
}

#[test]
fn test_tweak_and_untweak_roundtrip_over_many_samples() {
    for i in 0..SAMPLE_COUNT as u32 {
        let identity = sample_identity(i);
        let tweak = derive_even_tweaked_secret_key(&identity).unwrap().0;
        let original = identity.pubkey();
        let tweaked = tweak_pubkey(original, &tweak).unwrap();
        let untweaked = untweak_pubkey(tweaked, &tweak).unwrap();

        assert_eq!(untweaked, original, "sample {i}");
    }
}

#[test]
fn test_blinded_hop_encrypt_decrypt_roundtrip() {
    let recipient = sample_identity(0);
    let tweak = HopTweak::generate().unwrap();
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: tweak,
    };

    let message =
        encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
            .unwrap();
    let decrypted = decrypt_blinded_hop_for_intro(&recipient, &message).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_blinded_hop_plaintext_binary_roundtrip() {
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "example.com:9050".to_string(),
        next_hop_tweak: HopTweak::from_bytes(sample_secret_bytes(b"monad-plaintext-tweak", 0)),
    };

    let encoded = encode_blinded_hop_plaintext(&plaintext).unwrap();
    assert_eq!(&encoded[..32], plaintext.next_hop_tweak.as_bytes());
    assert_eq!(&encoded[32..], plaintext.next_hop_addr.as_bytes());
    assert_eq!(decode_blinded_hop_plaintext(&encoded).unwrap(), plaintext);
}

#[test]
fn test_blinded_hop_plaintext_rejects_empty_address() {
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: String::new(),
        next_hop_tweak: HopTweak::from_bytes(sample_secret_bytes(b"monad-plaintext-tweak", 1)),
    };

    assert!(matches!(
        encode_blinded_hop_plaintext(&plaintext),
        Err(BlindedHopError::InvalidPayload(
            "next hop address must not be empty"
        ))
    ));

    let encoded = vec![0u8; 32];
    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidPayload(
            "blinded hop payload too short"
        ))
    ));
}

#[test]
fn test_blinded_hop_plaintext_rejects_too_short_payload() {
    let encoded = vec![0u8; 31];
    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidPayload(
            "blinded hop payload too short"
        ))
    ));
}

#[test]
fn test_blinded_hop_plaintext_rejects_interior_null() {
    let mut encoded = vec![0u8; 32];
    encoded.extend_from_slice(b"example");
    encoded.push(0);
    encoded.extend_from_slice(b"com:9050");
    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidPayload(
            "blinded hop address contains interior null"
        ))
    ));
}

#[test]
fn test_blinded_hop_plaintext_rejects_invalid_utf8() {
    let mut encoded = vec![0u8; 32];
    encoded.extend_from_slice(&[0xff, 0xfe]);
    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidUtf8(_))
    ));
}

#[test]
fn test_blinded_hop_wrong_recipient_fails() {
    let recipient_a = sample_identity(0);
    let recipient_b = sample_identity(1);
    let tweak = HopTweak::generate().unwrap();
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: tweak,
    };

    let message =
        encrypt_blinded_hop_for_intro(recipient_a.pubkey().to_compressed_bytes(), &plaintext)
            .unwrap();
    let result = decrypt_blinded_hop_for_intro(&recipient_b, &message);
    assert!(matches!(
        result,
        Err(BlindedHopError::Decrypt)
            | Err(BlindedHopError::InvalidPayload(_))
            | Err(BlindedHopError::InvalidUtf8(_))
    ));
}

#[test]
fn test_blinded_hop_tweaked_pubkeys_are_always_even_over_many_samples() {
    for i in 0..SAMPLE_COUNT as u32 {
        let identity = sample_identity(i);
        let tweaked = derive_tweaked_hop_identity(&identity).unwrap();
        assert_eq!(
            tweaked.tweaked_pubkey.to_compressed_bytes()[0],
            0x02,
            "sample {i}"
        );
    }
}

#[test]
fn test_blinded_hop_ciphertext_tamper_fails_decryption() {
    let recipient = sample_identity(0);
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: derive_even_tweaked_secret_key(&recipient).unwrap().0,
    };
    let mut message =
        encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
            .unwrap();
    let last = message.ciphertext.len() - 1;
    message.ciphertext[last] ^= 0x01;

    assert!(matches!(
        decrypt_blinded_hop_for_intro(&recipient, &message),
        Err(BlindedHopError::Decrypt)
    ));
}

#[test]
fn test_blinded_hop_ephemeral_pubkey_tamper_fails_decryption() {
    let recipient = sample_identity(0);
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: derive_even_tweaked_secret_key(&recipient).unwrap().0,
    };
    let mut message =
        encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
            .unwrap();
    message.ephemeral_pubkey[10] ^= 0x01;

    assert!(matches!(
        decrypt_blinded_hop_for_intro(&recipient, &message),
        Err(BlindedHopError::Decrypt)
    ));
}

#[test]
fn test_blinded_hop_truncated_ciphertext_fails_decryption() {
    let recipient = sample_identity(0);
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: derive_even_tweaked_secret_key(&recipient).unwrap().0,
    };
    let mut message =
        encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
            .unwrap();
    message.ciphertext.pop();

    assert!(matches!(
        decrypt_blinded_hop_for_intro(&recipient, &message),
        Err(BlindedHopError::Decrypt)
    ));
}

#[test]
fn test_blinded_hop_invalid_ephemeral_point_fails_decryption() {
    let recipient = sample_identity(0);
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: derive_even_tweaked_secret_key(&recipient).unwrap().0,
    };
    let mut message =
        encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
            .unwrap();
    message.ephemeral_pubkey = [0u8; 33];

    assert!(matches!(
        decrypt_blinded_hop_for_intro(&recipient, &message),
        Err(BlindedHopError::Decrypt)
    ));
}

#[test]
fn test_mismatched_descriptor_pubkey_recovers_different_hidden_identity() {
    let intro_identity = sample_identity(0);
    let hidden_identity_a = sample_identity(1);
    let hidden_identity_b = sample_identity(2);
    let mut descriptor = build_blinded_hop_descriptor(
        intro_identity.pubkey().to_compressed_bytes(),
        "127.0.0.1:9002",
        &hidden_identity_a,
    )
    .unwrap();
    descriptor.tweaked_pubkey = derive_tweaked_hop_identity(&hidden_identity_b)
        .unwrap()
        .tweaked_pubkey;

    let plaintext = decrypt_blinded_hop_for_intro(&intro_identity, &descriptor.message).unwrap();
    match untweak_pubkey(descriptor.tweaked_pubkey, &plaintext.next_hop_tweak) {
        Ok(recovered_hidden) => assert_ne!(recovered_hidden, hidden_identity_a.pubkey()),
        Err(BlindedHopError::InvalidPublicKey) => {}
        Err(e) => panic!("unexpected untweak error: {e:?}"),
    }
}

#[test]
fn test_blinded_hop_uses_fresh_ephemeral_key() {
    let recipient = sample_identity(0);
    let tweak = HopTweak::generate().unwrap();
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: tweak,
    };

    let msg1 = encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
        .unwrap();
    let msg2 = encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
        .unwrap();
    assert_ne!(msg1.ephemeral_pubkey, msg2.ephemeral_pubkey);
    assert_ne!(msg1.ciphertext, msg2.ciphertext);
}

#[test]
fn test_build_blinded_hop_descriptor_roundtrip_and_recovery() {
    let intro_identity = sample_identity(0);
    let hidden_identity = sample_identity(1);
    let descriptor = build_blinded_hop_descriptor(
        intro_identity.pubkey().to_compressed_bytes(),
        "127.0.0.1:9002",
        &hidden_identity,
    )
    .unwrap();

    assert_descriptor_matches_hidden_hop(
        &descriptor,
        &intro_identity,
        &hidden_identity,
        "127.0.0.1:9002",
    );
}

#[test]
fn test_build_path_rejects_empty_input() {
    assert!(matches!(
        build_path(&[]),
        Err(BlindedHopError::InvalidPath(
            "path requires at least one real hop"
        ))
    ));
}

#[test]
fn test_build_path_rejects_blinded_first_hop() {
    let hop_a = sample_identity(0);
    let hop_b = sample_identity(1);
    assert!(matches!(
        build_path(&[
            PathHop {
                addr: "127.0.0.1:9251",
                identity: &hop_a,
                mode: PathHopMode::Blinded
            },
            PathHop {
                addr: "127.0.0.1:9252",
                identity: &hop_b,
                mode: PathHopMode::Cleartext
            },
        ]),
        Err(BlindedHopError::InvalidPath(
            "first path hop must be cleartext"
        ))
    ));
}

#[test]
fn test_build_path_supports_mixed_cleartext_and_blinded_hops() {
    let hop_a = sample_identity(0);
    let hop_b = sample_identity(1);
    let hop_c = sample_identity(2);
    let hop_d = sample_identity(3);
    let path = build_path(&[
        PathHop {
            addr: "127.0.0.1:9261",
            identity: &hop_a,
            mode: PathHopMode::Cleartext,
        },
        PathHop {
            addr: "127.0.0.1:9262",
            identity: &hop_b,
            mode: PathHopMode::Blinded,
        },
        PathHop {
            addr: "127.0.0.1:9263",
            identity: &hop_c,
            mode: PathHopMode::Cleartext,
        },
        PathHop {
            addr: "127.0.0.1:9264",
            identity: &hop_d,
            mode: PathHopMode::Blinded,
        },
    ])
    .unwrap();

    assert_eq!(path.hops.len(), 4);
    let PathNode::Blinded(descriptor_b) = &path.hops[1] else {
        panic!("expected blinded hop")
    };
    let PathNode::Cleartext(clear_c) = &path.hops[2] else {
        panic!("expected cleartext hop")
    };
    let PathNode::Blinded(descriptor_d) = &path.hops[3] else {
        panic!("expected blinded hop")
    };

    assert_descriptor_matches_hidden_hop(descriptor_b, &hop_a, &hop_b, "127.0.0.1:9262");
    assert_eq!(clear_c.addr, "127.0.0.1:9263");
    assert_eq!(clear_c.pubkey, hop_c.pubkey());
    assert_descriptor_matches_hidden_hop(descriptor_d, &hop_c, &hop_d, "127.0.0.1:9264");
}

#[tokio::test]
async fn test_tweaked_identity_serves_secp_noise_handshake() {
    let identity = sample_identity(10);
    let tweaked = derive_tweaked_hop_identity(&identity).unwrap();
    let responder = tweaked.responder_secret_key;
    let (mut a, mut b) = tokio::io::duplex(1 << 20);
    let tweaked_pubkey = tweaked.tweaked_pubkey;

    let initiator_task = tokio::spawn(async move {
        noise_secp256k1::handshake_initiator_with_pubkey(
            &mut a,
            tweaked_pubkey.to_compressed_bytes(),
        )
        .await
        .expect("initiator handshake should succeed")
    });
    let responder_task = tokio::spawn(async move {
        noise_secp256k1::handshake_responder_with_secret_key_bytes(&mut b, responder)
            .await
            .expect("responder handshake should succeed")
    });

    let (_, _, initiator_session_id) = initiator_task.await.unwrap();
    let (_, _, responder_session_id) = responder_task.await.unwrap();
    assert_eq!(initiator_session_id, responder_session_id);
}
