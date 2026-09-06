use super::math::{pubkey_from_secret_bytes, tweak_pubkey_with_parity, untweak_pubkey};
use super::path::build_blinded_hop_descriptor_with_tweak;
use super::payload::{
    decode_blinded_hop_plaintext, decrypt_blinded_hop_for_intro, encode_blinded_hop_plaintext,
    encrypt_blinded_hop_for_intro,
};
use super::types::HopTweak;
use super::*;
use crate::noise_secp256k1;
use crate::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair};
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

fn random_tweaked_hop(pubkey: Secp256k1Pubkey) -> (HopTweak, Secp256k1Pubkey, bool) {
    loop {
        let tweak = HopTweak::generate().unwrap();
        if let Ok((tweaked_pubkey, l_prime_y_is_odd)) = tweak_pubkey_with_parity(pubkey, &tweak) {
            return (tweak, tweaked_pubkey, l_prime_y_is_odd);
        }
    }
}

fn assert_descriptor_matches_hidden_hop(
    descriptor: &BlindedHopDescriptor,
    intro_identity: &SecpTransportKeypair,
    hidden_identity: &SecpTransportKeypair,
    expected_next_hop_addr: &str,
) {
    let plaintext = decrypt_blinded_hop_for_intro(intro_identity, &descriptor.message).unwrap();
    assert_eq!(plaintext.next_hop_addr, expected_next_hop_addr);

    let recovered_hidden = untweak_pubkey(
        descriptor.tweaked_pubkey,
        &plaintext.next_hop_tweak,
        plaintext.l_prime_y_is_odd,
    )
    .unwrap();
    assert_eq!(recovered_hidden, hidden_identity.pubkey());

    let tweaked = tweak_pubkey_with_parity(hidden_identity.pubkey(), &plaintext.next_hop_tweak)
        .unwrap()
        .0;
    assert_eq!(descriptor.tweaked_pubkey, tweaked);
}

#[test]
fn test_resolve_blinded_hop_for_intro_roundtrip() {
    let intro_identity = sample_identity(0);
    let hidden_identity = sample_identity(1);
    let descriptor = build_blinded_hop_descriptor(
        intro_identity.pubkey().to_compressed_bytes(),
        "10.1.2.3:9050",
        hidden_identity.pubkey(),
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
        hidden_identity.pubkey(),
    )
    .unwrap();

    let resolved = resolve_blinded_hop_for_intro(&intro_identity, &descriptor).unwrap();
    let responder_secret =
        derive_tweaked_responder_secret(&hidden_identity, resolved.tweak).unwrap();
    let derived_pubkey = pubkey_from_secret_bytes(&responder_secret).unwrap();
    assert_eq!(derived_pubkey, descriptor.tweaked_pubkey);
}

#[test]
fn test_even_and_odd_l_prime_flags_recover_real_key_and_normalized_secret() {
    let identity = sample_identity(0);
    for l_prime_y_is_odd in [false, true] {
        let (tweak, tweaked_pubkey, actual_odd) = loop {
            let tweak = HopTweak::generate().unwrap();
            let (tweaked_pubkey, actual_odd) =
                tweak_pubkey_with_parity(identity.pubkey(), &tweak).unwrap();
            if actual_odd == l_prime_y_is_odd {
                break (tweak, tweaked_pubkey, actual_odd);
            }
        };

        assert_eq!(actual_odd, l_prime_y_is_odd);
        assert_eq!(
            untweak_pubkey(tweaked_pubkey, &tweak, l_prime_y_is_odd).unwrap(),
            identity.pubkey(),
        );
        let derived_secret = derive_tweaked_responder_secret(&identity, tweak.raw_bytes()).unwrap();
        assert_eq!(
            pubkey_from_secret_bytes(&derived_secret).unwrap(),
            tweaked_pubkey
        );
    }
}

#[test]
fn test_tweak_pubkey_differs_from_original() {
    let identity = sample_identity(0);
    let (_, tweaked, _) = random_tweaked_hop(identity.pubkey());

    assert_ne!(tweaked, identity.pubkey());
}

#[test]
fn test_tweak_secret_matches_tweaked_pubkey_over_many_samples() {
    for i in 0..SAMPLE_COUNT as u32 {
        let identity = sample_identity(i);
        let (tweak, tweaked_pubkey, _) = random_tweaked_hop(identity.pubkey());
        let tweaked_secret = derive_tweaked_responder_secret(&identity, tweak.raw_bytes()).unwrap();

        assert_eq!(
            pubkey_from_secret_bytes(&tweaked_secret).unwrap(),
            tweaked_pubkey,
            "sample {i}"
        );
        assert_eq!(
            tweak_pubkey_with_parity(identity.pubkey(), &tweak)
                .unwrap()
                .0,
            tweaked_pubkey,
            "sample {i}"
        );
    }
}

#[test]
fn test_tweak_and_untweak_roundtrip_over_many_samples() {
    for i in 0..SAMPLE_COUNT as u32 {
        let identity = sample_identity(i);
        let (tweak, tweaked, l_prime_y_is_odd) = random_tweaked_hop(identity.pubkey());
        let original = identity.pubkey();
        assert_eq!(
            tweaked,
            tweak_pubkey_with_parity(original, &tweak).unwrap().0
        );
        let untweaked = untweak_pubkey(tweaked, &tweak, l_prime_y_is_odd).unwrap();

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
        l_prime_y_is_odd: false,
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
        l_prime_y_is_odd: true,
    };

    let encoded = encode_blinded_hop_plaintext(&plaintext).unwrap();
    assert_eq!(&encoded[..32], plaintext.next_hop_tweak.as_bytes());
    assert_eq!(encoded[32], 1);
    assert_eq!(&encoded[33..], plaintext.next_hop_addr.as_bytes());
    assert_eq!(decode_blinded_hop_plaintext(&encoded).unwrap(), plaintext);
}

#[test]
fn test_blinded_hop_plaintext_rejects_empty_address() {
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: String::new(),
        next_hop_tweak: HopTweak::from_bytes(sample_secret_bytes(b"monad-plaintext-tweak", 1)),
        l_prime_y_is_odd: false,
    };

    assert!(matches!(
        encode_blinded_hop_plaintext(&plaintext),
        Err(BlindedHopError::InvalidPayload(
            "next hop address must not be empty"
        ))
    ));

    let encoded = vec![0u8; 33];
    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidPayload(
            "blinded hop payload too short"
        ))
    ));
}

#[test]
fn test_blinded_hop_plaintext_rejects_too_short_payload() {
    let encoded = vec![0u8; 32];
    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidPayload(
            "blinded hop payload too short"
        ))
    ));
}

#[test]
fn test_blinded_hop_plaintext_rejects_invalid_parity_flag() {
    let mut encoded = vec![0u8; 33];
    encoded[32] = 2;
    encoded.extend_from_slice(b"example.com:9050");

    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidPayload(
            "invalid blinded-hop parity flag"
        ))
    ));
}

#[test]
fn test_blinded_hop_plaintext_rejects_pre_parity_flag_layout() {
    let mut encoded = vec![0u8; 32];
    encoded.extend_from_slice(b"example.com:9050");

    assert!(matches!(
        decode_blinded_hop_plaintext(&encoded),
        Err(BlindedHopError::InvalidPayload(
            "invalid blinded-hop parity flag"
        ))
    ));
}

#[test]
fn test_blinded_hop_plaintext_rejects_interior_null() {
    let mut encoded = vec![0u8; 33];
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
    let mut encoded = vec![0u8; 33];
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
        l_prime_y_is_odd: false,
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
        let (_, tweaked, _) = random_tweaked_hop(identity.pubkey());
        assert_eq!(tweaked.to_compressed_bytes()[0], 0x02, "sample {i}");
    }
}

#[test]
fn test_blinded_hop_ciphertext_tamper_fails_decryption() {
    let recipient = sample_identity(0);
    let plaintext = types::BlindedHopPlaintext {
        next_hop_addr: "10.1.2.3:9050".to_string(),
        next_hop_tweak: HopTweak::generate().unwrap(),
        l_prime_y_is_odd: false,
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
        next_hop_tweak: HopTweak::generate().unwrap(),
        l_prime_y_is_odd: false,
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
        next_hop_tweak: HopTweak::generate().unwrap(),
        l_prime_y_is_odd: false,
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
        next_hop_tweak: HopTweak::generate().unwrap(),
        l_prime_y_is_odd: false,
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
        hidden_identity_a.pubkey(),
    )
    .unwrap();
    descriptor.tweaked_pubkey = random_tweaked_hop(hidden_identity_b.pubkey()).1;

    let plaintext = decrypt_blinded_hop_for_intro(&intro_identity, &descriptor.message).unwrap();
    match untweak_pubkey(
        descriptor.tweaked_pubkey,
        &plaintext.next_hop_tweak,
        plaintext.l_prime_y_is_odd,
    ) {
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
        l_prime_y_is_odd: false,
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
        hidden_identity.pubkey(),
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
fn test_multi_hop_public_key_construction_supports_even_and_odd_tweaks() {
    let relay_a = sample_identity(0);
    let relay_b = sample_identity(1);
    let relay_c = sample_identity(2);
    let even_tweak = HopTweak::from_bytes([
        0x11, 0x60, 0x1c, 0x71, 0x78, 0x3b, 0xb7, 0xc2, 0x8e, 0x9e, 0x5b, 0x31, 0xe6, 0x8a, 0x5f,
        0xe5, 0x1f, 0xc8, 0x80, 0xb0, 0x29, 0x72, 0x54, 0xfb, 0x64, 0x19, 0x6b, 0x27, 0x3b, 0xcb,
        0x00, 0x89,
    ]);
    let odd_tweak = HopTweak::from_bytes([
        0x97, 0xfe, 0x0c, 0xf6, 0x97, 0xe0, 0x55, 0x3c, 0xb9, 0xbd, 0x01, 0x58, 0x79, 0x8f, 0x13,
        0x1e, 0xc1, 0x3b, 0x75, 0x9b, 0xda, 0xee, 0x1e, 0x54, 0x27, 0x0a, 0xe0, 0x95, 0x41, 0x7e,
        0x6f, 0x31,
    ]);

    assert!(
        !tweak_pubkey_with_parity(relay_b.pubkey(), &even_tweak)
            .unwrap()
            .1
    );
    assert!(
        tweak_pubkey_with_parity(relay_c.pubkey(), &odd_tweak)
            .unwrap()
            .1
    );

    let descriptor_b = build_blinded_hop_descriptor_with_tweak(
        relay_a.pubkey().to_compressed_bytes(),
        "127.0.0.1:9002",
        relay_b.pubkey(),
        even_tweak,
    )
    .unwrap();
    let descriptor_c = build_blinded_hop_descriptor_with_tweak(
        relay_b.pubkey().to_compressed_bytes(),
        "127.0.0.1:9003",
        relay_c.pubkey(),
        odd_tweak,
    )
    .unwrap();
    let path = Path {
        hops: vec![
            PathNode::Cleartext(CleartextHop {
                addr: "127.0.0.1:9001".to_string(),
                pubkey: relay_a.pubkey(),
            }),
            PathNode::Blinded(descriptor_b.clone()),
            PathNode::Blinded(descriptor_c.clone()),
        ],
    };

    assert_eq!(path.hops.len(), 3);

    let resolved_b = resolve_blinded_hop_for_intro(&relay_a, &descriptor_b).unwrap();
    let resolved_c = resolve_blinded_hop_for_intro(&relay_b, &descriptor_c).unwrap();
    assert_eq!(resolved_b.next_hop_real_pubkey, relay_b.pubkey());
    assert_eq!(resolved_c.next_hop_real_pubkey, relay_c.pubkey());

    let plaintext_b = decrypt_blinded_hop_for_intro(&relay_a, &descriptor_b.message).unwrap();
    let plaintext_c = decrypt_blinded_hop_for_intro(&relay_b, &descriptor_c.message).unwrap();
    assert!(!plaintext_b.l_prime_y_is_odd);
    assert!(plaintext_c.l_prime_y_is_odd);

    let responder_b = derive_tweaked_responder_secret(&relay_b, resolved_b.tweak).unwrap();
    let responder_c = derive_tweaked_responder_secret(&relay_c, resolved_c.tweak).unwrap();
    assert_eq!(
        pubkey_from_secret_bytes(&responder_b).unwrap(),
        descriptor_b.tweaked_pubkey
    );
    assert_eq!(
        pubkey_from_secret_bytes(&responder_c).unwrap(),
        descriptor_c.tweaked_pubkey
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
                pubkey: hop_a.pubkey(),
                mode: PathHopMode::Blinded
            },
            PathHop {
                addr: "127.0.0.1:9252",
                pubkey: hop_b.pubkey(),
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
            pubkey: hop_a.pubkey(),
            mode: PathHopMode::Cleartext,
        },
        PathHop {
            addr: "127.0.0.1:9262",
            pubkey: hop_b.pubkey(),
            mode: PathHopMode::Blinded,
        },
        PathHop {
            addr: "127.0.0.1:9263",
            pubkey: hop_c.pubkey(),
            mode: PathHopMode::Cleartext,
        },
        PathHop {
            addr: "127.0.0.1:9264",
            pubkey: hop_d.pubkey(),
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
    let (tweak, tweaked_pubkey, _) = random_tweaked_hop(identity.pubkey());
    let responder = derive_tweaked_responder_secret(&identity, tweak.raw_bytes()).unwrap();
    let (mut a, mut b) = tokio::io::duplex(1 << 20);

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
