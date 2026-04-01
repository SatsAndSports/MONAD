use anyhow::Result;
use monad_common::identity;
use rcgen::{CertificateParams, KeyPair};

/// Generated key material for a MONAD QUIC server.
pub struct KeyMaterial {
    /// PEM-encoded private key
    pub key_pem: String,
    /// PEM-encoded self-signed certificate
    pub cert_pem: String,
    /// Hex-encoded SPKI DER bytes (pinned public key for clients)
    pub pin_hex: String,
}

/// Generate a self-signed Ed25519 certificate from a seed and return the key material.
///
/// The seed must be a 32-byte Ed25519 private key seed. The certificate and
/// pinned public key are deterministically derived from it.
pub fn generate_from_seed(seed: &[u8; 32]) -> Result<KeyMaterial> {
    let pkcs8_der = identity::ed25519_seed_to_pkcs8_der(seed);
    let pkcs8_key = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_der);

    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key, &rcgen::PKCS_ED25519)?;

    // Compute the SPKI DER for pinning from the Ed25519 public key
    let ed25519_pub = identity::ed25519_seed_to_pubkey(seed)
        .map_err(|e| anyhow::anyhow!("failed to derive Ed25519 public key: {e}"))?;
    let spki_der = identity::ed25519_pubkey_to_spki_der(&ed25519_pub);
    let pin_hex = hex::encode(&spki_der);

    // Build self-signed certificate
    let mut params = CertificateParams::new(vec!["monad-relay".to_string()])?;
    params.is_ca = rcgen::IsCa::NoCa;

    let cert = params.self_signed(&key_pair)?;

    Ok(KeyMaterial {
        key_pem: key_pair.serialize_pem(),
        cert_pem: cert.pem(),
        pin_hex,
    })
}

/// Generate a new random identity and self-signed certificate.
///
/// This generates a fresh Ed25519 seed and derives everything from it.
pub fn generate() -> Result<KeyMaterial> {
    let (seed, _pubkey) = identity::generate_identity()
        .map_err(|e| anyhow::anyhow!("failed to generate identity: {e}"))?;
    generate_from_seed(&seed)
}

/// Generate a self-signed Ed25519 certificate and print it to stdout.
pub fn run_keygen() -> Result<()> {
    let km = generate()?;

    println!("# MONAD QUIC keypair");
    println!("#");
    println!("# Save the private key and certificate to files for the server.");
    println!("# Give the pinned public key (hex) to clients.");
    println!();
    println!("# --- Private key (PEM) ---");
    println!("{}", km.key_pem);
    println!("# --- Certificate (PEM) ---");
    println!("{}", km.cert_pem);
    println!("# --- Pinned public key (SPKI DER, hex) ---");
    println!("{}", km.pin_hex);
    println!();
    println!("# Example usage:");
    println!("#");
    println!("# Save key to server.key and cert to server.crt, then:");
    println!("#   monad-quic server --listen 0.0.0.0:4433 --cert server.crt --key server.key");
    println!("#");
    println!(
        "#   monad-quic client --connect 127.0.0.1:4433 --pin {}",
        km.pin_hex
    );

    Ok(())
}
