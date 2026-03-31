use anyhow::Result;
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

/// Generate a self-signed Ed25519 certificate and return the key material.
pub fn generate() -> Result<KeyMaterial> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;

    // The public_key_pem() method returns PEM-encoded SubjectPublicKeyInfo.
    // Parse that PEM to get the raw SPKI DER bytes for pinning.
    let spki_pem = key_pair.public_key_pem();
    let spki_der = pem::parse(&spki_pem)
        .map_err(|e| anyhow::anyhow!("failed to parse public key PEM: {e}"))?;
    let pin_hex = hex::encode(spki_der.contents());

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
    println!("# Client connects with:");
    println!(
        "#   monad-quic client --connect 127.0.0.1:4433 --pin {}",
        km.pin_hex
    );

    Ok(())
}
