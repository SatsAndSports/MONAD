# Why Not secp256k1 Everywhere?

This document records why MONAD still does **not** use secp256k1 everywhere in
the transport stack, even though secp256k1 transport identities are now used
for MONAD's TCP transport and for the secp-authenticated QUIC path.

The current transport split is documented in `ARCHITECTURE.md` under
**Current Transport Identity Model**.

## Why It Looks This Way

The current design is constrained by the specific libraries in use.

### Noise side

MONAD currently uses `snow` for Noise handshakes and transport.

The current protocol string is:

```text
Noise_NK_25519_ChaChaPoly_BLAKE2s
```

`snow` only exposes these DH choices:

- `25519`
- `448`

So the current Noise path is tied to X25519, not secp256k1.

### QUIC side

MONAD currently uses:

- `quinn` for QUIC
- `rustls` for TLS 1.3
- `rcgen` for self-signed certificate generation

`rcgen` supports standard certificate/signature paths such as:

- Ed25519
- P-256 / P-384 / P-521 ECDSA
- RSA

It does not expose a secp256k1 certificate path.

Because Ed25519 works cleanly for certificate generation and also gives us a stable identity from which X25519 can be derived, it was a practical unified choice.

## secp256k1 Research Summary

This section records the results of researching whether MONAD could switch both transport layers to secp256k1 public keys.

## QUIC / TLS Transport-Layer secp256k1

Conclusion: not practical with the current standards-compliant stack.

### Main blockers

#### 1. QUIC requires TLS 1.3

`quinn`'s QUIC implementation is based on TLS 1.3. A standards-compliant QUIC v1 stack therefore inherits TLS 1.3's algorithm support constraints.

#### 2. `rustls` has no secp256k1 TLS signature scheme

`rustls::SignatureScheme` includes items such as:

- `ECDSA_NISTP256_SHA256`
- `ECDSA_NISTP384_SHA384`
- `ECDSA_NISTP521_SHA512`
- `ED25519`
- `ED448`

It does not include a secp256k1 / ES256K-style scheme.

That means the TLS certificate authentication step cannot be expressed using secp256k1 within normal rustls TLS 1.3 support.

#### 3. `rustls` has no secp256k1 key exchange group

`rustls::NamedGroup` includes groups such as:

- `X25519`
- `X448`
- `secp256r1`
- `secp384r1`
- `secp521r1`

It does not include secp256k1.

So even aside from certificate signatures, TLS key exchange support is not aligned with secp256k1.

#### 4. Raw public keys do not solve the problem

`rustls` has support hooks for RFC 7250 raw public keys via verifier APIs such as `requires_raw_public_keys()`.

However, raw public keys only change how peer identity is carried. They do not invent new TLS signature schemes or new supported groups.

TLS still needs:

- a supported signature scheme for `CertificateVerify`
- supported key exchange groups for the handshake

Since rustls does not expose secp256k1 for those roles, raw public keys are not enough.

#### 5. `rcgen` does not provide secp256k1 certificate generation

The current QUIC path depends on `rcgen` to build self-signed certs. `rcgen` does not offer a secp256k1 certificate/signing path in the way MONAD would need.

### Standards-level evidence

This does not appear to be only a Rust ecosystem issue.

An OpenSSL report showed secp256k1 working in TLS 1.2 but failing in TLS 1.3 with a `no suitable signature algorithm` error. That lines up with the absence of a normal TLS 1.3 secp256k1 path.

### Practical meaning

If the goal is:

- QUIC connection
- transport-layer authentication
- pinned secp256k1 public key
- all happening inside standard QUIC/TLS itself

then the current answer is effectively no with `quinn` + `rustls`.

The only likely path would be a custom or nonstandard TLS/QUIC crypto implementation, which is far beyond a focused repo experiment.

## Noise Transport-Layer secp256k1

Conclusion: plausible, but not with `snow`.

### What blocks it today

MONAD's current Noise code uses `snow`, and `snow` only supports `25519` and `448` as DH choices.

So MONAD cannot switch the existing `snow` implementation to secp256k1 by configuration alone.

### What looks viable instead

Another Rust Noise implementation, `noise-protocol`, is abstract over the DH primitive via a `DH` trait.

That trait requires a backend to define:

- private key type
- public key type
- DH output type
- key generation
- public key derivation
- DH operation
- a name string for the protocol identity

This matters because `noise-protocol` builds the protocol name using the DH backend's declared name, i.e. a custom secp256k1 backend would lead to an explicit protocol identity such as:

```text
Noise_NK_secp256k1_ChaChaPoly_BLAKE2s
```

That would be a real Noise-framework instantiation, not just a Noise-like ad hoc handshake.

### Why secp256k1 looks implementable there

The `k256` crate provides:

- secp256k1 ECDH
- SEC1 public key encoding/decoding
- 32-byte shared-secret output

Those are the core ingredients needed for a custom Noise DH backend.

### Practical meaning

If MONAD ever wants secp256k1 at the Noise layer, the plausible path is:

- stop relying on `snow` for this experiment
- use `noise-protocol`
- implement a secp256k1 `DH` backend on top of `k256`
- keep the rest of the handshake pattern semantics in the Noise framework

So unlike QUIC/TLS, the Noise side is not fundamentally blocked.

## Combined Conclusion

If the goal is "make every transport path use secp256k1 and remove the legacy
Ed25519/X25519 QUIC/plain-noise path", the practical split is:

- QUIC/TLS transport-layer secp256k1: effectively blocked with the current stack
- Noise transport-layer secp256k1: plausible with a different Noise implementation

So there is still no realistic near-term path to making QUIC/TLS itself fully
secp256k1-native while staying on the current standards-compliant QUIC stack.

## Decision Record

At the time of writing:

- MONAD's plain TCP transport uses secp256k1 Noise
- MONAD's QUIC transport supports both the legacy Ed25519/plain-noise path and a secp-authenticated path
- QUIC/TLS certificate authentication is still not secp256k1-native; the secp QUIC path relies on post-handshake attestation rather than a secp256k1 TLS certificate
- the remaining blocker to a fully secp-only transport story is therefore concentrated in QUIC/TLS, not the Noise layer

## Future Experiment Ideas

If someone wants to revisit this later, the most promising focused experiments are:

1. A small standalone `noise-protocol` + `k256` prototype implementing `Noise_NK_secp256k1_ChaChaPoly_BLAKE2s`
2. A transport roundtrip test proving client-pinned server authentication over secp256k1 at the Noise layer
3. A separate research spike on whether any usable nonstandard QUIC/TLS path exists for secp256k1 transport-layer auth

The third item should be treated as a substantially larger effort than the first two.
