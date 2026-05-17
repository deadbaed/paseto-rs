//! PASETO v5 (RustCrypto) — DRAFT, post-quantum.
//!
//! **WARNING**: PASETO v5 is an unstable draft (paseto-standard/paseto-spec#36).
//! No reference implementation or test vectors exist yet. The on-wire format
//! may change without notice. This crate is marked `publish = false` and is
//! published only for experimentation.
//!
//! v5.local is identical to v3.local (HKDF-SHA384 / AES-256-CTR / HMAC-SHA384).
//! v5.public uses ML-DSA-87 (FIPS-204) instead of ECDSA-P384.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

/// Low level implementation primitives.
pub mod core;

pub use paseto_core::PasetoError;

/// A token with publically readable data, but not yet verified
#[cfg(feature = "verifying")]
pub type SignedToken<M, F = ()> = paseto_core::SignedToken<core::V5, M, F>;
/// A token with secret data
#[cfg(feature = "decrypting")]
pub type EncryptedToken<M, F = ()> = paseto_core::EncryptedToken<core::V5, M, F>;
/// A [`SignedToken`] that has been verified
#[cfg(feature = "verifying")]
pub type UnsignedToken<M, F = ()> = paseto_core::UnsignedToken<core::V5, M, F>;
/// An [`EncryptedToken`] that has been decrypted
#[cfg(feature = "decrypting")]
pub type UnencryptedToken<M, F = ()> = paseto_core::UnencryptedToken<core::V5, M, F>;

/// Private key used for [`encryption`](UnencryptedToken::encrypt) and [`decryption`](EncryptedToken::decrypt)
#[cfg(feature = "decrypting")]
pub type LocalKey = paseto_core::LocalKey<core::V5>;
/// Public key used for signature [`verification`](SignedToken::verify)
#[cfg(feature = "verifying")]
pub type PublicKey = paseto_core::PublicKey<core::V5>;
/// Private key used for token [`signing`](UnsignedToken::sign)
#[cfg(feature = "signing")]
pub type SecretKey = paseto_core::SecretKey<core::V5>;
