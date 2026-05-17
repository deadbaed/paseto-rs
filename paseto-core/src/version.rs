//! Various helper traits

use alloc::vec::Vec;

use crate::PasetoError;
use crate::key::{HasKey, KeyInner, KeyType, SealingKey};
use crate::sealed::Sealed;

/// An implementation of the PASETO cryptographic schemes.
pub trait Version: Send + Sync + Sized + 'static {
    /// Header for PASETO
    const HEADER: &'static str;
    /// Header for PASERK
    const PASERK_HEADER: &'static str = "k3";
}

type SealingKeyInner<V, P> = KeyInner<V, <P as Purpose>::SealingKey>;

/// This PASETO implementation can decrypt/verify tokens.
pub trait UnsealingVersion<P: Purpose>: HasKey<P> {
    /// Per-message random input.
    type Nonce: AsRef<[u8]>;

    /// Authenticator appended to the payload: MAC tag for [`Local`] or signature for [`Public`].
    type Tag: AsRef<[u8]>;

    /// Do not call this method directly. Use [`SealedToken::unseal`](crate::tokens::SealedToken::unseal) instead.
    ///
    /// `payload` arrives as `nonce || sealed(plaintext) || tag`. The implementer unseals in place
    /// and returns the plaintext.
    fn unseal<'a>(
        key: &KeyInner<Self, P>,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError>;
}

/// This PASETO implementation can sign/encrypt tokens.
pub trait SealingVersion<P: Purpose>: UnsealingVersion<P> + HasKey<P::SealingKey> {
    /// Generate the key that can unseal the tokens this key will seal.
    fn unsealing_key(key: &SealingKeyInner<Self, P>) -> KeyInner<Self, P>;

    /// Generate a random key
    fn random() -> Result<SealingKeyInner<Self, P>, PasetoError>;

    /// Do not call this method directly.
    fn nonce() -> Result<Self::Nonce, PasetoError>;

    /// Do not call this method directly. Use [`UnsealedToken::seal`](crate::tokens::UnsealedToken::seal) instead.
    ///
    /// `payload` arrives as `nonce || plaintext`. The implementer seals in place
    /// and appends the [`tag`](Self::Tag).
    fn dangerous_seal_with_nonce(
        key: &SealingKeyInner<Self, P>,
        encoding: &'static str,
        payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError>;
}

/// Marks a key as secret
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Secret;
/// Marks a key as public and tokens as signed
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Public;
/// Marks a key as symmetric and tokens as encrypted
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Local;
/// Marks a key as secret for unsealing keys
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PkeSecret;
/// Marks a key as public for sealing keys
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PkePublic;

impl Sealed for Secret {}
impl Sealed for Public {}
impl Sealed for Local {}

impl Sealed for PkeSecret {}
impl Sealed for PkePublic {}

/// A marker for [`Public`] and [`Local`], used for token encodings.
pub trait Purpose: KeyType {
    /// The key used to sign/encrypt tokens.
    type SealingKey: SealingKey;
}

impl Purpose for Public {
    type SealingKey = Secret;
}

impl Purpose for Local {
    type SealingKey = Local;
}
