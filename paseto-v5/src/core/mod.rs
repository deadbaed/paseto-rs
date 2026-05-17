#[cfg(feature = "decrypting")]
mod local;
#[cfg(feature = "verifying")]
mod public;

use paseto_core::version;

pub struct V5;

#[cfg(feature = "decrypting")]
#[derive(Clone)]
pub struct LocalKey([u8; 32]);

#[cfg(feature = "signing")]
pub struct SecretKey {
    seed: [u8; 32],
    signing: ml_dsa::SigningKey<ml_dsa::MlDsa87>,
}

#[cfg(feature = "verifying")]
#[derive(Clone)]
pub struct PublicKey(ml_dsa::VerifyingKey<ml_dsa::MlDsa87>);

#[cfg(feature = "signing")]
impl Clone for SecretKey {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            signing: self.signing.clone(),
        }
    }
}

impl version::Version for V5 {
    const HEADER: &'static str = "v5";
    const PASERK_HEADER: &'static str = "k5";
}
