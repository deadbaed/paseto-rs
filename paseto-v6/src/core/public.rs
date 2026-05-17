use alloc::boxed::Box;
use alloc::vec::Vec;

use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::Public;
use slh_dsa::Sha2_128s;
#[cfg(feature = "signing")]
use slh_dsa::signature::MultipartSigner;
use slh_dsa::signature::MultipartVerifier;

#[cfg(feature = "signing")]
use super::SecretKey;
use super::{PublicKey, V6};

const SLH_DSA_128S_VK_SIZE: usize = 32;
#[cfg(feature = "signing")]
const SLH_DSA_128S_SK_SIZE: usize = 64;
const SLH_DSA_128S_SIG_SIZE: usize = 7856;

impl HasKey<Public> for V6 {
    type Key = PublicKey;

    fn decode(bytes: &[u8]) -> Result<PublicKey, PasetoError> {
        if bytes.len() != SLH_DSA_128S_VK_SIZE {
            return Err(PasetoError::InvalidKey);
        }
        slh_dsa::VerifyingKey::<Sha2_128s>::try_from(bytes)
            .map(PublicKey)
            .map_err(|_| PasetoError::InvalidKey)
    }

    fn encode(key: &PublicKey) -> Box<[u8]> {
        key.0.to_bytes().as_slice().to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl HasKey<paseto_core::version::Secret> for V6 {
    type Key = SecretKey;

    fn decode(bytes: &[u8]) -> Result<SecretKey, PasetoError> {
        if bytes.len() != SLH_DSA_128S_SK_SIZE {
            return Err(PasetoError::InvalidKey);
        }
        slh_dsa::SigningKey::<Sha2_128s>::try_from(bytes)
            .map(SecretKey)
            .map_err(|_| PasetoError::InvalidKey)
    }

    fn encode(key: &SecretKey) -> Box<[u8]> {
        key.0.to_bytes().as_slice().to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl paseto_core::version::SealingVersion<Public> for V6 {
    fn unsealing_key(key: &SecretKey) -> PublicKey {
        use slh_dsa::signature::Keypair;
        PublicKey(key.0.verifying_key())
    }

    fn random() -> Result<SecretKey, PasetoError> {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        Ok(SecretKey(slh_dsa::SigningKey::<Sha2_128s>::new(&mut rng)))
    }

    fn nonce() -> Result<[u8; 0], PasetoError> {
        Ok([])
    }

    fn dangerous_seal_with_nonce(
        key: &SecretKey,
        encoding: &'static str,
        mut payload: Vec<u8>,
        footer: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasetoError> {
        let pae = build_pae_public(encoding, &payload, footer, aad);
        let signature: slh_dsa::Signature<Sha2_128s> = key.0.multipart_sign(&[&pae]);

        payload.extend_from_slice(signature.to_bytes().as_slice());
        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Public> for V6 {
    type Nonce = [u8; 0];
    type Tag = [u8; SLH_DSA_128S_SIG_SIZE];

    fn unseal<'a>(
        key: &PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let (cleartext, tag) = payload
            .split_last_chunk::<SLH_DSA_128S_SIG_SIZE>()
            .ok_or(PasetoError::InvalidToken)?;

        let signature = slh_dsa::Signature::<Sha2_128s>::try_from(&tag[..])
            .map_err(|_| PasetoError::InvalidToken)?;

        let pae = build_pae_public(encoding, cleartext, footer, aad);

        key.0
            .multipart_verify(&[&pae], &signature)
            .map_err(|_| PasetoError::CryptoError)?;

        Ok(cleartext)
    }
}

struct VecWriter<'a>(&'a mut Vec<u8>);
impl WriteBytes for VecWriter<'_> {
    fn write(&mut self, slice: &[u8]) {
        self.0.extend_from_slice(slice);
    }
}

fn build_pae_public(
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    use paseto_core::key::KeyType;

    let mut buf = Vec::with_capacity(cleartext.len() + footer.len() + aad.len() + 64);
    pre_auth_encode(
        [
            &[
                "v6".as_bytes(),
                encoding.as_bytes(),
                Public::HEADER.as_bytes(),
            ],
            &[cleartext],
            &[footer],
            &[aad],
        ],
        VecWriter(&mut buf),
    );
    buf
}
