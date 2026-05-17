use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "signing")]
use ml_dsa::Keypair;
#[cfg(feature = "signing")]
use ml_dsa::signature::MultipartSigner;
use ml_dsa::signature::MultipartVerifier;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature};
use paseto_core::PasetoError;
use paseto_core::key::HasKey;
use paseto_core::pae::{WriteBytes, pre_auth_encode};
use paseto_core::version::Public;

#[cfg(feature = "signing")]
use super::SecretKey;
use super::{PublicKey, V5};

const ML_DSA_87_VK_SIZE: usize = 2592;
const ML_DSA_87_SIG_SIZE: usize = 4627;
#[cfg(feature = "signing")]
const ML_DSA_87_SEED_SIZE: usize = 32;

impl HasKey<Public> for V5 {
    type Key = PublicKey;

    fn decode(bytes: &[u8]) -> Result<PublicKey, PasetoError> {
        if bytes.len() != ML_DSA_87_VK_SIZE {
            return Err(PasetoError::InvalidKey);
        }
        let encoded =
            EncodedVerifyingKey::<MlDsa87>::try_from(bytes).map_err(|_| PasetoError::InvalidKey)?;
        Ok(PublicKey(ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded)))
    }

    fn encode(key: &PublicKey) -> Box<[u8]> {
        key.0.encode().as_slice().to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl HasKey<paseto_core::version::Secret> for V5 {
    type Key = SecretKey;

    fn decode(bytes: &[u8]) -> Result<SecretKey, PasetoError> {
        let seed: [u8; ML_DSA_87_SEED_SIZE] =
            bytes.try_into().map_err(|_| PasetoError::InvalidKey)?;
        let signing = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed.into());
        Ok(SecretKey { seed, signing })
    }

    fn encode(key: &SecretKey) -> Box<[u8]> {
        key.seed.to_vec().into_boxed_slice()
    }
}

#[cfg(feature = "signing")]
impl paseto_core::version::SealingVersion<Public> for V5 {
    fn unsealing_key(key: &SecretKey) -> PublicKey {
        PublicKey(key.signing.verifying_key().clone())
    }

    fn random() -> Result<SecretKey, PasetoError> {
        let mut seed = [0u8; ML_DSA_87_SEED_SIZE];
        getrandom::fill(&mut seed).map_err(|_| PasetoError::CryptoError)?;
        let signing = ml_dsa::SigningKey::<MlDsa87>::from_seed(&seed.into());
        Ok(SecretKey { seed, signing })
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
        let vk = key.signing.verifying_key();
        let vk_bytes = vk.encode();

        let pae = build_pae_public(vk_bytes.as_slice(), encoding, &payload, footer, aad);
        let signature: Signature<MlDsa87> = key.signing.multipart_sign(&[&pae]);

        payload.extend_from_slice(signature.encode().as_slice());
        Ok(payload)
    }
}

impl paseto_core::version::UnsealingVersion<Public> for V5 {
    type Nonce = [u8; 0];
    type Tag = [u8; ML_DSA_87_SIG_SIZE];

    fn unseal<'a>(
        key: &PublicKey,
        encoding: &'static str,
        payload: &'a mut [u8],
        footer: &[u8],
        aad: &[u8],
    ) -> Result<&'a [u8], PasetoError> {
        let (cleartext, tag) = payload
            .split_last_chunk::<ML_DSA_87_SIG_SIZE>()
            .ok_or(PasetoError::InvalidToken)?;
        let tag: &[u8; ML_DSA_87_SIG_SIZE] = tag;

        let encoded = EncodedSignature::<MlDsa87>::try_from(&tag[..])
            .map_err(|_| PasetoError::InvalidToken)?;
        let signature = Signature::<MlDsa87>::decode(&encoded).ok_or(PasetoError::InvalidToken)?;

        let vk_bytes = key.0.encode();
        let pae = build_pae_public(vk_bytes.as_slice(), encoding, cleartext, footer, aad);

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
    vk: &[u8],
    encoding: &'static str,
    cleartext: &[u8],
    footer: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    use paseto_core::key::KeyType;

    let mut buf = Vec::with_capacity(vk.len() + cleartext.len() + footer.len() + aad.len() + 64);
    pre_auth_encode(
        [
            &[vk],
            &[
                "v5".as_bytes(),
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
