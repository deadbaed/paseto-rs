use paseto_core::key::{HasKey, Key, KeyType};
use paseto_core::paserk::{
    IdVersion, KeyText, PasswordWrappedKey, PieWrapVersion, PieWrappedKey, PkeSealingVersion,
    PkeUnsealingVersion, SealedKey,
};
use paseto_core::validation::NoValidation;
use paseto_core::version::{Local, PkeSecret, Public, SealingVersion, Secret, Version};
use paseto_core::{
    EncryptedToken, LocalKey, PublicKey, SecretKey, SignedToken, UnencryptedToken, UnsignedToken,
};
use paseto_test::{Bytes, eq_keys};
use proptest::prelude::*;

/// Re-decode a key's raw bytes under a (potentially different) version and
/// key-type. Used to:
/// - transfer keys between equivalent implementations (e.g. v3 <-> v3-aws-lc)
/// - re-tag a signing key as its PKE counterpart (`Public` -> `PkePublic`)
///   for versions where the byte layout is identical.
fn reencode_key<VA, KA, VB, KB>(key: &Key<VA, KA>) -> Key<VB, KB>
where
    VA: HasKey<KA>,
    VB: HasKey<KB> + Version,
    KA: KeyType,
    KB: KeyType,
{
    let raw = key.expose_key();
    KeyText::<VB, KB>::from_raw_bytes(raw.as_raw_bytes())
        .try_into()
        .expect("caller guarantees raw byte layout matches target version/key-type")
}

fn local_roundtrip<V>(claims: Vec<u8>, footer: Vec<u8>, aad: Vec<u8>) -> Result<(), TestCaseError>
where
    V: SealingVersion<Local>,
{
    let key = LocalKey::<V>::random().unwrap();
    let token = UnencryptedToken::<V, _>::new(Bytes(claims.clone()))
        .with_footer(footer.clone())
        .encrypt_with_aad(&key, &aad)
        .unwrap();

    let decrypted = token
        .decrypt_with_aad(&key, &aad, &NoValidation::dangerous_no_validation())
        .unwrap();

    prop_assert_eq!(decrypted.claims.0, claims);
    prop_assert_eq!(decrypted.footer, footer);
    Ok(())
}

// v1 and v2 reject non-empty AAD by spec; v3 and v4 accept arbitrary bytes.
macro_rules! local_roundtrip_test {
    ($name:ident, $version:ty, aad) => {
        local_roundtrip_test!($name, $version, aad, cases = 64);
    };
    ($name:ident, $version:ty, no_aad) => {
        local_roundtrip_test!($name, $version, no_aad, cases = 64);
    };
    ($name:ident, $version:ty, aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 0..256),
                footer in prop::collection::vec(any::<u8>(), 0..64),
                aad in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                local_roundtrip::<$version>(claims, footer, aad)?;
            }
        }
    };
    ($name:ident, $version:ty, no_aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 0..256),
                footer in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                local_roundtrip::<$version>(claims, footer, Vec::new())?;
            }
        }
    };
}

local_roundtrip_test!(local_roundtrip_v1, paseto_v1::core::V1, no_aad);
local_roundtrip_test!(local_roundtrip_v2, paseto_v2::core::V2, no_aad);
local_roundtrip_test!(local_roundtrip_v3, paseto_v3::core::V3, aad);
local_roundtrip_test!(local_roundtrip_v3_aws_lc, paseto_v3_aws_lc::core::V3, aad);
local_roundtrip_test!(local_roundtrip_v4, paseto_v4::core::V4, aad);
local_roundtrip_test!(local_roundtrip_v4_sodium, paseto_v4_sodium::core::V4, aad);
local_roundtrip_test!(local_roundtrip_v5, paseto_v5::core::V5, aad);
local_roundtrip_test!(local_roundtrip_v6, paseto_v6::core::V6, aad);

fn public_roundtrip<V>(claims: Vec<u8>, footer: Vec<u8>, aad: Vec<u8>) -> Result<(), TestCaseError>
where
    V: SealingVersion<Public>,
{
    let secret = SecretKey::<V>::random().unwrap();
    let public = secret.public_key();

    let token = UnsignedToken::<V, _>::new(Bytes(claims.clone()))
        .with_footer(footer.clone())
        .sign_with_aad(&secret, &aad)
        .unwrap();

    let verified = token
        .verify_with_aad(&public, &aad, &NoValidation::dangerous_no_validation())
        .unwrap();

    prop_assert_eq!(verified.claims.0, claims);
    prop_assert_eq!(verified.footer, footer);
    Ok(())
}

macro_rules! public_roundtrip_test {
    ($name:ident, $version:ty, aad) => {
        public_roundtrip_test!($name, $version, aad, cases = 64);
    };
    ($name:ident, $version:ty, no_aad) => {
        public_roundtrip_test!($name, $version, no_aad, cases = 64);
    };
    ($name:ident, $version:ty, aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 0..256),
                footer in prop::collection::vec(any::<u8>(), 0..64),
                aad in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                public_roundtrip::<$version>(claims, footer, aad)?;
            }
        }
    };
    ($name:ident, $version:ty, no_aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 0..256),
                footer in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                public_roundtrip::<$version>(claims, footer, Vec::new())?;
            }
        }
    };
}

public_roundtrip_test!(public_roundtrip_v1, paseto_v1::core::V1, no_aad);
public_roundtrip_test!(public_roundtrip_v2, paseto_v2::core::V2, no_aad);
public_roundtrip_test!(public_roundtrip_v3, paseto_v3::core::V3, aad);
public_roundtrip_test!(public_roundtrip_v3_aws_lc, paseto_v3_aws_lc::core::V3, aad);
public_roundtrip_test!(public_roundtrip_v4, paseto_v4::core::V4, aad);
public_roundtrip_test!(public_roundtrip_v4_sodium, paseto_v4_sodium::core::V4, aad);
// ML-DSA-87 signing is ~5-10ms.
public_roundtrip_test!(public_roundtrip_v5, paseto_v5::core::V5, aad, cases = 32);
// SLH-DSA-SHA2-128s signing is ~1-3s.
public_roundtrip_test!(public_roundtrip_v6, paseto_v6::core::V6, aad, cases = 2);

fn local_wire_roundtrip<V>(
    claims: Vec<u8>,
    footer: Vec<u8>,
    aad: Vec<u8>,
) -> Result<(), TestCaseError>
where
    V: SealingVersion<Local>,
{
    let key = LocalKey::<V>::random().unwrap();
    let token = UnencryptedToken::<V, _>::new(Bytes(claims.clone()))
        .with_footer(footer.clone())
        .encrypt_with_aad(&key, &aad)
        .unwrap();

    let wire = token.to_string();
    let parsed: EncryptedToken<V, Bytes, Vec<u8>> = wire.parse().unwrap();

    let decrypted = parsed
        .decrypt_with_aad(&key, &aad, &NoValidation::dangerous_no_validation())
        .unwrap();

    prop_assert_eq!(decrypted.claims.0, claims);
    prop_assert_eq!(decrypted.footer, footer);
    Ok(())
}

fn public_wire_roundtrip<V>(
    claims: Vec<u8>,
    footer: Vec<u8>,
    aad: Vec<u8>,
) -> Result<(), TestCaseError>
where
    V: SealingVersion<Public>,
{
    let secret = SecretKey::<V>::random().unwrap();
    let public = secret.public_key();

    let token = UnsignedToken::<V, _>::new(Bytes(claims.clone()))
        .with_footer(footer.clone())
        .sign_with_aad(&secret, &aad)
        .unwrap();

    let wire = token.to_string();
    let parsed: SignedToken<V, Bytes, Vec<u8>> = wire.parse().unwrap();

    let verified = parsed
        .verify_with_aad(&public, &aad, &NoValidation::dangerous_no_validation())
        .unwrap();

    prop_assert_eq!(verified.claims.0, claims);
    prop_assert_eq!(verified.footer, footer);
    Ok(())
}

macro_rules! wire_roundtrip_test {
    ($name:ident, $body:expr, aad) => {
        wire_roundtrip_test!($name, $body, aad, cases = 64);
    };
    ($name:ident, $body:expr, no_aad) => {
        wire_roundtrip_test!($name, $body, no_aad, cases = 64);
    };
    ($name:ident, $body:expr, aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 0..256),
                footer in prop::collection::vec(any::<u8>(), 0..64),
                aad in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                $body(claims, footer, aad)?;
            }
        }
    };
    ($name:ident, $body:expr, no_aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 0..256),
                footer in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                $body(claims, footer, Vec::new())?;
            }
        }
    };
}

wire_roundtrip_test!(
    wire_local_v1,
    local_wire_roundtrip::<paseto_v1::core::V1>,
    no_aad
);
wire_roundtrip_test!(
    wire_local_v2,
    local_wire_roundtrip::<paseto_v2::core::V2>,
    no_aad
);
wire_roundtrip_test!(
    wire_local_v3,
    local_wire_roundtrip::<paseto_v3::core::V3>,
    aad
);
wire_roundtrip_test!(
    wire_local_v3_aws_lc,
    local_wire_roundtrip::<paseto_v3_aws_lc::core::V3>,
    aad
);
wire_roundtrip_test!(
    wire_local_v4,
    local_wire_roundtrip::<paseto_v4::core::V4>,
    aad
);
wire_roundtrip_test!(
    wire_local_v4_sodium,
    local_wire_roundtrip::<paseto_v4_sodium::core::V4>,
    aad
);
wire_roundtrip_test!(
    wire_local_v5,
    local_wire_roundtrip::<paseto_v5::core::V5>,
    aad
);
wire_roundtrip_test!(
    wire_local_v6,
    local_wire_roundtrip::<paseto_v6::core::V6>,
    aad
);

wire_roundtrip_test!(
    wire_public_v1,
    public_wire_roundtrip::<paseto_v1::core::V1>,
    no_aad
);
wire_roundtrip_test!(
    wire_public_v2,
    public_wire_roundtrip::<paseto_v2::core::V2>,
    no_aad
);
wire_roundtrip_test!(
    wire_public_v3,
    public_wire_roundtrip::<paseto_v3::core::V3>,
    aad
);
wire_roundtrip_test!(
    wire_public_v3_aws_lc,
    public_wire_roundtrip::<paseto_v3_aws_lc::core::V3>,
    aad
);
wire_roundtrip_test!(
    wire_public_v4,
    public_wire_roundtrip::<paseto_v4::core::V4>,
    aad
);
wire_roundtrip_test!(
    wire_public_v4_sodium,
    public_wire_roundtrip::<paseto_v4_sodium::core::V4>,
    aad
);
wire_roundtrip_test!(
    wire_public_v5,
    public_wire_roundtrip::<paseto_v5::core::V5>,
    aad,
    cases = 32
);
wire_roundtrip_test!(
    wire_public_v6,
    public_wire_roundtrip::<paseto_v6::core::V6>,
    aad,
    cases = 2
);

/// Locate the payload and footer regions in a serialized PASETO.
/// Wire format is `vN.{purpose}.{base64-payload}` with an optional `.{base64-footer}` suffix.
fn split_wire(wire: &str) -> (usize, usize, Option<(usize, usize)>) {
    let bytes = wire.as_bytes();
    let mut dot_count = 0;
    let mut payload_start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'.' {
            dot_count += 1;
            if dot_count == 2 {
                payload_start = i + 1;
                break;
            }
        }
    }
    let footer_dot = bytes[payload_start..]
        .iter()
        .position(|&b| b == b'.')
        .map(|i| payload_start + i);
    let payload_end = footer_dot.unwrap_or(bytes.len());
    let footer = footer_dot.map(|d| (d + 1, bytes.len()));
    (payload_start, payload_end, footer)
}

fn flip_byte(wire: &str, idx: usize) -> String {
    let mut bytes = wire.as_bytes().to_vec();
    bytes[idx] ^= 1;
    String::from_utf8(bytes).expect("base64 alphabet is ASCII so xor of low bit stays ASCII")
}

fn local_tamper<V>(
    claims: Vec<u8>,
    footer: Vec<u8>,
    aad: Vec<u8>,
    payload_idx: usize,
    footer_idx: usize,
) -> Result<(), TestCaseError>
where
    V: SealingVersion<Local>,
{
    let key = LocalKey::<V>::random().unwrap();
    let token = UnencryptedToken::<V, _>::new(Bytes(claims))
        .with_footer(footer)
        .encrypt_with_aad(&key, &aad)
        .unwrap();
    let wire = token.to_string();
    let (p_start, p_end, footer_region) = split_wire(&wire);

    let parse_unseal = |w: &str, k: &LocalKey<V>, a: &[u8]| -> Result<(), ()> {
        let parsed: EncryptedToken<V, Bytes, Vec<u8>> = w.parse().map_err(|_| ())?;
        parsed
            .decrypt_with_aad(k, a, &NoValidation::dangerous_no_validation())
            .map(|_| ())
            .map_err(|_| ())
    };

    let payload_flip_idx = p_start + (payload_idx % (p_end - p_start));
    prop_assert!(parse_unseal(&flip_byte(&wire, payload_flip_idx), &key, &aad).is_err());

    if let Some((f_start, f_end)) = footer_region.filter(|(s, e)| e > s) {
        let f_idx = f_start + (footer_idx % (f_end - f_start));
        prop_assert!(parse_unseal(&flip_byte(&wire, f_idx), &key, &aad).is_err());
    }

    let wrong_key = LocalKey::<V>::random().unwrap();
    prop_assert!(parse_unseal(&wire, &wrong_key, &aad).is_err());

    let mut wrong_aad = aad.clone();
    wrong_aad.push(0xAA);
    prop_assert!(parse_unseal(&wire, &key, &wrong_aad).is_err());

    let truncated = &wire[..wire.len() - 1];
    prop_assert!(parse_unseal(truncated, &key, &aad).is_err());

    Ok(())
}

fn public_tamper<V>(
    claims: Vec<u8>,
    footer: Vec<u8>,
    aad: Vec<u8>,
    payload_idx: usize,
    footer_idx: usize,
) -> Result<(), TestCaseError>
where
    V: SealingVersion<Public>,
{
    let secret = SecretKey::<V>::random().unwrap();
    let public = secret.public_key();

    let token = UnsignedToken::<V, _>::new(Bytes(claims))
        .with_footer(footer)
        .sign_with_aad(&secret, &aad)
        .unwrap();
    let wire = token.to_string();
    let (p_start, p_end, footer_region) = split_wire(&wire);

    let parse_verify = |w: &str, k: &PublicKey<V>, a: &[u8]| -> Result<(), ()> {
        let parsed: SignedToken<V, Bytes, Vec<u8>> = w.parse().map_err(|_| ())?;
        parsed
            .verify_with_aad(k, a, &NoValidation::dangerous_no_validation())
            .map(|_| ())
            .map_err(|_| ())
    };

    let payload_flip_idx = p_start + (payload_idx % (p_end - p_start));
    prop_assert!(parse_verify(&flip_byte(&wire, payload_flip_idx), &public, &aad).is_err());

    if let Some((f_start, f_end)) = footer_region.filter(|(s, e)| e > s) {
        let f_idx = f_start + (footer_idx % (f_end - f_start));
        prop_assert!(parse_verify(&flip_byte(&wire, f_idx), &public, &aad).is_err());
    }

    let wrong_secret = SecretKey::<V>::random().unwrap();
    let wrong_public = wrong_secret.public_key();
    prop_assert!(parse_verify(&wire, &wrong_public, &aad).is_err());

    let mut wrong_aad = aad.clone();
    wrong_aad.push(0xAA);
    prop_assert!(parse_verify(&wire, &public, &wrong_aad).is_err());

    let truncated = &wire[..wire.len() - 1];
    prop_assert!(parse_verify(truncated, &public, &aad).is_err());

    Ok(())
}

macro_rules! tamper_test {
    ($name:ident, $body:expr, aad) => {
        tamper_test!($name, $body, aad, cases = 64);
    };
    ($name:ident, $body:expr, no_aad) => {
        tamper_test!($name, $body, no_aad, cases = 64);
    };
    ($name:ident, $body:expr, aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 1..256),
                footer in prop::collection::vec(any::<u8>(), 1..64),
                aad in prop::collection::vec(any::<u8>(), 0..64),
                payload_idx in any::<usize>(),
                footer_idx in any::<usize>(),
            ) {
                $body(claims, footer, aad, payload_idx, footer_idx)?;
            }
        }
    };
    ($name:ident, $body:expr, no_aad, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 1..256),
                footer in prop::collection::vec(any::<u8>(), 1..64),
                payload_idx in any::<usize>(),
                footer_idx in any::<usize>(),
            ) {
                $body(claims, footer, Vec::new(), payload_idx, footer_idx)?;
            }
        }
    };
}

tamper_test!(tamper_local_v1, local_tamper::<paseto_v1::core::V1>, no_aad);
tamper_test!(tamper_local_v2, local_tamper::<paseto_v2::core::V2>, no_aad);
tamper_test!(tamper_local_v3, local_tamper::<paseto_v3::core::V3>, aad);
tamper_test!(
    tamper_local_v3_aws_lc,
    local_tamper::<paseto_v3_aws_lc::core::V3>,
    aad
);
tamper_test!(tamper_local_v4, local_tamper::<paseto_v4::core::V4>, aad);
tamper_test!(
    tamper_local_v4_sodium,
    local_tamper::<paseto_v4_sodium::core::V4>,
    aad
);
tamper_test!(tamper_local_v5, local_tamper::<paseto_v5::core::V5>, aad);
tamper_test!(tamper_local_v6, local_tamper::<paseto_v6::core::V6>, aad);

tamper_test!(
    tamper_public_v1,
    public_tamper::<paseto_v1::core::V1>,
    no_aad
);
tamper_test!(
    tamper_public_v2,
    public_tamper::<paseto_v2::core::V2>,
    no_aad
);
tamper_test!(tamper_public_v3, public_tamper::<paseto_v3::core::V3>, aad);
tamper_test!(
    tamper_public_v3_aws_lc,
    public_tamper::<paseto_v3_aws_lc::core::V3>,
    aad
);
tamper_test!(tamper_public_v4, public_tamper::<paseto_v4::core::V4>, aad);
tamper_test!(
    tamper_public_v4_sodium,
    public_tamper::<paseto_v4_sodium::core::V4>,
    aad
);
tamper_test!(
    tamper_public_v5,
    public_tamper::<paseto_v5::core::V5>,
    aad,
    cases = 32
);
tamper_test!(
    tamper_public_v6,
    public_tamper::<paseto_v6::core::V6>,
    aad,
    cases = 2
);

fn local_cross_impl<VA, VB>(
    claims: Vec<u8>,
    footer: Vec<u8>,
    aad: Vec<u8>,
) -> Result<(), TestCaseError>
where
    VA: SealingVersion<Local>,
    VB: SealingVersion<Local>,
{
    let key_a = LocalKey::<VA>::random().unwrap();
    let key_b: LocalKey<VB> = reencode_key(&key_a);

    let token = UnencryptedToken::<VA, _>::new(Bytes(claims.clone()))
        .with_footer(footer.clone())
        .encrypt_with_aad(&key_a, &aad)
        .unwrap();
    let wire = token.to_string();

    let parsed: EncryptedToken<VB, Bytes, Vec<u8>> = wire.parse().unwrap();
    let decrypted = parsed
        .decrypt_with_aad(&key_b, &aad, &NoValidation::dangerous_no_validation())
        .unwrap();

    prop_assert_eq!(decrypted.claims.0, claims);
    prop_assert_eq!(decrypted.footer, footer);
    Ok(())
}

fn public_cross_impl<VA, VB>(
    claims: Vec<u8>,
    footer: Vec<u8>,
    aad: Vec<u8>,
) -> Result<(), TestCaseError>
where
    VA: SealingVersion<Public>,
    VB: SealingVersion<Public>,
{
    let secret_a = SecretKey::<VA>::random().unwrap();
    let public_a = secret_a.public_key();
    let public_b: PublicKey<VB> = reencode_key(&public_a);

    let token = UnsignedToken::<VA, _>::new(Bytes(claims.clone()))
        .with_footer(footer.clone())
        .sign_with_aad(&secret_a, &aad)
        .unwrap();
    let wire = token.to_string();

    let parsed: SignedToken<VB, Bytes, Vec<u8>> = wire.parse().unwrap();
    let verified = parsed
        .verify_with_aad(&public_b, &aad, &NoValidation::dangerous_no_validation())
        .unwrap();

    prop_assert_eq!(&verified.claims.0, &claims);
    prop_assert_eq!(&verified.footer, &footer);

    let secret_b: SecretKey<VB> = reencode_key(&secret_a);
    let token_b = UnsignedToken::<VB, _>::new(Bytes(claims.clone()))
        .with_footer(footer.clone())
        .sign_with_aad(&secret_b, &aad)
        .unwrap();
    let wire_b = token_b.to_string();
    let parsed_back: SignedToken<VA, Bytes, Vec<u8>> = wire_b.parse().unwrap();
    let verified_back = parsed_back
        .verify_with_aad(&public_a, &aad, &NoValidation::dangerous_no_validation())
        .unwrap();
    prop_assert_eq!(verified_back.claims.0, claims);
    prop_assert_eq!(verified_back.footer, footer);

    Ok(())
}

macro_rules! cross_impl_test {
    ($name:ident, $body:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
            #[test]
            fn $name(
                claims in prop::collection::vec(any::<u8>(), 0..256),
                footer in prop::collection::vec(any::<u8>(), 0..64),
                aad in prop::collection::vec(any::<u8>(), 0..64),
            ) {
                $body(claims, footer, aad)?;
            }
        }
    };
}

cross_impl_test!(
    cross_local_v3_to_aws_lc,
    local_cross_impl::<paseto_v3::core::V3, paseto_v3_aws_lc::core::V3>
);
cross_impl_test!(
    cross_local_aws_lc_to_v3,
    local_cross_impl::<paseto_v3_aws_lc::core::V3, paseto_v3::core::V3>
);
cross_impl_test!(
    cross_local_v4_to_sodium,
    local_cross_impl::<paseto_v4::core::V4, paseto_v4_sodium::core::V4>
);
cross_impl_test!(
    cross_local_sodium_to_v4,
    local_cross_impl::<paseto_v4_sodium::core::V4, paseto_v4::core::V4>
);

cross_impl_test!(
    cross_public_v3_to_aws_lc,
    public_cross_impl::<paseto_v3::core::V3, paseto_v3_aws_lc::core::V3>
);
cross_impl_test!(
    cross_public_aws_lc_to_v3,
    public_cross_impl::<paseto_v3_aws_lc::core::V3, paseto_v3::core::V3>
);
cross_impl_test!(
    cross_public_v4_to_sodium,
    public_cross_impl::<paseto_v4::core::V4, paseto_v4_sodium::core::V4>
);
cross_impl_test!(
    cross_public_sodium_to_v4,
    public_cross_impl::<paseto_v4_sodium::core::V4, paseto_v4::core::V4>
);

fn keytext_roundtrip<V, K>(key: Key<V, K>) -> Result<(), TestCaseError>
where
    V: HasKey<K>,
    K: KeyType,
{
    let text = key.expose_key();
    let s = text.to_string();
    let parsed: KeyText<V, K> = s.parse().unwrap();
    prop_assert_eq!(parsed.as_raw_bytes(), text.as_raw_bytes());

    let recovered: Key<V, K> = parsed.try_into().unwrap();
    prop_assert!(eq_keys(&key, &recovered));
    Ok(())
}

macro_rules! keytext_local_test {
    ($name:ident, $version:ty) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
            #[test]
            fn $name(_seed in any::<u64>()) {
                let key = LocalKey::<$version>::random().unwrap();
                keytext_roundtrip::<$version, Local>(key)?;
            }
        }
    };
}

macro_rules! keytext_secret_test {
    ($name:ident, $version:ty, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(_seed in any::<u64>()) {
                let secret = SecretKey::<$version>::random().unwrap();
                let public = secret.public_key();
                keytext_roundtrip::<$version, Public>(public)?;
                keytext_roundtrip::<$version, Secret>(secret)?;
            }
        }
    };
}

keytext_local_test!(keytext_local_v1, paseto_v1::core::V1);
keytext_local_test!(keytext_local_v2, paseto_v2::core::V2);
keytext_local_test!(keytext_local_v3, paseto_v3::core::V3);
keytext_local_test!(keytext_local_v3_aws_lc, paseto_v3_aws_lc::core::V3);
keytext_local_test!(keytext_local_v4, paseto_v4::core::V4);
keytext_local_test!(keytext_local_v4_sodium, paseto_v4_sodium::core::V4);
keytext_local_test!(keytext_local_v5, paseto_v5::core::V5);
keytext_local_test!(keytext_local_v6, paseto_v6::core::V6);

// v1 RSA keygen is slow; cap cases.
keytext_secret_test!(keytext_secret_v1, paseto_v1::core::V1, cases = 4);
keytext_secret_test!(keytext_secret_v2, paseto_v2::core::V2, cases = 64);
keytext_secret_test!(keytext_secret_v3, paseto_v3::core::V3, cases = 64);
keytext_secret_test!(
    keytext_secret_v3_aws_lc,
    paseto_v3_aws_lc::core::V3,
    cases = 64
);
keytext_secret_test!(keytext_secret_v4, paseto_v4::core::V4, cases = 64);
keytext_secret_test!(
    keytext_secret_v4_sodium,
    paseto_v4_sodium::core::V4,
    cases = 64
);
keytext_secret_test!(keytext_secret_v5, paseto_v5::core::V5, cases = 32);
// SLH-DSA-SHA2-128s keygen is fast (~milliseconds), but signing isn't.
keytext_secret_test!(keytext_secret_v6, paseto_v6::core::V6, cases = 32);

fn keyid_deterministic<V, K>(key: Key<V, K>) -> Result<(), TestCaseError>
where
    V: IdVersion + HasKey<K>,
    K: KeyType,
{
    let id1 = key.id();
    let text = key.expose_key();
    let bytes = text.as_raw_bytes().to_vec();
    let key2: Key<V, K> = KeyText::<V, K>::from_raw_bytes(&bytes).try_into().unwrap();
    let id2 = key2.id();
    prop_assert_eq!(id1.as_bytes(), id2.as_bytes());
    Ok(())
}

macro_rules! keyid_local_test {
    ($name:ident, $version:ty) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
            #[test]
            fn $name(_seed in any::<u64>()) {
                let key = LocalKey::<$version>::random().unwrap();
                keyid_deterministic::<$version, Local>(key)?;
            }
        }
    };
}

keyid_local_test!(keyid_v1, paseto_v1::core::V1);
keyid_local_test!(keyid_v2, paseto_v2::core::V2);
keyid_local_test!(keyid_v3, paseto_v3::core::V3);
keyid_local_test!(keyid_v3_aws_lc, paseto_v3_aws_lc::core::V3);
keyid_local_test!(keyid_v4, paseto_v4::core::V4);
keyid_local_test!(keyid_v4_sodium, paseto_v4_sodium::core::V4);
keyid_local_test!(keyid_v5, paseto_v5::core::V5);
keyid_local_test!(keyid_v6, paseto_v6::core::V6);

fn pke_roundtrip<V>() -> Result<(), TestCaseError>
where
    V: PkeSealingVersion + PkeUnsealingVersion + SealingVersion<Local>,
    <V as HasKey<Local>>::Key: Clone,
{
    let pdk = LocalKey::<V>::random().unwrap();

    let pke_sec = Key::<V, PkeSecret>::random().unwrap();
    let pke_pub = pke_sec.public_key();

    let sealed = pdk.clone().seal(&pke_pub).unwrap();
    let recovered = sealed.unseal(&pke_sec).unwrap();
    prop_assert!(eq_keys(&pdk, &recovered));

    let sealed = pdk.clone().seal(&pke_pub).unwrap();
    let s = sealed.to_string();
    let parsed: SealedKey<V> = s.parse().unwrap();
    let recovered2 = parsed.unseal(&pke_sec).unwrap();
    prop_assert!(eq_keys(&pdk, &recovered2));
    Ok(())
}

macro_rules! pke_test {
    ($name:ident, $version:ty, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(_seed in any::<u64>()) {
                pke_roundtrip::<$version>()?;
            }
        }
    };
}

// v1 PKE uses RSA-OAEP-4096 keys distinct from RSA-PSS-2048 signing keys; keygen is slow.
pke_test!(pke_v1, paseto_v1::core::V1, cases = 1);
pke_test!(pke_v2, paseto_v2::core::V2, cases = 32);
pke_test!(pke_v3, paseto_v3::core::V3, cases = 32);
pke_test!(pke_v3_aws_lc, paseto_v3_aws_lc::core::V3, cases = 32);
pke_test!(pke_v4, paseto_v4::core::V4, cases = 32);
pke_test!(pke_v4_sodium, paseto_v4_sodium::core::V4, cases = 32);
pke_test!(pke_v5, paseto_v5::core::V5, cases = 8);
pke_test!(pke_v6, paseto_v6::core::V6, cases = 8);

fn pie_local_roundtrip<V>() -> Result<(), TestCaseError>
where
    V: PieWrapVersion + SealingVersion<Local>,
    <V as HasKey<Local>>::Key: Clone,
{
    let target = LocalKey::<V>::random().unwrap();
    let wrapping = LocalKey::<V>::random().unwrap();

    let wrapped = target.clone().wrap_pie(&wrapping).unwrap();
    let s = wrapped.to_string();
    let parsed: PieWrappedKey<V, Local> = s.parse().unwrap();
    let unwrapped = parsed.unwrap(&wrapping).unwrap();
    prop_assert!(eq_keys(&target, &unwrapped));
    Ok(())
}

fn pie_secret_roundtrip<V>() -> Result<(), TestCaseError>
where
    V: PieWrapVersion + SealingVersion<Local> + SealingVersion<Public> + HasKey<Secret>,
    <V as HasKey<Secret>>::Key: Clone,
{
    let secret = SecretKey::<V>::random().unwrap();
    let wrapping = LocalKey::<V>::random().unwrap();

    let wrapped = secret.clone().wrap_pie(&wrapping).unwrap();
    let s = wrapped.to_string();
    let parsed: PieWrappedKey<V, Secret> = s.parse().unwrap();
    let unwrapped = parsed.unwrap(&wrapping).unwrap();
    prop_assert!(eq_keys(&secret, &unwrapped));
    Ok(())
}

macro_rules! pie_test {
    ($name:ident, $body:expr, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(_seed in any::<u64>()) {
                $body()?;
            }
        }
    };
}

pie_test!(
    pie_local_v1,
    pie_local_roundtrip::<paseto_v1::core::V1>,
    cases = 64
);
pie_test!(
    pie_local_v2,
    pie_local_roundtrip::<paseto_v2::core::V2>,
    cases = 64
);
pie_test!(
    pie_local_v3,
    pie_local_roundtrip::<paseto_v3::core::V3>,
    cases = 64
);
pie_test!(
    pie_local_v3_aws_lc,
    pie_local_roundtrip::<paseto_v3_aws_lc::core::V3>,
    cases = 64
);
pie_test!(
    pie_local_v4,
    pie_local_roundtrip::<paseto_v4::core::V4>,
    cases = 64
);
pie_test!(
    pie_local_v4_sodium,
    pie_local_roundtrip::<paseto_v4_sodium::core::V4>,
    cases = 64
);
pie_test!(
    pie_local_v5,
    pie_local_roundtrip::<paseto_v5::core::V5>,
    cases = 64
);
pie_test!(
    pie_local_v6,
    pie_local_roundtrip::<paseto_v6::core::V6>,
    cases = 64
);

// v1 SecretKey::random performs RSA-2048 keygen; cap cases.
pie_test!(
    pie_secret_v1,
    pie_secret_roundtrip::<paseto_v1::core::V1>,
    cases = 4
);
pie_test!(
    pie_secret_v2,
    pie_secret_roundtrip::<paseto_v2::core::V2>,
    cases = 64
);
pie_test!(
    pie_secret_v3,
    pie_secret_roundtrip::<paseto_v3::core::V3>,
    cases = 64
);
pie_test!(
    pie_secret_v3_aws_lc,
    pie_secret_roundtrip::<paseto_v3_aws_lc::core::V3>,
    cases = 64
);
pie_test!(
    pie_secret_v4,
    pie_secret_roundtrip::<paseto_v4::core::V4>,
    cases = 64
);
pie_test!(
    pie_secret_v4_sodium,
    pie_secret_roundtrip::<paseto_v4_sodium::core::V4>,
    cases = 64
);
pie_test!(
    pie_secret_v5,
    pie_secret_roundtrip::<paseto_v5::core::V5>,
    cases = 16
);
pie_test!(
    pie_secret_v6,
    pie_secret_roundtrip::<paseto_v6::core::V6>,
    cases = 16
);

/// Minimum-cost PBKW params per version, encoded as the wire-bytes layout
/// of the version's `Params` zerocopy struct.
///
/// PBKDF2 (v1, v3, v3-aws-lc): `iterations: U32be` -> 4 bytes, value 1.
/// Argon2id (v2, v4, v4-sodium): `mem: U64be, time: U32be, para: U32be` ->
/// 16 bytes; mem=8192 (argon2 minimum), time=1, para=1.
trait MinPwParams: paseto_core::paserk::PwWrapVersion
where
    Self::Params: zerocopy::FromBytes,
{
    const MIN_BYTES: &'static [u8];

    fn min_params() -> Self::Params {
        <Self::Params as zerocopy::FromBytes>::read_from_bytes(Self::MIN_BYTES)
            .expect("min params byte layout matches version Params struct")
    }
}

impl MinPwParams for paseto_v1::core::V1 {
    const MIN_BYTES: &'static [u8] = &[0, 0, 0, 1];
}
impl MinPwParams for paseto_v3::core::V3 {
    const MIN_BYTES: &'static [u8] = &[0, 0, 0, 1];
}
impl MinPwParams for paseto_v3_aws_lc::core::V3 {
    const MIN_BYTES: &'static [u8] = &[0, 0, 0, 1];
}
impl MinPwParams for paseto_v2::core::V2 {
    // mem = 8192 bytes (argon2 minimum), time = 1, para = 1
    const MIN_BYTES: &'static [u8] = &[
        0, 0, 0, 0, 0, 0, 0x20, 0, // mem: U64be = 8192
        0, 0, 0, 1, // time: U32be = 1
        0, 0, 0, 1, // para: U32be = 1
    ];
}
impl MinPwParams for paseto_v4::core::V4 {
    const MIN_BYTES: &'static [u8] = &[0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 1, 0, 0, 0, 1];
}
impl MinPwParams for paseto_v4_sodium::core::V4 {
    const MIN_BYTES: &'static [u8] = &[0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 1, 0, 0, 0, 1];
}
// v5 uses PBKDF2-HMAC-SHA384 (same params layout as v3).
impl MinPwParams for paseto_v5::core::V5 {
    const MIN_BYTES: &'static [u8] = &[0, 0, 0, 1];
}
// v6 uses Argon2id (same params layout as v4).
impl MinPwParams for paseto_v6::core::V6 {
    const MIN_BYTES: &'static [u8] = &[0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 1, 0, 0, 0, 1];
}

fn pbkw_local_roundtrip<V>(pw: Vec<u8>, alt_pw: Vec<u8>) -> Result<(), TestCaseError>
where
    V: MinPwParams + SealingVersion<Local>,
    V::Params: zerocopy::FromBytes,
    <V as HasKey<Local>>::Key: Clone,
{
    prop_assume!(pw != alt_pw);
    let key = LocalKey::<V>::random().unwrap();
    let params = V::min_params();

    let wrapped = key.clone().password_wrap_with_params(&pw, &params).unwrap();
    let s = wrapped.to_string();
    let parsed: PasswordWrappedKey<V, Local> = s.parse().unwrap();
    let unwrapped = parsed.unwrap(&pw).unwrap();
    prop_assert!(eq_keys(&key, &unwrapped));

    let wrong = key.password_wrap_with_params(&pw, &params).unwrap();
    prop_assert!(wrong.unwrap(&alt_pw).is_err());
    Ok(())
}

fn pbkw_secret_roundtrip<V>(pw: Vec<u8>, alt_pw: Vec<u8>) -> Result<(), TestCaseError>
where
    V: MinPwParams + SealingVersion<Public> + HasKey<Secret>,
    V::Params: zerocopy::FromBytes,
    <V as HasKey<Secret>>::Key: Clone,
{
    prop_assume!(pw != alt_pw);
    let secret = SecretKey::<V>::random().unwrap();
    let params = V::min_params();

    let wrapped = secret
        .clone()
        .password_wrap_with_params(&pw, &params)
        .unwrap();
    let s = wrapped.to_string();
    let parsed: PasswordWrappedKey<V, Secret> = s.parse().unwrap();
    let unwrapped = parsed.unwrap(&pw).unwrap();
    prop_assert!(eq_keys(&secret, &unwrapped));

    let wrong = secret.password_wrap_with_params(&pw, &params).unwrap();
    prop_assert!(wrong.unwrap(&alt_pw).is_err());
    Ok(())
}

macro_rules! pbkw_test {
    ($name:ident, $body:expr, cases = $cases:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases($cases))]
            #[test]
            fn $name(
                pw in prop::collection::vec(any::<u8>(), 1..32),
                alt_pw in prop::collection::vec(any::<u8>(), 1..32),
            ) {
                $body(pw, alt_pw)?;
            }
        }
    };
}

pbkw_test!(
    pbkw_local_v1,
    pbkw_local_roundtrip::<paseto_v1::core::V1>,
    cases = 16
);
pbkw_test!(
    pbkw_local_v2,
    pbkw_local_roundtrip::<paseto_v2::core::V2>,
    cases = 16
);
pbkw_test!(
    pbkw_local_v3,
    pbkw_local_roundtrip::<paseto_v3::core::V3>,
    cases = 16
);
pbkw_test!(
    pbkw_local_v3_aws_lc,
    pbkw_local_roundtrip::<paseto_v3_aws_lc::core::V3>,
    cases = 16
);
pbkw_test!(
    pbkw_local_v4,
    pbkw_local_roundtrip::<paseto_v4::core::V4>,
    cases = 16
);
pbkw_test!(
    pbkw_local_v4_sodium,
    pbkw_local_roundtrip::<paseto_v4_sodium::core::V4>,
    cases = 16
);
pbkw_test!(
    pbkw_local_v5,
    pbkw_local_roundtrip::<paseto_v5::core::V5>,
    cases = 16
);
pbkw_test!(
    pbkw_local_v6,
    pbkw_local_roundtrip::<paseto_v6::core::V6>,
    cases = 16
);

// v1 RSA-2048 keygen is the bottleneck here, not pbkw itself.
pbkw_test!(
    pbkw_secret_v1,
    pbkw_secret_roundtrip::<paseto_v1::core::V1>,
    cases = 4
);
pbkw_test!(
    pbkw_secret_v2,
    pbkw_secret_roundtrip::<paseto_v2::core::V2>,
    cases = 16
);
pbkw_test!(
    pbkw_secret_v3,
    pbkw_secret_roundtrip::<paseto_v3::core::V3>,
    cases = 16
);
pbkw_test!(
    pbkw_secret_v3_aws_lc,
    pbkw_secret_roundtrip::<paseto_v3_aws_lc::core::V3>,
    cases = 16
);
pbkw_test!(
    pbkw_secret_v4,
    pbkw_secret_roundtrip::<paseto_v4::core::V4>,
    cases = 16
);
pbkw_test!(
    pbkw_secret_v4_sodium,
    pbkw_secret_roundtrip::<paseto_v4_sodium::core::V4>,
    cases = 16
);
pbkw_test!(
    pbkw_secret_v5,
    pbkw_secret_roundtrip::<paseto_v5::core::V5>,
    cases = 16
);
pbkw_test!(
    pbkw_secret_v6,
    pbkw_secret_roundtrip::<paseto_v6::core::V6>,
    cases = 16
);
