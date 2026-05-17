use paseto_core::key::{HasKey, Key, KeyType};
use paseto_core::paserk::KeyText;
use paseto_core::validation::NoValidation;
use paseto_core::version::{Local, Public, SealingVersion, Version};
use paseto_core::{
    EncryptedToken, LocalKey, PublicKey, SecretKey, SignedToken, UnencryptedToken, UnsignedToken,
};
use paseto_test::Bytes;
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
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
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
    ($name:ident, $version:ty, no_aad) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
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
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
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
    ($name:ident, $version:ty, no_aad) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
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
    ($name:ident, $body:expr, no_aad) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
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
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
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
    ($name:ident, $body:expr, no_aad) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
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
