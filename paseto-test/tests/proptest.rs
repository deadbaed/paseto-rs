use paseto_core::validation::NoValidation;
use paseto_core::version::{Local, Public, SealingVersion};
use paseto_core::{
    EncryptedToken, LocalKey, SecretKey, SignedToken, UnencryptedToken, UnsignedToken,
};
use paseto_test::Bytes;
use proptest::prelude::*;

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
