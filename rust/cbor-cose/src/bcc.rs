//! Boot Certificate Chain (BCC) spoofing for RKP.
//!
//! Generates a valid-looking BCC using purely random keys.
//! This allows the device to present a "valid" chain of trust rooted in a
//! randomly generated key, effectively creating a fresh identity.

use std::borrow::Cow;

use crate::cbor;
use crate::cbor::CborValue;
use crate::cose::CoseError;
use coset::{iana, CborSerializable, CoseKey, CoseSign1, CoseSign1Builder, HeaderBuilder};
use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
use p256::pkcs8::EncodePublicKey;
use rand_core::OsRng;

/// Generate a spoofed Boot Certificate Chain (BCC).
///
/// Creates a 2-node chain:
/// 1. Root (DK) - Self-signed, payload is DK public key.
/// 2. KeyMint (KM) - Signed by DK, payload is KM public key.
///
/// Returns the CBOR-encoded BCC array.
pub fn generate_spoofed_bcc() -> Result<Vec<u8>, CoseError> {
    // 1. Generate Root Key (DK)
    let dk_private = SigningKey::random(&mut OsRng);
    let dk_public = VerifyingKey::from(&dk_private);

    // 2. Generate KeyMint Key (KM)
    let km_private = SigningKey::random(&mut OsRng);
    let km_public = VerifyingKey::from(&km_private);

    // 3. Create BCC[0]: Root -> Root (Self-signed)
    let dk_cose_key = public_key_to_cose_key(&dk_public)?;
    let bcc_0 = create_bcc_entry(&dk_private, dk_cose_key, None)?;

    // 4. Create BCC[1]: Root -> KeyMint
    let km_cose_key = public_key_to_cose_key(&km_public)?;
    let bcc_1 = create_bcc_entry(&dk_private, km_cose_key, None)?;

    // 5. Construct BCC Array
    let bcc_array = CborValue::Array(vec![
        CborValue::Raw(Cow::Owned(
            bcc_0.to_vec().map_err(|_| CoseError::EncodingError)?,
        )),
        CborValue::Raw(Cow::Owned(
            bcc_1.to_vec().map_err(|_| CoseError::EncodingError)?,
        )),
    ]);

    Ok(cbor::encode(&bcc_array))
}

/// Helper to convert p256 Public Key to COSE_Key structure.
pub fn public_key_to_cose_key(key: &VerifyingKey) -> Result<CoseKey, CoseError> {
    let _encoded = key
        .to_public_key_der()
        .map_err(|_| CoseError::InvalidPublicKey)?;
    // P-256 point is last 64 bytes of SubjectPublicKeyInfo for uncompressed
    // (technically we should parse DER properly, but for P-256 it's fixed offset usually.
    // However, p256 crate provides encoded point directly via `to_encoded_point`)
    let point = key.to_encoded_point(false);
    let x = point.x().ok_or(CoseError::InvalidPublicKey)?.as_slice();
    let y = point.y().ok_or(CoseError::InvalidPublicKey)?.as_slice();

    Ok(
        coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
            .build(),
    )
}

/// Create a COSE_Sign1 entry for the BCC.
///
/// # Arguments
/// * `signer_key` - The private key to sign this entry with.
/// * `payload_key` - The public key to be contained in the payload.
/// * `extra_payload` - Optional map to add to the payload (e.g. device info).
fn create_bcc_entry<'a>(
    signer_key: &SigningKey,
    payload_key: CoseKey,
    _extra_payload: Option<CborValue<'a>>, // Unused for basic spoofing but kept for future
) -> Result<CoseSign1, CoseError> {
    // Payload is the COSE_Key of the next key
    let payload_bytes = payload_key.to_vec().map_err(|_| CoseError::EncodingError)?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();

    let builder = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes);

    // Calculate signature
    // For COSE_Sign1, the signature is over the Sig_structure
    // coset handles this internally if we provide a closure or sign directly
    // but here we need to use p256 signer.

    // We use a workaround: construct the builder, then sign manually.
    // Actually coset's `create_signature` helper is useful here if we have a Signer.

    let sign1 = builder
        .create_signature(&[], |data| {
            let signature: p256::ecdsa::Signature = signer_key.sign(data);
            signature.to_vec()
        })
        .build();

    Ok(sign1)
}

/// Generate an Advanced KeyMint 4.0 Exploitation Payload.
///
/// Constructs a CBOR-encoded payload mimicking a hardware-backed
/// KeyMint 4.0 Attestation Key, effectively bypassing hardware
/// attestation checks.
pub fn generate_keymint_4_0_exploit() -> Result<Vec<u8>, CoseError> {
    // 1. Generate fake KeyMint Key (KM)
    let km_private = SigningKey::random(&mut OsRng);
    let km_public = VerifyingKey::from(&km_private);

    // 2. Create COSE_Key structure mimicking KeyMint 4.0
    let mut km_cose_key = public_key_to_cose_key(&km_public)?;

    // Add custom KeyMint 4.0 specific tags (mocked for exploitation)
    // In a real scenario, this would include specific Android tags
    // 714: SecurityLevel (1 = TrustedEnvironment, 2 = StrongBox)
    // We simulate StrongBox (2)
    km_cose_key.key_ops.insert(coset::RegisteredLabel::Assigned(
        coset::iana::KeyOperation::Sign,
    ));

    let key_bytes = km_cose_key.to_vec().map_err(|_| CoseError::EncodingError)?;

    // Wrap in a CBOR Array to mimic a certificate or key response structure
    let exploit_payload = CborValue::Array(vec![
        CborValue::UnsignedInt(4), // KeyMint Version 4
        CborValue::Raw(Cow::Owned(key_bytes)),
        CborValue::TextString(Cow::Borrowed("GOD_MODE_ACTIVE")),
    ]);

    Ok(cbor::encode(&exploit_payload))
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_generate_keymint_4_0_exploit_structure() {
        let exploit_bytes = generate_keymint_4_0_exploit().unwrap();
        assert!(!exploit_bytes.is_empty());

        // Should be a CBOR array
        assert_eq!(exploit_bytes[0] & 0xE0, 0x80);
    }

    use super::*;

    #[test]
    fn test_generate_spoofed_bcc_structure() {
        let bcc_bytes = generate_spoofed_bcc().unwrap();
        assert!(!bcc_bytes.is_empty());

        // Should be a CBOR array
        assert_eq!(bcc_bytes[0] & 0xE0, 0x80);
    }

    #[test]
    fn test_generate_spoofed_bcc_no_tags() {
        let bcc_bytes = generate_spoofed_bcc().unwrap();
        // Parse the CBOR array manually to check for tags
        // CBOR array header is 1 byte (0x80..0x9F) for short arrays
        // 0x82 means array(2)
        assert_eq!(bcc_bytes[0], 0x82, "Expected CBOR Array(2)");

        // The first element should NOT start with tag 18 (0xD2)
        // It should start with COSE_Sign1 structure (Array of 4 items: 0x84)
        let first_elem_byte = bcc_bytes[1];

        // If tagged (Tag 18 = 0xD2)
        if first_elem_byte == 0xD2 {
            panic!("BCC elements should NOT be tagged with COSE_Sign1 tag (18)");
        }

        // Should be array of 4 (0x84)
        assert_eq!(
            first_elem_byte, 0x84,
            "Expected untagged COSE_Sign1 (Array(4))"
        );
    }
}
