use crate::cbor::CborValue;
use crate::cose::CoseError;
use coset::CborSerializable;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;

pub fn generate_hardware_backed_simulation() -> Result<Vec<u8>, CoseError> {
    let hw_private = SigningKey::random(&mut OsRng);
    let hw_public = VerifyingKey::from(&hw_private);

    // Simulate a secure element response
    let mut hw_cose_key = crate::bcc::public_key_to_cose_key(&hw_public)?;

    hw_cose_key.key_ops.insert(coset::RegisteredLabel::Assigned(
        coset::iana::KeyOperation::Sign,
    ));

    let key_bytes = hw_cose_key.to_vec().map_err(|_| CoseError::EncodingError)?;

    let exploit_payload = CborValue::Array(vec![
        CborValue::TextString("TEE_SIMULATION".to_string().into()),
        CborValue::ByteString(key_bytes.into()),
        CborValue::UnsignedInt(9999), // Fake TEE Version
    ]);

    // Convert to bytes via our cbor encoder method
    Ok(crate::cbor::encode(&exploit_payload))
}
