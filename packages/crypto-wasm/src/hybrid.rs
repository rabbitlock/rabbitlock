use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

use crate::{crypto, pq};

pub const HYBRID_MAGIC: &[u8; 4] = b"RLK1";
pub const HYBRID_VERSION: u8 = 1;
pub const PAYLOAD_TYPE_FILE: u8 = 1;
pub const PAYLOAD_TYPE_DATA_KEY: u8 = 2;

pub const INFO_FILE: &[u8] = b"rabbitlock-file-v1";
pub const INFO_DATA_KEY: &[u8] = b"rabbitlock-sops-data-key-v1";

const IV_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const HEADER_SIZE: usize = 4 + 1 + 1 + pq::HYBRID_CIPHERTEXT_SIZE + IV_SIZE + TAG_SIZE;

pub struct HybridPayload {
    pub payload_type: u8,
    pub kem_ct: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

fn derive_symmetric_key(shared_secret: &[u8], info: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(okm)
}

pub fn pack_payload(
    payload_type: u8,
    kem_ct: &[u8],
    iv: &[u8],
    tag: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    if kem_ct.len() != pq::HYBRID_CIPHERTEXT_SIZE {
        return Err(format!(
            "Invalid KEM ciphertext length: expected {}, got {}",
            pq::HYBRID_CIPHERTEXT_SIZE,
            kem_ct.len()
        ));
    }
    if iv.len() != IV_SIZE {
        return Err(format!(
            "Invalid IV length: expected {}, got {}",
            IV_SIZE,
            iv.len()
        ));
    }
    if tag.len() != TAG_SIZE {
        return Err(format!(
            "Invalid tag length: expected {}, got {}",
            TAG_SIZE,
            tag.len()
        ));
    }

    let mut out = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    out.extend_from_slice(HYBRID_MAGIC);
    out.push(HYBRID_VERSION);
    out.push(payload_type);
    out.extend_from_slice(kem_ct);
    out.extend_from_slice(iv);
    out.extend_from_slice(tag);
    out.extend_from_slice(ciphertext);
    Ok(out)
}

pub fn unpack_payload(data: &[u8]) -> Result<HybridPayload, String> {
    if data.len() < HEADER_SIZE {
        return Err("Hybrid payload is too short".to_string());
    }

    if &data[..4] != HYBRID_MAGIC {
        return Err("Invalid hybrid payload magic".to_string());
    }

    let version = data[4];
    if version != HYBRID_VERSION {
        return Err(format!(
            "Unsupported hybrid payload version: {}",
            version
        ));
    }

    let payload_type = data[5];
    let mut offset = 6;

    let kem_ct_end = offset + pq::HYBRID_CIPHERTEXT_SIZE;
    let kem_ct = data[offset..kem_ct_end].to_vec();
    offset = kem_ct_end;

    let iv_end = offset + IV_SIZE;
    let iv = data[offset..iv_end].to_vec();
    offset = iv_end;

    let tag_end = offset + TAG_SIZE;
    let tag = data[offset..tag_end].to_vec();
    offset = tag_end;

    let ciphertext = data[offset..].to_vec();

    Ok(HybridPayload {
        payload_type,
        kem_ct,
        iv,
        tag,
        ciphertext,
    })
}

pub fn encrypt_payload(
    recipient_pubkey_hex: &str,
    plaintext: &[u8],
    info: &[u8],
    payload_type: u8,
) -> Result<Vec<u8>, String> {
    let pub_bytes =
        hex::decode(recipient_pubkey_hex).map_err(|e| format!("Invalid hex: {}", e))?;

    let (shared_secret, kem_ct) = pq::encapsulate(&pub_bytes)?;
    let key = derive_symmetric_key(&shared_secret, info)?;

    let mut iv = [0u8; IV_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);

    let (ciphertext, tag) =
        crypto::encrypt_aes256_gcm(&key, &iv, plaintext, info)?;

    pack_payload(payload_type, &kem_ct, &iv, &tag, &ciphertext)
}

pub fn decrypt_payload(
    secret_key_hex: &str,
    payload: &[u8],
    info: &[u8],
    expected_type: u8,
) -> Result<Vec<u8>, String> {
    let secret_bytes =
        hex::decode(secret_key_hex).map_err(|e| format!("Invalid hex: {}", e))?;

    let parsed = unpack_payload(payload)?;
    if parsed.payload_type != expected_type {
        return Err("Hybrid payload type mismatch".to_string());
    }

    let shared_secret = pq::decapsulate(&secret_bytes, &parsed.kem_ct)?;
    let key = derive_symmetric_key(&shared_secret, info)?;

    crypto::decrypt_aes256_gcm(
        &key,
        &parsed.iv,
        &parsed.ciphertext,
        &parsed.tag,
        info,
    )
}

pub fn payload_to_base64(payload: &[u8]) -> String {
    general_purpose::STANDARD.encode(payload)
}

pub fn payload_from_base64(payload_b64: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|e| format!("Invalid base64 payload: {}", e))
}
