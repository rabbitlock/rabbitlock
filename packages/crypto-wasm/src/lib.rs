use hex;
use rand::RngCore;
use wasm_bindgen::prelude::*;

pub mod crypto;
pub mod files;
pub mod hybrid;
pub mod pq;
pub mod sops;
pub mod shamir;

#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("Hello, {}! RabbitLock Wasm is Active.", name)
}

fn decrypt_hybrid_data_key(
    private_key: &str,
    recipients: &[sops::HybridRecipient],
) -> Result<Vec<u8>, String> {
    let mut last_error = String::new();

    for recipient in recipients {
        let payload = match hybrid::payload_from_base64(recipient.enc.trim()) {
            Ok(decoded) => decoded,
            Err(e) => {
                last_error = e;
                continue;
            }
        };

        match hybrid::decrypt_payload(
            private_key,
            &payload,
            hybrid::INFO_DATA_KEY,
            hybrid::PAYLOAD_TYPE_DATA_KEY,
        ) {
            Ok(key) => return Ok(key),
            Err(e) => last_error = e,
        }
    }

    Err(format!(
        "Could not decrypt data key. Last error: {}",
        last_error
    ))
}

#[wasm_bindgen]
pub fn parse_and_verify_sops(json_input: &str) -> String {
    match sops::parse_sops_json(json_input) {
        Ok(file) => format!(
            "Successfully parsed SOPS file. Version: {:?}",
            file.metadata.version
        ),
        Err(e) => format!("Error parsing SOPS file: {}", e),
    }
}

#[wasm_bindgen]
pub fn derive_hybrid_keypair(seed_hex: &str) -> Result<String, String> {
    let seed = hex::decode(seed_hex).map_err(|e| format!("Invalid hex: {}", e))?;
    let (secret, public) = pq::derive_keypair_from_seed(&seed)?;
    Ok(format!("{}:{}", hex::encode(secret), hex::encode(public)))
}

#[wasm_bindgen]
pub fn verify_sops_integrity(json_input: &str, data_key_hex: &str) -> String {
    let sops_file = match sops::parse_sops_json(json_input) {
        Ok(f) => f,
        Err(e) => return format!("Error parsing JSON: {}", e),
    };

    let mac = match &sops_file.metadata.mac {
        Some(m) => m,
        None => return "No MAC found in SOPS metadata.".to_string(),
    };

    let key_bytes = match hex::decode(data_key_hex) {
        Ok(b) => b,
        Err(e) => return format!("Invalid data key hex: {}", e),
    };

    // Decrypt MAC first
    let (mac_ciphertext, mac_iv, mac_tag) = match sops::parse_enc_string(mac) {
        Some(parts) => parts,
        None => return "Failed to parse encrypted MAC string".to_string(),
    };

    let last_modified_aad = match &sops_file.metadata.last_modified {
        Some(lm) => lm.clone(),
        None => return "No lastmodified date found".to_string(),
    };

    let decrypted_mac_bytes = match crypto::decrypt_aes256_gcm(
        &key_bytes,
        &mac_iv,
        &mac_ciphertext,
        &mac_tag,
        last_modified_aad.as_bytes(),
    ) {
        Ok(bytes) => bytes,
        Err(e) => return format!("Failed to decrypt MAC: {}", e),
    };

    let expected_mac = match String::from_utf8(decrypted_mac_bytes) {
        Ok(s) => s,
        Err(e) => return format!("Decrypted MAC is not valid UTF-8: {}", e),
    };

    let decrypted_tree = match sops::decrypt_tree(&sops_file.data, &key_bytes, "") {
        Ok(tree) => tree,
        Err(e) => return format!("Failed to decrypt tree for MAC: {}", e),
    };
    let computed_mac = sops::compute_mac(&decrypted_tree);

    if computed_mac == expected_mac {
        "Integrity Check Passed: MAC is valid.".to_string()
    } else {
        format!(
            "Integrity Check FAILED: Expected {}, Computed {}",
            expected_mac, computed_mac
        )
    }
}

#[wasm_bindgen]
pub fn encrypt_data_key(data_key_hex: &str, recipient_pubkey_hex: &str) -> Result<String, String> {
    let data_key = hex::decode(data_key_hex).map_err(|e| format!("Invalid data key hex: {}", e))?;
    let payload = hybrid::encrypt_payload(
        recipient_pubkey_hex,
        &data_key,
        hybrid::INFO_DATA_KEY,
        hybrid::PAYLOAD_TYPE_DATA_KEY,
    )?;
    Ok(hybrid::payload_to_base64(&payload))
}

#[wasm_bindgen]
pub fn decrypt_data_key(json_input: &str, private_key: &str) -> Result<String, String> {
    let sops_file =
        sops::parse_sops_json(json_input).map_err(|e| format!("Error parsing JSON: {}", e))?;

    let recipients = sops_file
        .metadata
        .hybrid
        .as_ref()
        .ok_or("No hybrid recipients found")?;

    let data_key = decrypt_hybrid_data_key(private_key, recipients)?;

    Ok(hex::encode(data_key))
}

#[wasm_bindgen]
pub fn decrypt_and_verify_sops(json_input: &str, private_key: &str) -> Result<String, String> {
    let sops_file =
        sops::parse_sops_json(json_input).map_err(|e| format!("Error parsing JSON: {}", e))?;

    let mac = sops_file
        .metadata
        .mac
        .as_deref()
        .ok_or("No MAC found in SOPS metadata")?;

    let recipients = sops_file
        .metadata
        .hybrid
        .as_ref()
        .ok_or("No hybrid recipients found")?;

    let data_key = decrypt_hybrid_data_key(private_key, recipients)?;

    // Now we must decrypt the MAC using the data key

    let (mac_ciphertext, mac_iv, mac_tag) =
        sops::parse_enc_string(mac).ok_or("Failed to parse encrypted MAC string")?;

    // SOPS uses the LastModified date as AAD for decrypting the MAC.

    // Format: RFC3339 (e.g. "2024-01-01T00:00:00Z")

    let last_modified_aad = match &sops_file.metadata.last_modified {
        Some(lm) => lm.clone(),

        None => {
            return Err("No lastmodified date found in metadata, cannot decrypt MAC".to_string())
        }
    };

    println!(
        "Attempting MAC decryption with AAD: {:?}",
        last_modified_aad
    );

    let decrypted_mac_bytes = crypto::decrypt_aes256_gcm(
        &data_key,
        &mac_iv,
        &mac_ciphertext,
        &mac_tag,
        last_modified_aad.as_bytes(),
    )
    .map_err(|e| format!("Failed to decrypt MAC: {}", e))?;

    let expected_mac = String::from_utf8(decrypted_mac_bytes)
        .map_err(|e| format!("Decrypted MAC is not valid UTF-8: {}", e))?;

    // SOPS computes MAC over DECRYPTED values, so we need to decrypt the tree first
    let decrypted_tree = sops::decrypt_tree(&sops_file.data, &data_key, "")
        .map_err(|e| format!("Failed to decrypt tree: {}", e))?;

    let computed_mac = sops::compute_mac(&decrypted_tree);

    if computed_mac == expected_mac {
        Ok("Integrity Check Passed: MAC is valid.".to_string())
    } else {
        Err(format!(
            "Integrity Check FAILED: Expected {}, Computed {}",
            expected_mac, computed_mac
        ))
    }
}

/// Decrypt and return the full decrypted SOPS file as JSON string
/// Returns: JSON string with decrypted values (sops metadata still encrypted)
#[wasm_bindgen]
pub fn decrypt_sops_content(json_input: &str, private_key: &str) -> Result<String, String> {
    let sops_file =
        sops::parse_sops_json(json_input).map_err(|e| format!("Error parsing JSON: {}", e))?;

    let recipients = sops_file
        .metadata
        .hybrid
        .as_ref()
        .ok_or("No hybrid recipients found")?;

    let data_key = decrypt_hybrid_data_key(private_key, recipients)?;

    let decrypted_tree = sops::decrypt_tree(&sops_file.data, &data_key, "")
        .map_err(|e| format!("Failed to decrypt tree: {}", e))?;

    let decrypted_value = serde_json::to_string_pretty(&decrypted_tree)
        .map_err(|e| format!("Failed to serialize decrypted content: {}", e))?;

    Ok(decrypted_value)
}

#[wasm_bindgen]
pub fn encrypt_sops_json(plain_json: &str, data_key_hex: &str) -> Result<String, String> {
    let data: serde_json::Value =
        serde_json::from_str(plain_json).map_err(|e| format!("Invalid JSON: {}", e))?;

    let data_key = hex::decode(data_key_hex).map_err(|e| format!("Invalid data key hex: {}", e))?;

    // 1. Compute MAC over plaintext data
    let mac_str = sops::compute_mac(&data);

    // 2. Encrypt the tree
    let encrypted_data = sops::encrypt_tree(&data, &data_key, "")?;

    // 3. Encrypt the MAC
    let mut iv = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut iv);

    // Use LastModified as AAD for MAC encryption.
    // Ideally we should generate a timestamp. For now, use a placeholder or provided one.
    // Let's use a fixed timestamp for MVP simplicity or generate one if we can.
    // 'time' crate is available in zip dependencies but maybe not direct.
    // Let's use a dummy timestamp for now, user can update it.
    let last_modified = "2025-01-01T00:00:00Z".to_string();

    let (mac_ciphertext, mac_tag) =
        crypto::encrypt_aes256_gcm(&data_key, &iv, mac_str.as_bytes(), last_modified.as_bytes())?;

    // Format MAC string: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
    use base64::{engine::general_purpose, Engine as _};
    let enc_mac = format!(
        "ENC[AES256_GCM,data:{},iv:{},tag:{},type:str]",
        general_purpose::STANDARD.encode(mac_ciphertext),
        general_purpose::STANDARD.encode(iv),
        general_purpose::STANDARD.encode(mac_tag)
    );

    // 4. Construct Output
    // This helper encrypts SOPS values but does not wrap the data key.
    // Use encrypt_sops_json_for_recipient to include hybrid recipients.

    // We can't easily construct SopsFile because 'data' is flattened.
    // Let's just merge the objects.

    if let serde_json::Value::Object(mut map) = encrypted_data {
        let metadata = serde_json::json!({
            "mac": enc_mac,
            "version": "rabbitlock-pq-1",
            "lastmodified": last_modified
        });
        map.insert("sops".to_string(), metadata);

        Ok(serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?)
    } else {
        Err("Root of JSON must be an object".to_string())
    }
}

#[wasm_bindgen]
pub fn encrypt_sops_json_for_recipient(
    plain_json: &str,
    recipient_pubkey_hex: &str,
) -> Result<String, String> {
    // Wrapper for single recipient - calls multi-recipient version
    encrypt_sops_json_for_recipients(plain_json, vec![recipient_pubkey_hex.to_string()])
}

/// Encrypt SOPS JSON for multiple recipients (team encryption)
/// recipient_pubkeys_hex: JSON array of public key hex strings
/// Returns: Encrypted SOPS JSON with multiple recipients
#[wasm_bindgen]
pub fn encrypt_sops_json_for_recipients(
    plain_json: &str,
    recipient_pubkeys_hex: Vec<String>,
) -> Result<String, String> {
    if recipient_pubkeys_hex.is_empty() {
        return Err("At least one recipient is required".to_string());
    }

    let data: serde_json::Value =
        serde_json::from_str(plain_json).map_err(|e| format!("Invalid JSON: {}", e))?;

    let mut data_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut data_key);

    let mac_str = sops::compute_mac(&data);
    let encrypted_data = sops::encrypt_tree(&data, &data_key, "")?;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);

    let last_modified = "2026-01-01T00:00:00Z".to_string();

    let (mac_ciphertext, mac_tag) =
        crypto::encrypt_aes256_gcm(&data_key, &iv, mac_str.as_bytes(), last_modified.as_bytes())?;

    use base64::{engine::general_purpose, Engine as _};
    let enc_mac = format!(
        "ENC[AES256_GCM,data:{},iv:{},tag:{},type:str]",
        general_purpose::STANDARD.encode(mac_ciphertext),
        general_purpose::STANDARD.encode(iv),
        general_purpose::STANDARD.encode(mac_tag)
    );

    // Encrypt data key for each recipient
    let mut hybrid_recipients = Vec::new();
    for recipient_pubkey_hex in recipient_pubkeys_hex {
        let wrapped_payload = hybrid::encrypt_payload(
            &recipient_pubkey_hex,
            &data_key,
            hybrid::INFO_DATA_KEY,
            hybrid::PAYLOAD_TYPE_DATA_KEY,
        )?;

        hybrid_recipients.push(sops::HybridRecipient {
            recipient: recipient_pubkey_hex.to_string(),
            enc: hybrid::payload_to_base64(&wrapped_payload),
        });
    }

    if let serde_json::Value::Object(mut map) = encrypted_data {
        let metadata = serde_json::json!({
            "mac": enc_mac,
            "version": "rabbitlock-pq-1",
            "lastmodified": last_modified,
            "hybrid": hybrid_recipients,
        });
        map.insert("sops".to_string(), metadata);

        Ok(serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?)
    } else {
        Err("Root of JSON must be an object".to_string())
    }
}

#[cfg(test)]

mod tests {

    use super::*;

    #[test]

    fn test_decrypt_data_key_hybrid_sops() {
        let seed = vec![7u8; 32];
        let (secret_key, public_key) = pq::derive_keypair_from_seed(&seed).unwrap();
        let recipient_pub = hex::encode(public_key);
        let secret_hex = hex::encode(secret_key);

        let json = encrypt_sops_json_for_recipient(r#"{"message":"hello"}"#, &recipient_pub)
            .expect("Failed to create hybrid SOPS JSON");

        let result = decrypt_data_key(&json, &secret_hex);
        assert!(result.is_ok(), "Decryption failed: {:?}", result.err());
        let key_hex = result.unwrap();
        assert!(key_hex.len() > 0, "Decrypted key should not be empty");
    }

    #[test]

    fn test_decrypt_and_verify_hybrid_sops() {
        let seed = vec![42u8; 32];
        let (secret_key, public_key) = pq::derive_keypair_from_seed(&seed).unwrap();
        let recipient_pub = hex::encode(public_key);
        let secret_hex = hex::encode(secret_key);

        let json = encrypt_sops_json_for_recipient(r#"{"message":"verify"}"#, &recipient_pub)
            .expect("Failed to create hybrid SOPS JSON");

        let result = decrypt_and_verify_sops(&json, &secret_hex);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }
}

// ============================================================================
// POST-QUANTUM HYBRID KEM (Xwing: ML-KEM-768 + X25519) Wasm exports
// ============================================================================

/// Generate a new hybrid keypair (X25519 + ML-KEM-768)
/// Returns: "secret_key_hex:public_key_hex"
#[wasm_bindgen]
pub fn pq_generate_keypair() -> String {
    let (sk, pk) = pq::generate_keypair();
    format!("{}:{}", hex::encode(sk), hex::encode(pk))
}

/// Encapsulate a shared secret for a recipient's hybrid public key
/// pub_key_hex: 1216 bytes (32 X25519 + 1184 ML-KEM) as hex
/// Returns: "shared_secret_hex:ciphertext_hex"
#[wasm_bindgen]
pub fn pq_encapsulate(pub_key_hex: &str) -> Result<String, String> {
    let pub_bytes = hex::decode(pub_key_hex).map_err(|e| format!("Invalid hex: {}", e))?;

    let (shared_secret, ciphertext) = pq::encapsulate(&pub_bytes)?;

    Ok(format!(
        "{}:{}",
        hex::encode(shared_secret),
        hex::encode(ciphertext)
    ))
}

/// Decapsulate a shared secret using your private key
/// secret_key_hex: 2432 bytes as hex
/// ciphertext_hex: 1120 bytes as hex
/// Returns: shared_secret_hex (64 hex chars = 32 bytes)
#[wasm_bindgen]
pub fn pq_decapsulate(secret_key_hex: &str, ciphertext_hex: &str) -> Result<String, String> {
    let sk = hex::decode(secret_key_hex).map_err(|e| format!("Invalid secret key hex: {}", e))?;

    let ct = hex::decode(ciphertext_hex).map_err(|e| format!("Invalid ciphertext hex: {}", e))?;
    let shared_secret = pq::decapsulate(&sk, &ct)?;

    Ok(hex::encode(shared_secret))
}

/// Generate a new ML-KEM-768 keypair (PQ-only)
/// Returns: "secret_key_hex:public_key_hex"
#[wasm_bindgen]
pub fn pq_mlkem_generate_keypair() -> String {
    let (sk, pk) = pq::mlkem_generate_keypair();
    format!("{}:{}", hex::encode(sk), hex::encode(pk))
}

/// Encapsulate a shared secret for an ML-KEM-768 public key (PQ-only)
/// pub_key_hex: 1184 bytes as hex
/// Returns: "shared_secret_hex:ciphertext_hex"
#[wasm_bindgen]
pub fn pq_mlkem_encapsulate(pub_key_hex: &str) -> Result<String, String> {
    let pub_bytes = hex::decode(pub_key_hex).map_err(|e| format!("Invalid hex: {}", e))?;
    let (ciphertext, shared_secret) = pq::mlkem_encapsulate(&pub_bytes)?;
    Ok(format!(
        "{}:{}",
        hex::encode(shared_secret),
        hex::encode(ciphertext)
    ))
}

/// Decapsulate a shared secret using an ML-KEM-768 secret key (PQ-only)
/// secret_key_hex: 2400 bytes as hex
/// ciphertext_hex: 1088 bytes as hex
/// Returns: shared_secret_hex (64 hex chars = 32 bytes)
#[wasm_bindgen]
pub fn pq_mlkem_decapsulate(secret_key_hex: &str, ciphertext_hex: &str) -> Result<String, String> {
    let sk = hex::decode(secret_key_hex).map_err(|e| format!("Invalid secret key hex: {}", e))?;
    let ct = hex::decode(ciphertext_hex).map_err(|e| format!("Invalid ciphertext hex: {}", e))?;
    let shared_secret = pq::mlkem_decapsulate(&sk, &ct)?;
    Ok(hex::encode(shared_secret))
}

/// Get the size constants for documentation

/// Get the size constants for documentation
#[wasm_bindgen]
pub fn pq_get_sizes() -> String {
    format!(
        r#"{{"public_key":{},"secret_key":{},"ciphertext":{},"shared_secret":{}}}"#,
        pq::HYBRID_PUBLIC_KEY_SIZE,
        pq::HYBRID_SECRET_KEY_SIZE,
        pq::HYBRID_CIPHERTEXT_SIZE,
        pq::SHARED_SECRET_SIZE
    )
}

// ============================================================================
// SHAMIR'S SECRET SHARING (SSS) Wasm exports
// ============================================================================

/// Split a secret (hex) into 'total' shares with 'threshold' required to recover
/// Returns: Array of hex strings (shares)
#[wasm_bindgen]
pub fn sss_split_secret(secret_hex: &str, threshold: u8, total: u8) -> Result<JsValue, String> {
    let shares = shamir::split_secret(secret_hex, threshold, total)?;
    serde_wasm_bindgen::to_value(&shares)
        .map_err(|e| format!("Serialization error: {}", e))
}

/// Recover a secret from an array of share hex strings
#[wasm_bindgen]
pub fn sss_recover_secret(shares_val: JsValue, threshold: u8) -> Result<String, String> {
    let shares: Vec<String> = serde_wasm_bindgen::from_value(shares_val)
        .map_err(|e| format!("Invalid shares array: {}", e))?;
        
    shamir::combine_shares(&shares, threshold)
}
