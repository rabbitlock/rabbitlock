use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct SopsFile {
    #[serde(flatten)]
    pub data: Value,

    #[serde(rename = "sops")]
    pub metadata: SopsMetadata,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SopsMetadata {
    pub mac: Option<String>,
    pub version: Option<String>,
    pub hybrid: Option<Vec<HybridRecipient>>,
    #[serde(rename = "lastmodified")]
    pub last_modified: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HybridRecipient {
    pub recipient: String,
    pub enc: String,
}

pub fn parse_sops_json(input: &str) -> Result<SopsFile, serde_json::Error> {
    serde_json::from_str(input)
}

/// Compute MAC over SOPS data tree using SHA-512.
/// SOPS computes MAC over the DECRYPTED values, not the encrypted ENC[] strings.
pub fn compute_mac(data: &Value) -> String {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    compute_mac_recursive(&mut hasher, data);
    format!("{:X}", hasher.finalize())
}

/// Decrypt all ENC[] values in the tree and return a new tree with decrypted values.
pub fn decrypt_tree(data: &Value, data_key: &[u8], aad_prefix: &str) -> Result<Value, String> {
    match data {
        Value::String(s) => {
            if s.starts_with("ENC[") {
                // Parse and decrypt the encrypted string
                let (ciphertext, iv, tag) =
                    parse_enc_string(s).ok_or("Failed to parse ENC string".to_string())?;

                // Decrypt using AES-256-GCM
                use crate::crypto;
                let decrypted_bytes = crypto::decrypt_aes256_gcm(
                    data_key,
                    &iv,
                    &ciphertext,
                    &tag,
                    aad_prefix.as_bytes(),
                )
                .map_err(|e| format!("Decryption failed: {}", e))?;

                // Convert back to appropriate type
                let decrypted_str = String::from_utf8(decrypted_bytes)
                    .map_err(|e| format!("Decrypted data is not valid UTF-8: {}", e))?;

                // Try to parse as JSON to get the original type
                if let Ok(v) = serde_json::from_str::<Value>(&decrypted_str) {
                    Ok(v)
                } else {
                    Ok(Value::String(decrypted_str))
                }
            } else {
                Ok(data.clone())
            }
        }
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                // Build AAD for nested values: key_path:
                let new_aad = format!("{}{}:", aad_prefix, k);
                match decrypt_tree(v, data_key, &new_aad) {
                    Ok(decrypted) => {
                        new_map.insert(k.clone(), decrypted);
                    }
                    Err(_) => {
                        new_map.insert(k.clone(), v.clone());
                    }
                }
            }
            Ok(Value::Object(new_map))
        }
        Value::Array(arr) => {
            let mut new_arr = Vec::new();
            for (i, v) in arr.iter().enumerate() {
                // AAD for arrays includes the index
                let new_aad = format!("{}{}:", aad_prefix, i);
                match decrypt_tree(v, data_key, &new_aad) {
                    Ok(decrypted) => {
                        new_arr.push(decrypted);
                    }
                    Err(_) => {
                        new_arr.push(v.clone());
                    }
                }
            }
            Ok(Value::Array(new_arr))
        }
        _ => Ok(data.clone()),
    }
}

fn compute_mac_recursive(hasher: &mut impl sha2::Digest, data: &Value) {
    match data {
        Value::Object(map) => {
            // Keys are now ordered (IndexMap) due to `preserve_order` feature.
            // We iterate in the order they appear in the map (insertion order = file order).
            // Do NOT sort.

            for (_k, v) in map {
                // Go SOPS implementation does NOT hash keys, only values (leaves).

                // Hash Value
                compute_mac_recursive(hasher, v);
            }
        }

        Value::Array(arr) => {
            for v in arr {
                compute_mac_recursive(hasher, v);
            }
        }
        Value::String(s) => {
            hasher.update(s.as_bytes());
        }
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                hasher.update(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                hasher.update(u.to_string().as_bytes());
            } else {
                // Float
                hasher.update(n.to_string().as_bytes());
            }
        }
        Value::Bool(b) => {
            // Go SOPS uses "True" / "False" (Title case)
            let s = if *b { "True" } else { "False" };
            hasher.update(s.as_bytes());
        }
        Value::Null => {
            // Go SOPS ToBytes returns error for nil, so valid SOPS files shouldn't have nulls in MAC
        }
    }
}

/// Encrypt all leaf values in the tree using the data_key.
pub fn encrypt_tree(data: &Value, data_key: &[u8], aad_prefix: &str) -> Result<Value, String> {
    match data {
        Value::String(s) => encrypt_leaf_value(s.as_bytes(), data_key, aad_prefix, "str"),
        Value::Number(n) => {
            let s = n.to_string();
            let type_str = if n.is_i64() { "int" } else { "float" };
            encrypt_leaf_value(s.as_bytes(), data_key, aad_prefix, type_str)
        }
        Value::Bool(b) => {
            let s = if *b { "True" } else { "False" };
            encrypt_leaf_value(s.as_bytes(), data_key, aad_prefix, "bool")
        }
        Value::Null => Ok(Value::Null),
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                let new_aad = format!("{}{}:", aad_prefix, k);
                let encrypted = encrypt_tree(v, data_key, &new_aad)?;
                new_map.insert(k.clone(), encrypted);
            }
            Ok(Value::Object(new_map))
        }
        Value::Array(arr) => {
            let mut new_arr = Vec::new();
            for (i, v) in arr.iter().enumerate() {
                let new_aad = format!("{}{}:", aad_prefix, i);
                let encrypted = encrypt_tree(v, data_key, &new_aad)?;
                new_arr.push(encrypted);
            }
            Ok(Value::Array(new_arr))
        }
    }
}

fn encrypt_leaf_value(
    plaintext: &[u8],
    data_key: &[u8],
    aad: &str,
    type_suffix: &str,
) -> Result<Value, String> {
    use crate::crypto;

    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);

    let (ciphertext, tag) = crypto::encrypt_aes256_gcm(data_key, &iv, plaintext, aad.as_bytes())?;

    let enc_str = format!(
        "ENC[AES256_GCM,data:{},iv:{},tag:{},type:{}]",
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(iv),
        general_purpose::STANDARD.encode(tag),
        type_suffix
    );

    Ok(Value::String(enc_str))
}

pub fn parse_enc_string(enc_str: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if !enc_str.starts_with("ENC[") || !enc_str.ends_with("]") {
        return None;
    }

    // remove ENC[ and ]
    let inner = &enc_str[4..enc_str.len() - 1];

    // Split by comma. Note: base64 shouldn't contain commas.
    let parts: Vec<&str> = inner.split(',').collect();

    let mut data = None;
    let mut iv = None;
    let mut tag = None;

    for part in parts {
        if let Some(val) = part.strip_prefix("data:") {
            let clean = val.replace(|c: char| c.is_whitespace(), "");

            data = general_purpose::STANDARD.decode(clean).ok();
        } else if let Some(val) = part.strip_prefix("iv:") {
            let clean = val.replace(|c: char| c.is_whitespace(), "");

            iv = general_purpose::STANDARD.decode(clean).ok();
        } else if let Some(val) = part.strip_prefix("tag:") {
            let clean = val.replace(|c: char| c.is_whitespace(), "");

            tag = general_purpose::STANDARD.decode(clean).ok();
        }
    }

    match (data, iv, tag) {
        (Some(d), Some(i), Some(t)) => Some((d, i, t)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sops_file() {
        let json = r#"{
            "hello": "ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]",
            "sops": {
                "mac": "123456",
                "version": "3.7.3",
                "hybrid": [
                    {
                        "recipient": "hybrid_pub_hex",
                        "enc": "base64_payload"
                    }
                ]
            }
        }"#;

        let sops_file = parse_sops_json(json).unwrap();
        assert_eq!(sops_file.metadata.version.unwrap(), "3.7.3");
        assert!(sops_file.data.get("hello").is_some());
    }

    #[test]
    fn test_mac_computation() {
        // Test that MAC computation works and is deterministic
        let json = r#"{
            "key1": "value1",
            "key2": {
                "nested": "value2"
            }
        }"#;
        let data: Value = serde_json::from_str(json).unwrap();

        let mac1 = compute_mac(&data);
        let mac2 = compute_mac(&data);

        assert_eq!(mac1, mac2);
        assert!(!mac1.is_empty());
    }

    #[test]
    fn test_mac_different_content() {
        // Different content should produce different MAC
        let json1 = r#"{"key": "value1"}"#;
        let json2 = r#"{"key": "value2"}"#;

        let data1: Value = serde_json::from_str(json1).unwrap();
        let data2: Value = serde_json::from_str(json2).unwrap();

        assert_ne!(compute_mac(&data1), compute_mac(&data2));
    }

    #[test]
    fn test_mac_ordering_matters() {
        // Key ordering should affect MAC (SOPS preserves insertion order)
        let json1 = r#"{"a": "1", "b": "2"}"#;
        let json2 = r#"{"b": "2", "a": "1"}"#;

        let data1: Value = serde_json::from_str(json1).unwrap();
        let data2: Value = serde_json::from_str(json2).unwrap();

        assert_ne!(compute_mac(&data1), compute_mac(&data2));
    }
}
