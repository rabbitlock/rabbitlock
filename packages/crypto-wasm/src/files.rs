use std::io::Write;
use wasm_bindgen::prelude::*;
use zip::write::FileOptions;

use crate::hybrid;

#[derive(serde::Deserialize)]
pub struct FileEntry {
    pub path: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

#[wasm_bindgen]
pub fn create_zip_archive(files_js: JsValue) -> Result<Vec<u8>, String> {
    let files: Vec<FileEntry> = serde_wasm_bindgen::from_value(files_js)
        .map_err(|e| format!("Failed to parse files: {}", e))?;

    let mut buf = Vec::new();
    {
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o755);

        for file in files {
            zip.start_file(file.path, options)
                .map_err(|e| format!("Zip error: {}", e))?;
            zip.write_all(&file.data)
                .map_err(|e| format!("Zip write error: {}", e))?;
        }
        zip.finish()
            .map_err(|e| format!("Zip finish error: {}", e))?;
    }

    Ok(buf)
}

#[wasm_bindgen]
pub fn encrypt_binary_hybrid(data: &[u8], recipient_pubkey_hex: &str) -> Result<Vec<u8>, String> {
    hybrid::encrypt_payload(
        recipient_pubkey_hex,
        data,
        hybrid::INFO_FILE,
        hybrid::PAYLOAD_TYPE_FILE,
    )
}

#[wasm_bindgen]
pub fn decrypt_binary_hybrid(data: &[u8], secret_key_hex: &str) -> Result<Vec<u8>, String> {
    match hybrid::decrypt_payload(
        secret_key_hex,
        data,
        hybrid::INFO_FILE,
        hybrid::PAYLOAD_TYPE_FILE,
    ) {
        Ok(plaintext) => Ok(plaintext),
        Err(err) => {
            if err.contains("Invalid hybrid payload magic") {
                return Err("Not a RabbitLock .rlk file.".to_string());
            }
            if err.contains("Hybrid payload is too short") {
                return Err("File is too short or corrupted.".to_string());
            }
            if err.contains("payload type mismatch") {
                return Err("Not a RabbitLock file payload.".to_string());
            }
            if err.contains("AES-GCM")
                || err.contains("aead::Error")
                || err.contains("decapsulation failed")
            {
                return Err(
                    "Decryption failed. This file may be encrypted for a different identity or is corrupted.".to_string(),
                );
            }
            Err(format!("Decryption failed: {}", err))
        }
    }
}
