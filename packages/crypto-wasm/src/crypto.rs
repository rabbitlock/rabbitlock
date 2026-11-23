use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aes::Aes256;
use aes_gcm::{
    aead::{consts::U32, Aead, Key},
    Aes256Gcm, AesGcm, KeyInit,
};

pub fn decrypt_aes256_gcm(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err(format!("Key length must be 32 bytes (got {})", key.len()));
    }

    let key_arr = Key::<Aes256Gcm>::from_slice(key);

    let mut payload_vec = ciphertext.to_vec();
    payload_vec.extend_from_slice(tag);

    let payload = aes_gcm::aead::Payload {
        msg: payload_vec.as_ref(),
        aad: aad,
    };

    if iv.len() == 12 {
        let cipher = Aes256Gcm::new(key_arr);
        let nonce = GenericArray::from_slice(iv);
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("AES-GCM (12-byte IV) decryption failed: {}", e))
    } else if iv.len() == 32 {
        // Use AesGcm with U32 nonce size
        let cipher = AesGcm::<Aes256, U32>::new(key_arr);
        let nonce = GenericArray::from_slice(iv);
        cipher
            .decrypt(nonce, payload)
            .map_err(|e| format!("AES-GCM (32-byte IV) decryption failed: {}", e))
    } else {
        Err(format!("Unsupported IV length: {}", iv.len()))
    }
}

pub fn encrypt_aes256_gcm(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if key.len() != 32 {
        return Err(format!("Key length must be 32 bytes (got {})", key.len()));
    }

    let key_arr = Key::<Aes256Gcm>::from_slice(key);
    let payload = aes_gcm::aead::Payload {
        msg: plaintext,
        aad: aad,
    };

    if iv.len() == 12 {
        let cipher = Aes256Gcm::new(key_arr);
        let nonce = GenericArray::from_slice(iv);
        let ciphertext_with_tag = cipher
            .encrypt(nonce, payload)
            .map_err(|e| format!("AES-GCM (12-byte IV) encryption failed: {}", e))?;

        // Split tag (last 16 bytes)
        if ciphertext_with_tag.len() < 16 {
            return Err("Ciphertext too short".to_string());
        }
        let split_idx = ciphertext_with_tag.len() - 16;
        let ciphertext = ciphertext_with_tag[..split_idx].to_vec();
        let tag = ciphertext_with_tag[split_idx..].to_vec();

        Ok((ciphertext, tag))
    } else {
        Err("Only 12-byte IV is supported for new encryption".to_string())
    }
}

#[cfg(test)]
mod tests {
    #[test]

    fn test_aes_gcm_32_byte_nonce() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};

        use aes_gcm::aes::Aes256;

        use aes_gcm::AesGcm;

        use aes_gcm::aead::consts::U32;

        use aes_gcm::aead::generic_array::GenericArray;

        let key = GenericArray::from_slice(&[0u8; 32]);

        let cipher = AesGcm::<Aes256, U32>::new(key);

        let nonce = GenericArray::from_slice(&[0u8; 32]); // 32 bytes

        let payload = Payload {
            msg: b"hello",

            aad: b"",
        };

        let ct = cipher.encrypt(nonce, payload).unwrap();

        // decrypt

        let payload_dec = Payload {
            msg: &ct, // ct includes tag

            aad: b"",
        };

        let pt = cipher.decrypt(nonce, payload_dec).unwrap();

        assert_eq!(pt, b"hello");
    }
}
