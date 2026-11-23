// Post-Quantum Hybrid KEM using RustCrypto ML-KEM + X25519
//
// This implements the RabbitLock hybrid key exchange combining:
// - Classical: X25519 (Elliptic Curve Diffie-Hellman)
// - Post-Quantum: ML-KEM-768 (Kyber - Module-Lattice based, FIPS 203)
//
// Security: If either algorithm remains secure, the shared secret is protected.
// This provides defense-in-depth against classical cryptanalysis and quantum attacks (Shor's algorithm).
//
// Reference: https://eprint.iacr.org/2024/039 (Xwing hybrid KEM)

use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext as MLKEMCiphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

// Type aliases for ML-KEM keys
type MLKEM768SecretKey = <MlKem768 as KemCore>::DecapsulationKey;
type MLKEM768PublicKey = <MlKem768 as KemCore>::EncapsulationKey;
type MLKEM768Ciphertext = MLKEMCiphertext<MlKem768>;

pub const X25519_SECRET_KEY_SIZE: usize = 32;
pub const MLKEM768_SECRET_KEY_SIZE: usize = 2400;
pub const HYBRID_SECRET_KEY_SIZE: usize = X25519_SECRET_KEY_SIZE + MLKEM768_SECRET_KEY_SIZE;

pub const X25519_PUBLIC_KEY_SIZE: usize = 32;
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
pub const HYBRID_PUBLIC_KEY_SIZE: usize = X25519_PUBLIC_KEY_SIZE + MLKEM768_PUBLIC_KEY_SIZE;

pub const X25519_CIPHERTEXT_SIZE: usize = 32;
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
pub const HYBRID_CIPHERTEXT_SIZE: usize = X25519_CIPHERTEXT_SIZE + MLKEM768_CIPHERTEXT_SIZE;

pub const SHARED_SECRET_SIZE: usize = 32;

/// Generate an ML-KEM-768 keypair (PQ-only)
pub fn mlkem_generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = ChaCha20Rng::from_entropy();
    let (mlkem768_secret, mlkem768_public) = MlKem768::generate(&mut rng);
    (
        mlkem768_secret.as_bytes().as_slice().to_vec(),
        mlkem768_public.as_bytes().as_slice().to_vec(),
    )
}

/// Encapsulate using ML-KEM-768 (PQ-only)
/// Returns (ciphertext, shared_secret)
pub fn mlkem_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mlkem768_public_array: [u8; MLKEM768_PUBLIC_KEY_SIZE] = public_key
        .try_into()
        .map_err(|_| "Invalid ML-KEM public key length: expected 1184 bytes".to_string())?;
    let ek = MLKEM768PublicKey::from_bytes((&mlkem768_public_array).into());

    let (mlkem768_ct, mlkem768_ss) = ek
        .encapsulate(&mut rng)
        .map_err(|e| format!("ML-KEM encapsulation failed: {:?}", e))?;

    Ok((
        mlkem768_ct.as_slice().to_vec(),
        mlkem768_ss.as_slice().to_vec(),
    ))
}

/// Decapsulate using ML-KEM-768 (PQ-only)
pub fn mlkem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mlkem768_secret_array: [u8; MLKEM768_SECRET_KEY_SIZE] = secret_key
        .try_into()
        .map_err(|_| "Invalid ML-KEM secret key length: expected 2400 bytes".to_string())?;
    let dk = MLKEM768SecretKey::from_bytes((&mlkem768_secret_array).into());

    let mlkem768_ct_array: [u8; MLKEM768_CIPHERTEXT_SIZE] = ciphertext
        .try_into()
        .map_err(|_| "Invalid ML-KEM ciphertext length: expected 1088 bytes".to_string())?;
    let mlkem768_ct = MLKEM768Ciphertext::from(mlkem768_ct_array);

    let mlkem768_ss = dk
        .decapsulate(&mlkem768_ct)
        .map_err(|e| format!("ML-KEM decapsulation failed: {:?}", e))?;

    Ok(mlkem768_ss.as_slice().to_vec())
}

/// Hybrid keypair containing both classical and PQ components
#[derive(Clone)]
pub struct HybridKeypair {
    // Classical: X25519
    pub x25519_secret: StaticSecret,
    pub x25519_public: PublicKey,

    // Post-Quantum: ML-KEM-768
    pub mlkem768_secret: MLKEM768SecretKey,
    pub mlkem768_public: MLKEM768PublicKey,
}

impl HybridKeypair {
    /// Generate a new hybrid keypair
    pub fn generate() -> Self {
        let mut rng = ChaCha20Rng::from_entropy();

        // Generate X25519 keypair
        let x25519_secret = StaticSecret::random_from_rng(&mut rng);
        let x25519_public = PublicKey::from(&x25519_secret);

        // Generate ML-KEM-768 keypair
        let (mlkem768_secret, mlkem768_public) = MlKem768::generate(&mut rng);

        Self {
            x25519_secret,
            x25519_public,
            mlkem768_secret,
            mlkem768_public,
        }
    }

    /// Get the combined public key bytes for storage/sharing
    /// Format: [X25519_public (32 bytes)] + [ML-KEM_public (1184 bytes)] = 1216 bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HYBRID_PUBLIC_KEY_SIZE);
        bytes.extend_from_slice(self.x25519_public.as_bytes());
        bytes.extend_from_slice(self.mlkem768_public.as_bytes().as_slice());
        bytes
    }

    /// Get the combined secret key bytes for storage
    /// Format: [X25519_secret (32 bytes)] + [ML-KEM_secret (2400 bytes)] = 2432 bytes
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HYBRID_SECRET_KEY_SIZE);
        bytes.extend_from_slice(self.x25519_secret.as_bytes());
        bytes.extend_from_slice(self.mlkem768_secret.as_bytes().as_slice());
        bytes
    }
}

/// Hybrid ciphertext containing both encapsulated secrets
#[derive(Serialize, Deserialize, Clone)]
pub struct HybridCiphertext {
    // ML-KEM-768 ciphertext
    pub mlkem768_ct: Vec<u8>,

    // X25519 ephemeral public key
    pub x25519_ephemeral_pk: Vec<u8>,
}

impl HybridCiphertext {
    /// Serialize the ciphertext for storage/transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HYBRID_CIPHERTEXT_SIZE);
        bytes.extend_from_slice(&self.mlkem768_ct);
        bytes.extend_from_slice(&self.x25519_ephemeral_pk);
        bytes
    }

    /// Parse ciphertext from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != HYBRID_CIPHERTEXT_SIZE {
            return Err(format!(
                "Invalid ciphertext length: expected {}, got {}",
                HYBRID_CIPHERTEXT_SIZE,
                bytes.len()
            ));
        }

        Ok(Self {
            mlkem768_ct: bytes[..MLKEM768_CIPHERTEXT_SIZE].to_vec(),
            x25519_ephemeral_pk: bytes[MLKEM768_CIPHERTEXT_SIZE..].to_vec(),
        })
    }
}

/// Encapsulate a shared secret using the recipient's hybrid public key
/// Returns (ciphertext, shared_secret)
pub fn hybrid_encapsulate(
    x25519_public: &[u8],
    mlkem768_public: &[u8],
) -> Result<(HybridCiphertext, Vec<u8>), String> {
    let mut rng = ChaCha20Rng::from_entropy();

    // 1. ML-KEM-768 Encapsulation (Post-Quantum)
    let mlkem768_public_array: [u8; MLKEM768_PUBLIC_KEY_SIZE] = mlkem768_public
        .try_into()
        .map_err(|_| "Invalid ML-KEM public key length: expected 1184 bytes".to_string())?;
    let ek = MLKEM768PublicKey::from_bytes((&mlkem768_public_array).into());

    let (mlkem768_ct, mlkem768_ss) = ek
        .encapsulate(&mut rng)
        .map_err(|e| format!("ML-KEM encapsulation failed: {:?}", e))?;

    // 2. X25519 Encapsulation (Classical)
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let x25519_public_array: [u8; X25519_PUBLIC_KEY_SIZE] = x25519_public
        .try_into()
        .map_err(|_| "Invalid X25519 public key length".to_string())?;
    let remote_public = PublicKey::from(x25519_public_array);

    let x25519_ss = ephemeral_secret.diffie_hellman(&remote_public);

    // 3. Hybrid KDF: Combine both shared secrets using SHA3-512
    let mut hasher = Sha3_512::new();
    hasher.update(mlkem768_ss.as_slice());
    hasher.update(x25519_ss.as_bytes());
    let combined = hasher.finalize();

    // Take first 32 bytes as the final shared secret (256-bit)
    let shared_secret = combined[..SHARED_SECRET_SIZE].to_vec();
    let ciphertext = HybridCiphertext {
        mlkem768_ct: mlkem768_ct.as_slice().to_vec(),
        x25519_ephemeral_pk: ephemeral_public.as_bytes().to_vec(),
    };

    Ok((ciphertext, shared_secret))
}

/// Decapsulate a shared secret using your private key
pub fn hybrid_decapsulate(
    x25519_secret: &[u8],
    mlkem768_secret: &[u8],
    ciphertext: &HybridCiphertext,
) -> Result<Vec<u8>, String> {
    // 1. ML-KEM-768 Decapsulation (Post-Quantum)
    let mlkem768_secret_array: [u8; MLKEM768_SECRET_KEY_SIZE] = mlkem768_secret
        .try_into()
        .map_err(|_| "Invalid ML-KEM secret key length: expected 2400 bytes".to_string())?;
    let dk = MLKEM768SecretKey::from_bytes((&mlkem768_secret_array).into());

    let mlkem768_ct_array: [u8; MLKEM768_CIPHERTEXT_SIZE] = ciphertext
        .mlkem768_ct
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid ML-KEM ciphertext length".to_string())?;
    let mlkem768_ct = MLKEM768Ciphertext::from(mlkem768_ct_array);

    let mlkem768_ss = dk
        .decapsulate(&mlkem768_ct)
        .map_err(|e| format!("ML-KEM decapsulation failed: {:?}", e))?;

    // 2. X25519 Decapsulation (Classical)
    let x25519_secret_array: [u8; X25519_SECRET_KEY_SIZE] = x25519_secret
        .try_into()
        .map_err(|_| "Invalid X25519 secret key length".to_string())?;
    let secret = StaticSecret::from(x25519_secret_array);

    let ephemeral_public_array: [u8; X25519_PUBLIC_KEY_SIZE] = ciphertext
        .x25519_ephemeral_pk
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid ephemeral public key length".to_string())?;
    let ephemeral_public = PublicKey::from(ephemeral_public_array);

    let x25519_ss = secret.diffie_hellman(&ephemeral_public);

    // 3. Hybrid KDF: Combine both shared secrets using SHA3-512
    let mut hasher = Sha3_512::new();
    hasher.update(mlkem768_ss.as_slice());
    hasher.update(x25519_ss.as_bytes());
    let combined = hasher.finalize();

    // Take first 32 bytes as the final shared secret (256-bit)
    let shared_secret = combined[..SHARED_SECRET_SIZE].to_vec();

    Ok(shared_secret)
}

/// Convenience wrapper for Wasm exports: generate keypair and return (secret_key, public_key)
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let keypair = HybridKeypair::generate();
    (keypair.secret_key_bytes(), keypair.public_key_bytes())
}

pub fn derive_keypair_from_seed(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if seed.len() != 32 {
        return Err("Seed must be 32 bytes".to_string());
    }

    let mut rng = ChaCha20Rng::from_seed(
        seed.try_into()
            .map_err(|_| "Invalid seed length".to_string())?,
    );

    let x25519_secret = StaticSecret::random_from_rng(&mut rng);
    let x25519_public = PublicKey::from(&x25519_secret);
    let (mlkem768_secret, mlkem768_public) = MlKem768::generate(&mut rng);

    let keypair = HybridKeypair {
        x25519_secret,
        x25519_public,
        mlkem768_secret,
        mlkem768_public,
    };

    Ok((keypair.secret_key_bytes(), keypair.public_key_bytes()))
}

/// Convenience wrapper for Wasm exports: encapsulate to public key bytes
pub fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if public_key.len() != HYBRID_PUBLIC_KEY_SIZE {
        return Err(format!(
            "Invalid public key length: expected {}, got {}",
            HYBRID_PUBLIC_KEY_SIZE,
            public_key.len()
        ));
    }

    let x25519_pk = &public_key[..X25519_PUBLIC_KEY_SIZE];
    let mlkem768_pk = &public_key[X25519_PUBLIC_KEY_SIZE..];

    let (ct, ss) = hybrid_encapsulate(x25519_pk, mlkem768_pk)?;
    Ok((ss, ct.to_bytes()))
}

/// Convenience wrapper for Wasm exports: decapsulate using secret key and ciphertext
pub fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != HYBRID_SECRET_KEY_SIZE {
        return Err(format!(
            "Invalid secret key length: expected {}, got {}",
            HYBRID_SECRET_KEY_SIZE,
            secret_key.len()
        ));
    }

    if ciphertext.len() != HYBRID_CIPHERTEXT_SIZE {
        return Err(format!(
            "Invalid ciphertext length: expected {}, got {}",
            HYBRID_CIPHERTEXT_SIZE,
            ciphertext.len()
        ));
    }

    let x25519_sk = &secret_key[..X25519_SECRET_KEY_SIZE];
    let mlkem768_sk = &secret_key[X25519_SECRET_KEY_SIZE..];

    let ct = HybridCiphertext::from_bytes(ciphertext)?;
    hybrid_decapsulate(x25519_sk, mlkem768_sk, &ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keypair_generation() {
        let keypair = HybridKeypair::generate();
        assert_eq!(keypair.public_key_bytes().len(), HYBRID_PUBLIC_KEY_SIZE);
        assert_eq!(keypair.secret_key_bytes().len(), HYBRID_SECRET_KEY_SIZE);
    }

    #[test]
    fn test_hybrid_encapsulate_decapsulate() {
        let recipient = HybridKeypair::generate();

        let (ct, ss_sender) = hybrid_encapsulate(
            recipient.x25519_public.as_bytes(),
            recipient.mlkem768_public.as_bytes().as_slice(),
        )
        .expect("Encapsulation should succeed");

        let ss_receiver = hybrid_decapsulate(
            recipient.x25519_secret.as_bytes(),
            recipient.mlkem768_secret.as_bytes().as_slice(),
            &ct,
        )
        .expect("Decapsulation should succeed");

        assert_eq!(ss_sender, ss_receiver);
        assert_eq!(ss_sender.len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_hybrid_ciphertext_serialization() {
        let keypair = HybridKeypair::generate();
        let (ct, _) = hybrid_encapsulate(
            keypair.x25519_public.as_bytes(),
            keypair.mlkem768_public.as_bytes().as_slice(),
        )
        .unwrap();

        let bytes = ct.to_bytes();
        assert_eq!(bytes.len(), HYBRID_CIPHERTEXT_SIZE);

        let parsed = HybridCiphertext::from_bytes(&bytes).expect("Parsing should succeed");

        assert_eq!(parsed.mlkem768_ct, ct.mlkem768_ct);
        assert_eq!(parsed.x25519_ephemeral_pk, ct.x25519_ephemeral_pk);
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let keypair1 = HybridKeypair::generate();
        let keypair2 = HybridKeypair::generate();

        let (_, ss1) = hybrid_encapsulate(
            keypair1.x25519_public.as_bytes(),
            keypair1.mlkem768_public.as_bytes().as_slice(),
        )
        .unwrap();

        let (_, ss2) = hybrid_encapsulate(
            keypair2.x25519_public.as_bytes(),
            keypair2.mlkem768_public.as_bytes().as_slice(),
        )
        .unwrap();

        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_mlkem_encapsulate_decapsulate() {
        let (sk, pk) = mlkem_generate_keypair();
        let (ct, ss_sender) = mlkem_encapsulate(&pk).expect("Encapsulation should succeed");
        let ss_receiver = mlkem_decapsulate(&sk, &ct).expect("Decapsulation should succeed");
        assert_eq!(ss_sender, ss_receiver);
    }
}
