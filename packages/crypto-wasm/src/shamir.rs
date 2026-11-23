use sharks::{Sharks, Share};
use hex;
use std::convert::TryFrom; 

pub fn split_secret(secret_hex: &str, threshold: u8, total: u8) -> Result<Vec<String>, String> {
    let secret = hex::decode(secret_hex)
        .map_err(|e| format!("Invalid hex secret: {}", e))?;

    if secret.is_empty() {
        return Err("Secret cannot be empty".to_string());
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    
    let shares: Vec<Share> = dealer.take(total as usize).collect();
    
    let mut shares_hex = Vec::new();
    for share in shares {
        let bytes: Vec<u8> = (&share).into(); 
        shares_hex.push(hex::encode(bytes));
    }
    
    Ok(shares_hex)
}

pub fn combine_shares(shares_hex: &[String], threshold: u8) -> Result<String, String> {
    let mut shares: Vec<Share> = Vec::new();
    
    for s in shares_hex {
        let bytes = hex::decode(s).map_err(|e| format!("Invalid share hex: {}", e))?;
        // Try convert back
        // If From invalid, we need another way.
        // Usually `Share::try_from(slice)` works. 
        // Note: verify if `Share` is `pub struct Share(pub(crate) Vec<u8>);`
        
        let share = Share::try_from(bytes.as_slice())
             .map_err(|e| format!("Invalid share data: {}", e))?;
             
        shares.push(share);
    }
    
    let sharks = Sharks(threshold);
    let secret_bytes = sharks.recover(&shares)
        .map_err(|e| format!("Recovery failed: {}", e))?;
        
    Ok(hex::encode(secret_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_combine() {
        let secret = "deadbeef";
        let threshold = 3;
        let total = 5;
        
        let shares = split_secret(secret, threshold, total).expect("Split failed");
        assert_eq!(shares.len(), 5);
        
        let subset1 = &shares[0..3];
        let recovered = combine_shares(subset1, threshold).expect("Combine failed");
        assert_eq!(recovered, secret);
        
        let subset2 = &shares[0..2];
        let result = combine_shares(subset2, threshold);
        // sharks recover might fail OR return incorrect result depending on impl
        // But with Result return type, it implies validation check.
        assert!(result.is_err());
    }
}
