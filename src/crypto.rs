use ark_ff::{BigInt, BigInteger, PrimeField};
use babyjubjub_ark::{Fr, PrivateKey};
use poseidon_ark::Poseidon;
use sha3::{Digest, Sha3_256};

pub fn ext_generate_pubkey(raw_sign: Vec<u8>) -> Vec<u8> {
    let res = generate_pubkey(raw_sign);
    let mut result = Vec::new();
    result.extend_from_slice(&res.0);
    result.extend_from_slice(&res.1);
    result
}

/// Function takes the raw users signature over the message "MACI"
/// And returns a corresponding BabyJubJub public key
/// Which is obtained by hashing the signature and converting it to a field element
pub fn generate_pubkey(raw_sign: Vec<u8>) -> ([u8; 32], [u8; 32]) {

    // Use SHA256 hash function to hash the signature bytes
    let mut hasher = Sha3_256::new();

    // Write an input message
    hasher.update(raw_sign);

    // Read hash digest and consume hasher
    let result = hasher.finalize();

    let hashed_sign: [u8; 32] = result.into();

    // Convert the hash to a field element of BBJJ curve - private key
    let priv_key = PrivateKey::import(Vec::from(hashed_sign)).unwrap();

    // Convert Private Key to Public Key
    let public_key = priv_key.public();

    let (x, y) = (public_key.x, public_key.y);

    /// Serialise - 
    /// TODO - check this is consisent with TS Version, that is that the public key is of the same format in both
    return (convert_u64_to_bytes32(x.0.0), convert_u64_to_bytes32(y.0.0));
}


// Converts the field element to bytes32
fn convert_u64_to_bytes32(pp_str: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32]; // Initialize a 32-byte array filled with zeros

    for (i, &num) in pp_str.iter().enumerate() {
        let offset = i * 8; // Calculate the offset for each u64
        bytes[offset..offset + 8].copy_from_slice(&num.to_be_bytes());
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pubkey() {
        let raw_sign = vec![0u8; 100];
        let (x, y) = generate_pubkey(raw_sign);
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        println!("Public Key: {:?}, {:?}", x, y)
    }

    #[test]
    fn test_convert_fr_to_bytes32() {
        let pk = PrivateKey {
            key: [0; 32]
        };

        let pubk = pk.public();

        println!("Public Key: {:?}", pubk.x.0.to_string());
    }
}