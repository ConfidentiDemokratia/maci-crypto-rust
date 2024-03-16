use ark_bn254::fr::Fr as Fr_bn254;
use ark_ff::{BigInt, BigInteger, PrimeField};
use babyjubjub_ark::{Point, PrivateKey, Signature};
use dusk_jubjub::{BlsScalar, Fq, JubJubAffine};
use dusk_poseidon::PoseidonCipher;
use poseidon_ark::Poseidon;
use sha3::{Digest, Sha3_256};

uniffi::include_scaffolding!("example"); // "example" is the name of the .udl file

pub fn ext_generate_keys(signed_bytes: Vec<u8>) -> Vec<u8> {
    let (prk, pbk) = generate_keys(signed_bytes);
    let mut result = Vec::new();
    result.extend_from_slice(&prk);
    result.extend_from_slice(&pbk.0);
    result.extend_from_slice(&pbk.1);
    result
}

fn gen_dh_keypair(prk: Vec<u8>, pbk: Vec<u8>) -> Point {

    // Extract private key from bytes
    let priv_key = PrivateKey::import(prk).unwrap();

    // Extract public key from bytes
    // First, split the public key into x and y
    // Check if the size of the public key is correct
    if pbk.len() != 64 {
        panic!("Public key is not of the correct size");
    }
    let x_bytes = &pbk[0..32];
    let y_bytes = &pbk[32..64];
    let x = Fr_bn254::from_be_bytes_mod_order(x_bytes);
    let y = Fr_bn254::from_be_bytes_mod_order(y_bytes);
    let pub_key = Point {
        x,
        y,
    };

    // Generate the shared secret
    let shared_secret = pub_key.mul_scalar(&priv_key.scalar_key());


    // Return the shared secret
    shared_secret
}


/// External function to be used by SWIFT
/// TODO - confirm that the function is consistent with the TS version
/// TODO - confirm the correct integration between two ARK versions
/// TODO - move all code to the same ARK version - DUSK
/// Encrypts a message using the Poseidon Cipher
pub fn encrypt(prk: Vec<u8>, pbk: Vec<u8>, message: Vec<u8>) -> Vec<u8> {

    // Make sure that the message has no more than 64 bytes
    assert!(message.len() == 64, "The message should be 64 bytes long");

    // Generate the shared secret
    let shared_secret = gen_dh_keypair(prk, pbk);
    let x_bytes = shared_secret.x.into_bigint().to_bytes_be();
    let y_bytes = shared_secret.y.into_bigint().to_bytes_be();

    let prepped_shared_secret = JubJubAffine::from_raw_unchecked(
        Fq::from_bytes(<&[u8; 32]>::try_from(&*x_bytes).unwrap()).unwrap(),
        Fq::from_bytes(<&[u8; 32]>::try_from(&*y_bytes).unwrap()).unwrap(),
    );

    // Generate a random nonce that will be public
    let nonce = BlsScalar::from(0);

    // Convert the message to a series of field elements
    let mut prepped_message = Vec::new();
    for i in (0..message.len()).step_by(32) {
        let f = if i + 32 <= message.len() {
            // Extract 8 bytes
            let slice = &message[i..i + 32];

            BlsScalar::from_bytes(<&[u8; 32]>::try_from(slice).unwrap())
        } else {
            // Extract the remaining bytes
            let slice = &message[i..];

            // TODO - remove this as it should throw an error

            // Extend the slice to 32 bytes
            let mut extended_slice = Vec::new();
            extended_slice.extend_from_slice(slice);
            extended_slice.extend_from_slice(&vec![0u8; 32 - slice.len()]);
            BlsScalar::from_bytes(<&[u8; 32]>::try_from(extended_slice.as_slice()).unwrap())
        };

        prepped_message.push(f.unwrap());
    }

    // Encrypt the message
    let cipher = PoseidonCipher::encrypt(&prepped_message, &prepped_shared_secret, &nonce);


    // Get the output of the cipher
    let enc_bytes = cipher.cipher().to_vec().iter().map(|x| x.to_bytes()).flatten().collect();

    enc_bytes
}


/// External function to be used by SWIFT
/// TODO - confirm that the function is consistent with the TS version
/// Decrypts a message which was encrypted by the Poseidon Cipher
pub fn decrypt(prk: Vec<u8>, pbk: Vec<u8>, enc: Vec<u8>) -> Vec<u8> {

    // Generate the shared secret
    let shared_secret = gen_dh_keypair(prk, pbk);
    let x_bytes = shared_secret.x.into_bigint().to_bytes_be();
    let y_bytes = shared_secret.y.into_bigint().to_bytes_be();

    let prepped_shared_secret = JubJubAffine::from_raw_unchecked(
        Fq::from_bytes(<&[u8; 32]>::try_from(&*x_bytes).unwrap()).unwrap(),
        Fq::from_bytes(<&[u8; 32]>::try_from(&*y_bytes).unwrap()).unwrap(),
    );

    // Generate a random nonce that will be public
    let nonce = BlsScalar::from(0);

    // Convert the message to a series of field elements
    let mut prepped_enc = Vec::new();
    for i in (0..enc.len()).step_by(32) {
        let f = if i + 32 <= enc.len() {
            // Extract 8 bytes
            let slice = &enc[i..i + 32];

            BlsScalar::from_bytes(<&[u8; 32]>::try_from(slice).unwrap())
        } else {
            // Extract the remaining bytes
            let slice = &enc[i..];

            // TODO - remove this as it should throw an error
            // Extend the slice to 32 bytes
            let mut extended_slice = Vec::new();
            extended_slice.extend_from_slice(slice);
            extended_slice.extend_from_slice(&vec![0u8; 32 - slice.len()]);
            BlsScalar::from_bytes(<&[u8; 32]>::try_from(extended_slice.as_slice()).unwrap())
        };

        prepped_enc.push(f.unwrap());
    }

    // Encrypt the message
    // Check that the prepped_enc has size 3
    assert!(prepped_enc.len() == 3, "The size of the prepped_enc is not 3");

    let prepped_enc = [prepped_enc[0], prepped_enc[1], prepped_enc[2]];

    let cipher = PoseidonCipher::new(prepped_enc);
    let message = PoseidonCipher::decrypt(&cipher, &prepped_shared_secret, &nonce).unwrap();

    message.to_vec().iter().map(|x| x.to_bytes()).flatten().collect()
}


/// External function to be used by SWIFT
/// TODO - confirm taht the function is consistent with the TS version
pub fn ext_sign_pubkey(to_sign: Vec<u8>, prk: Vec<u8>) -> Vec<u8> {
    let signature = sign_pubkey(to_sign, prk);
    // Serialise the signature
    let r_b8_x = convert_big_int_to_bytes32(signature.r_b8.x.into_bigint());
    let r_b8_y = convert_big_int_to_bytes32(signature.r_b8.y.into_bigint());
    let s = convert_big_int_to_bytes32(signature.s.into_bigint());

    // Combine the signature into a single byte array
    let mut result = Vec::new();
    result.extend_from_slice(&r_b8_x);
    result.extend_from_slice(&r_b8_y);
    result.extend_from_slice(&s);

    result
}

/// Function that takes a message to sign and a private key and returns a signature
fn sign_pubkey(to_sign: Vec<u8>, prk: Vec<u8>) -> Signature {

    // Extract private key from bytes
    let priv_key = PrivateKey::import(prk).unwrap();

    // Hash the to_sign message to a series of field elements
    let ra = hash_bytes(to_sign);

    // Sign the message

    // Sign the message
    priv_key.sign(ra).unwrap()
}

/// Function takes the raw users signature over the message "MACI"
/// And returns a corresponding BabyJubJub public key
/// Which is obtained by hashing the signature and converting it to a field element
pub fn generate_keys(raw_sign: Vec<u8>) -> ([u8; 32], ([u8; 32], [u8; 32])) {

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
    return (convert_big_int_to_bytes32(priv_key.scalar_key().into_bigint()), (convert_big_int_to_bytes32(x.0), convert_big_int_to_bytes32(y.0)));
}

pub fn hash_embedding(embedding: Vec<u8>) -> Vec<u8> {
    let hash_f = hash_bytes(embedding);

    // Return the hash
    return hash_f.into_bigint().to_bytes_be();
}

/// Functiont that takes a embedding as bytes and returns a Poseidon hash of the embedding
pub fn hash_bytes(embedding: Vec<u8>) -> ark_bn254::Fr {

    // Create a new Poseidon instance
    let poseidon = Poseidon::new();

    // Group the embedding into a field element by combining the 8 bytes into a single Field element
    // This should fit into the field element of the curve
    // As p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    // https://iden3-docs.readthedocs.io/en/latest/_downloads/33717d75ab84e11313cc0d8a090b636f/Baby-Jubjub.pdf
    // TODO - make sure this fits and is optimal

    // TODO - make this function consistent with the TS version
    let mut vec_f = Vec::new();

    for i in (0..embedding.len()).step_by(8) {
        let f = if i + 8 <= embedding.len() {
            // Extract 8 bytes
            let slice = &embedding[i..i + 8];

            Fr_bn254::from_le_bytes_mod_order(slice)
        } else {
            // Extract the remaining bytes
            let slice = &embedding[i..];

            Fr_bn254::from_le_bytes_mod_order(slice)
        };

        vec_f.push(f);
    }


    // Hash the embedding
    poseidon.hash(vec_f).unwrap()
}


// Converts the field element to bytes32
fn convert_big_int_to_bytes32(pp_str: BigInt<4>) -> [u8; 32] {
    let mut bytes = [0u8; 32]; // Initialize a 32-byte array filled with zeros

    for (i, &num) in pp_str.0.iter().enumerate() {
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
        let (prk, (x, y)) = generate_keys(raw_sign);
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        println!("Public Key: {:?}, {:?}", x, y)
    }

    #[test]
    fn test_hash_embedding() {
        let embedding = vec![0u8; 100];
        let hash = hash_embedding(embedding);
        assert_eq!(hash.len(), 32);
        println!("Hash: {:?}", hash)
    }

    #[test]
    fn test_convert_fr_to_bytes32() {
        let pk = PrivateKey {
            key: [0; 32]
        };

        let pubk = pk.public();

        println!("Public Key: {:?}", pubk.x.0.to_string());
    }

    #[test]
    fn test_sign_pubkey() {
        let to_sign = vec![0u8; 100];
        let prk = vec![0u8; 32];
        let signature = sign_pubkey(to_sign, prk);
        assert_eq!(signature.r_b8.x.0.0.len(), 4);
        assert_eq!(signature.r_b8.y.0.0.len(), 4);
        assert_eq!(signature.s.0.0.len(), 4);
        println!("Signature: {:?}", signature)
    }

    #[test]
    fn test_encrypt() {
        let prk = vec![0u8; 32];
        let pbk = vec![0u8; 64];
        let message = vec![0u8; 64];
        let enc = encrypt(prk, pbk, message);
        println!("Encrypted: {:?}", enc)
    }

    #[test]
    fn test_decrypt() {
        let prk = vec![0u8; 32];
        let pbk = vec![0u8; 64];
        let message = vec![1u8; 64];
        let enc = encrypt(prk.clone(), pbk.clone(), message.clone());
        let dec = decrypt(prk, pbk, enc);
        assert!(dec.len() > 0);
        assert_eq!(dec.len(), message.len());
        assert!(dec == message);
        println!("Original : {:?}", message);
        println!("Decrypted: {:?}", dec)
    }
}
