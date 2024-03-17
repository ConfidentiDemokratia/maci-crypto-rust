# Rust Crypto FFI Library for [MACI](https://maci.pse.dev/docs/primitives/)

This Rust library provides a set of cryptographic operations designed to support Minimal Anti-Collusion Infrastructure (
MACI), in places, where using native TypeScript Code is not supported.

Through a Foreign Function
Interface (FFI), these operations can be utilized by various programming languages, enabling the integration of secure,
private voting in diverse systems. In our case, we are using this library to introduce the MACI project to iOS targets.

## Features

Our library exports a collection of cryptographic functions essential for ensuring the anonymity and privacy of votes,
including:

- **Encryption and Decryption**: Securely encrypt and decrypt messages using public and private key pairs.
- **Extended Signature and Key Generation**: Generate extended signatures and cryptographic keys for enhanced security
  measures.

These functionalities are crucial for the development of systems that require secure, anonymous communication channels,
such as private voting mechanisms in decentralized applications.

## Exported Functions

The library provides the following namespace with cryptographic functions:

```rust
namespace example {
// Encrypts a message using a private and a public key.
bytes encrypt(bytes prk, bytes pbk, bytes message);

// Decrypts an encrypted message using a private and a public key.
bytes decrypt(bytes prk, bytes pbk, bytes enc);

// Generates an extended signature public key.
bytes ext_sign_pubkey(bytes to_sign, bytes prk);

// Generates cryptographic keys from signed bytes.
bytes ext_generate_keys(bytes signed_bytes);
};
```

## Future Work

### Merge Cryptography

We plan to merge the functionality of our current cryptographic schemes with the following:

- **Poseidon-ark and BabyJubJub-ark**: To be integrated with
- **Dusk-Poseidon and Dusk-JubJub**: Implementing equivalent functionalities.

### Testing Consistency

Add tests to ensure the consistency of the cryptographic operations with the TypeScript implementation. 
