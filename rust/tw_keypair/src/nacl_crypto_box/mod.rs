// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2017 Trust Wallet.

use crate::{KeyPairError, KeyPairResult};
use crypto_box::aead::Aead;
use tw_hash::H192;
use tw_memory::Data;

pub mod public_key;
pub mod secret_key;

use public_key::PublicKey;
use secret_key::SecretKey;

const NONCE_LEN: usize = H192::LEN;

pub struct CryptoBox;

impl CryptoBox {
    /// Encrypts message using `other_pubkey` and `my_secret`.
    /// The output will have a randomly generated nonce prepended to it.
    /// The output will be Overhead + 24 bytes longer than the original.
    pub fn encrypt_easy(
        my_secret: &SecretKey,
        other_pubkey: &PublicKey,
        message: &[u8],
    ) -> KeyPairResult<Data> {
        use crate::rand::OsRng;
        use crypto_box::aead::AeadCore;

        let nonce = crypto_box::SalsaBox::generate_nonce(&mut OsRng);
        let nonce = H192::try_from(nonce.as_slice()).map_err(|_| KeyPairError::InternalError)?;
        let encrypted = Self::encrypt(my_secret, other_pubkey, message, nonce)?;

        let ecrypted_with_nonce: Data = nonce
            .as_slice()
            .iter()
            .chain(encrypted.iter())
            .copied()
            .collect();
        Ok(ecrypted_with_nonce)
    }

    /// Encrypts message using `other_pubkey`, `my_secret` and explicit `nonce`.
    pub fn encrypt(
        my_secret: &SecretKey,
        other_pubkey: &PublicKey,
        message: &[u8],
        nonce: H192,
    ) -> KeyPairResult<Data> {
        let nonce = crypto_box::Nonce::from(nonce.take());
        let salsa_box = crypto_box::SalsaBox::new(other_pubkey.inner(), my_secret.inner());
        salsa_box
            .encrypt(&nonce, message)
            .map_err(|_| KeyPairError::InternalError)
    }

    /// Decrypts box produced by [`CryptoBox::encrypt_easy`].
    /// We assume a 24-byte nonce is prepended to the encrypted text in box.
    pub fn decrypt_easy(
        my_secret: &SecretKey,
        other_pubkey: &PublicKey,
        encrypted_with_nonce: &[u8],
    ) -> KeyPairResult<Data> {
        if encrypted_with_nonce.len() < NONCE_LEN {
            return Err(KeyPairError::InvalidEncryptedMessage);
        }

        let nonce = H192::try_from(&encrypted_with_nonce[..NONCE_LEN])
            .map_err(|_| KeyPairError::InternalError)?;
        let encrypted = &encrypted_with_nonce[NONCE_LEN..];

        Self::decrypt(my_secret, other_pubkey, encrypted, nonce)
    }

    /// Decrypts a box produced by [`CryptoBox::encrypt`] by using the same `nonce`.
    pub fn decrypt(
        my_secret: &SecretKey,
        other_pubkey: &PublicKey,
        encrypted: &[u8],
        nonce: H192,
    ) -> KeyPairResult<Data> {
        let nonce = crypto_box::Nonce::from(nonce.take());
        let salsa_box = crypto_box::SalsaBox::new(other_pubkey.inner(), my_secret.inner());
        salsa_box
            .decrypt(&nonce, encrypted)
            .map_err(|_| KeyPairError::InvalidEncryptedMessage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_encoding::hex::ToHex;
    use tw_hash::H256;

    /// This test uses values generated by using https://github.com/kevinburke/nacl library.
    #[test]
    fn test_encrypt_decrypt() {
        let my_secret =
            H256::from("d465226bebafda6bcd6e1783712e9f7fad6385ef2210630887b6564cb4f6e051");
        let my_secret = SecretKey::try_from(my_secret.as_slice()).unwrap();
        let my_public = my_secret.public_key();

        let other_secret =
            H256::from("dd87000d4805d6fbd89ae1352f5e4445648b79d5e901c92aebcb610e9be468e4");
        let other_secret = SecretKey::try_from(other_secret.as_slice()).unwrap();
        let other_public = other_secret.public_key();

        // 7a7b9c8fee6e3c597512848c7d513e7131193cdfd410ff6611522fdeea99d7160873182019d7a18502f22c5e3644d26a2b669365
        let nonce = H192::from("7a7b9c8fee6e3c597512848c7d513e7131193cdfd410ff66");
        let message = b"Hello, world";

        let encrypted = CryptoBox::encrypt(&my_secret, &other_public, message, nonce).unwrap();
        assert_eq!(
            encrypted.to_hex(),
            "11522fdeea99d7160873182019d7a18502f22c5e3644d26a2b669365"
        );

        // Step 2. Make sure the Box can be decrypted by the other side.
        let decrypted = CryptoBox::decrypt(&other_secret, &my_public, &encrypted, nonce).unwrap();
        assert_eq!(
            decrypted, message,
            "Decrypted message differs from the original message"
        );
    }

    #[test]
    fn test_encrypt_decrypt_easy() {
        let my_secret = SecretKey::random();
        let my_public = my_secret.public_key();

        let other_secret = SecretKey::random();
        let other_public = other_secret.public_key();

        let message = b"Test message to be encrypted";

        let encrypted_with_nonce =
            CryptoBox::encrypt_easy(&my_secret, &other_public, message).unwrap();

        // Step 2. Make sure the Box can be decrypted by the other side.
        let decrypted =
            CryptoBox::decrypt_easy(&other_secret, &my_public, &encrypted_with_nonce).unwrap();
        assert_eq!(
            decrypted, message,
            "Decrypted message differs from the original message"
        );
    }
}
