pub mod aes_ni;
pub mod gcm;

use sha256;
use zeroize::Zeroize;
use bytemuck::{bytes_of, bytes_of_mut};

/// Newtype for aes key.
pub struct Key {
    value: u128,
}

impl Key {
    /// Generates Key struct from text input.
    pub fn parse(key_text: &str) -> Self {
        let hash = sha256::digest(key_text);

        let mut key = [0u8; 16];
        key.copy_from_slice(&hash.as_bytes()[..16]);

        Self { value: u128::from_ne_bytes(key) }
    }

    /// Getter for numeric key value.
    pub fn extract(&self) -> u128 {
        self.value
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Generates aes key schedule.
pub(crate) fn gen_encryption_key_schedule(key: u128) -> [u32; 44] {
    let mut encryption_key_schedule: [u32; 44] = [0; 44];
    unsafe {
        aes_ni::aesni_gen_encryption_key_schedule(
            bytes_of(&key).as_ptr(),
            encryption_key_schedule.as_mut_ptr(),
        );
    }

    encryption_key_schedule
}

#[allow(dead_code)]
/// Generates aes decrypting key schedule.
pub(crate) fn gen_decryption_key_schedule(encryption_key_schedule: [u32; 44]) -> [u32; 44] {
    let mut decryption_key_schedule: [u32; 44] = [0; 44];
    unsafe {
        aes_ni::aesni_gen_decryption_key_schedule(
            encryption_key_schedule.as_ptr(),
            decryption_key_schedule.as_mut_ptr(),
        )
    }

    decryption_key_schedule
}

/// Performs aes block encryption.
pub(crate) fn encrypt_block(encryption_key_schedule: [u32; 44], plain_text: u128) -> u128 {
    let mut cypher_text: u128 = 0;
    unsafe {
        aes_ni::aesni_encrypt_block(
            bytes_of(&plain_text).as_ptr(),
            bytes_of_mut(&mut cypher_text).as_mut_ptr(),
            encryption_key_schedule.as_ptr(),
        );
    }

    cypher_text
}

#[allow(dead_code)]
/// Performs aes block decryption.
pub(crate) fn decrypt_block(decryption_key_schedule: [u32; 44], cypher_text: u128) -> u128 {
    let mut plain_text: u128 = 0;
    unsafe {
        aes_ni::aesni_decrypt_block(
            bytes_of(&cypher_text).as_ptr(),
            bytes_of_mut(&mut plain_text).as_mut_ptr(),
            decryption_key_schedule.as_ptr(),
        );
    }

    plain_text
}

#[cfg(test)]

mod tests {
    use super::*;
    use rand::Rng;


    #[test]
    fn encrypt_decrypt_block() {
        let key_text = "test_key";
        let key = Key::parse(key_text);
        let key_val = key.extract();

        let enc_key_schedule = gen_encryption_key_schedule(key_val);
        let dec_key_schedule = gen_decryption_key_schedule(enc_key_schedule);

        let mut rng = rand::thread_rng();
        let block: u128 = rng.gen();

        let encrypted_block = encrypt_block(enc_key_schedule, block);
        let decrypted_block = decrypt_block(dec_key_schedule, encrypted_block);

        assert_eq!(block, decrypted_block)
    }
}
