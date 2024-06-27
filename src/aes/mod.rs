pub mod aes_ni;
pub mod gcm;
use bytemuck::{bytes_of, bytes_of_mut};

pub struct Key {
    value: u128,
}

impl Key {
    pub fn parse(key_text: String) -> Self {
        let mut key_bytes = key_text.as_bytes();
        let mut key_len = key_bytes.len();

        //todo
        if key_len == 0 {
            println!("Fuck you");
        }

        if key_len > 16 {
            key_len = 16;
            key_bytes = &key_bytes[0..16]
        }

        let mut key_bytes_array = [0u8; 16];
        key_bytes_array[..key_len].copy_from_slice(key_bytes);

        Self {
            value: u128::from_ne_bytes(key_bytes_array),
        }
    }

    pub fn extract(&self) -> u128 {
        self.value
    }
}

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
