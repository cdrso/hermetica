pub mod aes_ni;
pub mod gcm;
use bytemuck::{bytes_of, bytes_of_mut};

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
