use std::{
    fs,
    io::{BufWriter, Write},
    path::PathBuf,
    u128,
};

extern "C" {
    pub(crate) fn aesni_gen_key_schedule(key: *const u8, key_schedule: *mut u32);

    pub(crate) fn aesni_gen_key_schedule_decrypt(
        key_schedule: *const u32,
        key_schedule_decrypt: *mut u32,
    );
    pub(crate) fn aesni_encrypt_block(
        input_block: *const u8,
        output_block: *mut u8,
        key_schedule: *const u32,
    );
    pub(crate) fn aesni_decrypt_block(
        input_block: *const u8,
        output_block: *mut u8,
        key_schedule: *const u32,
    );
}

pub struct Encrypt {
    key: u128,
    key_schedule: [u32; 44],
    plain_text: Vec<u128>,
}

pub struct Decrypt {
    key: u128,
    key_schedule_decrypt: [u32; 44],
    cypher_text: Vec<u128>,
}

impl Encrypt {
    pub fn new(key: u128, file: &PathBuf) -> Self {
        let file_data = fs::read(file).expect("Failed to read file");
        let mut plain_text: Vec<u128> = Vec::new();

        for block_slice in file_data.chunks(16) {
            let block_bytes: [u8; 16] = if block_slice.len() == 16 {
                // Directly convert the slice to an array if the length is 16
                block_slice.try_into().expect("slice with incorrect length")
            } else {
                // Pad the slice with zeros to reach 16 bytes
                let mut padded_block_bytes = [0u8; 16];
                padded_block_bytes[0..block_slice.len()].copy_from_slice(block_slice);
                padded_block_bytes
            };

            let block: u128 = u128::from_ne_bytes(block_bytes);
            plain_text.push(block);
        }

        let key_bytes = key.to_ne_bytes();
        let mut key_schedule: [u32; 44] = [0; 44];

        unsafe {
            aesni_gen_key_schedule(key_bytes.as_ptr(), key_schedule.as_mut_ptr());
        }

        Self {
            key,
            key_schedule,
            plain_text,
        }
    }

    fn encrypt_block(&self, block: u128) -> u128 {
        let encrypted_block: u128 = 0;

        let block_bytes = block.to_ne_bytes();
        let mut encrypted_block_bytes = encrypted_block.to_ne_bytes();

        unsafe {
            aesni_encrypt_block(
                block_bytes.as_ptr(),
                encrypted_block_bytes.as_mut_ptr(),
                self.key_schedule.as_ptr(),
            );
        }

        u128::from_ne_bytes(encrypted_block_bytes)
    }

    pub fn run(&self, output_path: &PathBuf) {
        let file = fs::File::create(output_path).expect("Unable to create file");
        let mut buf_writer = BufWriter::new(file);

        for block in self.plain_text.iter() {
            let cyphertext: u128 = Self::encrypt_block(&self, *block);
            buf_writer.write(&cyphertext.to_ne_bytes()).unwrap();
        }
        buf_writer.flush().unwrap();

        println!("Encryption completed successfully.");
    }
}

impl Decrypt {
    pub fn new(key: u128, file: &PathBuf) -> Self {
        let file_data = fs::read(file).expect("Failed to read file");
        let mut cypher_text: Vec<u128> = Vec::new();

        for block_slice in file_data.chunks(16) {
            let block_bytes: [u8; 16] = if block_slice.len() == 16 {
                // Directly convert the slice to an array if the length is 16
                block_slice.try_into().expect("slice with incorrect length")
            } else {
                // find better padding method than zeroes
                let mut padded_block_bytes = [0u8; 16];
                padded_block_bytes[0..block_slice.len()].copy_from_slice(block_slice);
                padded_block_bytes
            };

            let block: u128 = u128::from_ne_bytes(block_bytes);
            cypher_text.push(block);
        }

        let key_bytes = key.to_ne_bytes();
        let mut key_schedule: [u32; 44] = [0; 44];
        let mut key_schedule_decrypt: [u32; 44] = [0; 44];

        unsafe {
            aesni_gen_key_schedule(key_bytes.as_ptr(), key_schedule.as_mut_ptr());
            aesni_gen_key_schedule_decrypt(
                key_schedule.as_ptr(),
                key_schedule_decrypt.as_mut_ptr(),
            );
        }

        Self {
            key,
            key_schedule_decrypt,
            cypher_text,
        }
    }

    fn decrypt_block(&self, block: u128) -> u128 {
        let decrypted_block: u128 = 0;

        let block_bytes = block.to_ne_bytes();
        let mut decrypted_block_bytes = decrypted_block.to_ne_bytes();

        unsafe {
            aesni_decrypt_block(
                block_bytes.as_ptr(),
                decrypted_block_bytes.as_mut_ptr(),
                self.key_schedule_decrypt.as_ptr(),
            );
        }

        u128::from_ne_bytes(decrypted_block_bytes)
    }

    pub fn run(&self, output_path: &PathBuf) {
        let file = fs::File::create(output_path).expect("Unable to create file");
        let mut buf_writer = BufWriter::new(file);

        let len = &self.cypher_text.len();

        for (i, block) in self.cypher_text.iter().enumerate() {
            let plain_text: u128 = Self::decrypt_block(&self, *block);

            let mut plain_text_bytes = &plain_text.to_ne_bytes()[0..16];
            if i == len - 1 {
                let mut j = 16 - 1;
                while j > 0 && plain_text_bytes[j] == 0 {
                    plain_text_bytes = &plain_text_bytes[0..j];
                    j -= 1;
                }
            }

            buf_writer.write(plain_text_bytes).unwrap();
        }
        buf_writer.flush().unwrap();

        println!("Decryption completed successfully.");
    }
}

//test if file with just '1' and direct encryption of '1' give same result

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key: u128 = 987654321;
        let mut key_schedule: [u32; 44] = [0; 44];
        let mut key_schedule_decrypt: [u32; 44] = [0; 44];
        let test_block: u128 = 69;
        let encrypted_block: u128 = 0;
        let decrypted_block: u128 = 0;

        let key_bytes = key.to_ne_bytes();
        let test_block_bytes = test_block.to_ne_bytes();
        let mut encrypted_block_bytes = encrypted_block.to_ne_bytes();
        let mut decrypted_block_bytes = decrypted_block.to_ne_bytes();

        unsafe {
            aesni_gen_key_schedule(key_bytes.as_ptr(), key_schedule.as_mut_ptr());
            aesni_encrypt_block(
                test_block_bytes.as_ptr(),
                encrypted_block_bytes.as_mut_ptr(),
                key_schedule.as_ptr(),
            );
            aesni_gen_key_schedule_decrypt(
                key_schedule.as_ptr(),
                key_schedule_decrypt.as_mut_ptr(),
            );
            aesni_decrypt_block(
                encrypted_block_bytes.as_ptr(),
                decrypted_block_bytes.as_mut_ptr(),
                key_schedule_decrypt.as_ptr(),
            );
        }

        assert_eq!(
            u128::from_ne_bytes(test_block_bytes),
            u128::from_ne_bytes(decrypted_block_bytes)
        );
    }
}
