extern "C" {
    fn aesni_gen_key_schedule(key: *const u8, key_schedule: *mut u32);
    fn aesni_encrypt_block(input_block: *const u8, output_block: *mut u8, key_schedule: *const u32);
    fn aesni_decrypt_block(input_block: *const u8, output_block: *mut u8, key_schedule: *const u32);
}

fn main() {
    let key: u128 = 1;
    let mut key_schedule: [u32; 44] = [0; 44];
    let test_block: u128 = 1;
    let encrypted_block: u128 = 0;
    let decrypted_block: u128 = 0;

    // to_ne_bytes is copying so not ok
    let key_bytes = key.to_ne_bytes();
    let test_block_bytes = test_block.to_ne_bytes();
    let mut encrypted_block_bytes = encrypted_block.to_ne_bytes();
    let mut decrypted_block_bytes = decrypted_block.to_ne_bytes();

    unsafe {
        aesni_gen_key_schedule(key_bytes.as_ptr(), key_schedule.as_mut_ptr());
        aesni_encrypt_block(test_block_bytes.as_ptr(), encrypted_block_bytes.as_mut_ptr(), key_schedule.as_ptr());
        aesni_decrypt_block(encrypted_block_bytes.as_ptr(), decrypted_block_bytes.as_mut_ptr(), key_schedule.as_ptr());
    }

    for byte in &decrypted_block_bytes {
        print!("{:02x} ", byte);
    }
}
