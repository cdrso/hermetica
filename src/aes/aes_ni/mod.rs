extern "C" {
    pub(crate) fn aesni_gen_encryption_key_schedule(
        key: *const u8,
        encryption_key_schedule: *mut u32,
    );

    pub(crate) fn aesni_gen_decryption_key_schedule(
        encryption_key_schedule: *const u32,
        decryption_key_schedule: *mut u32,
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
