fn main() {
    const FILES: [&str; 5] = [
        "aes_ni/asm/aesni_encrypt_block.s",
        "aes_ni/asm/aesni_decrypt_block.s",
        "aes_ni/asm/aesni_gen_decryption_key_schedule.s",
        "aes_ni/asm/aesni_gen_encryption_key_schedule.s",
        "gcm/clmul/asm/clmul_gf.s",
    ];

    const ROOT: &str = "src/aes/";
    let paths = FILES.iter().map(|file| format!("{}{}", ROOT, file));

    let mut nasm = nasm_rs::Build::new();
    let mut linker = cc::Build::new();

    nasm.files(paths);
    nasm.include(ROOT);

    for o in nasm.compile_objects().expect(
        "
        Compiling NASM files:
        Ensure it is installed and in your path
        https://www.nasm.us/",
    ) {
        linker.object(o);
    }
    linker.compile("hermetica");
}
