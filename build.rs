fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo::rerun-if-changed=src/hello.c");

    const FILES: [&str; 4] = [
        "aesni_gen_key_schedule.s",
        "aesni_gen_key_schedule_decrypt.s",
        "aesni_encrypt_block.s",
        "aesni_decrypt_block.s",
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
