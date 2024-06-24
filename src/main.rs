mod aes;

use clap::{Parser, ValueEnum};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Parser)]
struct CommandLineArgs {
    #[arg(value_enum)]
    op: Mode,
    path: PathBuf,
}

#[derive(ValueEnum, Clone)]
enum Mode {
    #[value(alias = "-enc", alias = "--encrypt")]
    Encrypt,
    #[value(alias = "-dec", alias = "--decrypt")]
    Decrypt,
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    let args = CommandLineArgs::parse();

    println!("Insert Key");
    let key_input = rpassword::read_password().unwrap();

    let key_bytes = key_input.as_bytes();
    let key_len = key_bytes.len();
    let sliced_key_bytes = if key_len > 16 {
        &key_bytes[0..16]
    } else {
        key_bytes
    };

    let mut key_bytes_array = [0u8; 16];

    key_bytes_array[0..sliced_key_bytes.len()].copy_from_slice(&sliced_key_bytes);

    // Convert the key_bytes_array to u128
    let key = u128::from_ne_bytes(key_bytes_array);

    match args.op {
        Mode::Encrypt => {
            println!("Encrypting file: {:?}", args.path);
            let path = args.path.clone();
            let mut os_string: OsString = path.into();
            os_string.push(".hmtc");
            let output: PathBuf = os_string.into();
            let encrypt = aes::gcm::GcmEncrypt::new(key, args.path, output)
                .expect("input file does not exist");
            let _ = encrypt.encrypt();
        }
        Mode::Decrypt => {
            println!("Decrypting file: {:?}", args.path);
            let mut output = args.path.clone();
            output.set_extension("");
            let decrypt = aes::gcm::GcmDecrypt::new(key, args.path, output)
                .expect("input file does not exist");
            let _ = decrypt.decrypt();
        }
    }
}
