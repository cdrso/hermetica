mod aes;

use aes::gcm::{DecryptorInstance, EncryptorInstance, GcmError};
use clap::{Parser, ValueEnum};
use rpassword::read_password;
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::exit;

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

    // Parse dont validate!
    // struct key(u128)
    println!("Insert Key");
    let key_input_1 = read_password().expect("Failed to read password");

    println!("Confirm Key");
    let key_input_2 = read_password().expect("Failed to read password");

    if key_input_1 != key_input_2 {
        println!("Key inputs do not match, aborting");
        exit(1);
    }

    let key_bytes = key_input_1.as_bytes();
    let key_len = key_bytes.len();
    let sliced_key_bytes = if key_len > 16 {
        &key_bytes[0..16]
    } else {
        key_bytes
    };

    let mut key_bytes_array = [0u8; 16];
    key_bytes_array[..sliced_key_bytes.len()].copy_from_slice(sliced_key_bytes);

    let key = u128::from_ne_bytes(key_bytes_array);

    match args.op {
        Mode::Encrypt => handle_encryption(key, &args.path),
        Mode::Decrypt => handle_decryption(key, &args.path),
    }
}

fn handle_encryption(key: u128, input_path: &PathBuf) {
    let output_path = input_path.clone();
    let mut os_string: OsString = output_path.into();
    os_string.push(".hmtc");
    let output_path: PathBuf = os_string.into();

    let mut gcm =
        EncryptorInstance::new(key, input_path.clone(), output_path.clone()).expect("test");
    if let Err(err) = gcm.encrypt() {
        handle_gcm_error(*err);
    } else {
        println!("Encryption successful! Encrypted file: {:?}", output_path);
    }
}

fn handle_decryption(key: u128, input_path: &PathBuf) {
    let mut output_path = input_path.clone();
    output_path.set_extension(""); // Removes extension

    let mut gcm =
        DecryptorInstance::new(key, output_path.clone(), input_path.clone()).expect("test");
    if let Err(err) = gcm.decrypt() {
        handle_gcm_error(*err);
    } else {
        println!("Decryption successful! Decrypted file: {:?}", output_path);
    }
}

fn handle_gcm_error(err: GcmError) {
    match err {
        GcmError::TagMismatch => {
            eprintln!("Tag mismatch error");
            eprintln!("The file may have been tampered with or the key is incorrect");
        }
        GcmError::IoError(io_err) => {
            eprintln!("IO error: {}", io_err);
        }
    }
}
