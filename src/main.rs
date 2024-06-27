mod aes;

use aes::gcm::{DecryptorInstance, EncryptorInstance, GcmError};
use aes::Key;
use clap::{Parser, ValueEnum};
use rpassword::read_password;
use std::env;
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

    println!("Insert Key:");
    let key_input_1 = read_password().expect("Failed to read password");
    println!("Confirm Key");
    let key_input_2 = read_password().expect("Failed to read password");

    if key_input_1 != key_input_2 {
        println!("Key inputs do not match, aborting");
        exit(1);
    }

    //type driven design
    let parsed_key = Key::parse(key_input_1);

    match args.op {
        Mode::Encrypt => handle_encryption(parsed_key, &args.path),
        Mode::Decrypt => handle_decryption(parsed_key, &args.path),
    }
}

fn handle_encryption(key: Key, input_path: &PathBuf) {
    let key = key.extract();
    let mut output_path = input_path.clone();
    output_path.as_mut_os_string().push(".hmtc");

    let mut gcm =
        EncryptorInstance::new(key, input_path.clone(), output_path.clone()).expect("test");
    if let Err(err) = gcm.encrypt() {
        handle_gcm_error(*err);
    } else {
        println!("Encryption successful! Encrypted file: {:?}", output_path);
    }
}

fn handle_decryption(key: Key, input_path: &PathBuf) {
    let key = key.extract();
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
            eprintln!("Either this is not an htmc file, the file has been tampered with or the key is incorrect");
        }
        GcmError::IoError(io_err) => {
            eprintln!("IO error: {}", io_err);
        }
    }
}
