mod aes;

use aes::gcm::{GcmError, GcmInstance};
use aes::Key;
use clap::{Parser, ValueEnum};
use rpassword::read_password;
use std::env;
use std::path::PathBuf;

/*
 * try to get rid of clap and rpassword, just std if possible
 * I don't really like this main file
 */

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
    let key_text_1 = read_password().expect("Failed to read password");
    println!("Confirm Key:");
    let key_text_2 = read_password().expect("Failed to read password");

    if key_text_1 != key_text_2 {
        println!("Key inputs do not match, aborting");
        return;
    }
    let key = Key::parse(key_text_1);

    match args.op {
        Mode::Encrypt => handle_encryption(key, args.path),
        Mode::Decrypt => handle_decryption(key, args.path),
    }
}

fn handle_encryption(key: Key, file: PathBuf) {
    let key_val = key.extract();
    let gcm = GcmInstance::new(key_val);

    if let Err(err) = gcm.encrypt(file) {
        handle_gcm_error(err);
    }
}

fn handle_decryption(key: Key, file: PathBuf) {
    let key_val = key.extract();
    let gcm = GcmInstance::new(key_val);

    if let Err(err) = gcm.decrypt(file) {
        handle_gcm_error(err);
    }
}

fn handle_gcm_error(err: GcmError) {
    match err {
        GcmError::TagMismatch => {
            eprintln!("Tag mismatch error");
            eprintln!("Either this is not an htmc file, the file may have been tampered with or the key is incorrect");
        }
        GcmError::IoError(io_err) => {
            eprintln!("IO error: {}", io_err);
        }
    }
}
