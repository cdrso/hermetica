mod aes;

use aes::Key;
use std::env;
use std::path::PathBuf;
use rpassword::prompt_password;
use aes::gcm::{GcmError, GcmInstance};

enum Mode {
    Encryption,
    Decryption,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Hermetica: hardware accelerated aes-gcm file encryption");
        eprintln!("Copyright (C) 2024 Alejandro Cadarso\n");
        eprintln!("Usage: hermetica -e <file> for encryption");
        eprintln!("       hermetica -d <file> for decryption");
        return;
    }

    let mode = match args[1].as_str() {
        "-e" => Mode::Encryption,
        "-d" => Mode::Decryption,
        _ => {
            eprintln!("Invalid operation. Use -e for encryption or -d for decryption.");
            return;
        }
    };

    let file = PathBuf::from(&args[2]);

    let key_str_1 = prompt_password("Insert Key: ").expect("Failed to read password");
    let key_str_2 = prompt_password("Confirm Key: ").expect("Failed to read password");

    if key_str_1 != key_str_2 {
        println!("Key inputs do not match, aborting");
        return;
    }
    let key = Key::parse(key_str_1);

    match mode {
        Mode::Encryption => handle_encryption(key, file),
        Mode::Decryption => handle_decryption(key, file),
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
