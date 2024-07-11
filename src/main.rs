mod aes;

use std::env;
use aes::Key;
use std::path::PathBuf;
use rpassword::prompt_password;
use aes::gcm::{GcmError, GcmInstance, GcmMode};

fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Hermetica: hardware accelerated aes-gcm file encryption");
        eprintln!("Copyright (C) 2024 Alejandro Cadarso\n");
        eprintln!("Usage: hermetica -e <file> for encryption");
        eprintln!("       hermetica -d <file> for decryption");
        return;
    }

    let mode = match args[1].as_str() {
        "-e" => GcmMode::Encryption,
        "-d" => GcmMode::Decryption,
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
    let key_val = key.extract();
    let gcm = GcmInstance::new(key_val);

    let runner = match mode {
        GcmMode::Encryption => gcm.encrypt(file),
        GcmMode::Decryption => gcm.decrypt(file),
    };

    match runner {
        Ok((tag, output_path)) => {
            println!("Operation completed successfully.");
            println!("Output file: {:?}", output_path);
            println!("Tag: {:032x}", tag);
        }
        Err(err) => handle_gcm_error(err),
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
        GcmError::BarError(bar_err) => {
            eprintln!("Indicatif styling error: {}", bar_err);
        }
        GcmError::ThreadJoinError(thread_err) => {
            eprintln!("Parallel processing error: {:?}", thread_err);
        }
    }
}
