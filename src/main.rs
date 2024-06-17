mod aes;
use aes::gcm::{GcmDecrypt, GcmEncrypt};

use crate::aes::*;
use std::path::PathBuf;

fn main() {
    let key: u128 = 1;

    let input = PathBuf::from("/home/alejandro/acnDev/hermetica/src/file.txt");
    //input.set_file_name("file.txt");

    //let output = PathBuf::from("/home/acn/Dev/hermetica/src/cypher.txt");
    //output.set_file_name("cypher.txt");

    let encrypted_file = PathBuf::from("/home/alejandro/acnDev/hermetica/src/file.hmtc");
    //output.set_file_name("cypher.txt");

    /*
    let encrypt = Encrypt::new(key, &input);
    encrypt.run(&output);
    */

    unsafe {
        let mut encrypt_gcm = GcmEncrypt::new(key, input);
        encrypt_gcm.encrypt();

        let mut decrypt_gcm = GcmDecrypt::new(key, encrypted_file);
        decrypt_gcm.decrypt();
    }

    /*
    let decrypt = Decrypt::new(key, &output);
    decrypt.run(&decrypted_output);
    */
}
