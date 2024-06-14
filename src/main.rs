mod aes;
use crate::aes::*;
use std::path::PathBuf;

fn main() {
    let key: u128 = 1;

    let input = PathBuf::from("/home/acn/Dev/hermetica/src/file.txt");
    //input.set_file_name("file.txt");

    let output = PathBuf::from("/home/acn/Dev/hermetica/src/cypher.txt");
    //output.set_file_name("cypher.txt");

    let decrypted_output = PathBuf::from("/home/acn/Dev/hermetica/src/decypher.txt");
    //output.set_file_name("cypher.txt");

    let encrypt = Encrypt::new(key, &input);
    encrypt.run(&output);

    let decrypt = Decrypt::new(key, &output);
    decrypt.run(&decrypted_output);
}
