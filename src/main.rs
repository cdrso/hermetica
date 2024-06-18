mod aes;
use std::path::PathBuf;
use std::env;

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    let key: u128 = 1;

    let input = PathBuf::from("/home/alejandro/acnDev/hermetica/test_files/file.txt");
    //input.set_file_name("file.txt");

    //let output = PathBuf::from("/home/acn/Dev/hermetica/src/cypher.txt");
    //output.set_file_name("cypher.txt");

    let encrypted_file = PathBuf::from("/home/alejandro/acnDev/hermetica/test_files/file.hmtc");
    //output.set_file_name("cypher.txt");

    //let encrypt = Encrypt::new(key, &input);
    //encrypt.run(&output);

    let encrypt_gcm = aes::gcm::GcmEncrypt::new(key, input).expect("hehe");
    let _ = encrypt_gcm.encrypt();

    let decrypt_gcm = aes::gcm::GcmDecrypt::new(key, encrypted_file).expect("huha");
    let _ = decrypt_gcm.decrypt();

    //let decrypt = Decrypt::new(key, &output);
    //decrypt.run(&decrypted_output);
}
