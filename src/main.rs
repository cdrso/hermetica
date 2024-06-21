mod aes;
use std::env;
use std::path::PathBuf;

fn main() {
    env::set_var("RUST_BACKTRACE", "1");

    let key: u128 = 1;

    let input = PathBuf::from("/home/alejandro/acnDev/hermetica/test_files/correct_software.mp4");
    //input.set_file_name("file.txt");

    let encrypted_file = PathBuf::from("/home/alejandro/acnDev/hermetica/test_files/correct_software.hmtc");
    //output.set_file_name("cypher.txt");

    let output = PathBuf::from("/home/alejandro/acnDev/hermetica/test_files/decypher.mp4");
    //output.set_file_name("cypher.txt");

    //let encrypt = Encrypt::new(key, &input);
    //encrypt.run(&output);

    let encrypt_gcm = aes::gcm::GcmEncrypt::new(key, input, encrypted_file.clone()).expect("hehe");
    let _ = encrypt_gcm.encrypt();

    let decrypt_gcm = aes::gcm::GcmDecrypt::new(key, encrypted_file, output).expect("huha");
    let _ = decrypt_gcm.decrypt();

    //let decrypt = Decrypt::new(key, &output);
    //decrypt.run(&decrypted_output);
}
