use crate::aes;
use std::path::PathBuf;
use std::{fs, u128, u8};
use std::io::{BufWriter, Write};

// IV IS 96 BIT AND CONCATENATED TO 32 BIT CTR

pub struct GcmEncrypt {
    iv: [u8; 96], // random (truly random)
    key_schedule: [u32; 44], // gen from user key
    plain_text: Vec<u8>, // file
    cypher_text: Vec<u8>,
    tag: u128
}

impl GcmEncrypt {
    pub fn new(key: u128, file: PathBuf) -> Self {
        let plain_text: Vec<u8> = fs::read(file).expect("Failed to read file");
        let cypher_text: Vec<u8> = vec![0; plain_text.len()];

        let iv: [u8; 96] = [0; 96];
        let tag: u128 = 0;

        let key_bytes = key.to_ne_bytes();

        let key_schedule;
        unsafe {
            key_schedule = aes::gen_key_schedule(key_bytes);
        }

        Self {
            iv,
            key_schedule,
            plain_text,
            cypher_text,
            tag
        }
    }

    pub fn encrypt(&mut self) {
        let mut offset = 0;

        /*
        self.cypher_text.splice(offset..offset+12, self.iv);
        offset += 12;
        */

        let mut ctr_index: u32 = 0;
        for plain_text_block in self.plain_text.chunks(16) {

            let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
            let ctr: [u8; 16] = ctr_vec.try_into().expect("hehe");

            let encrypted_counter = Self::encrypt_aes_block(&self, ctr);

            let mut cypher_text: [u8; 16] = [0; 16];
            for i in 0..16 {
                // what happens on last block?
                cypher_text[i] = encrypted_counter[i] ^ plain_text_block[i]
            }

            self.cypher_text.splice(offset..offset+16, cypher_text);

            ctr_index += 1;
            offset += 16;
        }

        self.set_tag();

        /*
        let file_buf = fs::File::create(encrypted_file).expect("Unable to create file");
        let mut buf_writer = BufWriter::new(file_buf);

        // first block is iv
        buf_writer.write(&self.iv.to_ne_bytes()).unwrap();

        let mut ctr: u128 = self.iv;
        for plain_text_block in self.plain_text.chunks(16) {
            let encrypted_counter  = Self::encrypt_block(&self, ctr.to_ne_bytes());

            let mut cypher_text: [u8; 16] = [0; 16];
            for i in 0..16 {
                // what happens on last block?
                // TODO
                cypher_text[i] = encrypted_counter[i] ^ plain_text_block[i]
            }
            ctr += 1;

            buf_writer.write(&cypher_text).unwrap();
        }
        buf_writer.flush().unwrap();

        println!("Encryption completed successfully.");
        */
    }

    fn encrypt_aes_block(&self, block_bytes: [u8; 16]) -> [u8; 16] {


        let encrypted_block_bytes;
        unsafe {
            encrypted_block_bytes = aes::encrypt(self.key_schedule, block_bytes);
        }

        encrypted_block_bytes
    }

    fn set_tag(&mut self) {
        let mut tag: [u8; 16] = [0; 16];
        let h = self.encrypt_aes_block(tag);

        for cypher_block in self.cypher_text.chunks(16) {
            let mult_h: [u8; 16] = Self::gf_mult(h, cypher_block.try_into().expect("hehe"));

            for i in 0..16 {
                tag[i] ^= mult_h[i];
            }
        }

        // xor len
        for i in 0..16 {
            tag[i] ^= self.plain_text.len().to_ne_bytes()[i];
        }

        // iv times h
        let iv: Vec<u8> = self.iv.into_iter().chain([0, 0, 0, 0]).collect();
        let mult_last: [u8; 16] = Self::gf_mult(iv.try_into().expect("guarrada gorda"), h);

        for i in 0..16 {
            tag[i] ^= mult_last[i];
        }

        self.tag = u128::from_ne_bytes(tag);
    }

    fn gf_mult(prod1: [u8; 16], prod2: [u8; 16]) -> [u8; 16] {
        let mut mult_h: [u8; 16] = [0; 16];

        for i in 0..16 {
            if prod1[i]!= 0 {
                for j in 0..16 {
                    mult_h[(i + j) % 16] ^= prod2[j];
                }
            }
        }

        mult_h
    }
}

pub struct GcmDecrypt {
    iv: u128, //first 128 bits of encrypted file
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt
    cypher_text: Vec<u8>, //file
    plain_text: Vec<u8>,
    tag: u128 //first 128 bits of encrypted file
}

impl GcmDecrypt {
    pub fn new(key: u128, file: PathBuf) -> Self{
        let cypher_text: Vec<u8> = fs::read(file).expect("Failed to read file");
        let plain_text: Vec<u8> = vec![0; cypher_text.len() - 32];

        let len = cypher_text.len();
        let iv: u128 = u128::from_ne_bytes(cypher_text[..16].try_into().expect("hehe")); // First 16 bytes
        let tag: u128 = u128::from_ne_bytes(cypher_text[len - 16..].try_into().expect("hehe")); // Last 16 bytes

        let key_bytes = key.to_ne_bytes();

        let key_schedule: [u32; 44];
        unsafe {
            key_schedule = aes::gen_key_schedule(key_bytes);
        }


        Self {
            iv,
            key_schedule,
            cypher_text,
            plain_text,
            tag
        }
    }

    pub fn decrypt(&mut self) {
        let mut offset = 0;

        /*
        self.cypher_text.splice(offset..offset+16, self.iv.to_ne_bytes());
        offset += 16;
        */

        let mut ctr: u128 = self.iv;
        for plain_text_block in self.plain_text.chunks(16) {
            let encrypted_counter  = Self::encrypt_aes_block(&self, ctr.to_ne_bytes());

            let mut cypher_text: [u8; 16] = [0; 16];
            for i in 0..16 {
                // what happens on last block?
                cypher_text[i] = encrypted_counter[i] ^ plain_text_block[i]
            }

            self.cypher_text.splice(offset..offset+16, cypher_text);

            ctr += 1;
            offset += 16;
        }

        //self.set_tag();
    }

    fn encrypt_aes_block(&self, block_bytes: [u8; 16]) -> [u8; 16] {

        let encrypted_block_bytes;
        unsafe {
            encrypted_block_bytes = aes::encrypt(self.key_schedule, block_bytes);
        }

        encrypted_block_bytes
    }
}


