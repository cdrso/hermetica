pub mod clmul;
use crate::aes;
use rand::Rng;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::path::PathBuf;
use std::io::Read;
use std::io::Write;

// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

pub(crate) fn gf_mult(operand_a: [u8; 16], operand_b: [u8; 16]) -> [u8; 16] {
    let mut product: [u8; 16] = [0; 16];
    unsafe {
        clmul::clmul_gf(operand_a.as_ptr(), operand_b.as_ptr(), product.as_mut_ptr());
    }

    product
}

// last block is not 128 bits but the size of the plain text, discard the rest

pub struct GcmEncrypt {
    iv: [u8; 12],            // random (truly random) | owned
    key_schedule: [u32; 44], // gen from user key | ownded
    plain_text: PathBuf,     // file path buf bufread bufwrite | not owned
    length: u64,
    cypher_text: Vec<u8>,    // path buf | owned
    tag: Option<[u8; 16]>,           //first 128 bits of encrypted file | owned
}

impl GcmEncrypt {
    pub fn new(key: u128, plain_text: PathBuf) -> Result<GcmEncrypt, Box<dyn Error>> {
        let length = fs::metadata(&plain_text)?.len();

        // check
        let cypher_text: Vec<u8> = vec![0; length.try_into()?];

        // https://csrc.nist.gov/pubs/sp/800/38/d/final
        let iv: [u8; 12] = rand::thread_rng().gen::<[u8; 12]>();

        let tag = None;

        let key_schedule = aes::gen_encryption_key_schedule(key.to_ne_bytes());

        Ok(Self {
            iv,
            key_schedule,
            plain_text,
            length,
            cypher_text,
            tag,
        })
    }

    pub fn encrypt(mut self) -> Result<(), Box<dyn Error>> {
        let file = File::open(&self.plain_text)?;
        let mut reader = BufReader::new(file);

        let mut offset = 0;
        let mut ctr_index: u32 = 1;
        let mut buffer: [u8; 16] = [0; 16];

        let mut tag: [u8; 16] = [0; 16];
        let h = aes::encrypt_block(self.key_schedule, tag);

        let read_range = match self.length%16 {
            0 => self.length/16,
            _ => self.length/16 + 1
        };

        for _ in 0..read_range - 1 {
            reader.read_exact(&mut buffer)?;

            let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
            let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

            let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
            let mut cypher_text: [u8; 16] = [0; 16];

            for i in 0..16 {
                cypher_text[i] = encrypted_counter[i] ^ buffer[i];
            }

            let mult_h: [u8; 16] = gf_mult(h, cypher_text);
            for i in 0..16 {
                tag[i] ^= mult_h[i];
            }

            self.cypher_text.splice(offset..offset + 16, cypher_text);

            ctr_index += 1;
            offset += 16;
        }

        let bytes_read = reader.read(&mut buffer)?;
        println!("bytes read last block: {}", bytes_read);

        let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
        let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

        let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
        let mut cypher_text: [u8; 16] = [0; 16];

        for i in 0..bytes_read {
            cypher_text[i] = encrypted_counter[i] ^ buffer[i];
        }

        let mult_h: [u8; 16] = gf_mult(h, cypher_text);
        for i in 0..16 {
            tag[i] ^= mult_h[i];
        }

        // hay que hacer esto, splice no funciona si no
        let last_cypher_text_vec = cypher_text[0..bytes_read].to_vec();

        self.cypher_text.splice(offset..offset + bytes_read, last_cypher_text_vec);
        assert_eq!(offset+bytes_read, self.length.try_into()?);


        // add lenght to tag
        for i in 0..16 {
            tag[i] ^= u128::from(self.length).to_ne_bytes()[i];
        }

        // add iv || 0 to tag
        let iv: Vec<u8> = self.iv.into_iter().chain([0, 0, 0, 0]).collect();
        let mult_last: [u8; 16] = gf_mult(iv.try_into().expect("guarrada gorda"), h);

        for i in 0..16 {
            tag[i] ^= mult_last[i];
        }

        self.tag = Some(tag);

        let output_file = fs::File::create("/home/alejandro/acnDev/hermetica/test_files/file.hmtc")
            .expect("Unable to create file");
        let mut buf_writer = BufWriter::new(output_file);

        buf_writer.write(&self.iv)?;
        buf_writer.write(&self.cypher_text)?;
        buf_writer.write(&self.tag.unwrap())?;
        buf_writer.flush()?;

        Ok(())
    }

}

pub struct GcmDecrypt {
    iv: Option<[u8; 12]>,            // random (truly random) | not owned?
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    cypher_text: PathBuf,    //file | not owned
    length: u64,
    plain_text: Vec<u8>,    // | owned
    tag: Option<[u8; 16]>,          //first 128 bits of encrypted file // | not owned
}

impl GcmDecrypt {
    pub fn new(key: u128, cypher_text: PathBuf) -> Result<GcmDecrypt, Box<dyn Error>> {
        let length = fs::metadata(&cypher_text)?.len()-28; //12 bytes IV 16 bytes tag
        let plain_text: Vec<u8> = vec![0; length.try_into()?];
        let key_schedule = aes::gen_encryption_key_schedule(key.to_ne_bytes());

        Ok(Self {
            iv: None,
            key_schedule,
            plain_text,
            length,
            cypher_text,
            tag: None,
        })
    }

    pub fn decrypt(mut self) -> Result<(), Box<dyn Error>> {
        let file = File::open(&self.cypher_text)?;
        let mut reader = BufReader::new(file);

        let mut offset = 0;
        let mut ctr_index: u32 = 1;
        let mut iv_buffer: [u8; 12] = [0; 12];
        let mut cypher_buffer: [u8; 16] = [0; 16];
        let mut tag_buffer: [u8; 16] = [0; 16];

        //calculate last cypher block lenght
        //metadata - iv - tag

        reader.read_exact(&mut iv_buffer)?;

        self.iv = Some(iv_buffer);

        let mut tag: [u8; 16] = [0; 16];
        let h = aes::encrypt_block(self.key_schedule, tag);

        let remainder = self.length % 16;
        let read_range = match remainder {
            0 => self.length/16,
            _ => self.length/16 + 1
        };

        for _ in 0..(read_range - 1) {
            reader.read_exact(&mut cypher_buffer)?;

            let ctr_vec: Vec<u8> = self.iv.unwrap().into_iter().chain(ctr_index.to_ne_bytes()).collect();
            let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

            let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
            let mut plain_text: [u8; 16] = [0; 16];

            for i in 0..16 {
                plain_text[i] = encrypted_counter[i] ^ cypher_buffer[i];
            }

            let mult_h: [u8; 16] = gf_mult(h, cypher_buffer.try_into().expect("hehu"));
            for i in 0..16 {
                tag[i] ^= mult_h[i];
            }

            self.plain_text.splice(offset..offset + 16, plain_text);

            ctr_index += 1;
            offset += 16;
        }

        let mut last_cypher_buffer = match remainder {
            0 => vec![0; 16],
            _ => vec![0; remainder.try_into()?]
        };

        // aquí bytes read no debería ser 16 si no el len del cypher
        // read exact remainder o 16
        // el remainder no se guarda un block en el cyher si no que solo lo correspondiente
        // al cifrado original
        let bytes_read = reader.read_exact(&mut last_cypher_buffer)?;

        let ctr_vec: Vec<u8> = self.iv.unwrap().into_iter().chain(ctr_index.to_ne_bytes()).collect();
        let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

        let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
        let mut plain_text: [u8; 16] = [0; 16];

        for i in 0..last_cypher_buffer.len() {
            plain_text[i] = encrypted_counter[i] ^ last_cypher_buffer[i];
        }

        let mut last_cypher_buffer_mult: Vec<u8> = last_cypher_buffer.clone(); //.resize_with(16, || 0);
        last_cypher_buffer_mult.resize_with(16, || 0);

        let mult_h: [u8; 16] = gf_mult(h, last_cypher_buffer_mult.try_into().expect("hehe"));
        for i in 0..16 {
            tag[i] ^= mult_h[i];
        }

        // hay que hacer esto, splice no funciona si no
        let last_plain_text_vec = plain_text[0..last_cypher_buffer.len()].to_vec();

        //bytes read va a ser siempre 16
        self.plain_text.splice(offset..offset + last_cypher_buffer.len(), last_plain_text_vec);
        assert_eq!(offset + last_cypher_buffer.len(), self.length.try_into()?);
        println!("cypher length:    {}", self.length);
        println!("decypher length:  {}", offset + last_cypher_buffer.len());

        for i in 0..16 {
            //check
            tag[i] ^= u128::from(self.length).to_ne_bytes()[i];
        }

        let iv: Vec<u8> = self.iv.unwrap().into_iter().chain([0, 0, 0, 0]).collect();
        let mult_last: [u8; 16] = gf_mult(iv.try_into().expect("guarrada gorda"), h);

        for i in 0..16 {
            tag[i] ^= mult_last[i];
        }

        let bytes_read = reader.read_exact(&mut tag_buffer)?;

        // need to compute tag and compare to read from file
        // assert!(self.tag == tag_buffer);

        // tag is last 16 bytes

        let output_file = fs::File::create("/home/alejandro/acnDev/hermetica/test_files/decypher.txt")
            .expect("Unable to create file");
        let mut buf_writer = BufWriter::new(output_file);

        buf_writer.write(&self.plain_text)?;
        buf_writer.flush()?;

        Ok(())
    }
}

/*
///////////////////////////////////

use crate::aes;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::{fs, u128, u8};
use rand::Rng;

// IV IS 96 BIT AND CONCATENATED TO 32 BIT CTR
// encryption can run in paralell and then sync threads to do writebuf in correct order
// philosophy of software design + idiomatic rust refactor
// use borrowed types as arguments over borrowing an owned type -> &T over &Vec<T>
// dont think default constructor makes sense here

// vectors are not a good idea because we run out of space
// custom types for aes_block, iv, tag, key_schedule?
// temporary mutability using nested block
// return consumed argument on error
// functional programming and pattern matching instead of ifelse....

// should the struct own the plain text?
// sould the struct own the cypher?
// Vec aesBlock { NOT MUTABLE
// value: u128
// bytes: [u8; 16] does this even make sense
// } ?
// does it make sense to store iv as aesBlock with last 4 bytes as 0
// make aesBlock from iv and u32 ctr
pub struct GcmEncrypt {
    iv: [u8; 12],            // random (truly random) | owned
    key_schedule: [u32; 44], // gen from user key | ownded
    plain_text: Vec<u8>,     // file path buf bufread bufwrite | not owned
    cypher_text: Vec<u8>,    // path buf | owned
    tag: [u8; 16],           //first 128 bits of encrypted file | owned
}

impl GcmEncrypt {
    pub unsafe fn new(key: u128, file: PathBuf) -> Self {
        let plain_text: Vec<u8> = fs::read(file).expect("Failed to read file");
        let cypher_text: Vec<u8> = vec![0; plain_text.len()];

        //let iv: [u8; 12] = [0; 12];
        // https://csrc.nist.gov/pubs/sp/800/38/d/final
        let iv: [u8; 12] = rand::thread_rng().gen::<[u8; 12]>();
        //println!("iv:               {:?}", iv);
        let tag: [u8; 16] = [0; 16];
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
            tag,
        }
    }

    pub fn encrypt(&mut self) {
        let mut offset = 0;

        //check index
        let mut ctr_index: u32 = 1;
        for plain_text_block in self.plain_text.chunks(16) {

            let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
            let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

            let encrypted_counter = Self::encrypt_aes_block(&self, ctr);

            let mut cypher_text: [u8; 16] = [0; 16];
            let plain_text_len = plain_text_block.len();
            for i in 0..plain_text_len {
                cypher_text[i] = encrypted_counter[i] ^ plain_text_block[i]
            }

            self.cypher_text.splice(offset..offset + 16, cypher_text);

            ctr_index += 1;
            offset += 16;
        }

        self.set_tag();

        let file = fs::File::create("/home/alejandro/acnDev/hermetica/src/file.hmtc")
            .expect("Unable to create file");
        let mut buf_writer = BufWriter::new(file);

        buf_writer.write(&self.iv).unwrap();
        buf_writer.write(&self.cypher_text).unwrap();
        buf_writer.write(&self.tag).unwrap();
        buf_writer.flush().unwrap();

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
            let mult_h: [u8; 16] = Self::gf_mult(h, cypher_block.try_into().expect("hehu"));

            for i in 0..16 {
                tag[i] ^= mult_h[i];
            }
        }

        // xor len
        // len is 8 need to expand to
        let len: u128 = self.plain_text.len().try_into().expect("hahu");
        for i in 0..16 {
            tag[i] ^= len.to_ne_bytes()[i];
        }

        // iv times h
        let iv: Vec<u8> = self.iv.into_iter().chain([0, 0, 0, 0]).collect();
        let mult_last: [u8; 16] = Self::gf_mult(iv.try_into().expect("guarrada gorda"), h);

        for i in 0..16 {
            tag[i] ^= mult_last[i];
        }

        self.tag = tag;
    }

    fn gf_mult(operand_a: [u8; 16], operand_b: [u8; 16]) -> [u8; 16] {
        // https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

        let product;
        unsafe {
            product = aes::mul_gf(operand_a, operand_b);
        }

        product
    }
}

pub struct GcmDecrypt {
    iv: [u8; 12],            // random (truly random) | not owned?
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    cypher_text: Vec<u8>,    //file | not owned
    plain_text: Vec<u8>,   // | owned
    tag: [u8; 16], //first 128 bits of encrypted file // | not owned
}

impl GcmDecrypt {
    pub fn new(key: u128, file: PathBuf) -> Self {
        let file_data: Vec<u8> = fs::read(file).expect("Failed to read file");
        let plain_text: Vec<u8> = vec![0; file_data.len() - 28];

        let len = file_data.len();
        let iv: [u8; 12] = file_data[..12].try_into().expect("hehu"); // First 16 bytes
        let tag: [u8; 16] = file_data[len - 16..].try_into().expect("hwh"); // Last 16 bytes
        let cypher_text: Vec<u8> = file_data[12..len - 16].try_into().expect("wawa");

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
            tag,
        }
    }

    pub fn decrypt(&mut self) {
        /*
        self.cypher_text.splice(offset..offset+16, self.iv.to_ne_bytes());
        offset += 16;
        */

        /*
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
        */

        let mut offset = 0;

        /*
        self.cypher_text.splice(offset..offset+12, self.iv);
        offset += 12;
        */

        //check index
        let mut ctr_index: u32 = 1;
        for cypher_text_block in self.cypher_text.chunks(16) {
            //if smaller than 16 need to expand or not xor the missing part

            let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
            let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

            let encrypted_counter = Self::encrypt_aes_block(&self, ctr);

            let mut plain_text: [u8; 16] = [0; 16];
            let hehe_len = cypher_text_block.len();
            for i in 0..hehe_len {
                // what happens on last block?
                plain_text[i] = encrypted_counter[i] ^ cypher_text_block[i]
            }

            self.plain_text.splice(offset..offset + 16, plain_text);

            ctr_index += 1;
            offset += 16;
        }

        self.set_tag();

        let file = fs::File::create("/home/alejandro/acnDev/hermetica/src/decypher.txt")
            .expect("Unable to create file");
        let mut buf_writer = BufWriter::new(file);

        buf_writer.write(&self.plain_text).unwrap();
        buf_writer.flush().unwrap();
    }

    // this should not be a method but parent module functionality
    fn encrypt_aes_block(&self, block_bytes: [u8; 16]) -> [u8; 16] {
        let encrypted_block_bytes;
        unsafe {
            encrypted_block_bytes = aes::encrypt(self.key_schedule, block_bytes);
        }

        encrypted_block_bytes
    }

    //make sure this is ok, also probably should not be a method
    fn set_tag(&mut self) {
        let mut tag: [u8; 16] = [0; 16];
        let h = self.encrypt_aes_block(tag);

        for cypher_block in self.cypher_text.chunks(16) {
            let mult_h: [u8; 16] = Self::gf_mult(h, cypher_block.try_into().expect("hehu"));

            for i in 0..16 {
                tag[i] ^= mult_h[i];
            }
        }

        // xor len
        let len: u128 = self.plain_text.len().try_into().expect("hahu");
        for i in 0..16 {
            tag[i] ^= len.to_ne_bytes()[i];
        }

        // iv times h
        let iv: Vec<u8> = self.iv.into_iter().chain([0, 0, 0, 0]).collect();
        let mult_last: [u8; 16] = Self::gf_mult(iv.try_into().expect("guarrada gorda"), h);

        for i in 0..16 {
            tag[i] ^= mult_last[i];
        }

        assert_eq!(tag, self.tag);
        // println!("file tag:         {:?}", tag);
        // println!("calculated tag:   {:?}", self.tag);
    }

    // should not be a method
    fn gf_mult(operand_a: [u8; 16], operand_b: [u8; 16]) -> [u8; 16] {
        // https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

        let product;
        unsafe {
            product = aes::mul_gf(operand_a, operand_b);
        }

        product
    }
}
*/
