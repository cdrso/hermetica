pub mod clmul;
use crate::aes;
use bytemuck::{bytes_of, bytes_of_mut, from_bytes};
use rand::Rng;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::usize;

const MB: usize = 1 << 20;
// Bufreader, one Buf for each thread, do benchmarking to chose buffer size for example 1MB
// so for example 6 threads with 1MB buffer each, each thread computes its own tag fragment (xor is
// commutative)
// each thread computes the cypher for its read buffer
// need to sync ctr so thread 1 reads/writes first chunk, thread 2 second chunk etc
// last block should be processed after threads are merged and final tag operations computed

// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

pub(crate) fn gf_mult(operand_a: u128, operand_b: u128) -> u128 {
    let mut product: u128 = 0;
    unsafe {
        clmul::clmul_gf(
            bytes_of(&operand_a).as_ptr(),
            bytes_of(&operand_b).as_ptr(),
            bytes_of_mut(&mut product).as_mut_ptr(),
        );
    }

    product
}

// last block is not 128 bits but the size of the plain text, discard the rest

pub struct GcmEncrypt {
    iv: [u8; 12],                // random (truly random) | owned
    key_schedule: [u32; 44],     // gen from user key | ownded
    plain_text: BufReader<File>, //bufreader    // file path buf bufread bufwrite | not owned
    length: usize,
    cypher_text: BufWriter<File>, //bufwriter  // path buf | owned
    tag: Option<u128>,            //first 128 bits of encrypted file | owned
}

impl GcmEncrypt {
    pub fn new(
        key: u128,
        plain_text_path: PathBuf,
        cypher_text_path: PathBuf,
    ) -> Result<GcmEncrypt, Box<dyn Error>> {
        //TODO
        let length = fs::metadata(&plain_text_path)?.len() as usize;

        // https://csrc.nist.gov/pubs/sp/800/38/d/final
        let iv: [u8; 12] = rand::thread_rng().gen::<[u8; 12]>();

        let tag = None;

        let key_schedule = aes::gen_encryption_key_schedule(key);

        let input_file = File::open(plain_text_path)?;
        let plain_text = BufReader::new(input_file);

        let output_file = fs::File::create(cypher_text_path)?;
        let cypher_text = BufWriter::new(output_file);

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
        println!("encrypting...");

        self.cypher_text.write(&self.iv)?;

        let mut tag: u128 = 0;
        let h = aes::encrypt_block(self.key_schedule, tag);

        let mut ctr_index: u32 = 0;

        // each bufread read will be 1MB
        let mut read_buffer: [u8; MB] = [0; MB];

        // how many 1MB reads are necesary for the entire file
        let bufread_cnt = (self.length + MB - 1) / MB;

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&self.iv); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(&bytes_of(&ctr_index)); // copy counter bytes into the array

        // add plain text lenght to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));
        ctr_index += 1;

        for block_cnt in 0..(bufread_cnt) {
            let mut offset = 0;

            let buffer_size = if block_cnt == bufread_cnt - 1 {
                let remaining = self.length - block_cnt * MB;
                let mut last_buffer = vec![0u8; remaining];
                self.plain_text.read_exact(&mut last_buffer)?;
                read_buffer[..remaining].copy_from_slice(&last_buffer);
                remaining
            } else {
                // This is a full buffer; read 1MB of data
                self.plain_text.read_exact(&mut read_buffer)?;
                MB
            };

            let buf_blocks = (buffer_size + 15) / 16; // Calculate number of 16-byte blocks

            for i in 0..buf_blocks {
                ctr_arr[12..].copy_from_slice(&bytes_of(&ctr_index)); // copy counter bytes into the array

                let encrypted_counter =
                    aes::encrypt_block(self.key_schedule, *(from_bytes(&ctr_arr)));

                let block_size = if offset + 16 <= buffer_size {
                    16
                } else {
                    buffer_size - offset
                };

                let cypher_text: u128;
                if i == buf_blocks - 1 {
                    // Last iteration logic
                    let mut block = [0u8; 16]; // Create a temporary array with 16 bytes
                    block[..block_size].copy_from_slice(&read_buffer[offset..offset + block_size]);
                    cypher_text =
                        encrypted_counter ^ from_bytes(&block);
                } else {
                    // Normal iteration logic
                    cypher_text =
                        encrypted_counter ^ from_bytes(&read_buffer[offset..offset + block_size]);
                }

                tag ^= gf_mult(h, cypher_text);
                self.cypher_text.write(&bytes_of(&cypher_text)[0..block_size]).unwrap();

                ctr_index += 1;
                offset += block_size;
            }
        }

        tag ^= self.length as u128;

        self.tag = Some(tag);

        self.cypher_text.write(bytes_of(&tag));

        self.cypher_text.flush();

        Ok(())
    }
}

pub struct GcmDecrypt {
    iv: Option<[u8; 12]>,         // random (truly random) | not owned?
    key_schedule: [u32; 44],      //gen from key, no need for key_schedule_decrypt | owned
    cypher_text: BufReader<File>, //file | not owned
    length: usize,
    plain_text: BufWriter<File>, // | owned
    tag: Option<u128>,           //first 128 bits of encrypted file // | not owned
}

impl GcmDecrypt {
    pub fn new(
        key: u128,
        cypher_text_path: PathBuf,
        plain_text_path: PathBuf,
    ) -> Result<GcmDecrypt, Box<dyn Error>> {
        let length = (fs::metadata(&cypher_text_path)?.len() - 28) as usize; //12 bytes IV 16 bytes tag
        let key_schedule = aes::gen_encryption_key_schedule(key);

        let input_file = File::open(&cypher_text_path)?;
        let cypher_text = BufReader::new(input_file);

        let output_file = fs::File::create(&plain_text_path)?;
        let plain_text = BufWriter::new(output_file);

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
        println!("decrypting...");

        let mut iv_buffer: [u8; 12] = [0; 12];
        let mut tag_buffer: [u8; 16] = [0; 16];

        self.cypher_text.read_exact(&mut iv_buffer)?;
        self.iv = Some(iv_buffer);

        let mut tag = 0u128;
        let h = aes::encrypt_block(self.key_schedule, tag);

        let mut ctr_index: u32 = 0;

        let mut read_buffer: [u8; MB] = [0; MB];

        let bufread_cnt = (self.length + MB - 1) / MB;

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&self.iv.unwrap()); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(&bytes_of(&ctr_index)); // copy counter bytes into the array

        // add iv to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));
        ctr_index += 1;

        for block_cnt in 0..(bufread_cnt) {
            let mut offset = 0;

            let buffer_size = if block_cnt == bufread_cnt - 1 {
                let remaining = self.length - block_cnt * MB;
                let mut last_buffer = vec![0u8; remaining];
                self.cypher_text.read_exact(&mut last_buffer);
                read_buffer[..remaining].copy_from_slice(&last_buffer);
                remaining
            } else {
                // This is a full buffer; read 1MB of data
                self.cypher_text.read_exact(&mut read_buffer)?;
                MB
            };

            let buf_blocks = (buffer_size + 15) / 16; // Calculate number of 16-byte blocks

            for i in 0..buf_blocks {
                ctr_arr[12..].copy_from_slice(&bytes_of(&ctr_index)); // copy counter bytes into the array

                let encrypted_counter =
                    aes::encrypt_block(self.key_schedule, *(from_bytes(&ctr_arr)));

                let block_size = if offset + 16 <= buffer_size {
                    16
                } else {
                    buffer_size - offset
                };

                let plain_text: u128;
                if i == buf_blocks - 1 {
                    // Last iteration logic
                    let mut block = [0u8; 16]; // Create a temporary array with 16 bytes
                    block[..block_size].copy_from_slice(&read_buffer[offset..offset + block_size]);
                    plain_text =
                        encrypted_counter ^ from_bytes(&block);
                    tag ^= gf_mult(h, *from_bytes(&block));
                } else {
                    // Normal iteration logic
                    plain_text =
                        encrypted_counter ^ from_bytes(&read_buffer[offset..offset + block_size]);
                    tag ^= gf_mult(h, *from_bytes(&read_buffer[offset..offset + block_size]));
                }
                    self.plain_text.write(&bytes_of(&plain_text)[0..block_size]).unwrap();

                ctr_index += 1;
                offset += block_size;
            }
        }

        tag ^= self.length as u128;

        self.cypher_text.read_exact(&mut tag_buffer)?;

        self.tag = Some(tag);

        //assert_eq!(self.tag, Some(*from_bytes(&tag_buffer)));
        //println!("tag is correct");
        self.plain_text.flush()?;

        Ok(())
    }
}
