pub mod clmul;

use crate::aes;
use bytemuck::{bytes_of, bytes_of_mut, from_bytes};
use rand::Rng;
use std::error::Error;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use rayon::prelude::*;

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

pub struct GcmInstance {
    iv: Option<[u8; 12]>,    // random (truly random) | not owned?
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    tag: Option<u128>,       //first 128 bits of encrypted file // | not owned
    length: Option<usize>,
    cypher_text: PathBuf, //file | not owned
    plain_text: PathBuf,  // | owned
}

#[derive(Debug)]
pub enum GcmError {
    IoError(std::io::Error),
    TagMismatch,
}

impl std::fmt::Display for GcmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            GcmError::IoError(ref err) => write!(f, "IO error: {}", err),
            GcmError::TagMismatch => write!(f, "Tag mismatch during decryption"),
        }
    }
}

impl From<std::io::Error> for Box<GcmError> {
    fn from(err: std::io::Error) -> Self {
        Box::new(GcmError::IoError(err))
    }
}

impl Error for GcmError {}

impl GcmInstance {
    pub fn new(key: u128, plain_text: PathBuf, cypher_text: PathBuf) -> Self {
        let key_schedule = aes::gen_encryption_key_schedule(key);

        Self {
            iv: None,
            key_schedule,
            tag: None,
            length: None,
            plain_text,
            cypher_text,
        }
    }

    pub fn encrypt(mut self) -> Result<(), Box<GcmError>> {
        let length = fs::metadata(&self.plain_text)?.len() as usize;
        self.length = Some(length);

        // https://csrc.nist.gov/pubs/sp/800/38/d/final
        let iv: [u8; 12] = rand::thread_rng().gen::<[u8; 12]>();
        self.iv = Some(iv);

        let input_file = File::open(self.plain_text)?;
        let mut plain_text_buf = BufReader::new(input_file);

        let output_file = fs::File::create(self.cypher_text)?;
        let mut cypher_text_buf = BufWriter::new(output_file);

        println!("encrypting...");

        cypher_text_buf.write_all(&iv)?;

        let mut tag = 0u128;
        let h = aes::encrypt_block(self.key_schedule, tag);

        let mut ctr_index: u32 = 0;

        // each bufread read will be 1MB
        let mut read_buffer: [u8; MB] = [0; MB];
        let mut write_buffer: [u8; MB] = [0; MB];

        // how many 1MB reads are necesary for the entire file
        let bufread_cnt = (length + MB - 1) / MB;

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(bytes_of(&ctr_index)); // copy counter bytes into the array

        // add IV to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));
        //ctr_index += 1;

        // To be parallelized
        // thread 1 buffer 0
        for buffer_index in 0..(bufread_cnt) {
            //let mut offset = 0;

            let buffer_size = if buffer_index == bufread_cnt - 1 {
                let remaining = length - buffer_index * MB;
                let mut last_read_buffer = vec![0u8; remaining];
                plain_text_buf.read_exact(&mut last_read_buffer)?;
                read_buffer[..remaining].copy_from_slice(&last_read_buffer);
                remaining
            } else {
                // This is a full buffer; read 1MB of data
                plain_text_buf.read_exact(&mut read_buffer)?;
                MB
            };

            let ctr_init = 0;
            let local_iv = self.iv.unwrap();
            let local_key_schedule = self.key_schedule;

            //the fucking iterator version is 5 times slower
            let block_vec: Vec<u8> =
                read_buffer[..buffer_size]
                .par_chunks_mut(16)
                .enumerate()
                .flat_map(|(index, block)| {
                    let ctr = (index + ctr_init) as u32;

                    //overhead
                    let mut ctr_arr = [0u8; 16];
                    ctr_arr[..12].copy_from_slice(&local_iv);

                    let encrypted_counter =
                        //bytemuck??
                        aes::encrypt_block(local_key_schedule, *from_bytes(&ctr_arr));

                    //how much overhead is doing this always
                    let zero_cnt = 16 - block.len();
                    //dont think this is doing anything to block , check this
                    block.to_vec().extend(std::iter::repeat(0).take(zero_cnt));
                    // no, index / 16 maybe
                    // and wont hold for last
                    /*
                       if index == (buffer_size + 15) / 16 - 1 {
                    //println!("did i get here");
                    //panic!("i got here");
                       }
                       */

                    let output = encrypted_counter ^ from_bytes(&block);
                    let mult_h = gf_mult(h, output);

                    /*
                    tag_u.fetch_xor((mult_h >> 64) as u64, Ordering::Relaxed);
                    tag_l.fetch_xor(mult_h as u64, Ordering::Relaxed);
                    */

                    output.to_ne_bytes()[..16-zero_cnt].to_owned()
                })
                .collect();


            //split for loop in threads
            //each thread gets its apropiate slice from the write and read buffer
            //each thread computes its tag
            //

            /*
            //rayon
            let buf_blocks = (buffer_size + 15) / 16; // Calculate number of 16-byte blocks
            for i in 0..buf_blocks {
                ctr_arr[12..].copy_from_slice(bytes_of(&ctr_index)); // copy counter bytes into the array

                let encrypted_counter =
                    aes::encrypt_block(self.key_schedule, *(from_bytes(&ctr_arr)));

                let block_size = if offset + 16 <= buffer_size {
                    16
                } else {
                    buffer_size - offset
                };

                let cypher_text: u128 = if i == buf_blocks - 1 {
                    // Last iteration logic
                    let mut block = [0u8; 16]; // Create a temporary array with 16 bytes
                    block[..block_size].copy_from_slice(&read_buffer[offset..offset + block_size]);
                    encrypted_counter ^ from_bytes(&block)
                } else {
                    // Normal iteration logic
                    encrypted_counter ^ from_bytes(&read_buffer[offset..offset + block_size])
                };

                tag ^= gf_mult(h, cypher_text);

                write_buffer[offset..offset+block_size].copy_from_slice(&bytes_of(&cypher_text)[0..block_size]);

                ctr_index += 1;
                offset += block_size;
            }
            //rayon
            */

            //main thing here is reusing write buffer for writing?
            cypher_text_buf
                //.write_all(&write_buffer[0..offset])
                .write_all(&block_vec)
                .unwrap();
        }

        tag ^= length as u128;

        self.tag = Some(tag);

        cypher_text_buf.write_all(bytes_of(&tag))?;

        cypher_text_buf.flush()?;

        Ok(())
    }

    pub fn decrypt(mut self) -> Result<(), Box<GcmError>> {
        let length = (fs::metadata(&self.cypher_text)?.len() - 28) as usize; //12 bytes IV 16 bytes tag
        self.length = Some(length);

        let input_file = File::open(&self.cypher_text)?;
        let mut cypher_text_buf = BufReader::new(&input_file);

        let mut tmp = self.plain_text.clone();
        tmp.set_file_name("tmp_dec");

        let output_file = fs::File::create(&tmp)?;
        let mut tmp_buf = BufWriter::new(&output_file);

        let mut iv_buffer: [u8; 12] = [0; 12];
        let mut tag_buffer: [u8; 16] = [0; 16];

        println!("decrypting...");

        cypher_text_buf.read_exact(&mut iv_buffer)?;
        self.iv = Some(iv_buffer);

        let mut tag = 0u128;
        let h = aes::encrypt_block(self.key_schedule, tag);

        let mut ctr_index: u32 = 0;

        let mut read_buffer: [u8; MB] = [0; MB];
        let mut write_buffer: [u8; MB] = [0; MB];

        let bufread_cnt = (length + MB - 1) / MB;

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv_buffer); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(bytes_of(&ctr_index)); // copy counter bytes into the array

        // add iv to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));
        ctr_index += 1;

        for buffer_index in 0..(bufread_cnt) {
            let mut offset = 0;

            let buffer_size = if buffer_index == bufread_cnt - 1 {
                let remaining = length - buffer_index * MB;
                let mut last_buffer = vec![0u8; remaining];
                cypher_text_buf.read_exact(&mut last_buffer)?;
                read_buffer[..remaining].copy_from_slice(&last_buffer);
                remaining
            } else {
                // This is a full buffer; read 1MB of data
                cypher_text_buf.read_exact(&mut read_buffer)?;
                MB
            };

            let buf_blocks = (buffer_size + 15) / 16; // Calculate number of 16-byte blocks

            for i in 0..buf_blocks {
                ctr_arr[12..].copy_from_slice(bytes_of(&ctr_index)); // copy counter bytes into the array

                let encrypted_counter =
                    aes::encrypt_block(self.key_schedule, *(from_bytes(&ctr_arr)));

                let block_size = if offset + 16 <= buffer_size {
                    16
                } else {
                    buffer_size - offset
                };

                let plain_text: u128 = if i == buf_blocks - 1 {
                    // Last iteration logic
                    let mut block = encrypted_counter.to_ne_bytes(); // Create a temporary array with 16 bytes
                    block[..block_size].copy_from_slice(&read_buffer[offset..offset + block_size]);
                    tag ^= gf_mult(h, *from_bytes(&block));

                    encrypted_counter ^ from_bytes(&block)
                } else {
                    // Normal iteration logic
                    tag ^= gf_mult(h, *from_bytes(&read_buffer[offset..offset + block_size]));

                    encrypted_counter ^ from_bytes(&read_buffer[offset..offset + block_size])
                };

                write_buffer[offset..offset+block_size].copy_from_slice(&bytes_of(&plain_text)[0..block_size]);

                ctr_index += 1;
                offset += block_size;
            }

            tmp_buf
                .write_all(&write_buffer[0..offset])
                .unwrap();
        }

        tag ^= length as u128;

        cypher_text_buf.read_exact(&mut tag_buffer)?;

        self.tag = Some(tag);

        if tag != u128::from_ne_bytes(tag_buffer) {
            fs::remove_file(tmp)?;
            return Err(Box::new(GcmError::TagMismatch));
        }

        tmp_buf.flush()?;
        fs::remove_file(&self.plain_text)?;
        fs::rename(&tmp, &self.plain_text)?;

        Ok(())
    }
}
