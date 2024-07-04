pub mod clmul;

use crate::aes;
use bytemuck::{bytes_of, bytes_of_mut, from_bytes};
use rand::Rng;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write, Seek};
use std::path::PathBuf;
use std::thread::scope;
use aligned_array::{Aligned, A16, AsAlignedChunks};
use generic_array::GenericArray;
use generic_array::typenum::U8;

// shorthand aliases to make it easier to write tests
type A16Bytes<N> = Aligned<A16, GenericArray<u8, N>>;

//https://docs.rs/aligned-array/latest/aligned_array/index.html

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
pub struct EncryptorInstance {
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    length: usize,
    cypher_text: PathBuf, //file | not owned
    plain_text: PathBuf,  // | owned
}


pub struct DecryptorInstance {
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    length: usize,
    cypher_text: PathBuf,
    plain_text: PathBuf,
}

trait ProcessBuffer {
    fn process_buffer(&mut self, buffer_index: usize) -> Result<(), Box<GcmError>>;
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

impl EncryptorInstance {
    pub fn new(key: u128, plain_text: PathBuf, cypher_text: PathBuf) -> Result<Self, Box<GcmError>> {
        let key_schedule = aes::gen_encryption_key_schedule(key);
        let length = fs::metadata(&plain_text)?.len() as usize;

        Ok(Self {
            key_schedule,
            length,
            plain_text,
            cypher_text,
        })
    }

    pub fn encrypt(self) -> Result<(), Box<GcmError>> {
        let iv: [u8; 12] = rand::thread_rng().gen::<[u8; 12]>();

        let input_file = File::open(self.plain_text)?;
        let mut plain_text_buf = BufReader::new(input_file);

        let output_file = fs::File::create(self.cypher_text)?;
        let mut cypher_text_buf = BufWriter::new(output_file);

        println!("encrypting...");

        cypher_text_buf.write_all(&iv)?;

        let mut tag = 0u128;
        let h = aes::encrypt_block(self.key_schedule, 0u128);

        // each bufread read will be 1MB
        let mut read_buffer = [0u8; MB];

        // how many 1MB reads are necesary for the entire file
        let bufread_cnt = (self.length + MB - 1) / MB;

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(bytes_of(&0u32)); // copy counter bytes into the array

        // add IV to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));

        dbg!(tag);

        for buffer_index in 0..(bufread_cnt) {

            let buffer_size = if buffer_index == bufread_cnt - 1 {
                let remaining = self.length - buffer_index * MB;
                let mut last_read_buffer = vec![0u8; remaining];
                plain_text_buf.read_exact(&mut last_read_buffer)?;
                read_buffer[..remaining].copy_from_slice(&last_read_buffer);
                remaining
            } else {
                // This is a full buffer; read 1MB of data
                plain_text_buf.read_exact(&mut read_buffer)?;
                MB
            };

            let buf_blocks = (buffer_size + 15) / 16; // Calculate number of 16-byte blocks

            //par
            scope(|scope| {
                let t1_read_buffer = &read_buffer[..((buf_blocks / 2) * 16)];
                let mut t1_write_buffer = vec![0u8; (buf_blocks / 2) * 16];
                let mut t1_tag: u128 = 0u128;
                let mut t1_offset = 0;
                let mut t1_ctr: u32 = 1u32;
                let mut t1_ctr_arr: [u8; 16] = ctr_arr;

                let t1 = scope.spawn(move || {
                    for _i in 0..(buf_blocks / 2) {
                        t1_ctr_arr[12..].copy_from_slice(bytes_of(&t1_ctr)); // copy counter bytes into the array

                        let encrypted_counter =
                            aes::encrypt_block(self.key_schedule, *(from_bytes(&t1_ctr_arr)));

                        let block_size = 16;

                        let cypher_text =
                            encrypted_counter ^ from_bytes(&t1_read_buffer[t1_offset..t1_offset + block_size]);

                        t1_tag ^= gf_mult(h, cypher_text);

                        t1_write_buffer[t1_offset..t1_offset+block_size].copy_from_slice(&bytes_of(&cypher_text)[..block_size]);

                        t1_ctr += 1;
                        t1_offset += block_size;
                    }

                    (t1_tag, t1_offset, t1_ctr, t1_write_buffer)
                });

                let t2_read_buffer = &read_buffer[(buf_blocks / 2) * 16..];
                let mut t2_write_buffer = vec![0u8; buffer_size - (buf_blocks / 2) * 16];
                let mut t2_tag: u128 = 0u128;
                let mut t2_offset = 0;
                let mut t2_ctr: u32 = ((buf_blocks / 2) + 1) as u32;
                let mut t2_ctr_arr: [u8; 16] = ctr_arr;

                let t2 = scope.spawn(move || {
                    for i in 0..(buf_blocks - buf_blocks / 2) {
                        t2_ctr_arr[12..].copy_from_slice(bytes_of(&t2_ctr)); // copy counter bytes into the array

                        let encrypted_counter =
                            aes::encrypt_block(self.key_schedule, *(from_bytes(&t2_ctr_arr)));

                        //epa
                        let block_size = if (t2_offset + (buf_blocks / 2) * 16) + 16 <= buffer_size {
                            16
                        } else {
                            buffer_size - (t2_offset + (buf_blocks / 2) * 16)
                        };

                        let cypher_text: u128 = if i == (buf_blocks - buf_blocks / 2) - 1  {
                            // Last iteration logic
                            let mut block = [0u8; 16]; // Create a temporary array with 16 bytes
                            block[..block_size].copy_from_slice(&t2_read_buffer[t2_offset..t2_offset + block_size]);
                            encrypted_counter ^ from_bytes(&block)
                        } else {
                            encrypted_counter ^ from_bytes(&t2_read_buffer[t2_offset..t2_offset + block_size])
                        };

                        t2_tag ^= gf_mult(h, cypher_text);

                        t2_write_buffer[t2_offset..t2_offset+block_size].copy_from_slice(&bytes_of(&cypher_text)[..block_size]);

                        t2_ctr += 1;
                        t2_offset += block_size;
                    }
                    (t2_tag, t2_offset, t2_ctr, t2_write_buffer)
                });

                let (t1_tag, t1_offset, _t1_ctr, t1_write_buffer ) = t1.join().unwrap();
                let (t2_tag, t2_offset, t2_ctr, t2_write_buffer ) = t2.join().unwrap();

                assert_eq!(buf_blocks as u32, t2_ctr - 1);
                assert_eq!(t1_offset + t2_offset, buffer_size);

                tag ^= t1_tag;
                tag ^= t2_tag;

                cypher_text_buf
                    .write_all(&t1_write_buffer[..t1_offset])
                    .unwrap();
                cypher_text_buf
                    .write_all(&t2_write_buffer[..t2_offset])
                    .unwrap();
            });
        }

        tag ^= self.length as u128;

        dbg!(tag);

        cypher_text_buf.write_all(bytes_of(&tag))?;

        cypher_text_buf.flush()?;

        Ok(())
    }
}

impl DecryptorInstance {
    pub fn new(key: u128, plain_text: PathBuf, cypher_text: PathBuf) -> Result<Self, Box<GcmError>> {
        let key_schedule = aes::gen_encryption_key_schedule(key);
        let length = (fs::metadata(&cypher_text)?.len() - 28) as usize;

        Ok(Self {
            key_schedule,
            length,
            plain_text,
            cypher_text,
        })
    }
    pub fn decrypt(self) -> Result<(), Box<GcmError>> {
        let input_file = File::open(&self.cypher_text)?;
        let mut cypher_text_buf = BufReader::new(&input_file);

        let mut tmp = self.plain_text.clone();
        tmp.set_file_name("tmp_dec");

        let output_file = fs::File::create(&tmp)?;
        let mut tmp_buf = BufWriter::new(&output_file);

        let mut iv: [u8; 12] = [0; 12];
        let mut read_tag: [u8; 16] = [0; 16];

        println!("decrypting...");

        cypher_text_buf.read_exact(&mut iv)?;

        let tag_position = self.length as u64 + 12; // cyphertext + IV offset
        cypher_text_buf.seek(std::io::SeekFrom::Start(tag_position))?;
        cypher_text_buf.read_exact(&mut read_tag)?;
        let read_tag = u128::from_ne_bytes(read_tag);

        dbg!(read_tag);

        let cypher_position = 12;
        cypher_text_buf.seek(std::io::SeekFrom::Start(cypher_position))?;

        let mut tag = 0u128;
        let h = aes::encrypt_block(self.key_schedule, tag);

        let mut ctr_index: u32 = 0;

        let mut read_buffer: [u8; MB] = [0; MB];
        let mut write_buffer: [u8; MB] = [0; MB];

        let bufread_cnt = (self.length + MB - 1) / MB;

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(bytes_of(&ctr_index)); // copy counter bytes into the array

        // add iv to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));

        dbg!(tag);

        ctr_index += 1;

        for buffer_index in 0..(bufread_cnt) {
            let mut offset = 0;

            let buffer_size = if buffer_index == bufread_cnt - 1 {
                let remaining = self.length - buffer_index * MB;
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

            //par
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
                    dbg!("{}", tag);
                    dbg!("{}", ctr_index);
                    dbg!("{}", buffer_size);
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
            //par

            tmp_buf
                .write_all(&write_buffer[0..offset])
                .unwrap();
        }

        tag ^= self.length as u128;

        if tag != read_tag {
            // if i remove the commented out blocks then it does not crash
            fs::remove_file(tmp)?;
            return Err(Box::new(GcmError::TagMismatch));
        }

        tmp_buf.flush()?;
        fs::remove_file(&self.plain_text)?;
        fs::rename(&tmp, &self.plain_text)?;

        Ok(())
    }
}


