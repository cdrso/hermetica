pub mod clmul;

use crate::aes;
use bytemuck::{bytes_of, bytes_of_mut, from_bytes};
use rand::Rng;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::PathBuf;

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
    iv: [u8; 12],            // random (truly random) | not owned?
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    length: usize,
    cypher_text: BufWriter<File>, //file | not owned
    plain_text: BufReader<File>,  // | owned
    context: GcmContext,
}

pub struct DecryptorInstance {
    iv: [u8; 12],            // random (truly random) | not owned?
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    length: usize,
    cypher_text: BufReader<File>,
    tmp_plain_text: BufWriter<File>,
    tag: u128,
    context: GcmContext,
}

struct GcmContext {
    ctr: u32,
    ctr_arr: [u8; 16],
    gcm_h: u128,
    computed_tag: u128,
    intermediate_read_buffer: Vec<u8>,
    intermediate_write_buffer: Vec<u8>,
    intermediate_buffer_cnt: usize,
}

enum GcmMode {
    Encrypt,
    Decrypt,
}

trait OperationMode {
    fn mode(&self) -> GcmMode;
}

impl OperationMode for EncryptorInstance {
    fn mode(&self) -> GcmMode {
        GcmMode::Encrypt
    }
}

impl OperationMode for DecryptorInstance {
    fn mode(&self) -> GcmMode {
        GcmMode::Decrypt
    }
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

trait ProcessBuffer {
    fn process_buffer(&mut self, buffer_index: usize) -> Result<(), Box<GcmError>>;
}

// When evaluating the if expresion the compiler sees that it's either a
// tautology or a contradicion effectively removing the other branch on optimization
// This trick achieves conditional macro expansion on the caller macro
macro_rules! conditional_expansion_helper {
    ($mode: expr, $encryption_expression:expr, $decryption_expression:expr) => {
        if let GcmMode::Encrypt = $mode {
            $encryption_expression
        } else {
            $decryption_expression
        }
    };
}

macro_rules! impl_process_buffer {
    ($instance: ty, $reader: ident, $writer: ident) => {
        impl ProcessBuffer for $instance {
            fn process_buffer(&mut self, buffer_index: usize) -> Result<(), Box<GcmError>> {
                let mut offset = 0;

                let buffer_size = if buffer_index == self.context.intermediate_buffer_cnt - 1 {
                    let remaining = self.length - buffer_index * MB;
                    let mut last_read_buffer = vec![0u8; remaining];
                    self.$reader.read_exact(&mut last_read_buffer)?;
                    self.context.intermediate_read_buffer[..remaining]
                        .copy_from_slice(&last_read_buffer);
                    remaining
                } else {
                    self.$reader
                        .read_exact(&mut self.context.intermediate_read_buffer)?;
                    MB
                };

                let buf_blocks = (buffer_size + 15) / 16;
                for i in 0..buf_blocks {
                    self.context.ctr_arr[12..].copy_from_slice(bytes_of(&self.context.ctr));

                    let encrypted_counter =
                        aes::encrypt_block(self.key_schedule, *(from_bytes(&self.context.ctr_arr)));

                    let block_size = if offset + 16 <= buffer_size {
                        16
                    } else {
                        buffer_size - offset
                    };

                    let output: u128;
                    if i == buf_blocks - 1
                        && buffer_index == self.context.intermediate_buffer_cnt - 1
                    {
                        let mut block = conditional_expansion_helper!(
                            self.mode(),
                            vec![0u8; 16],
                            encrypted_counter.to_ne_bytes().to_vec()
                        );

                        block[..block_size].copy_from_slice(
                            &self.context.intermediate_read_buffer[offset..offset + block_size],
                        );

                        output = encrypted_counter ^ from_bytes(&block);

                        let gf_mult_operand =
                            conditional_expansion_helper!(self.mode(), output, *from_bytes(&block));

                        self.context.computed_tag ^= gf_mult(self.context.gcm_h, gf_mult_operand);
                    } else {
                        output = encrypted_counter
                            ^ from_bytes(
                                &self.context.intermediate_read_buffer[offset..offset + block_size],
                            );
                        let gf_mult_operand = conditional_expansion_helper!(
                            self.mode(),
                            output,
                            *from_bytes(
                                &self.context.intermediate_read_buffer[offset..offset + block_size]
                            )
                        );
                        self.context.computed_tag ^= gf_mult(self.context.gcm_h, gf_mult_operand);
                    };

                    self.context.intermediate_write_buffer[offset..offset + block_size]
                        .copy_from_slice(&bytes_of(&output)[0..block_size]);

                    self.context.ctr += 1;
                    offset += block_size;
                }
                self.$writer
                    .write_all(&self.context.intermediate_write_buffer[0..offset])?;

                Ok(())
            }
        }
    };
}

impl_process_buffer!(EncryptorInstance, plain_text, cypher_text);
impl_process_buffer!(DecryptorInstance, cypher_text, tmp_plain_text);

impl EncryptorInstance {
    pub fn new(
        key: u128,
        plain_text_path: PathBuf,
        cypher_text_path: PathBuf,
    ) -> Result<Self, Box<GcmError>> {
        let key_schedule = aes::gen_encryption_key_schedule(key);
        let length = fs::metadata(&plain_text_path)?.len() as usize;
        // https://csrc.nist.gov/pubs/sp/800/38/d/final
        let iv: [u8; 12] = rand::thread_rng().gen::<[u8; 12]>();

        let input_file = File::open(&plain_text_path)?;
        let plain_text = BufReader::new(input_file);

        let output_file = fs::File::create(&cypher_text_path)?;
        let mut cypher_text = BufWriter::new(output_file);

        let intermediate_read_buffer = vec![0u8; MB];
        let intermediate_write_buffer = vec![0u8; MB];
        let intermediate_buffer_cnt = (length + MB - 1) / MB;

        let mut computed_tag = 0u128;
        let gcm_h = aes::encrypt_block(key_schedule, computed_tag);

        let mut ctr = 0u32;
        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(bytes_of(&ctr)); // copy counter bytes into the array

        cypher_text.write_all(&iv)?;

        // add IV to tag
        computed_tag ^= gf_mult(gcm_h, *(from_bytes(&ctr_arr)));
        ctr += 1;

        Ok(Self {
            iv,
            key_schedule,
            length,
            cypher_text,
            plain_text,
            context: GcmContext {
                ctr,
                ctr_arr,
                gcm_h,
                computed_tag,
                intermediate_read_buffer,
                intermediate_write_buffer,
                intermediate_buffer_cnt,
            },
        })
    }

    pub fn encrypt(&mut self) -> Result<(), Box<GcmError>> {
        for buffer_index in 0..self.context.intermediate_buffer_cnt {
            self.process_buffer(buffer_index)?;
        }
        self.context.computed_tag ^= self.length as u128;
        self.cypher_text
            .write_all(bytes_of(&self.context.computed_tag))?;
        self.cypher_text.flush()?;

        Ok(())
    }
}

impl DecryptorInstance {
    pub fn new(
        key: u128,
        plain_text_path: PathBuf,
        cypher_text_path: PathBuf,
    ) -> Result<Self, Box<GcmError>> {
        let key_schedule = aes::gen_encryption_key_schedule(key);
        let length = (fs::metadata(&cypher_text_path)?.len() - 28) as usize;

        let input_file = File::open(&cypher_text_path)?;
        let mut cypher_text = BufReader::new(input_file);

        //instead add tmp to name
        let mut tmp = plain_text_path.clone();
        tmp.set_file_name("tmp_dec");

        let output_file = fs::File::create(&tmp)?;
        let tmp_plain_text = BufWriter::new(output_file);

        let mut iv: [u8; 12] = [0; 12];
        let mut tag: [u8; 16] = [0; 16];

        cypher_text.read_exact(&mut iv)?;

        let intermediate_read_buffer = vec![0u8; MB];
        let intermediate_write_buffer = vec![0u8; MB];
        let intermediate_buffer_cnt = (length + MB - 1) / MB;

        let mut computed_tag = 0u128;
        let gcm_h = aes::encrypt_block(key_schedule, computed_tag);

        let mut ctr = 0u32;
        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv); // copy IV bytes into the array
        ctr_arr[12..].copy_from_slice(bytes_of(&ctr)); // copy counter bytes into the array

        let tag_position = length as u64 + 12; // cyphertext + IV offset
        cypher_text.seek(std::io::SeekFrom::Start(tag_position))?;
        cypher_text.read_exact(&mut tag)?;
        let tag = u128::from_ne_bytes(tag);

        let cypher_position = 12;
        cypher_text.seek(std::io::SeekFrom::Start(cypher_position))?;

        computed_tag ^= gf_mult(gcm_h, *(from_bytes(&ctr_arr)));
        ctr += 1;

        Ok(Self {
            iv,
            key_schedule,
            length,
            cypher_text,
            tmp_plain_text,
            tag,
            context: GcmContext {
                ctr,
                ctr_arr,
                gcm_h,
                computed_tag,
                intermediate_read_buffer,
                intermediate_write_buffer,
                intermediate_buffer_cnt,
            },
        })
    }

    pub fn decrypt(&mut self) -> Result<(), Box<GcmError>> {
        for buffer_index in 0..self.context.intermediate_buffer_cnt {
            self.process_buffer(buffer_index)?;
        }
        self.context.computed_tag ^= self.length as u128;
        if self.context.computed_tag != self.tag {
            //fs::remove_file(tmp)?;
            return Err(Box::new(GcmError::TagMismatch));
        }
        self.tmp_plain_text.flush()?;
        //fs::remove_file(&self.plain_text)?;
        //fs::rename(&tmp, &self.plain_text)?;

        Ok(())
    }
}
