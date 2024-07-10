pub mod clmul;

use std::fs;
use std::fmt;
use rand::Rng;
use crate::aes;
use std::thread;
use std::fs::File;
use std::path::PathBuf;
use bytemuck::{bytes_of, bytes_of_mut};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};

pub enum GcmMode {
    Encryption,
    Decryption
}

pub struct GcmInstance {
    key_schedule: [u32; 44],
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

impl From<std::io::Error> for GcmError {
    fn from(err: std::io::Error) -> Self {
        GcmError::IoError(err)
    }
}

pub type GcmResult<T> = Result<T, GcmError>;

struct GcmEncrypt;
struct GcmDecrypt;

trait GcmOperation: Sync {
    fn process_block(&self, block: &[u8], counter: u128, key_schedule: &[u32; 44]) -> [u8; 16];
    fn update_tag(&self, block: &[u8], tag: &mut u128, h: u128);
}

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

impl GcmOperation for GcmEncrypt {
    fn process_block(&self, block: &[u8], counter: u128, key_schedule: &[u32; 44]) -> [u8; 16] {
        let encrypted_counter = aes::encrypt_block(*key_schedule, counter);
        let mut result = [0u8; 16];
        for (i, &byte) in block.iter().enumerate() {
            result[i] = byte ^ ((encrypted_counter >> (8 * (15 - i))) as u8);
        }
        result
    }

    fn update_tag(&self, block: &[u8], tag: &mut u128, h: u128) {
        *tag ^= gf_mult(h, u128::from_ne_bytes(block.try_into().unwrap()));
    }
}

impl GcmOperation for GcmDecrypt {
    fn process_block(&self, block: &[u8], counter: u128, key_schedule: &[u32; 44]) -> [u8; 16] {
        let encrypted_counter = aes::encrypt_block(*key_schedule, counter);
        let mut result = [0u8; 16];
        for (i, &byte) in block.iter().enumerate() {
            result[i] = byte ^ ((encrypted_counter >> (8 * (15 - i))) as u8);
        }
        result
    }

    fn update_tag(&self, block: &[u8], tag: &mut u128, h: u128) {
        *tag ^= gf_mult(h, u128::from_ne_bytes(block.try_into().unwrap()));
    }
}

const BUFFER_SIZE: usize = 1 << 20;

impl GcmInstance {
    pub fn new(key: u128) -> Self {
        let key_schedule = aes::gen_encryption_key_schedule(key);
        Self { key_schedule }
    }

    fn init(&self, input_path: &PathBuf, mode: &GcmMode) -> GcmResult<(BufReader<File>, BufWriter<File>, [u8; 12], PathBuf)> {
        let input_file = fs::File::open(input_path)?;
        let mut input = BufReader::new(input_file);

        let (output_path, iv) = match mode {
            GcmMode::Encryption => {
                let mut output_path = input_path.clone();
                output_path.as_mut_os_string().push(".hmtc");
                let iv: [u8; 12] = rand::thread_rng().gen();
                (output_path, iv)
            },
            GcmMode::Decryption => {
                let mut output_path = input_path.clone();
                output_path.set_extension("");
                let mut iv = [0u8; 12];
                input.read_exact(&mut iv)?;
                (output_path, iv)
            },
        };

        let output_file = fs::File::create(&output_path)?;
        let output = BufWriter::new(output_file);

        Ok((input, output, iv, output_path))
    }

    fn compute<T: GcmOperation + ?Sized>(
        &self,
        input: &mut BufReader<File>,
        output: &mut BufWriter<File>,
        iv: &[u8; 12],
        op: &T,
    ) -> GcmResult<u128> {
        let h = aes::encrypt_block(self.key_schedule, 0u128);
        let mut tag = gf_mult(h, u128::from_ne_bytes([&iv[..], &[0u8; 4]].concat().try_into().unwrap()));

        let length = input.get_ref().metadata()?.len() as usize;
        let bufread_cnt = (length + BUFFER_SIZE - 1) / BUFFER_SIZE;

        let pb = ProgressBar::new(bufread_cnt as u64);
        pb.set_style(ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        ).unwrap());

        let thread_num = thread::available_parallelism()?.get();
        let mut ctr: u32 = 1;

        for _ in 0..bufread_cnt {
            let mut buffer = [0u8; BUFFER_SIZE];
            let bytes_read = input.read(&mut buffer)?;
            let blocks_count = (bytes_read + 15) / 16;
            let blocks_per_thread = (blocks_count + thread_num - 1) / thread_num;

            thread::scope(|s| {
                let mut handles = vec![];
                for thread_index in 0..thread_num {
                    let start = thread_index * blocks_per_thread * 16;
                    let end = (start + blocks_per_thread * 16).min(bytes_read);
                    if start >= end {
                        break;
                    }
                    let handle = s.spawn(move || {
                        let mut local_tag = 0u128;
                        let mut processed = [0u8; BUFFER_SIZE];
                        let mut processed_len = 0;
                        for (i, chunk) in buffer[start..end].chunks(16).enumerate() {
                            let counter = u128::from_ne_bytes([&iv[..], &(ctr + (thread_index * blocks_per_thread + i) as u32).to_be_bytes()].concat().try_into().unwrap());
                            let mut block = [0u8; 16];
                            block[..chunk.len()].copy_from_slice(chunk);
                            let processed_block = op.process_block(&block, counter, &self.key_schedule);
                            op.update_tag(&processed_block[..chunk.len()], &mut local_tag, h);
                            processed[processed_len..processed_len + chunk.len()].copy_from_slice(&processed_block[..chunk.len()]);
                            processed_len += chunk.len();
                        }
                        (local_tag, processed, processed_len)
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    let (local_tag, processed, processed_len) = handle.join().unwrap();
                    tag ^= local_tag;
                    output.write_all(&processed[..processed_len])?;
                }
                Ok::<_, std::io::Error>(())
            })?;

            ctr += blocks_count as u32;
            pb.inc(1);
        }

        pb.finish_with_message("done");
        tag ^= length as u128;
        Ok(tag)
    }

    fn finalize(&self, output: &mut BufWriter<File>, tag: u128, mode: &GcmMode, output_path: &PathBuf) -> GcmResult<()> {
        match mode {
            GcmMode::Encryption => {
                output.write_all(&tag.to_be_bytes())?;
            },
            GcmMode::Decryption => {
                let mut read_tag = [0u8; 16];
                output.get_ref().seek(SeekFrom::End(-16))?;
                output.get_ref().read_exact(&mut read_tag)?;
                if tag != u128::from_be_bytes(read_tag) {
                    fs::remove_file(output_path)?;
                    return Err(GcmError::TagMismatch);
                }
                output.get_ref().set_len(output.get_ref().metadata()?.len() - 16)?;
            },
        }
        output.flush()?;
        Ok(())
    }

    pub fn encrypt(&self, plain_text: PathBuf) -> GcmResult<(u128, PathBuf)> {
        let (mut input, mut output, iv, output_path) = self.init(&plain_text, &GcmMode::Encryption)?;
        output.write_all(&iv)?;
        let tag = self.compute(&mut input, &mut output, &iv, &GcmEncrypt)?;
        self.finalize(&mut output, tag, &GcmMode::Encryption, &output_path)?;
        Ok((tag, output_path))
    }

    pub fn decrypt(&self, cypher_text: PathBuf) -> GcmResult<(u128, PathBuf)> {
        let (mut input, mut output, iv, output_path) = self.init(&cypher_text, &GcmMode::Decryption)?;
        let tag = self.compute(&mut input, &mut output, &iv, &GcmDecrypt)?;
        self.finalize(&mut output, tag, &GcmMode::Decryption, &output_path)?;
        Ok((tag, output_path))
    }
}
