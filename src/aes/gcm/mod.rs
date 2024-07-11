pub mod clmul;

use crate::aes;
use bytemuck::{bytes_of, bytes_of_mut, from_bytes};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::cmp;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::thread;

const BUFFER_SIZE: usize = 1 << 20;
const AES_BLOCK_SIZE: usize = 16;

#[derive(PartialEq)]
pub enum GcmMode {
    Encryption,
    Decryption,
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
    fn process_block(
        &self,
        key_schedule: &[u32; 44],
        read_bytes: &[u8],
        counter: u128,
        tag: &mut u128,
        h: u128,
    ) -> u128;
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
    fn process_block(
        &self,
        key_schedule: &[u32; 44],
        read_bytes: &[u8],
        counter: u128,
        tag: &mut u128,
        h: u128,
    ) -> u128 {
        let encrypted_counter = aes::encrypt_block(*key_schedule, counter);
        let len = read_bytes.len();
        let mut block = [0u8; AES_BLOCK_SIZE];
        block[..len].copy_from_slice(&read_bytes[..len]);
        let cypher_block = encrypted_counter ^ u128::from_ne_bytes(block);
        *tag ^= gf_mult(h, cypher_block);

        cypher_block
    }
}

impl GcmOperation for GcmDecrypt {
    fn process_block(
        &self,
        key_schedule: &[u32; 44],
        read_bytes: &[u8],
        counter: u128,
        tag: &mut u128,
        h: u128,
    ) -> u128 {
        let encrypted_counter = aes::encrypt_block(*key_schedule, counter);
        let len = read_bytes.len();
        let mut block: [u8; AES_BLOCK_SIZE] = encrypted_counter.to_ne_bytes();
        block[..len].copy_from_slice(&read_bytes[..len]);
        *tag ^= gf_mult(h, u128::from_ne_bytes(block));


        encrypted_counter ^ u128::from_ne_bytes(block)
    }
}

impl GcmInstance {
    pub fn new(key: u128) -> Self {
        let key_schedule = aes::gen_encryption_key_schedule(key);
        Self { key_schedule }
    }

    fn init(
        &self,
        input_path: &PathBuf,
        mode: &GcmMode,
    ) -> GcmResult<(BufReader<File>, BufWriter<File>, [u8; 12], PathBuf)> {
        let input_file = fs::File::open(input_path)?;
        let mut input = BufReader::new(input_file);

        let (output_path, iv) = match mode {
            GcmMode::Encryption => {
                let mut output_path = input_path.clone();
                output_path.as_mut_os_string().push(".hmtc");
                //TODO
                let iv: [u8; 12] = rand::thread_rng().gen();
                (output_path, iv)
            }
            GcmMode::Decryption => {
                let mut output_path = input_path.clone();
                output_path.set_extension("");
                let mut iv = [0u8; 12];
                input.read_exact(&mut iv)?;
                (output_path, iv)
            }
        };

        let output_file = match mode {
            GcmMode::Encryption => fs::File::create(&output_path)?,
            GcmMode::Decryption => {
                let mut tmp_path = output_path.clone();
                tmp_path.set_file_name("tmp_dec");
                fs::File::create(tmp_path)?
            }
        };
        let output = BufWriter::new(output_file);

        Ok((input, output, iv, output_path))
    }

    fn compute<T: GcmOperation + ?Sized>(
        &self,
        input: &mut BufReader<File>,
        output: &mut BufWriter<File>,
        iv: &[u8; 12],
        op: &T,
        mode: &GcmMode,
    ) -> GcmResult<u128> {
        let h = aes::encrypt_block(self.key_schedule, 0u128);
        let mut ctr_arr = [0u8; AES_BLOCK_SIZE];
        ctr_arr[..12].copy_from_slice(iv);
        let mut tag = gf_mult(h, *from_bytes(&ctr_arr));

        //gives different lengths
        let length = match mode {
            GcmMode::Encryption => input.get_ref().metadata()?.len() as usize,
            // 28 = tag bytes + iv bytes = 16 + 12
            GcmMode::Decryption => (input.get_ref().metadata()?.len() - 28) as usize,
        };

        let mut buffer = [0u8; BUFFER_SIZE];
        let bufread_cnt = (length + BUFFER_SIZE - 1) / BUFFER_SIZE;

        let pb = ProgressBar::new(bufread_cnt as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})",
            )
            .unwrap(),
        );

        let thread_num = thread::available_parallelism()?.get();
        let mut ctr: u32 = 1;

        for buffer_index in 0..bufread_cnt {
            let mut bytes_read = BUFFER_SIZE;
            if buffer_index == bufread_cnt - 1 {
                bytes_read = length - (buffer_index * BUFFER_SIZE)
            }

            input.read_exact(&mut buffer[..bytes_read])?;
            //dbg!(input.stream_position()?);
            let blocks_count = (bytes_read + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE;
            let blocks_per_thread = (blocks_count + thread_num - 1) / thread_num;

            thread::scope(|s| {
                let mut thread_results = Vec::new();
                for thread_id in 0..thread_num {
                    let start = thread_id * (blocks_per_thread * AES_BLOCK_SIZE);
                    let end = (start + (blocks_per_thread * AES_BLOCK_SIZE)).min(bytes_read);
                    let thread_blocks = (end - start + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE;

                    let thread_read_buffer = &buffer[start..end];
                    let mut thread_write_buffer = vec![0u8; end - start];
                    let mut thread_tag: u128 = 0u128;
                    let mut thread_offset = 0;
                    let mut thread_ctr_arr = ctr_arr;
                    let mut thread_ctr: u32 = ctr + (start / AES_BLOCK_SIZE) as u32;

                    let handle = s.spawn(move || {
                        //no tiene en cuenta el remainder
                        for _ in 0..thread_blocks {
                            thread_ctr_arr[12..].copy_from_slice(bytes_of(&thread_ctr));

                            let block_size =
                                cmp::min(AES_BLOCK_SIZE, (end - start) - thread_offset);
                            let read_bytes =
                                &thread_read_buffer[thread_offset..thread_offset + block_size];

                            match mode {
                                GcmMode::Encryption => {
                                    let processed_block = op.process_block(
                                        &self.key_schedule,
                                        read_bytes,
                                        u128::from_ne_bytes(thread_ctr_arr),
                                        &mut thread_tag,
                                        h,
                                    );
                                    thread_write_buffer[thread_offset..thread_offset + block_size]
                                        .copy_from_slice(&bytes_of(&processed_block)[..block_size]);
                                }
                                GcmMode::Decryption => {
                                    let processed_block = op.process_block(
                                        &self.key_schedule,
                                        read_bytes,
                                        u128::from_ne_bytes(thread_ctr_arr),
                                        &mut thread_tag,
                                        h,
                                    );
                                    thread_write_buffer[thread_offset..thread_offset + block_size]
                                        .copy_from_slice(&bytes_of(&processed_block)[..block_size]);
                                }
                            }

                            thread_ctr += 1;
                            thread_offset += block_size;
                        }
                        (thread_tag, thread_ctr, thread_write_buffer, thread_offset)
                    });
                    thread_results.push(handle);
                }
                for handle in thread_results {
                    let (thread_tag, thread_ctr, thread_write_buffer, thread_offset) =
                        handle.join().unwrap();
                    tag ^= thread_tag;
                    output.write_all(&thread_write_buffer[..thread_offset])?;
                    ctr = ctr.max(thread_ctr);
                }
                Ok::<_, GcmError>(())
            })?;
            output.flush()?;
            pb.inc(1);
        }
        pb.finish_with_message("done");
        tag ^= length as u128;
        Ok(tag)
    }

    fn finalize(
        &self,
        input: &mut BufReader<File>,
        output: &mut BufWriter<File>,
        tag: u128,
        mode: &GcmMode,
        output_path: &PathBuf,
    ) -> GcmResult<()> {
        match mode {
            GcmMode::Encryption => {
                output.write_all(&tag.to_be_bytes())?;
            }
            GcmMode::Decryption => {
                let mut read_tag = [0u8; 16];
                // tag is the last 16 bytes of encrypted file
                input.seek(SeekFrom::End(-16))?;
                input.read_exact(&mut read_tag)?;
                if tag != u128::from_be_bytes(read_tag) {
                    fs::remove_file(PathBuf::from("tmp_dec"))?;
                    return Err(GcmError::TagMismatch);
                }
                fs::rename(PathBuf::from("tmp_dec"), output_path)?;
            }
        }
        output.flush()?;
        Ok(())
    }

    pub fn encrypt(&self, plain_text: PathBuf) -> GcmResult<(u128, PathBuf)> {
        let (mut reader, mut writer, iv, encrypted_file_path) =
            self.init(&plain_text, &GcmMode::Encryption)?;
        writer.write_all(&iv)?;
        let tag = self.compute(
            &mut reader,
            &mut writer,
            &iv,
            &GcmEncrypt,
            &GcmMode::Encryption,
        )?;
        self.finalize(
            &mut reader,
            &mut writer,
            tag,
            &GcmMode::Encryption,
            &encrypted_file_path,
        )?;
        Ok((tag, encrypted_file_path))
    }

    pub fn decrypt(&self, cypher_text: PathBuf) -> GcmResult<(u128, PathBuf)> {
        let (mut reader, mut writer, iv, decrypted_file_path) =
            self.init(&cypher_text, &GcmMode::Decryption)?;
        let tag = self.compute(
            &mut reader,
            &mut writer,
            &iv,
            &GcmDecrypt,
            &GcmMode::Decryption,
        )?;
        self.finalize(
            &mut reader,
            &mut writer,
            tag,
            &GcmMode::Decryption,
            &decrypted_file_path,
        )?;
        Ok((tag, decrypted_file_path))
    }
}
