pub mod clmul;

use std::fs;
use std::fmt;
use rand::Rng;
use crate::aes;
use std::thread;
use std::path::PathBuf;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use bytemuck::{bytes_of, bytes_of_mut, from_bytes, cast_slice_mut};

// https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

/*
 * what is needed from user for a gcm instance?
 * key and file
 * file should be tied to encryption or decryption, not to struct or so i think
 */
/*
 * maybe more generalized implementation
 * general case -> encrypt &[u8]
 * extrapolate file to general case
 * Really? In the end this is a file encryption application
 */

pub struct GcmInstance {
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
}

#[derive(Debug)]
pub enum GcmError {
    IoError(std::io::Error),
    TagMismatch,
}

pub type GcmResult<T> = Result<T, GcmError>;

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

/*
 * steps to decompose encryption-decryption
 * init -> everything before := Bufreader/writer, iv, tag, ctr_arr, thread_num?
 * encrypt-decrypt each intermediate buffer
 * end -> everyting after := last tag xor with len, flush
 * consider structs that encapsulate repeader arguments
 */
/*
 * try to make the most out of indicatif
 * might as well if going to use it
 */

const BUFFER_SIZE: usize = 1 << 20;
impl GcmInstance {
    pub fn new(key: u128) -> Self {
        let key_schedule = aes::gen_encryption_key_schedule(key);

        Self { key_schedule }
    }

    pub fn encrypt(&self, plain_text: PathBuf) -> GcmResult<(u128, PathBuf)> {
        let length = fs::metadata(&plain_text)?.len() as usize;

        let input_file = fs::File::open(&plain_text)?;
        let mut plain_text_buf = BufReader::new(input_file);

        let mut cypher_text = plain_text;
        cypher_text.as_mut_os_string().push(".hmtc");

        let output_file = fs::File::create(&cypher_text)?;
        let mut cypher_text_buf = BufWriter::new(output_file);

        let iv: [u8; 12] = rand::thread_rng().gen::<[u8; 12]>();

        cypher_text_buf.write_all(&iv)?;

        let mut tag = 0u128;
        let h = aes::encrypt_block(self.key_schedule, 0u128);

        let mut unaligned_read_buffer: [u128; BUFFER_SIZE / 16] = [0; BUFFER_SIZE / 16];
        let read_buffer: &mut [u8] = cast_slice_mut(&mut unaligned_read_buffer);
        let bufread_cnt = (length + BUFFER_SIZE - 1) / BUFFER_SIZE;

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv); // copy IV bytes into the array

        // add IV to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));

        let thread_num = thread::available_parallelism()?.get();

        let mut ctr: u32 = 1u32;

        let pb = ProgressBar::new(bufread_cnt as u64);
        pb.set_message(format!("Encrypting -> {:?}", cypher_text));
        pb.set_style(
            ProgressStyle::with_template(
                "{msg} {spinner:.red} {elapsed_precise} {bar:.cyan/blue} ({pos}/{len}, ETA {eta})",
            )
            .unwrap(),
        );

        for buffer_index in 0..(bufread_cnt) {
            let buffer_size = if buffer_index == bufread_cnt - 1 {
                let remaining = length - buffer_index * BUFFER_SIZE;
                let mut last_read_buffer = vec![0u8; remaining];
                plain_text_buf.read_exact(&mut last_read_buffer)?;
                read_buffer[..remaining].copy_from_slice(&last_read_buffer);
                remaining
            } else {
                // This is a full buffer; read 1MB of data
                plain_text_buf.read_exact(read_buffer)?;
                BUFFER_SIZE
            };

            let buf_blocks = (buffer_size + 15) / 16;
            let blocks_per_thread = buf_blocks / thread_num;
            let remainder_blocks = buf_blocks % thread_num;

            thread::scope(|scope| {
                let mut thread_results = Vec::new();

                for thread_id in 0..thread_num {
                    let start_block = thread_id * blocks_per_thread;
                    let end_block = if thread_id == thread_num - 1 {
                        start_block + blocks_per_thread + remainder_blocks
                    } else {
                        start_block + blocks_per_thread
                    };

                    let thread_read_buffer =
                        &read_buffer[(start_block * 16)..((end_block * 16).min(buffer_size))];
                    let mut thread_write_buffer = vec![0u8; (end_block - start_block) * 16];
                    let mut thread_tag: u128 = 0u128;
                    let mut thread_offset = 0;
                    let mut thread_ctr_arr: [u8; 16] = ctr_arr;
                    let mut thread_ctr: u32 = ctr + (start_block as u32);

                    let thread = scope.spawn(move || {
                        for _ in 0..(end_block - start_block) {
                            thread_ctr_arr[12..].copy_from_slice(bytes_of(&thread_ctr));

                            let encrypted_counter = aes::encrypt_block(
                                self.key_schedule,
                                *(from_bytes(&thread_ctr_arr)),
                            );

                            let mut block_size = 16;

                            let cypher_text: u128 = if thread_offset + 16 > thread_read_buffer.len()
                            {
                                block_size = thread_read_buffer.len() - thread_offset;
                                let mut block = [0u8; 16];
                                block[..block_size]
                                    .copy_from_slice(&thread_read_buffer[thread_offset..]);
                                encrypted_counter ^ from_bytes(&block)
                            } else {
                                encrypted_counter
                                    ^ from_bytes(
                                        &thread_read_buffer
                                            [thread_offset..thread_offset + block_size],
                                    )
                            };

                            thread_tag ^= gf_mult(h, cypher_text);
                            thread_write_buffer[thread_offset..thread_offset + block_size]
                                .copy_from_slice(&bytes_of(&cypher_text)[..block_size]);

                            thread_ctr += 1;
                            thread_offset += block_size;
                        }

                        (thread_tag, thread_offset, thread_ctr, thread_write_buffer)
                    });

                    thread_results.push(thread);
                }

                for result in thread_results {
                    let (thread_tag, thread_offset, thread_ctr, thread_write_buffer) =
                        result.join().unwrap();
                    tag ^= thread_tag;
                    cypher_text_buf
                        .write_all(&thread_write_buffer[..thread_offset])
                        .unwrap();
                    ctr = ctr.max(thread_ctr);
                }
            });
            pb.inc(1);
        }

        tag ^= length as u128;

        cypher_text_buf.write_all(bytes_of(&tag))?;
        cypher_text_buf.flush()?;

        pb.finish_with_message("Writing to disk");
        Ok((tag, cypher_text))
    }

    pub fn decrypt(&self, cypher_text: PathBuf) -> GcmResult<(u128, PathBuf)> {
        let length = (fs::metadata(&cypher_text)?.len() - 28) as usize;

        let input_file = fs::File::open(&cypher_text)?;
        let mut cypher_text_buf = BufReader::new(&input_file);

        let mut plain_text = cypher_text;
        plain_text.set_extension(""); // Removes extension

        let mut tmp = plain_text.clone();
        tmp.set_file_name("tmp_dec");

        let output_file = fs::File::create(&tmp)?;
        let mut tmp_buf = BufWriter::new(&output_file);

        let mut iv: [u8; 12] = [0; 12];
        let mut read_tag: [u8; 16] = [0; 16];

        cypher_text_buf.read_exact(&mut iv)?;

        let tag_position = length as u64 + 12; // cyphertext + IV offset
        cypher_text_buf.seek(SeekFrom::Start(tag_position))?;
        cypher_text_buf.read_exact(&mut read_tag)?;
        let read_tag = u128::from_ne_bytes(read_tag);

        let cypher_position = 12;
        cypher_text_buf.seek(SeekFrom::Start(cypher_position))?;

        let mut tag = 0u128;
        let h = aes::encrypt_block(self.key_schedule, 0u128);

        let mut ctr_arr = [0u8; 16]; // create a fixed-size array with 16 bytes
        ctr_arr[..12].copy_from_slice(&iv); // copy IV bytes into the array

        // add iv to tag
        tag ^= gf_mult(h, *(from_bytes(&ctr_arr)));

        let thread_num = thread::available_parallelism()?.get();

        let mut ctr: u32 = 1u32;
        let mut unaligned_read_buffer: [u128; BUFFER_SIZE / 16] = [0; BUFFER_SIZE / 16];
        let read_buffer: &mut [u8] = cast_slice_mut(&mut unaligned_read_buffer);
        let bufread_cnt = (length + BUFFER_SIZE - 1) / BUFFER_SIZE;

        let pb = ProgressBar::new(bufread_cnt as u64);
        pb.set_message(format!("Decrypting -> {:?}", plain_text));
        pb.set_style(
            ProgressStyle::with_template(
                "{msg} {spinner:.red} {elapsed_precise} {bar:.cyan/blue} ({pos}/{len}, ETA {eta})",
            )
            .unwrap(),
        );

        for buffer_index in 0..(bufread_cnt) {
            let buffer_size = if buffer_index == bufread_cnt - 1 {
                let remaining = length - buffer_index * BUFFER_SIZE;
                let mut last_buffer = vec![0u8; remaining];
                cypher_text_buf.read_exact(&mut last_buffer)?;
                read_buffer[..remaining].copy_from_slice(&last_buffer);
                remaining
            } else {
                // This is a full buffer; read 1MB of data
                cypher_text_buf.read_exact(read_buffer)?;
                BUFFER_SIZE
            };

            let buf_blocks = (buffer_size + 15) / 16;
            let blocks_per_thread = buf_blocks / thread_num;
            let remainder_blocks = buf_blocks % thread_num;

            thread::scope(|scope| {
                let mut thread_results = Vec::new();

                for thread_id in 0..thread_num {
                    let start_block = thread_id * blocks_per_thread;
                    let end_block = if thread_id == thread_num - 1 {
                        start_block + blocks_per_thread + remainder_blocks
                    } else {
                        start_block + blocks_per_thread
                    };

                    let thread_read_buffer =
                        &read_buffer[(start_block * 16)..((end_block * 16).min(buffer_size))];
                    let mut thread_write_buffer = vec![0u8; (end_block - start_block) * 16];
                    let mut thread_tag: u128 = 0u128;
                    let mut thread_offset = 0;
                    let mut thread_ctr_arr: [u8; 16] = ctr_arr;
                    let mut thread_ctr: u32 = ctr + (start_block as u32);

                    let thread = scope.spawn(move || {
                        for _ in 0..(end_block - start_block) {
                            thread_ctr_arr[12..].copy_from_slice(bytes_of(&thread_ctr));

                            let encrypted_counter = aes::encrypt_block(
                                self.key_schedule,
                                *(from_bytes(&thread_ctr_arr)),
                            );

                            let mut block_size = 16;

                            let plain_text: u128 = if thread_offset + 16 > thread_read_buffer.len()
                            {
                                block_size = thread_read_buffer.len() - thread_offset;
                                let mut block = [0u8; 16];
                                block[..block_size]
                                    .copy_from_slice(&thread_read_buffer[thread_offset..]);
                                block[block_size..].copy_from_slice(
                                    &encrypted_counter.to_ne_bytes()[block_size..],
                                );
                                thread_tag ^= gf_mult(h, *from_bytes(&block));

                                encrypted_counter ^ from_bytes(&block)
                            } else {
                                thread_tag ^= gf_mult(
                                    h,
                                    *from_bytes(
                                        &thread_read_buffer
                                            [thread_offset..thread_offset + block_size],
                                    ),
                                );
                                encrypted_counter
                                    ^ from_bytes(
                                        &thread_read_buffer
                                            [thread_offset..thread_offset + block_size],
                                    )
                            };

                            thread_write_buffer[thread_offset..thread_offset + block_size]
                                .copy_from_slice(&bytes_of(&plain_text)[..block_size]);

                            thread_ctr += 1;
                            thread_offset += block_size;
                        }

                        (thread_tag, thread_offset, thread_ctr, thread_write_buffer)
                    });

                    thread_results.push(thread);
                }

                for result in thread_results {
                    let (thread_tag, thread_offset, thread_ctr, thread_write_buffer) =
                        result.join().unwrap();
                    tag ^= thread_tag;
                    tmp_buf
                        .write_all(&thread_write_buffer[..thread_offset])
                        .unwrap();
                    ctr = ctr.max(thread_ctr);
                }
            });
            pb.inc(1);
        }

        tag ^= length as u128;
        if tag != read_tag {
            fs::remove_file(tmp)?;
            return Err(GcmError::TagMismatch);
        }

        tmp_buf.flush()?;
        fs::remove_file(&plain_text)?;
        fs::rename(&tmp, &plain_text)?;

        pb.finish_with_message("Writing to disk");
        Ok((tag, plain_text))
    }
}
