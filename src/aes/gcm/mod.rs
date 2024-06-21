pub mod clmul;
use crate::aes;
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

//const MB: usize = 1_048_576;

struct Number {
    usize: usize,
    u64: u64,
}

const MB: Number = Number {
    usize: 1_048_576usize,
    u64: 1_048_576u64,
};

// Bufreader, one Buf for each thread, do benchmarking to chose buffer size for example 1MB
// so for example 6 threads with 1MB buffer each, each thread computes its own tag fragment (xor is
// commutative)
// each thread computes the cypher for its read buffer
// need to sync ctr so thread 1 reads/writes first chunk, thread 2 second chunk etc
// last block should be processed after threads are merged and final tag operations computed

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
    length: usize,
    cypher_text: PathBuf,  // path buf | owned
    tag: Option<[u8; 16]>, //first 128 bits of encrypted file | owned
}

impl GcmEncrypt {
    pub fn new(
        key: u128,
        plain_text: PathBuf,
        cypher_text: PathBuf,
    ) -> Result<GcmEncrypt, Box<dyn Error>> {
        //TODO
        let length = fs::metadata(&plain_text)?.len() as usize;

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
        println!("encrypting...");
        let input_file = File::open(&self.plain_text)?;
        let mut buf_reader = BufReader::new(input_file);

        let output_file = fs::File::create(&self.cypher_text)?;
        let mut buf_writer = BufWriter::new(output_file);

        buf_writer.write(&self.iv)?;

        let mut tag: [u8; 16] = [0; 16];
        let h = aes::encrypt_block(self.key_schedule, tag);

        let mut offset = 0;
        let mut ctr_index: u32 = 1;

        // each bufread read will be 1MB
        let mut read_buffer: [u8; MB.usize] = [0; MB.usize];

        // how many 1MB reads are necesary for the entire file
        let mut bufread_cnt = self.length / MB.usize;
        if self.length % MB.usize != 0 {
            bufread_cnt += 1;
        }

        // from 0 to bufread_cnt-1 read_exact read_buffer of 1MB
        // last bufread read_exact last buffer size
        // std::thread::available_parallelism

        // need to keep offset
        for _ in 0..(bufread_cnt - 1) {
            offset = 0;
            buf_reader.read_exact(&mut read_buffer)?;
            // el último del buffer debe ser de 16 bits siempre
            // define offset here? reseting makes sense
            for _ in 0..(MB.u64 / 16) {
                // last iter is out of range by exacly 16 bits so one block, why?
                // function(&mut ctr, &mut offset, &read_buffer) buffer len or calculate inside
                let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
                let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

                let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
                let mut cypher_text: [u8; 16] = [0; 16];

                for i in 0..16 {
                    cypher_text[i] = encrypted_counter[i] ^ read_buffer[offset..offset + 16][i];
                }

                let mult_h: [u8; 16] = gf_mult(h, cypher_text);
                for i in 0..16 {
                    tag[i] ^= mult_h[i];
                }

                buf_writer.write(&cypher_text)?;

                ctr_index += 1;
                offset += 16;
            }
            // write every 1MB
            buf_writer.flush();
        }

        let read_buffer_last_size = match self.length % MB.usize {
            0 => MB.usize,
            _ => self.length % MB.usize,
        };

        let mut read_buffer_last: Vec<u8> = vec![0; read_buffer_last_size];

        let mut last_buf_blocks = read_buffer_last_size / 16;
        if last_buf_blocks % 16 != 0 {
            last_buf_blocks += 1;
        }

        let last_buf_last_block_size = match read_buffer_last_size % 16 {
            0 => 16,
            _ => read_buffer_last_size % 16,
        };

        offset = 0;

        //need to compute read_buffer and
        //number of 16 blocks in read_buffer + remainder
        //last
        buf_reader.read_exact(&mut read_buffer_last)?;
        for _ in 0..(last_buf_blocks - 1) {
            let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
            let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

            let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
            let mut cypher_text: [u8; 16] = [0; 16];

            for i in 0..16 {
                cypher_text[i] = encrypted_counter[i] ^ read_buffer_last[offset..offset + 16][i];
            }

            let mult_h: [u8; 16] = gf_mult(h, cypher_text);
            for i in 0..16 {
                tag[i] ^= mult_h[i];
            }

            buf_writer.write(&cypher_text)?;

            ctr_index += 1;
            offset += 16;
        }

        // does offset apply for read_buffer_last

        let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
        let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

        let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
        let mut cypher_text: [u8; 16] = [0; 16];

        for i in 0..last_buf_last_block_size {
            cypher_text[i] = encrypted_counter[i]
                ^ read_buffer_last[offset..offset + last_buf_last_block_size][i];
        }

        let mult_h: [u8; 16] = gf_mult(h, cypher_text);
        for i in 0..16 {
            tag[i] ^= mult_h[i];
        }

        buf_writer.write(&cypher_text[0..last_buf_last_block_size])?;

        //assert_eq!(offset + bytes_read, self.length.try_into()?);

        // add lenght to tag
        for i in 0..16 {
            tag[i] ^= u128::from(self.length as u64).to_ne_bytes()[i];
        }

        // add iv || 0 to tag
        let iv: Vec<u8> = self.iv.into_iter().chain([0, 0, 0, 0]).collect();
        let mult_last: [u8; 16] = gf_mult(iv.try_into().expect("guarrada gorda"), h);
        for i in 0..16 {
            tag[i] ^= mult_last[i];
        }

        self.tag = Some(tag);

        buf_writer.write(&self.tag.unwrap())?;

        buf_writer.flush();

        // if you know read_buffer_last.len then you know if last block size is different than 16
        // you also know the exact last block size so take that special case into account

        // 1MB is arbitrary, this should not be hardcoded and allow for diferent sizes
        // should benchmark to find ideal size, python script?

        // this should encrypt the entire file

        ///////////////////////////////////////
        /*
        let read_range = match self.length % 16 {
            0 => self.length / 16,
            _ => self.length / 16 + 1,
        };

        for _ in 0..read_range - 1 {
            reader.read_exact(&mut read_buffer)?;

            let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
            let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

            let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
            let mut cypher_text: [u8; 16] = [0; 16];

            for i in 0..16 {
                cypher_text[i] = encrypted_counter[i] ^ read_buffer[i];
            }

            let mult_h: [u8; 16] = gf_mult(h, cypher_text);
            for i in 0..16 {
                tag[i] ^= mult_h[i];
            }

            buf_writer.write(&cypher_text)?;

            ctr_index += 1;
            offset += 16;
        }

        let bytes_read = reader.read(&mut read_buffer)?;

        let ctr_vec: Vec<u8> = self.iv.into_iter().chain(ctr_index.to_ne_bytes()).collect();
        let ctr: [u8; 16] = ctr_vec.try_into().expect("heha");

        let encrypted_counter = aes::encrypt_block(self.key_schedule, ctr);
        let mut cypher_text: [u8; 16] = [0; 16];

        for i in 0..bytes_read {
            cypher_text[i] = encrypted_counter[i] ^ read_buffer[i];
        }

        buf_writer.write(&cypher_text[0..bytes_read])?;

        let mult_h: [u8; 16] = gf_mult(h, cypher_text);
        for i in 0..16 {
            tag[i] ^= mult_h[i];
        }

        assert_eq!(offset + bytes_read, self.length.try_into()?);

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

        buf_writer.write(&self.tag.unwrap())?;
        buf_writer.flush()?;
        */

        Ok(())
    }
}

pub struct GcmDecrypt {
    iv: Option<[u8; 12]>,    // random (truly random) | not owned?
    key_schedule: [u32; 44], //gen from key, no need for key_schedule_decrypt | owned
    cypher_text: PathBuf,    //file | not owned
    length: u64,
    plain_text: PathBuf,   // | owned
    tag: Option<[u8; 16]>, //first 128 bits of encrypted file // | not owned
}

impl GcmDecrypt {
    pub fn new(
        key: u128,
        cypher_text: PathBuf,
        plain_text: PathBuf,
    ) -> Result<GcmDecrypt, Box<dyn Error>> {
        let length = fs::metadata(&cypher_text)?.len() - 28; //12 bytes IV 16 bytes tag
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
        println!("decrypting...");
        let input_file = File::open(&self.cypher_text)?;
        let mut reader = BufReader::new(input_file);

        let output_file = fs::File::create(&self.plain_text)?;
        let mut buf_writer = BufWriter::new(output_file);

        let mut offset = 0;
        let mut ctr_index: u32 = 1;
        let mut iv_buffer: [u8; 12] = [0; 12];
        let mut cypher_buffer: [u8; 16] = [0; 16];
        let mut tag_buffer: [u8; 16] = [0; 16];

        reader.read_exact(&mut iv_buffer)?;
        self.iv = Some(iv_buffer);

        let mut tag: [u8; 16] = [0; 16];
        let h = aes::encrypt_block(self.key_schedule, tag);

        let remainder = self.length % 16;
        let read_range = match remainder {
            0 => self.length / 16,
            _ => self.length / 16 + 1,
        };

        for _ in 0..(read_range - 1) {
            reader.read_exact(&mut cypher_buffer)?;

            let ctr_vec: Vec<u8> = self
                .iv
                .unwrap()
                .into_iter()
                .chain(ctr_index.to_ne_bytes())
                .collect();
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

            buf_writer.write(&plain_text)?;

            ctr_index += 1;
            offset += 16;
        }

        let mut last_cypher_buffer = match remainder {
            0 => vec![0; 16],
            _ => vec![0; remainder.try_into()?],
        };

        reader.read_exact(&mut last_cypher_buffer)?;

        let ctr_vec: Vec<u8> = self
            .iv
            .unwrap()
            .into_iter()
            .chain(ctr_index.to_ne_bytes())
            .collect();
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

        buf_writer.write(&plain_text[0..last_cypher_buffer.len()])?;
        assert_eq!(offset + last_cypher_buffer.len(), self.length.try_into()?);
        println!("lenght is correct");

        for i in 0..16 {
            tag[i] ^= u128::from(self.length).to_ne_bytes()[i];
        }

        let iv: Vec<u8> = self.iv.unwrap().into_iter().chain([0, 0, 0, 0]).collect();
        let mult_last: [u8; 16] = gf_mult(iv.try_into().expect("guarrada gorda"), h);

        for i in 0..16 {
            tag[i] ^= mult_last[i];
        }

        reader.read_exact(&mut tag_buffer)?;

        self.tag = Some(tag_buffer);

        assert_eq!(self.tag, Some(tag));
        println!("tag is correct");
        buf_writer.flush()?;

        Ok(())
    }
}
