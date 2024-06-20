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
    length: u64,
    cypher_text: PathBuf,  // path buf | owned
    tag: Option<[u8; 16]>, //first 128 bits of encrypted file | owned
}

impl GcmEncrypt {
    pub fn new(
        key: u128,
        plain_text: PathBuf,
        cypher_text: PathBuf,
    ) -> Result<GcmEncrypt, Box<dyn Error>> {
        let length = fs::metadata(&plain_text)?.len();

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
        let input_file = File::open(&self.plain_text)?;
        let mut reader = BufReader::new(input_file);

        let output_file = fs::File::create(&self.cypher_text)?;
        let mut buf_writer = BufWriter::new(output_file);

        buf_writer.write(&self.iv)?;

        let mut offset = 0;
        let mut ctr_index: u32 = 1;
        let mut read_buffer: [u8; 16] = [0; 16];

        let mut tag: [u8; 16] = [0; 16];
        let h = aes::encrypt_block(self.key_schedule, tag);

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
        buf_writer.flush()?;

        Ok(())
    }
}

