# Design Notes

src/
---/main.rs
---/aes/
-------/aes-ni/
--------------/aesni asm file(s)
-------/gcm/
-----------/pclmulqdq/
---------------------/pclmulqdq asm file(s)
-----------/mod.rs
-------/mod.rs

/test folder that has files for encryption/decryption

## mod AES

### mod.rs
implementation for the aes module

should have

- ffi for asm functions
- wrappers for functions
- basic aes operations that are not contained in wrappers

### aes-ni
src/aes/aes-ni contains the asm files in nasm syntax to perform standart aes operations with hardware acceleration
should the asm wrappers be here instead of mod.rs for aes module?
dont think so

### gcm
#### pclmulqdq
src/aes/gcm/pclmulqdq contains the asm file(s) in nasm syntax to perform gcm operations with hardware acceleration (multiplication in GF)
should the asm wrappers be here instead of mod.rs for aes::gcm module?
#### mod.rs
src/aes/gcm/mod.rs

implementation for the gcm module

should have

specific types for key, iv, key schedule??? impl For for IV?
types are going to be the biggest pain to pass between byte/word representations and numbers

- GcmEncrypt Struct
    data structure that represents file encryption with IV, key schedule,  plain text, cypher text, tag
    pub method ::new(key, file)
        creates a new GcmEncrypt instance given a key and a file
        generates random IV and computes key_schedule
        populates plain_text field with file
    pub method ::gen_cypher()
        encrypts the plain text into cypher text
        CTR with IV and key_schedule
    pub method ::write_encrypted_file //is this good naming convention?
        writes iv + cypher + tag to file
    prv method ::gen_tag()
        computes tag for a given GcmEncrypt instance if Some(cyphertext)

- GcmDecrypt Struct
    data structure that represents file decryption with IV, key schedule,  plain text, cypher text, tag
    pub method ::new(key, file)
        creates a new GcmDecrypt instance given a key and a file
        populates cypher text with file (minus tag and iv)
        computes key_schedule, extracts tag and iv, assert missing bytes
        generates and checks tag
    pub method ::gen_decypher()
        decrypts the cypher text into plain text
    pub method ::write_decrypted_file //is this good naming convention?
        writes plain text to file
    prv method ::gen_tag()
        computes tag for a given GcmDecrypt instance


