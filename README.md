# Hermetica

Hardware-Accelerated File Encryption and Decryption

## Overview

Hermetica is a high-performance Rust application for rapid file encryption and decryption. It leverages hardware acceleration and efficient multithreading to maximize performance across all available CPU cores.

> **Important Security Disclaimer:** Hermetica implements a custom, from-scratch AES-GCM implementation. It has not undergone formal security audits and is not recommended for production or security-critical applications without thorough review and testing.

## Key Features

- Hardware acceleration using x86 `AES-NI` and `PCLMULQDQ` instruction sets
- Highly efficient multithreading utilizing all available CPU cores
- Seamless integration of Rust and x86 assembly for optimal performance

## Technical Details

- **Algorithm:** [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- **Hardware Requirements:** x86 processor with `AES-NI` and `PCLMULQDQ` support
- **Tools used:**
  - Rust for application logic and safe concurrency
  - NASM Assembly for performance-critical cryptographic operations
- **Concurrency Model:** Rust's scoped threads for low-overhead parallel processing

## Performance

Hermetica is engineered for speed and efficiency:

- Fully utilizes all available CPU threads for parallel processing
- Dedicated instruction sets significantly outperform bare software implementation
- Performance is orders of magnitude faster than Rayon-based parallelism
  - Rayon's overhead did not yield performance improvements on this specific use case
- Speed limited by disk I/O operations
  - Cryptographic operations are highly optimized and intensive computation is not the limiting factor

## Getting Started

1. run `cargo install hermetica`

## Usage

Hermetica provides simple command-line operations for file encryption and decryption:

- **Encryption:** `hermetica -e <input_file> `
- **Decryption:** `hermetica -d <input_file>`

## Limitations and Considerations

- Compatible only with x86 processors supporting `AES-NI` and `PCLMULQDQ` instructions
- Not suitable for production or security-critical applications without thorough review and testing

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the LICENSE file for full details.

