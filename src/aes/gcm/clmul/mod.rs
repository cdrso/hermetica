extern "C" {
    /// FFI for hardware accelerated Galois field multiplication.
    pub(crate) fn clmul_gf(operand_a: *const u8, operand_b: *const u8, result: *mut u8);
}
