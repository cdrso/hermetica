extern "C" {
    pub(crate) fn clmul_gf(operand_a: *const u8, operand_b: *const u8, result: *mut u8);
}
