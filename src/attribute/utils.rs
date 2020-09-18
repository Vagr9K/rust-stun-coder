/// XORs a u8 slice
pub fn xor_byte_range(target: &mut [u8], xor: &[u8]) {
    // Make sure the target slice size is matching or bigger than the xor slice size.
    std::debug_assert!(
        target.len() <= xor.len(),
        "Target size is bigger than the XOR slice size. Target: {}, XOR: {}.",
        target.len(),
        xor.len()
    );

    target
        .iter_mut()
        .zip(xor.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
}
