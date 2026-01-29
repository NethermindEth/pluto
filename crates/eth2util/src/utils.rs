/// Converts an integer to big-endian byte representation without leading zeros.
pub(crate) fn to_big_endian(value: usize) -> Vec<u8> {
    value
        .to_be_bytes()
        .into_iter()
        .skip_while(|x| *x == 0)
        .collect()
}
