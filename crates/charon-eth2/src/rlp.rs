use thiserror::Error;

use crate::utils;

/// An error that can occur when decoding or encoding RLP data.
#[derive(Debug, Error)]
pub enum RlpError {
    /// The input is too short.
    #[error("input too short")]
    InputTooShort,
    /// The length is negative.
    #[error("negative length")]
    NegativeLength,
    /// The length is too large.
    #[error("length overflow")]
    Overflow,
}

type Result<T> = std::result::Result<T, RlpError>;

/// Decodes a list of byte slices from RLP encoded data.
pub fn decode_bytes_list(input: &[u8]) -> Result<Vec<Vec<u8>>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let (offset, length) = decode_length(input)?;

    if offset.wrapping_add(length) > input.len() {
        return Err(RlpError::InputTooShort);
    }

    let mut items = Vec::new();
    let mut i = offset;

    while i < offset.wrapping_add(length) {
        let (item_offset, item_length) = decode_length(&input[i..])?;
        let start = i.wrapping_add(item_offset);
        let end = start.wrapping_add(item_length);

        if end > input.len() || start > end {
            return Err(RlpError::InputTooShort);
        }

        items.push(input[start..end].to_vec());
        i = end;
    }

    Ok(items)
}

/// Encodes a list of byte slices into RLP format.
pub fn encode_bytes_list(items: &[impl AsRef<[u8]>]) -> Vec<u8> {
    let encoded_items: Vec<u8> = items
        .iter()
        .flat_map(|item| encode_bytes(item.as_ref()))
        .collect();

    let length_prefix = encode_length(encoded_items.len(), 0xc0);
    [length_prefix, encoded_items].concat()
}

/// Decodes a single byte slice from RLP encoded data.
pub fn decode_bytes(input: &[u8]) -> Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let (offset, length) = decode_length(input)?;

    if offset.wrapping_add(length) > input.len() {
        return Err(RlpError::InputTooShort);
    }

    Ok(input[offset..offset.wrapping_add(length)].to_vec())
}

/// Encodes a single byte slice into RLP format.
pub fn encode_bytes(item: &[u8]) -> Vec<u8> {
    if item.len() == 1 && item[0] < 0x80 {
        return item.to_vec();
    }

    let length_prefix = encode_length(item.len(), 0x80);
    [length_prefix, item.to_vec()].concat()
}

/// Decodes the RLP encoding prefix, returning the offset and length.
fn decode_length(item: &[u8]) -> Result<(usize, usize)> {
    if item.is_empty() {
        return Err(RlpError::InputTooShort);
    }

    let prefix = item[0];

    match prefix {
        0x00..=0x7f => Ok((0, 1)),
        0x80..=0xb7 => Ok((1, usize::from(prefix.wrapping_sub(0x80)))),
        0xb8..=0xbf => {
            let length_size = usize::from(prefix.wrapping_sub(0xb7));
            let offset = 1usize.wrapping_add(length_size);
            let length = from_big_endian(item, 1, length_size)?;

            validate_length_and_offset(offset, length)?;
            Ok((offset, length))
        }
        0xc0..=0xf7 => Ok((1, usize::from(prefix.wrapping_sub(0xc0)))),
        0xf8..=0xff => {
            let length_size = usize::from(prefix.wrapping_sub(0xf7));
            let offset = 1usize.wrapping_add(length_size);
            let length = from_big_endian(item, 1, length_size)?;

            validate_length_and_offset(offset, length)?;
            Ok((offset, length))
        }
    }
}

/// Validates that length is non-negative and no overflow occurs.
fn validate_length_and_offset(offset: usize, length: usize) -> Result<()> {
    offset
        .checked_add(length)
        .ok_or(RlpError::Overflow)
        .map(|_| ())
}

/// Encodes the length with the given offset into RLP prefix format.
fn encode_length(length: usize, offset: u8) -> Vec<u8> {
    if length < 56 {
        return vec![
            u8::try_from(length)
                .expect("length is always less than 56")
                .wrapping_add(offset),
        ];
    }

    let big_endian = utils::to_big_endian(length);
    let prefix = u8::try_from(big_endian.len())
        .expect("big_endian.len() is always less than 256")
        .wrapping_add(offset)
        .wrapping_add(55);

    [vec![prefix], big_endian].concat()
}

/// Decodes a big-endian integer from a byte slice at the given offset and
/// length.
fn from_big_endian(bytes: &[u8], offset: usize, length: usize) -> Result<usize> {
    if offset >= bytes.len() || offset.wrapping_add(length) > bytes.len() {
        return Err(RlpError::InputTooShort);
    }

    let result = bytes[offset..offset.wrapping_add(length)]
        .iter()
        .try_fold(0usize, |acc, &byte| {
            acc.checked_shl(8)
                .and_then(|shifted| shifted.checked_add(byte as usize))
        })
        .ok_or(RlpError::Overflow)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOREM_IN: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit";
    const LOREM_OUT: &[u8] = &[
        0xb8, 0x38, b'L', b'o', b'r', b'e', b'm', b' ', b'i', b'p', b's', b'u', b'm', b' ', b'd',
        b'o', b'l', b'o', b'r', b' ', b's', b'i', b't', b' ', b'a', b'm', b'e', b't', b',', b' ',
        b'c', b'o', b'n', b's', b'e', b'c', b't', b'e', b't', b'u', b'r', b' ', b'a', b'd', b'i',
        b'p', b'i', b's', b'i', b'c', b'i', b'n', b'g', b' ', b'e', b'l', b'i', b't',
    ];

    #[test]
    fn test_bytes_list_cat_dog() {
        let input = vec![b"cat".to_vec(), b"dog".to_vec()];
        let expected = vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g'];

        let encoded = encode_bytes_list(&input.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        assert_eq!(encoded, expected);

        let decoded = decode_bytes_list(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_bytes_list_empty() {
        let input: Vec<Vec<u8>> = vec![];
        let expected = vec![0xc0];

        let encoded = encode_bytes_list(&input.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        assert_eq!(encoded, expected);

        let decoded = decode_bytes_list(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_bytes_list_long() {
        let input = vec![
            LOREM_IN.to_vec(),
            LOREM_IN.to_vec(),
            LOREM_IN.to_vec(),
            LOREM_IN.to_vec(),
            LOREM_IN.to_vec(),
            LOREM_IN.to_vec(),
            LOREM_IN.to_vec(),
            LOREM_IN.to_vec(),
        ];

        let mut expected = vec![0xf9, 0x01, 0xd0];
        for _ in 0..8 {
            expected.extend_from_slice(LOREM_OUT);
        }

        let encoded = encode_bytes_list(&input.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        assert_eq!(encoded, expected);

        let decoded = decode_bytes_list(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_bytes_dog() {
        let input = b"dog";
        let expected = vec![0x83, b'd', b'o', b'g'];

        let encoded = encode_bytes(input);
        assert_eq!(encoded, expected);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_bytes_empty() {
        let input = b"";
        let expected = vec![0x80];

        let encoded = encode_bytes(input);
        assert_eq!(encoded, expected);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_bytes_single_zero() {
        let input = &[0x00];
        let expected = vec![0x00];

        let encoded = encode_bytes(input);
        assert_eq!(encoded, expected);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_bytes_single_low() {
        let input = &[0x0f];
        let expected = vec![0x0f];

        let encoded = encode_bytes(input);
        assert_eq!(encoded, expected);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_bytes_lorem() {
        let encoded = encode_bytes(LOREM_IN);
        assert_eq!(encoded, LOREM_OUT);

        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, LOREM_IN);
    }

    #[test]
    fn test_various_lengths() {
        for length in [0, 1, 55, 56, 1023, 1024] {
            let buf: Vec<u8> = (0..length)
                .map(|i| u8::try_from(i % 256).unwrap())
                .collect();

            let encoded = encode_bytes(&buf);
            let decoded = decode_bytes(&encoded).unwrap();

            assert_eq!(decoded, buf, "Failed for length {}", length);
        }
    }

    #[test]
    fn test_roundtrip_bytes() {
        let data = b"hello world";
        let encoded = encode_bytes(data);
        let decoded = decode_bytes(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_bytes_list() {
        let items = vec![b"foo".to_vec(), b"bar".to_vec(), b"baz".to_vec()];
        let encoded = encode_bytes_list(&items.iter().map(|v| v.as_slice()).collect::<Vec<_>>());
        let decoded = decode_bytes_list(&encoded).unwrap();
        assert_eq!(decoded, items);
    }

    #[test]
    fn test_decode_empty_input() {
        assert!(decode_bytes(&[]).unwrap().is_empty());
        assert!(decode_bytes_list(&[]).unwrap().is_empty());
    }

    #[test]
    fn test_decode_bytes_list_input_too_short() {
        // Malformed input: claims to have more data than available
        let result = decode_bytes_list(&[0xc5, 0x83]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_bytes_input_too_short() {
        // Malformed input: claims to have more data than available
        let result = decode_bytes(&[0x85, 0x01, 0x02]);
        assert!(result.is_err());
    }
}
