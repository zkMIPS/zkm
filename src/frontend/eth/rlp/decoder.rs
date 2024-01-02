//! This file implements RLP decoder.
//!
//! Reference: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
//!
//! We have a total of 6 different ways of representing Merkle Patricia Tries.
//! - Encoded versions
//!     1. Encoded MPT : vec<u8>
//!     2. Padded Encoded MPT : ([u8; usize], usize)
//!     3. Circuit Padded Encoded MPT : (ArrayVariable<ByteVariable, ENCODING_LEN>, Variable)
//! - Decoded versions
//!     1'. MPT : RLPItem
//!     2'. Padded MPT : MPTNodeFixedSize
//!     3'. Circuit Padded MPT : (ArrayVariable<ArrayVariable<ByteVariable, 32>, 17>, Variable)
//!         TODO: This will be a new type called MPTFixedSizeVariable.
//!
//! We offer three decoding methods:
//! - decode: 1 -> 1'
//! - decode_padded_mpt_node: 2 -> 2'
//! - DecodeHint: 3 -> 3'
//!
//! Type conversions can be done as following:
//! - Conversions between encoded types
//!     - 1 -> 2: Using the to_fixed_size method
//! - Conversions between decoded types
//!     - 2' -> 1': a.iter().take(len).clone().collect()
//!
//! 1 and 1' are in this file, decoder.rs. 2 and 2' are in utils.rs. Finally, 3 and 3' are in
//! builder.rs.

use crate::utils::stream::Stream;

/// An item is a string (i.e., byte array) or a list of items.
#[derive(PartialEq, Debug)]
pub enum RLPItem {
    String(Vec<u8>),
    List(Vec<RLPItem>),
}

/// Private helper method to convert a byte array in big endian to a usize.
fn be_conversion(ls: &[u8]) -> usize {
    ls.iter()
        .rev()
        .enumerate()
        .fold(0, |acc, (i, x)| acc + ((*x as usize) << (8 * i as u32)))
}

/// Private helper method to decode an RLP-encoded byte array in a stream.
fn decode_with_stream(st: &mut Stream<u8>) -> RLPItem {
    let next_byte = st.read_exact(1)[0];
    if next_byte < 0x7f {
        // The prefix indicates that the byte has its own RLP encoding.
        RLPItem::String(vec![next_byte])
    } else if next_byte <= 0xB7 {
        // The byte indicates a short string containing up to 55 bytes.
        let length = (next_byte - 0x80) as usize;
        RLPItem::String(st.read_exact(length).to_vec())
    } else if next_byte <= 0xBF {
        // The byte indicates a long string containing more than 55 bytes.
        let nb_length_bytes = (next_byte - 0xB7) as usize;
        let length_data = st.read_exact(nb_length_bytes);

        let length = be_conversion(length_data);
        RLPItem::String(st.read_exact(length).to_vec())
    } else if next_byte <= 0xF7 {
        // The byte indicates a short list, where the payload is 0-55 bytes.
        let length = (next_byte - 0xC0) as usize;

        // Here, we need to process length _bytes_, not length _items_.
        let pos = st.position();
        let mut elements = Vec::new();
        while st.position() < pos + length {
            elements.push(decode_with_stream(st));
        }
        RLPItem::List(elements)
    } else {
        // The byte indicates a longer list.
        let nb_length_bytes = (next_byte - 0xf7) as usize;
        let length_data = st.read_exact(nb_length_bytes);

        // Convert the length data to a usize.
        let length = be_conversion(length_data);

        // Here, we need to process length _bytes_, not length _items_.
        let next_index = st.position();
        let mut elements = Vec::new();
        while st.position() < next_index + length {
            elements.push(decode_with_stream(st));
        }
        RLPItem::List(elements)
    }
}

/// Takes an RLP-encoded byte array and returns the decoded item.
pub fn decode(data: &[u8]) -> RLPItem {
    let mut st = Stream::new(data.to_vec());
    decode_with_stream(&mut st)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::bytes;

    fn test_decoder(encoding: Vec<u8>, exp: RLPItem) {
        let decoded = decode(&encoding);
        assert_eq!(decoded, exp);
    }

    #[test]
    fn test_simple_list() {
        let encoding: Vec<u8> = bytes!("0x82006f");
        let exp = RLPItem::String(vec![0x00, 0x6f]);
        test_decoder(encoding, exp)
    }

    #[test]
    fn test_empty_string() {
        let encoding: Vec<u8> = bytes!("0x80");
        let exp = RLPItem::String(vec![]);
        test_decoder(encoding, exp)
    }

    #[test]
    fn test_empty_list() {
        let encoding: Vec<u8> = bytes!("0xc0");
        let exp = RLPItem::List(vec![]);
        test_decoder(encoding, exp)
    }

    #[test]
    fn test_single_hash() {
        let encoding: Vec<u8> =
            bytes!("0xa04cfa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28");
        let exp = RLPItem::String(bytes!(
            "0x4cfa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28"
        ));
        test_decoder(encoding, exp)
    }

    #[test]
    fn test_list_hash() {
        // A list of 3 hashes.
        let encoding: Vec<u8> =
            bytes!("0xf863a011fa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28a022fa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28a033fa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28");
        let exp = RLPItem::List(vec![
            RLPItem::String(bytes!(
                "0x11fa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28"
            )),
            RLPItem::String(bytes!(
                "0x22fa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28"
            )),
            RLPItem::String(bytes!(
                "0x33fa7808badb1e62513ba42486f21240f696a9ffc6d598273d226cc5b30bfe28"
            )),
        ]);
        test_decoder(encoding, exp)
    }

    #[test]
    fn test_branch_node() {
        // A list of 17 hashes, most of them are empty.
        let encoding: Vec<u8> =
            bytes!("0xf851808080808080808080808080a035d937961d73f8a0eea9ae41b2f4cbb73c1d2c0666ea35f1ae05c43b5896b1098080a0b286218777cc1883b08227a900f3b4b876e52de06e342560852a263838d4c8a280");
        let mut exp: Vec<RLPItem> = vec![];
        for i in 0..17 {
            if i == 12 {
                exp.push(RLPItem::String(bytes!(
                    "0x35d937961d73f8a0eea9ae41b2f4cbb73c1d2c0666ea35f1ae05c43b5896b109"
                )));
            } else if i == 15 {
                exp.push(RLPItem::String(bytes!(
                    "0xb286218777cc1883b08227a900f3b4b876e52de06e342560852a263838d4c8a2"
                )));
            } else {
                exp.push(RLPItem::String(vec![]));
            }
        }
        test_decoder(encoding, RLPItem::List(exp))
    }

    #[test]
    fn test_nested_list() {
        let encoding: Vec<u8> = bytes!("0xc801c502c2030405c0");
        // The original value is ["0x01", ["0x02", ["0x03", "0x04"], "0x05"], []].
        let mut exp: Vec<RLPItem> = vec![];
        exp.push(RLPItem::String(bytes!("0x01")));
        exp.push(RLPItem::List(vec![
            RLPItem::String(bytes!("0x02")),
            RLPItem::List(vec![
                RLPItem::String(bytes!("0x03")),
                RLPItem::String(bytes!("0x04")),
            ]),
            RLPItem::String(bytes!("0x05")),
        ]));
        exp.push(RLPItem::List(vec![]));

        test_decoder(encoding, RLPItem::List(exp))
    }
}
