//! # Pluto Proto
//!
//! A thin shim over the [`prost`] runtime that Pluto's generated protobuf code
//! is routed through via
//! `prost_build::Config::prost_path("::pluto_proto::prost")`
//! (see `pluto-build-proto`).
//!
//! Everything is re-exported from `prost` unchanged **except** the protobuf map
//! encoders ([`prost::encoding::btree_map`] / [`prost::encoding::hash_map`]),
//! which are overridden to always emit a map entry's key **and** value fields.
//!
//! ## Why
//!
//! `prost` follows the proto3 convention of omitting a scalar field that equals
//! its default, and applies that rule *inside* map entries too: an entry whose
//! key is the empty string, or whose value is empty bytes, is encoded with that
//! field dropped. Charon's Go marshaler (`proto.MarshalOptions{Deterministic:
//! true}`) always emits both fields. Because Pluto SSZ-hashes the deterministic
//! protobuf encoding to derive QBFT consensus value hashes, that single-byte
//! divergence would make a pluto node and a charon node compute different
//! hashes for the same `UnsignedDataSet`, breaking consensus in a mixed
//! cluster.
//!
//! Routing all generated code through this shim makes map encoding
//! charon-compatible for **every** message uniformly, rather than
//! special-casing individual types at each hashing call site. Decoding is
//! untouched — `prost` already accepts both the explicit-empty and omitted
//! forms — so `merge` is re-exported verbatim.
//!
//! Note that this only changes the bytes for entries with an empty key or empty
//! value; entries with non-empty keys and values (the only shape that occurs in
//! normal operation) encode identically to stock `prost`.

/// Drop-in replacement for the `prost` crate.
///
/// Generated code refers to items as `::pluto_proto::prost::…`; the glob
/// re-export forwards everything to the real crate, and the nested
/// [`encoding`](crate::prost::encoding)
/// module shadows only the map encoders.
pub mod prost {
    pub use ::prost::*;

    /// Mirror of [`prost::encoding`] with charon-compatible map encoders.
    pub mod encoding {
        pub use ::prost::encoding::*;

        // A map entry is a length-delimited submessage with the key at field 1
        // and the value at field 2. This generates `encode`/`encoded_len` (and
        // their `_with_default` variants, used for proto2 enum-valued maps)
        // that — unlike stock prost — never skip a field that equals
        // its default, so the wire bytes match charon's Go marshaler
        // exactly. `merge` / `merge_with_default` are re-exported from
        // prost: decoding already accepts both the explicit-empty and
        // omitted forms, so the read path needs no change.
        //
        // The arithmetic and `usize as u64` casts mirror prost's own map
        // encoding verbatim; the workspace lints that would otherwise flag them
        // are relaxed for this faithful reproduction.
        macro_rules! charon_map_encoders {
            ($map_ty:ident, $prost_mod:ident) => {
                // Signatures mirror prost's map encoders exactly (the generated
                // code calls them positionally), and the body reproduces prost's
                // encoding arithmetic verbatim; relax the lints that would flag
                // that faithful reproduction.
                #[allow(
                    clippy::arithmetic_side_effects,
                    clippy::cast_possible_truncation,
                    clippy::too_many_arguments
                )]
                mod encoders {
                    use core::hash::Hash;

                    use ::prost::{
                        bytes::BufMut,
                        encoding::{
                            WireType, encode_key, encode_varint, encoded_len_varint, key_len,
                        },
                    };

                    use super::$map_ty;

                    /// See module docs: like `prost`'s `encode`, but never skips
                    /// a default key or value.
                    pub fn encode<K, V, B, KE, KL, VE, VL>(
                        key_encode: KE,
                        key_encoded_len: KL,
                        val_encode: VE,
                        val_encoded_len: VL,
                        tag: u32,
                        values: &$map_ty<K, V>,
                        buf: &mut B,
                    ) where
                        K: Default + Eq + Hash + Ord,
                        V: Default + PartialEq,
                        B: BufMut,
                        KE: Fn(u32, &K, &mut B),
                        KL: Fn(u32, &K) -> usize,
                        VE: Fn(u32, &V, &mut B),
                        VL: Fn(u32, &V) -> usize,
                    {
                        encode_with_default(
                            key_encode,
                            key_encoded_len,
                            val_encode,
                            val_encoded_len,
                            &V::default(),
                            tag,
                            values,
                            buf,
                        )
                    }

                    /// See module docs: like `prost`'s `encoded_len`, but counts
                    /// both fields of every entry.
                    pub fn encoded_len<K, V, KL, VL>(
                        key_encoded_len: KL,
                        val_encoded_len: VL,
                        tag: u32,
                        values: &$map_ty<K, V>,
                    ) -> usize
                    where
                        K: Default + Eq + Hash + Ord,
                        V: Default + PartialEq,
                        KL: Fn(u32, &K) -> usize,
                        VL: Fn(u32, &V) -> usize,
                    {
                        encoded_len_with_default(
                            key_encoded_len,
                            val_encoded_len,
                            &V::default(),
                            tag,
                            values,
                        )
                    }

                    /// See module docs. The value default is accepted for
                    /// signature parity with prost but intentionally unused: we
                    /// emit every field regardless.
                    pub fn encode_with_default<K, V, B, KE, KL, VE, VL>(
                        key_encode: KE,
                        key_encoded_len: KL,
                        val_encode: VE,
                        val_encoded_len: VL,
                        _val_default: &V,
                        tag: u32,
                        values: &$map_ty<K, V>,
                        buf: &mut B,
                    ) where
                        K: Default + Eq + Hash + Ord,
                        V: PartialEq,
                        B: BufMut,
                        KE: Fn(u32, &K, &mut B),
                        KL: Fn(u32, &K) -> usize,
                        VE: Fn(u32, &V, &mut B),
                        VL: Fn(u32, &V) -> usize,
                    {
                        for (key, val) in values.iter() {
                            let len = key_encoded_len(1, key) + val_encoded_len(2, val);
                            encode_key(tag, WireType::LengthDelimited, buf);
                            encode_varint(len as u64, buf);
                            key_encode(1, key, buf);
                            val_encode(2, val, buf);
                        }
                    }

                    /// See [`encode_with_default`]; `_val_default` is likewise
                    /// unused.
                    pub fn encoded_len_with_default<K, V, KL, VL>(
                        key_encoded_len: KL,
                        val_encoded_len: VL,
                        _val_default: &V,
                        tag: u32,
                        values: &$map_ty<K, V>,
                    ) -> usize
                    where
                        K: Default + Eq + Hash + Ord,
                        V: PartialEq,
                        KL: Fn(u32, &K) -> usize,
                        VL: Fn(u32, &V) -> usize,
                    {
                        key_len(tag) * values.len()
                            + values
                                .iter()
                                .map(|(key, val)| {
                                    let len = key_encoded_len(1, key) + val_encoded_len(2, val);
                                    encoded_len_varint(len as u64) + len
                                })
                                .sum::<usize>()
                    }
                }

                pub use encoders::{
                    encode, encode_with_default, encoded_len, encoded_len_with_default,
                };
                // Decoding is unchanged; reuse prost's merge functions verbatim.
                pub use ::prost::encoding::$prost_mod::{merge, merge_with_default};
            };
        }

        /// `BTreeMap` map encoders that always emit both entry fields.
        pub mod btree_map {
            use ::prost::alloc::collections::BTreeMap;

            charon_map_encoders!(BTreeMap, btree_map);
        }

        /// `HashMap` map encoders that always emit both entry fields.
        pub mod hash_map {
            use std::collections::HashMap;

            charon_map_encoders!(HashMap, hash_map);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ::prost::{
        bytes::Buf,
        encoding::{DecodeContext, string},
    };

    use crate::prost::encoding::btree_map;

    /// A `map<string, string>` entry keeps both fields on the wire even when
    /// the key or value is the empty-string default (which stock prost
    /// would drop).
    #[test]
    fn encode_emits_empty_key_and_value_fields() {
        let mut map = BTreeMap::new();
        map.insert(String::new(), "val".to_string());

        let mut buf = Vec::new();
        btree_map::encode(
            string::encode,
            string::encoded_len,
            string::encode,
            string::encoded_len,
            1,
            &map,
            &mut buf,
        );

        // entry(tag 1, len 7) { key(0a 00) value(12 03 "val") }
        assert_eq!(buf, [0x0a, 0x07, 0x0a, 0x00, 0x12, 0x03, b'v', b'a', b'l']);
    }

    /// `encoded_len` must equal the number of bytes `encode` actually writes,
    /// including the always-emitted default fields.
    #[test]
    fn encoded_len_matches_encode() {
        let mut map = BTreeMap::new();
        map.insert(String::new(), String::new());
        map.insert("key".to_string(), "value".to_string());

        let mut buf = Vec::new();
        btree_map::encode(
            string::encode,
            string::encoded_len,
            string::encode,
            string::encoded_len,
            3,
            &map,
            &mut buf,
        );

        let len = btree_map::encoded_len(string::encoded_len, string::encoded_len, 3, &map);
        assert_eq!(buf.len(), len);
    }

    /// The re-exported `merge` round-trips the shim's own output, so decoding
    /// is unaffected by the always-emit change.
    #[test]
    fn merge_round_trips_shim_encoding() {
        let mut map = BTreeMap::new();
        map.insert(String::new(), "val".to_string());
        map.insert("key".to_string(), String::new());

        let mut buf = Vec::new();
        btree_map::encode(
            string::encode,
            string::encoded_len,
            string::encode,
            string::encoded_len,
            1,
            &map,
            &mut buf,
        );

        // Decode each map entry back through the re-exported merge. prost's map
        // merge consumes the length-delimited entry itself, so we only strip
        // the field tag that precedes each occurrence.
        let mut decoded: BTreeMap<String, String> = BTreeMap::new();
        let mut slice: &[u8] = &buf;
        while slice.has_remaining() {
            let _field_tag = slice.get_u8();
            btree_map::merge(
                string::merge,
                string::merge,
                &mut decoded,
                &mut slice,
                DecodeContext::default(),
            )
            .unwrap();
        }

        assert_eq!(decoded, map);
    }
}
