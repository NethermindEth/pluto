//! `Marshal` trait, error type, and the `register_signed_data_codecs!` table
//! that wires every [`SignedData`](crate::types::SignedData) type into the
//! parsigex serialization path.
//!
//! The macro is the *only* legal way to make a type usable as `SignedData`:
//! it emits the `Marshal` impl, an entry in the duty-keyed dispatch table
//! consumed by [`crate::parsigex_codec::deserialize_signed_data`], and
//! generated round-trip / json-fallback / duty-dispatch tests.

/// Codec error reported by [`Marshal`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum MarshalError {
    /// SSZ codec failure.
    #[error("ssz: {0}")]
    Ssz(String),
    /// JSON codec failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// Custom error message bubbled up from a wrapper constructor.
    #[error("custom: {0}")]
    Custom(String),
    /// All registered codecs failed to decode the bytes.
    #[error("all codecs failed")]
    AllFailed,
}

impl From<crate::ssz_codec::SszCodecError> for MarshalError {
    fn from(err: crate::ssz_codec::SszCodecError) -> Self {
        MarshalError::Ssz(err.to_string())
    }
}

impl From<ssz::DecodeError> for MarshalError {
    fn from(err: ssz::DecodeError) -> Self {
        MarshalError::Ssz(format!("{err:?}"))
    }
}

impl From<crate::signeddata::SignedDataError> for MarshalError {
    fn from(err: crate::signeddata::SignedDataError) -> Self {
        MarshalError::Custom(err.to_string())
    }
}

/// Self-describing serialize/deserialize trait for `SignedData` types.
///
/// `marshal` is dyn-compatible (vtable dispatch on `&dyn SignedData`).
/// `unmarshal` is statically dispatched (`Self: Sized`); duty-keyed decode for
/// `Box<dyn SignedData>` lives in
/// [`crate::parsigex_codec::deserialize_signed_data`] and uses the table
/// registered by [`register_signed_data_codecs!`].
pub trait Marshal {
    /// Serializes this value to the wire format chosen by its registered
    /// codec.
    fn marshal(&self) -> Result<Vec<u8>, MarshalError>;

    /// Deserializes a value of `Self` from bytes encoded by [`Self::marshal`].
    fn unmarshal(bytes: &[u8]) -> Result<Self, MarshalError>
    where
        Self: Sized;
}

/// Returns `true` when the trimmed byte slice starts with `{`, indicating
/// JSON object data.
#[doc(hidden)]
#[must_use]
pub fn looks_like_json(bytes: &[u8]) -> bool {
    bytes.iter().find(|b| !b.is_ascii_whitespace()).copied() == Some(b'{')
}

/// Single row in the duty-keyed dispatch table: `(duty, priority, decoder)`.
///
/// `priority` orders the decoders within one `DutyType` — lower runs first.
/// Each `decoder` consumes raw bytes and returns a `Box<dyn SignedData>`.
#[doc(hidden)]
pub type DispatchEntry = (
    crate::types::DutyType,
    u8,
    fn(&[u8]) -> Result<Box<dyn crate::types::SignedData>, MarshalError>,
);

// ---------------------------------------------------------------------------
// register_signed_data_codecs! — single source of truth for SignedData wiring
// ---------------------------------------------------------------------------

/// Registers `SignedData` types and emits, for each entry:
///
/// 1. An `impl Marshal` whose codec choice (json / ssz_then_json) is the single
///    source of truth for both encode and decode.
/// 2. An entry in `dispatch_table()` consumed by
///    [`crate::parsigex_codec::deserialize_signed_data`] when an entry has a
///    `duty:` field.
/// 3. Auto-generated round-trip, json-fallback, and duty-dispatch tests under
///    `#[cfg(test)] mod generated_codec_tests::<TypeName>`.
///
/// Entry forms:
///
/// ```text
/// // SSZ-then-JSON, registered for duty dispatch
/// Foo {
///     duty: <DutyType variant>, priority: <u8>,
///     codec: ssz_then_json(<encode_fn>, <decode_fn>),
///     sample: <fn() -> Foo>,
/// },
///
/// // JSON-only, registered for duty dispatch (priority defaults to 0)
/// Bar {
///     duty: <DutyType variant>,
///     codec: json,
///     sample: <fn() -> Bar>,
/// },
///
/// // Marshal impl + tests, no duty dispatch
/// Baz {
///     codec: ssz_then_json(<encode_fn>, <decode_fn>),
///     sample: <fn() -> Baz>,
/// },
/// ```
///
/// `encode_fn` and `decode_fn` are paths to functions with signatures
/// `fn(&Self) -> Result<Vec<u8>, E1>` and `fn(&[u8]) -> Result<Self, E2>`
/// respectively, where `MarshalError: From<E1> + From<E2>`. Wrappers whose
/// inner SSZ helpers operate on the inner field (e.g. `phase0::Attestation`
/// rather than `Attestation`) get a one-line adapter at the top of
/// `signeddata.rs`.
#[macro_export]
macro_rules! register_signed_data_codecs {
    ( $( $ty:ident { $($body:tt)* } ),* $(,)? ) => {
        // 1) Marshal impls.
        $( $crate::__marshal_impl! { $ty , $($body)* } )*

        // 2) Duty-keyed dispatch table. Built once on first call and cached.
        #[doc(hidden)]
        pub(crate) fn dispatch_table() -> &'static [$crate::marshal::DispatchEntry] {
            static TABLE: ::std::sync::OnceLock<::std::vec::Vec<$crate::marshal::DispatchEntry>> =
                ::std::sync::OnceLock::new();
            TABLE
                .get_or_init(|| {
                    let mut __table: ::std::vec::Vec<$crate::marshal::DispatchEntry> =
                        ::std::vec::Vec::new();
                    $( $crate::__dispatch_push! { __table , $ty , $($body)* } )*
                    __table
                })
                .as_slice()
        }

        // 3) Generated tests (one inner module per entry).
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod generated_codec_tests {
            $( $crate::__generated_tests! { $ty , $($body)* } )*
        }
    };
}

/// Marshal impl for a single entry.
///
/// `ssz_then_json(enc, dec)` expects the following signatures, so that the
/// macro can directly delegate without further glue:
///
/// ```text
/// fn enc(value: &Self) -> Result<Vec<u8>, E1> where MarshalError: From<E1>;
/// fn dec(bytes: &[u8]) -> Result<Self,    E2> where MarshalError: From<E2>;
/// ```
///
/// Wrappers whose inner SSZ helpers operate on the inner field
/// (e.g. `phase0::Attestation` rather than `Attestation`) get a one-line
/// adapter at the top of `signeddata.rs`.
#[doc(hidden)]
#[macro_export]
macro_rules! __marshal_impl {
    // ssz_then_json
    (
        $ty:ident,
        $( duty: $_duty:ident , $( priority: $_prio:literal , )? )?
        codec: ssz_then_json($enc:path, $dec:path $(,)?),
        sample: $_sample:path $(,)?
    ) => {
        impl $crate::marshal::Marshal for $ty {
            fn marshal(
                &self,
            ) -> ::std::result::Result<::std::vec::Vec<u8>, $crate::marshal::MarshalError> {
                $enc(self).map_err(::core::convert::Into::into)
            }

            fn unmarshal(bytes: &[u8]) -> ::std::result::Result<Self, $crate::marshal::MarshalError>
            where
                Self: ::core::marker::Sized,
            {
                if $crate::marshal::looks_like_json(bytes) {
                    return ::serde_json::from_slice::<Self>(bytes)
                        .map_err($crate::marshal::MarshalError::from);
                }
                $dec(bytes).map_err(::core::convert::Into::into)
            }
        }
    };

    // json
    (
        $ty:ident,
        $( duty: $_duty:ident , $( priority: $_prio:literal , )? )?
        codec: json,
        sample: $_sample:path $(,)?
    ) => {
        impl $crate::marshal::Marshal for $ty {
            fn marshal(
                &self,
            ) -> ::std::result::Result<::std::vec::Vec<u8>, $crate::marshal::MarshalError> {
                ::serde_json::to_vec(self).map_err($crate::marshal::MarshalError::from)
            }

            fn unmarshal(bytes: &[u8]) -> ::std::result::Result<Self, $crate::marshal::MarshalError>
            where
                Self: ::core::marker::Sized,
            {
                ::serde_json::from_slice::<Self>(bytes).map_err($crate::marshal::MarshalError::from)
            }
        }
    };
}

/// Pushes one row into the dispatch table being built. Entries without a
/// `duty:` field expand to nothing so they don't appear in the table.
#[doc(hidden)]
#[macro_export]
macro_rules! __dispatch_push {
    // duty + explicit priority
    (
        $table:ident, $ty:ident,
        duty: $duty:ident , priority: $prio:literal ,
        codec: $_codec:ident $(($($_codec_arg:tt)*))? ,
        sample: $_sample:path $(,)?
    ) => {
        $table.push((
            $crate::types::DutyType::$duty,
            $prio,
            (|bytes: &[u8]| -> ::std::result::Result<
                ::std::boxed::Box<dyn $crate::types::SignedData>,
                $crate::marshal::MarshalError,
            > {
                <$ty as $crate::marshal::Marshal>::unmarshal(bytes).map(|v| {
                    ::std::boxed::Box::new(v) as ::std::boxed::Box<dyn $crate::types::SignedData>
                })
            }) as fn(&[u8]) -> ::std::result::Result<
                ::std::boxed::Box<dyn $crate::types::SignedData>,
                $crate::marshal::MarshalError,
            >,
        ));
    };

    // duty only — priority defaults to 0
    (
        $table:ident, $ty:ident,
        duty: $duty:ident ,
        codec: $codec:ident $(($($codec_arg:tt)*))? ,
        sample: $sample:path $(,)?
    ) => {
        $crate::__dispatch_push! {
            $table, $ty,
            duty: $duty , priority: 0 ,
            codec: $codec $(($($codec_arg)*))? ,
            sample: $sample,
        }
    };

    // no duty — no dispatch entry
    (
        $table:ident, $ty:ident,
        codec: $_codec:ident $(($($_codec_arg:tt)*))? ,
        sample: $_sample:path $(,)?
    ) => {};
}

/// Generated tests for a single entry. Emits a per-type module with up to
/// three `#[test]` functions — `roundtrip`, `json_fallback` (only for
/// `ssz_then_json` codecs), and `duty_dispatch` (only when a duty is set).
#[doc(hidden)]
#[macro_export]
macro_rules! __generated_tests {
    // ssz_then_json with duty (+ optional priority)
    (
        $ty:ident,
        duty: $duty:ident , $( priority: $_prio:literal , )?
        codec: ssz_then_json $(($($_codec_arg:tt)*))? ,
        sample: $sample:path $(,)?
    ) => {
        #[allow(non_snake_case)]
        mod $ty {
            use super::super::*;

            #[test]
            fn roundtrip() {
                let v: $ty = $sample();
                let bytes = <$ty as $crate::marshal::Marshal>::marshal(&v).unwrap();
                let back = <$ty as $crate::marshal::Marshal>::unmarshal(&bytes).unwrap();
                assert_eq!(v, back);
            }

            #[test]
            fn json_fallback() {
                let v: $ty = $sample();
                let bytes = ::serde_json::to_vec(&v).unwrap();
                assert_eq!(bytes.first(), Some(&b'{'));
                let back = <$ty as $crate::marshal::Marshal>::unmarshal(&bytes).unwrap();
                assert_eq!(v, back);
            }

            #[test]
            fn duty_dispatch() {
                let v: $ty = $sample();
                let bytes = <$ty as $crate::marshal::Marshal>::marshal(&v).unwrap();
                let duty = $crate::types::DutyType::$duty;
                let boxed = $crate::parsigex_codec::deserialize_signed_data(&duty, &bytes).unwrap();
                let any = boxed as ::std::boxed::Box<dyn ::std::any::Any>;
                let back = *any.downcast::<$ty>().expect("type mismatch in dispatch");
                assert_eq!(v, back);
            }
        }
    };

    // json with duty (+ optional priority)
    (
        $ty:ident,
        duty: $duty:ident , $( priority: $_prio:literal , )?
        codec: json,
        sample: $sample:path $(,)?
    ) => {
        #[allow(non_snake_case)]
        mod $ty {
            use super::super::*;

            #[test]
            fn roundtrip() {
                let v: $ty = $sample();
                let bytes = <$ty as $crate::marshal::Marshal>::marshal(&v).unwrap();
                let back = <$ty as $crate::marshal::Marshal>::unmarshal(&bytes).unwrap();
                assert_eq!(v, back);
            }

            #[test]
            fn duty_dispatch() {
                let v: $ty = $sample();
                let bytes = <$ty as $crate::marshal::Marshal>::marshal(&v).unwrap();
                let duty = $crate::types::DutyType::$duty;
                let boxed = $crate::parsigex_codec::deserialize_signed_data(&duty, &bytes).unwrap();
                let any = boxed as ::std::boxed::Box<dyn ::std::any::Any>;
                let back = *any.downcast::<$ty>().expect("type mismatch in dispatch");
                assert_eq!(v, back);
            }
        }
    };

    // ssz_then_json without duty
    (
        $ty:ident,
        codec: ssz_then_json $(($($_codec_arg:tt)*))? ,
        sample: $sample:path $(,)?
    ) => {
        #[allow(non_snake_case)]
        mod $ty {
            use super::super::*;

            #[test]
            fn roundtrip() {
                let v: $ty = $sample();
                let bytes = <$ty as $crate::marshal::Marshal>::marshal(&v).unwrap();
                let back = <$ty as $crate::marshal::Marshal>::unmarshal(&bytes).unwrap();
                assert_eq!(v, back);
            }

            #[test]
            fn json_fallback() {
                let v: $ty = $sample();
                let bytes = ::serde_json::to_vec(&v).unwrap();
                assert_eq!(bytes.first(), Some(&b'{'));
                let back = <$ty as $crate::marshal::Marshal>::unmarshal(&bytes).unwrap();
                assert_eq!(v, back);
            }
        }
    };

    // json without duty
    (
        $ty:ident,
        codec: json,
        sample: $sample:path $(,)?
    ) => {
        #[allow(non_snake_case)]
        mod $ty {
            use super::super::*;

            #[test]
            fn roundtrip() {
                let v: $ty = $sample();
                let bytes = <$ty as $crate::marshal::Marshal>::marshal(&v).unwrap();
                let back = <$ty as $crate::marshal::Marshal>::unmarshal(&bytes).unwrap();
                assert_eq!(v, back);
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_json_ignores_leading_whitespace() {
        assert!(looks_like_json(b"{\"a\":1}"));
        assert!(looks_like_json(b"   \n\t{\"a\":1}"));
        assert!(!looks_like_json(b"\x00\x01\x02"));
        assert!(!looks_like_json(b""));
        assert!(!looks_like_json(b"\"x\""));
    }
}
