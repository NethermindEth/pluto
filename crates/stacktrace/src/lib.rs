//! Raise-location and stack-trace capture for `thiserror` types.
//!
//! [`located`] rewrites every unnamed `#[from] T` field of an error type into
//! [`LocatedError<T>`] and gives the type a `#[track_caller]` `From<T>`, so a
//! `?` conversion records where it happened and what the stack looked like
//! there. The wrapper's `Display` is the inner error's message unchanged; its
//! `Debug` adds a Java-style `Caused by:` block with one `\tat` line per frame.
//!
//! ```
//! #[pluto_stacktrace::located]
//! #[derive(Debug, thiserror::Error)]
//! enum LoadError {
//!     #[error("read failed: {0}")]
//!     Io(#[from] std::io::Error),
//! }
//!
//! fn load() -> Result<String, LoadError> {
//!     Ok(std::fs::read_to_string("does-not-exist")?)
//! }
//!
//! let error = load().expect_err("the file is missing");
//! println!("{error:?}");
//! ```
//!
//! Derived from `backerror` 0.1.8 (Apache-2.0), <https://github.com/tinglou/oh-my-rust-crates>
//! commit `bc046ce8ec70242d47f724c33ba1d417347deb60`, path
//! `backerror-rs/backerror`.

extern crate self as pluto_stacktrace;

mod located_error;
mod stacktrace;

pub use located_error::LocatedError;
pub use pluto_stacktrace_macros::located;

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[derive(Debug, Clone, thiserror::Error)]
    #[error("leaf")]
    struct Leaf;

    #[derive(Debug, thiserror::Error)]
    #[error("middle")]
    struct Middle {
        #[source]
        source: Leaf,
    }

    #[located]
    #[derive(Debug, thiserror::Error)]
    enum Wrapper {
        #[error("wrapped: {0}")]
        Leaf(#[from] Leaf),
        #[error("nested: {0}")]
        Middle(#[from] Middle),
    }

    /// Stand-in for a trait-bounded generic parameter whose associated type is
    /// an error.
    trait HashWalker {
        type Error: Error;
    }

    #[derive(Debug)]
    struct TestWalker;

    impl HashWalker for TestWalker {
        type Error = Leaf;
    }

    #[located]
    #[derive(Debug, thiserror::Error)]
    enum WalkError<H: HashWalker> {
        #[error("walker: {0}")]
        Walker(<H as HashWalker>::Error),
        #[error("leaf: {0}")]
        Leaf(#[from] Leaf),
    }

    #[test]
    fn from_conversion_records_the_raise_location() {
        let error = LocatedError::from(Leaf);

        let debug = format!("{error:?}");
        assert!(debug.contains(file!()), "{debug}");
        assert!(debug.contains("Caused by: "), "{debug}");
        assert!(debug.contains("\tat "), "{debug}");
    }

    #[test]
    fn generated_from_impl_records_the_raise_location() {
        let error = Wrapper::from(Leaf);

        let debug = format!("{error:?}");
        assert!(debug.contains(file!()), "{debug}");
    }

    #[test]
    fn display_is_the_thiserror_message() {
        assert_eq!(LocatedError::from(Leaf).to_string(), "leaf");
        assert_eq!(Wrapper::from(Leaf).to_string(), "wrapped: leaf");
        assert_eq!(
            Wrapper::from(Middle { source: Leaf }).to_string(),
            "nested: middle"
        );
    }

    #[test]
    fn source_skips_the_wrapper() {
        let error = LocatedError::from(Middle { source: Leaf });

        let source = error.source().expect("Middle carries a source");
        assert_eq!(source.to_string(), "leaf");
    }

    #[test]
    fn generic_error_types_are_instrumented() {
        let error = WalkError::<TestWalker>::from(Leaf);

        assert_eq!(error.to_string(), "leaf: leaf");
        let debug = format!("{error:?}");
        assert!(debug.contains(file!()), "{debug}");

        assert_eq!(
            WalkError::<TestWalker>::Walker(Leaf).to_string(),
            "walker: leaf"
        );
    }
}
