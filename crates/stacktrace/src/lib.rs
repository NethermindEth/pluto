//! Raise-location and stack-trace capture for `thiserror` types.
//!
//! [`located`] rewrites every unnamed `#[from] T` field of an error type into
//! [`LocatedError<T>`] and gives the type a `#[track_caller]` `From<T>`, so a
//! `?` conversion records where it happened and what the stack looked like
//! there. The wrapper's `Display` is the inner error's message unchanged; its
//! `Debug` adds a Java-style `Caused by:` block with one `\tat` line per frame,
//! outermost cause first.
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
    use std::{any::type_name, error::Error};

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

    #[located]
    #[derive(Debug, thiserror::Error)]
    enum One {
        #[error("one: {0}")]
        Leaf(#[from] Leaf),
    }

    #[located]
    #[derive(Debug, thiserror::Error)]
    enum Two {
        #[error("two: {0}")]
        One(#[from] One),
    }

    #[located]
    #[derive(Debug, thiserror::Error)]
    enum Three {
        #[error("three: {0}")]
        Two(#[from] Two),
    }

    fn raise_one() -> Result<(), One> {
        Err(Leaf)?;
        Ok(())
    }

    fn raise_two() -> Result<(), Two> {
        raise_one()?;
        Ok(())
    }

    fn raise_three() -> Result<(), Three> {
        raise_two()?;
        Ok(())
    }

    /// The `Caused by:` header of each block and the frame lines under it.
    fn cause_blocks(rendered: &str) -> Vec<(&str, Vec<&str>)> {
        let mut blocks: Vec<(&str, Vec<&str>)> = Vec::new();

        for line in rendered.lines() {
            if let Some(header) = line.strip_prefix("Caused by: ") {
                blocks.push((header, Vec::new()));
            } else if let Some(frame) = line.strip_prefix("\tat ")
                && let Some((_, frames)) = blocks.last_mut()
            {
                frames.push(frame);
            }
        }

        blocks
    }

    /// Asserts each frame line names the expected symbol.
    ///
    /// A frame line carries a `(file:line)` suffix only where the build has
    /// debug info, and the last one of a block also carries the delimiters an
    /// enclosing `Debug` glued onto it.
    fn assert_frames(frames: &[&str], symbols: &[&str]) {
        assert_eq!(frames.len(), symbols.len(), "{frames:?}");

        for (frame, symbol) in frames.iter().zip(symbols) {
            assert!(frame.starts_with(symbol), "{frame} does not name {symbol}");
        }
    }

    /// Asserts the invariants a `Debug` rendering must hold at any nesting
    /// depth.
    fn assert_well_formed(rendered: &str) {
        assert!(!rendered.ends_with('\n'), "{rendered}");

        let mut depth: isize = 0;
        for ch in rendered.chars() {
            match ch {
                '(' => depth = depth.saturating_add(1),
                ')' => depth = depth.saturating_sub(1),
                _ => {}
            }
            assert!(depth >= 0, "{rendered}");
        }
        assert_eq!(depth, 0, "{rendered}");

        for line in rendered.lines().skip(1) {
            assert!(
                line.starts_with("Caused by: ") || line.starts_with("\tat "),
                "{line}\n\n{rendered}"
            );
        }
    }

    #[test]
    fn renders_a_two_level_nest() {
        let rendered = format!("{:?}", raise_two().expect_err("raise_one fails"));
        assert_well_formed(&rendered);

        assert_eq!(rendered.lines().next(), Some("One(Leaf(Leaf"), "{rendered}");
        let last = rendered.lines().last().expect("a last line");
        assert!(
            last.starts_with("\tat ") && last.ends_with("))"),
            "{rendered}"
        );

        let blocks = cause_blocks(&rendered);
        assert_eq!(blocks.len(), 2, "{rendered}");
        assert!(blocks[0].0.starts_with(type_name::<One>()), "{rendered}");
        assert!(
            blocks[0].1[0].starts_with("pluto_stacktrace::tests::raise_two"),
            "{rendered}"
        );
        assert!(blocks[1].0.starts_with(type_name::<Leaf>()), "{rendered}");
        assert_frames(&blocks[1].1, &["pluto_stacktrace::tests::raise_one"]);
    }

    #[test]
    fn renders_a_three_level_nest() {
        let rendered = format!("{:?}", raise_three().expect_err("raise_one fails"));
        assert_well_formed(&rendered);

        assert_eq!(
            rendered.lines().next(),
            Some("Two(One(Leaf(Leaf"),
            "{rendered}"
        );
        let last = rendered.lines().last().expect("a last line");
        assert!(
            last.starts_with("\tat ") && last.ends_with(")))"),
            "{rendered}"
        );

        let blocks = cause_blocks(&rendered);
        assert_eq!(blocks.len(), 3, "{rendered}");
        assert!(blocks[0].0.starts_with(type_name::<Two>()), "{rendered}");
        assert!(
            blocks[0].1[0].starts_with("pluto_stacktrace::tests::raise_three"),
            "{rendered}"
        );
        assert!(blocks[1].0.starts_with(type_name::<One>()), "{rendered}");
        assert_frames(&blocks[1].1, &["pluto_stacktrace::tests::raise_two"]);
        assert!(blocks[2].0.starts_with(type_name::<Leaf>()), "{rendered}");
        assert_frames(&blocks[2].1, &["pluto_stacktrace::tests::raise_one"]);
    }
}
