//! The [`LocatedError`] wrapper and its rendering.

use std::{
    any::type_name,
    backtrace::Backtrace,
    borrow::{Borrow, Cow},
    error::Error,
    fmt,
    ops::Deref,
    panic::Location,
    sync::Arc,
};

use crate::stacktrace::{self, Frame};

/// Prefix of a cause line.
const CAUSED_BY: &str = "Caused by: ";

/// Prefix of a frame line.
const AT: &str = "\tat ";

/// An error paired with the location it was converted at and the stack trace
/// captured there.
///
/// `Display` renders the inner error verbatim; `Debug` renders the location and
/// the frames.
pub struct LocatedError<E: Error> {
    inner: E,
    location: &'static Location<'static>,
    backtrace: Arc<Backtrace>,
}

impl<E: Error> LocatedError<E> {
    /// Renders the inner error's `Debug` output with this error's cause block
    /// spliced in ahead of the causes it already carries.
    fn fmt_stacktrace(&self, frames: &[Frame], f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cause = format!(
            "{CAUSED_BY}{}: {} ({})",
            type_name::<E>(),
            self.inner,
            self.location
        );
        let at: Vec<String> = frames.iter().map(frame_line).collect();
        let inner = format!("{:?}", self.inner);

        let mut output: Vec<Cow<'_, str>> = Vec::new();
        let mut spliced = false;

        for line in inner.lines() {
            if spliced {
                match repeated_frame_tail(&at, line) {
                    Some(tail) => append(&mut output, tail),
                    None => output.push(Cow::Borrowed(line)),
                }
            } else {
                if line.starts_with(CAUSED_BY) {
                    spliced = true;
                    output.push(Cow::Borrowed(&cause));
                    output.extend(at.iter().map(|line| Cow::Borrowed(line.as_str())));
                }
                output.push(Cow::Borrowed(line));
            }
        }

        if !spliced {
            output.push(Cow::Borrowed(&cause));
            output.extend(at.iter().map(|line| Cow::Borrowed(line.as_str())));
        }

        f.write_str(&output.join("\n"))
    }
}

/// Puts closing delimiters back on the line they were glued to.
fn append<'a>(output: &mut Vec<Cow<'a, str>>, tail: &'a str) {
    if tail.is_empty() {
        return;
    }

    match output.last_mut() {
        Some(last) => *last = Cow::Owned(format!("{last}{tail}")),
        None => output.push(Cow::Borrowed(tail)),
    }
}

/// Renders one `\tat` line.
fn frame_line(frame: &Frame) -> String {
    if frame.file.is_empty() {
        format!("{AT}{}", frame.func)
    } else {
        format!("{AT}{} ({}:{})", frame.func, frame.file, frame.line)
    }
}

/// Matches `line` against a frame this error already printed, yielding the
/// closing delimiters an enclosing `Debug` glued onto it.
///
/// A capture taken deeper in the stack ends in the same frames as this one, so
/// its cause block repeats them verbatim.
fn repeated_frame_tail<'a>(at: &[String], line: &'a str) -> Option<&'a str> {
    if !line.starts_with(AT) {
        return None;
    }

    at.iter().find_map(|frame| {
        let tail = line.strip_prefix(frame.as_str())?;
        tail.chars()
            .all(|ch| matches!(ch, ')' | '}' | ']' | ',' | ' '))
            .then_some(tail)
    })
}

impl<E: Error> Error for LocatedError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source()
    }
}

impl<E: Error> fmt::Display for LocatedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl<E: Error> fmt::Debug for LocatedError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match stacktrace::parse(&self.backtrace) {
            Some(frames) => self.fmt_stacktrace(&frames, f),
            None => write!(
                f,
                "{:?} at ({}) by {}",
                self.inner,
                self.location,
                type_name::<E>()
            ),
        }
    }
}

impl<E: Error> From<E> for LocatedError<E> {
    #[track_caller]
    fn from(inner: E) -> Self {
        LocatedError {
            inner,
            location: Location::caller(),
            backtrace: Arc::new(Backtrace::force_capture()),
        }
    }
}

impl<E: Error> AsRef<E> for LocatedError<E> {
    fn as_ref(&self) -> &E {
        &self.inner
    }
}

impl<E: Error> Deref for LocatedError<E> {
    type Target = E;

    fn deref(&self) -> &E {
        &self.inner
    }
}

impl<E: Error> Borrow<E> for LocatedError<E> {
    fn borrow(&self) -> &E {
        &self.inner
    }
}

impl<E: Error + Clone> Clone for LocatedError<E> {
    fn clone(&self) -> Self {
        LocatedError {
            inner: self.inner.clone(),
            location: self.location,
            backtrace: Arc::clone(&self.backtrace),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, thiserror::Error)]
    #[error("leaf")]
    struct Leaf;

    fn assert_send_sync<T: Send + Sync>() {}

    fn assert_clone<T: Clone>() {}

    #[test]
    fn marker_traits_are_derived_from_the_inner_error() {
        assert_send_sync::<LocatedError<std::io::Error>>();
        assert_send_sync::<LocatedError<Leaf>>();
        assert_clone::<LocatedError<Leaf>>();
    }

    #[test]
    fn clone_preserves_location_and_message() {
        let error = LocatedError::from(Leaf);
        let clone = error.clone();

        assert_eq!(error.location, clone.location);
        assert_eq!(format!("{error:?}"), format!("{clone:?}"));
    }

    #[test]
    fn deref_and_borrow_reach_the_inner_error() {
        let error = LocatedError::from(Leaf);

        assert_eq!(error.to_string(), "leaf");
        assert_eq!(AsRef::<Leaf>::as_ref(&error).to_string(), "leaf");
        assert_eq!(Borrow::<Leaf>::borrow(&error).to_string(), "leaf");
        assert_eq!(Deref::deref(&error).to_string(), "leaf");
    }
}
