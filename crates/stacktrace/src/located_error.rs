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

use crate::stacktrace::StackTrace;

/// Prefix of a `Debug` cause block, matching the `anyhow`/`eyre` convention.
const CAUSED_BY: &str = "Caused by: ";

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
    /// spliced in.
    fn fmt_stacktrace(&self, stacktrace: &StackTrace, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner_debug = format!("{:?}", self.inner);
        let mut output: Vec<Cow<'_, str>> = Vec::new();
        let mut spliced = false;

        for line in inner_debug.lines() {
            if spliced {
                let line = Cow::Borrowed(line);
                if !output.contains(&line) {
                    output.push(line);
                }
            } else {
                if line.starts_with(CAUSED_BY) {
                    spliced = true;
                    self.push_cause(stacktrace, &mut output);
                }
                output.push(Cow::Borrowed(line));
            }
        }

        if !spliced {
            self.push_cause(stacktrace, &mut output);
        }

        for line in output {
            writeln!(f, "{line}")?;
        }

        Ok(())
    }

    /// Appends this error's cause line followed by one `\tat` line per frame.
    fn push_cause<'a>(&self, stacktrace: &StackTrace, output: &mut Vec<Cow<'a, str>>) {
        output.push(Cow::Owned(format!(
            "{CAUSED_BY}{}: {} ({})",
            type_name::<E>(),
            self.inner,
            self.location
        )));

        for frame in &stacktrace.frames {
            let line = if frame.file.is_empty() {
                format!("\tat {}", frame.func)
            } else {
                format!("\tat {} ({}:{})", frame.func, frame.file, frame.line)
            };
            output.push(Cow::Owned(line));
        }
    }
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
        match StackTrace::parse(&self.backtrace) {
            Some(stacktrace) => self.fmt_stacktrace(&stacktrace, f),
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
