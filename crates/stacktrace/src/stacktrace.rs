//! Parser turning the `Debug` rendering of a [`Backtrace`] into structured
//! frames.

use std::backtrace::{Backtrace, BacktraceStatus};

/// Frames of a captured backtrace, innermost first.
#[derive(Debug)]
pub struct StackTrace {
    /// Parsed frames.
    pub frames: Vec<StackTraceFrame>,
}

/// One resolved backtrace frame.
#[derive(Debug)]
pub struct StackTraceFrame {
    /// Demangled symbol name.
    pub func: String,
    /// Source file, empty when the frame carries no debug info.
    pub file: String,
    /// Source line, `0` when the frame carries no debug info.
    pub line: u32,
}

impl StackTrace {
    /// Parses a captured backtrace, yielding `None` when nothing was captured.
    pub fn parse(backtrace: &Backtrace) -> Option<Self> {
        if backtrace.status() != BacktraceStatus::Captured {
            return None;
        }

        let mut stacktrace = Self::parse_debug_str(&format!("{backtrace:?}"))?;
        stacktrace.normalize();
        Some(stacktrace)
    }

    /// Parses the `Backtrace [{ fn: …, file: …, line: … }, …]` rendering.
    pub fn parse_debug_str(debug: &str) -> Option<Self> {
        const LEADING: &str = "Backtrace ";

        let frames_part = debug.trim().strip_prefix(LEADING)?.trim();
        let content = frames_part.strip_prefix('[')?.strip_suffix(']')?;

        let mut frames = Vec::new();
        let mut depth: usize = 0;
        let mut frame_start = None;

        for (index, ch) in content.char_indices() {
            match ch {
                '{' => {
                    if depth == 0 {
                        frame_start = Some(index);
                    }
                    depth = depth.saturating_add(1);
                }
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0
                        && let Some(start) = frame_start.take()
                        && let Some(frame) = content.get(start..=index).and_then(parse_frame)
                    {
                        frames.push(frame);
                    }
                }
                _ => {}
            }
        }

        (!frames.is_empty()).then_some(StackTrace { frames })
    }

    /// Drops the leading frames belonging to the capture machinery itself.
    fn normalize(&mut self) {
        while self.frames.first().is_some_and(|frame| {
            frame.func.starts_with("std::backtrace")
                || frame.func.starts_with("pluto_stacktrace::located_error")
        }) {
            self.frames.remove(0);
        }
    }
}

/// Parses `{ fn: "…", file: "…", line: 123 }`.
fn parse_frame(frame: &str) -> Option<StackTraceFrame> {
    let inner = frame.trim().strip_prefix('{')?.strip_suffix('}')?;

    Some(StackTraceFrame {
        func: find_value(inner, "fn:")?,
        file: find_value(inner, "file:").unwrap_or_default(),
        line: find_value(inner, "line:")
            .and_then(|line| line.parse().ok())
            .unwrap_or_default(),
    })
}

/// Reads the value of `key` from a `key: "value"` or `key: 123` sequence.
fn find_value(input: &str, key: &str) -> Option<String> {
    let rest = input.split_once(key)?.1.trim_start();

    let Some(quoted) = rest.strip_prefix('"') else {
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        let value = rest.get(..end)?.trim();
        return (!value.is_empty()).then(|| value.to_owned());
    };

    let mut escaped = false;
    for (index, ch) in quoted.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return quoted.get(..index).map(str::to_owned);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_capture() {
        let backtrace = Backtrace::force_capture();
        let stacktrace = StackTrace::parse(&backtrace).expect("force_capture is always captured");

        assert!(!stacktrace.frames.is_empty());
        assert!(
            stacktrace
                .frames
                .iter()
                .any(|frame| frame.func.contains("parses_a_real_capture"))
        );
    }

    #[test]
    fn parses_frames_with_braces_in_the_symbol_name() {
        let debug =
            r#"Backtrace [{ fn: "a::b::{{closure}}", file: "src/a.rs", line: 7 }, { fn: "c::d" }]"#;
        let stacktrace = StackTrace::parse_debug_str(debug).expect("two frames");

        assert_eq!(stacktrace.frames.len(), 2);
        assert_eq!(stacktrace.frames[0].func, "a::b::{{closure}}");
        assert_eq!(stacktrace.frames[0].file, "src/a.rs");
        assert_eq!(stacktrace.frames[0].line, 7);
        assert_eq!(stacktrace.frames[1].func, "c::d");
        assert_eq!(stacktrace.frames[1].file, "");
        assert_eq!(stacktrace.frames[1].line, 0);
    }

    #[test]
    fn normalize_drops_capture_machinery_frames() {
        let debug = concat!(
            r#"Backtrace [{ fn: "std::backtrace::Backtrace::create", file: "b.rs", line: 1 }, "#,
            r#"{ fn: "pluto_stacktrace::located_error::x", file: "l.rs", line: 2 }, "#,
            r#"{ fn: "app::main", file: "m.rs", line: 3 }]"#
        );
        let mut stacktrace = StackTrace::parse_debug_str(debug).expect("three frames");
        stacktrace.normalize();

        assert_eq!(stacktrace.frames.len(), 1);
        assert_eq!(stacktrace.frames[0].func, "app::main");
    }

    #[test]
    fn rejects_input_that_is_not_a_backtrace_rendering() {
        assert!(StackTrace::parse_debug_str("<disabled>").is_none());
        assert!(StackTrace::parse_debug_str("Backtrace []").is_none());
    }
}
