//! Parser turning the `Debug` rendering of a [`Backtrace`] into structured
//! frames, trimmed to the ones worth reading.

use std::backtrace::{Backtrace, BacktraceStatus};

/// One resolved backtrace frame.
#[derive(Debug)]
pub(crate) struct Frame {
    /// Demangled symbol name.
    pub(crate) func: String,
    /// Source file, empty when the frame carries no debug info.
    pub(crate) file: String,
    /// Source line, `0` when the frame carries no debug info.
    pub(crate) line: u32,
}

/// Parses a captured backtrace, yielding `None` when nothing was captured.
pub(crate) fn parse(backtrace: &Backtrace) -> Option<Vec<Frame>> {
    if backtrace.status() != BacktraceStatus::Captured {
        return None;
    }

    let mut frames = parse_debug_str(&format!("{backtrace:?}"))?;
    normalize(&mut frames);
    Some(frames)
}

/// Parses the `Backtrace [{ fn: …, file: …, line: … }, …]` rendering.
fn parse_debug_str(debug: &str) -> Option<Vec<Frame>> {
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

    (!frames.is_empty()).then_some(frames)
}

/// Drops leading conversion machinery, everything from the first runtime or
/// harness boundary onwards, and trailing call shims.
///
/// A step that would leave no frames at all is skipped.
fn normalize(frames: &mut Vec<Frame>) {
    let genuine = frames
        .iter()
        .position(|frame| !is_conversion_machinery(&frame.func));
    if let Some(genuine) = genuine {
        frames.drain(..genuine);
    }

    let boundary = frames
        .iter()
        .position(|frame| is_runtime_boundary(&frame.func));
    if let Some(boundary) = boundary
        && boundary > 0
    {
        frames.truncate(boundary);
    }

    let last = frames.iter().rposition(|frame| !is_call_shim(&frame.func));
    if let Some(last) = last {
        frames.truncate(last.saturating_add(1));
    }
}

/// First identifier of a symbol, skipping one leading `<`.
fn crate_root(func: &str) -> &str {
    let symbol = func.strip_prefix('<').unwrap_or(func);
    let end = symbol
        .find(|ch: char| !ch.is_alphanumeric() && ch != '_')
        .unwrap_or(symbol.len());

    symbol.get(..end).unwrap_or_default()
}

/// Frames the capture and the `?` conversion push above the raise site.
///
/// Whether the unwinder's own frames are rendered depends on the target, so
/// `std::backtrace` and `std::backtrace_rs` are matched anywhere in the symbol.
fn is_conversion_machinery(func: &str) -> bool {
    func.contains("std::backtrace")
        || func.contains("pluto_stacktrace::located_error")
        || (func.contains("as core::convert::From<") && func.ends_with(">::from"))
        || (func.contains("as core::convert::Into<") && func.ends_with(">::into"))
        || func.ends_with("::from_residual")
}

/// Frames where an async runtime or a test harness takes over from the caller.
fn is_runtime_boundary(func: &str) -> bool {
    func.contains("__rust_begin_short_backtrace")
        || func.starts_with("std::rt::lang_start")
        || matches!(crate_root(func), "tokio" | "test")
}

/// Frames that only forward a call to the frame above them.
fn is_call_shim(func: &str) -> bool {
    func.contains("as core::ops::function::Fn")
        || matches!(crate_root(func), "core" | "std" | "alloc")
}

/// Parses `{ fn: "…", file: "…", line: 123 }`, where `file` and `line` may be
/// absent.
fn parse_frame(frame: &str) -> Option<Frame> {
    let body = frame.trim().strip_prefix('{')?.strip_suffix('}')?;

    let (func, body) = take_field(body, "fn:")?;
    let (file, body) = take_field(body, "file:").unwrap_or(("", body));
    let line = take_field(body, "line:")
        .and_then(|(line, _)| line.parse().ok())
        .unwrap_or_default();

    Some(Frame {
        func: func.to_owned(),
        file: file.to_owned(),
        line,
    })
}

/// Takes `key` and its `"quoted"` or bare value off the front of `body`,
/// yielding the value and what follows it.
fn take_field<'a>(body: &'a str, key: &str) -> Option<(&'a str, &'a str)> {
    let rest = body.trim_start();
    let rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
    let rest = rest.strip_prefix(key)?.trim_start();

    match rest.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"'),
        None => Some(match rest.split_once(',') {
            Some((value, tail)) => (value.trim_end(), tail),
            None => (rest.trim_end(), ""),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pluto enr` failing on the main thread, debug profile.
    const CLI_MAIN_THREAD: &[&str] = &[
        "<pluto_stacktrace::located_error::LocatedError<pluto_p2p::k1::K1Error> as core::convert::From<pluto_p2p::k1::K1Error>>::from",
        "<pluto_p2p::k1::K1Error as core::convert::Into<pluto_stacktrace::located_error::LocatedError<pluto_p2p::k1::K1Error>>>::into",
        "pluto::commands::enr::run",
        "pluto::run::{closure#0}",
        "pluto::main::{closure#0}",
        "<core::pin::Pin<alloc::boxed::Box<pluto::main::{closure#0}>> as core::future::future::Future>::poll",
        "<tokio::runtime::park::CachedParkThread>::block_on::<...>::{closure#0}",
        "tokio::task::coop::with_budget::<...>",
        "tokio::task::coop::budget::<...>",
        "<tokio::runtime::park::CachedParkThread>::block_on::<...>",
        "<tokio::runtime::context::blocking::BlockingRegionGuard>::block_on::<...>",
        "<tokio::runtime::scheduler::multi_thread::MultiThread>::block_on::<...>::{closure#0}",
        "tokio::runtime::context::runtime::enter_runtime::<...>",
        "<tokio::runtime::scheduler::multi_thread::MultiThread>::block_on::<...>",
        "<tokio::runtime::runtime::Runtime>::block_on_inner::<...>",
        "<tokio::runtime::runtime::Runtime>::block_on::<pluto::main::{closure#0}>",
        "pluto::main",
        "<fn() -> std::process::ExitCode as core::ops::function::FnOnce<()>>::call_once",
        "std::sys::backtrace::__rust_begin_short_backtrace::<fn() -> std::process::ExitCode, std::process::ExitCode>",
        "std::rt::lang_start::<std::process::ExitCode>::{closure#0}",
        "<&dyn core::ops::function::Fn<(), Output = i32> + core::marker::Sync + core::panic::unwind_safe::RefUnwindSafe as core::ops::function::FnOnce<()>>::call_once",
        "std::panicking::catch_unwind::do_call::<...>",
        "std::panicking::catch_unwind::<...>",
        "std::panic::catch_unwind::<...>",
        "std::rt::lang_start_internal::{closure#0}",
        "std::panicking::catch_unwind::do_call::<std::rt::lang_start_internal::{closure#0}, isize>",
        "std::panicking::catch_unwind::<isize, std::rt::lang_start_internal::{closure#0}>",
        "std::panic::catch_unwind::<std::rt::lang_start_internal::{closure#0}, isize>",
        "std::rt::lang_start_internal",
        "std::rt::lang_start::<std::process::ExitCode>",
        "main",
        "__libc_start_call_main",
        "__libc_start_main_alias_1",
        "_start",
    ];

    /// The same `pluto enr` failure built with `--release`, where inlining
    /// collapses the runtime into `pluto::main`.
    const CLI_RELEASE: &[&str] = &[
        "<pluto_stacktrace::located_error::LocatedError<pluto_p2p::k1::K1Error> as core::convert::From<pluto_p2p::k1::K1Error>>::from",
        "pluto::commands::enr::run",
        "pluto::run::{closure#0}",
        "pluto::main::{closure#0}",
        "pluto::main",
        "std::sys::backtrace::__rust_begin_short_backtrace::<fn() -> std::process::ExitCode, std::process::ExitCode>",
        "std::rt::lang_start::<std::process::ExitCode>::{closure#0}",
        "std::rt::lang_start_internal",
        "main",
        "__libc_start_call_main",
        "__libc_start_main_alias_1",
        "_start",
    ];

    /// `?` in a workspace function called straight from a `#[test]` body.
    const TEST_CAPTURE: &[&str] = &[
        "<pluto_stacktrace::located_error::LocatedError<app::Leaf> as core::convert::From<app::Leaf>>::from",
        "<app::Wrapper as core::convert::From<app::Leaf>>::from",
        "<core::result::Result<(), app::Wrapper> as core::ops::try_trait::FromResidual<...>>::from_residual",
        "app::hop",
        "app::a_test",
        "<app::a_test as core::ops::function::FnOnce<()>>::call_once",
        "test::__rust_begin_short_backtrace::<...>",
        "test::run_test::{closure#0}",
        "<std::sys::thread::unix::Thread>::new::thread_start",
    ];

    /// A raise whose only genuine frames are already inside the runtime.
    const RUNTIME_ONLY: &[&str] = &[
        "<pluto_stacktrace::located_error::LocatedError<app::Leaf> as core::convert::From<app::Leaf>>::from",
        "<app::Leaf as core::convert::Into<app::Wrapper>>::into",
        "tokio::task::coop::budget::<...>",
        "<tokio::runtime::runtime::Runtime>::block_on::<...>",
    ];

    /// An `aarch64` capture, where the unwinder renders its own frames above
    /// the wrapper.
    const UNWINDER_FRAMES: &[&str] = &[
        "std::backtrace_rs::backtrace::libunwind::trace",
        "std::backtrace_rs::backtrace::trace_unsynchronized::<<std::backtrace::Backtrace>::create::{closure#0}>",
        "<std::backtrace::Backtrace>::create",
        "<pluto_stacktrace::located_error::LocatedError<E> as core::convert::From<E>>::from",
        "<app::Wrapper as core::convert::From<app::Leaf>>::from",
        "<core::result::Result<T,F> as core::ops::try_trait::FromResidual<...>>::from_residual",
        "app::hop",
        "app::a_test",
    ];

    /// A `--release` capture where inlining leaves a single call shim above the
    /// harness.
    const INLINED_RELEASE: &[&str] = &[
        "<app::a_test as core::ops::function::FnOnce<()>>::call_once",
        "test::__rust_begin_short_backtrace::<...>",
    ];

    fn trim(funcs: &[&str]) -> Vec<String> {
        let mut frames: Vec<Frame> = funcs
            .iter()
            .map(|func| Frame {
                func: (*func).to_owned(),
                file: String::new(),
                line: 0,
            })
            .collect();
        normalize(&mut frames);

        frames.into_iter().map(|frame| frame.func).collect()
    }

    #[test]
    fn trims_conversion_machinery_the_harness_and_call_shims() {
        assert_eq!(trim(TEST_CAPTURE), ["app::hop", "app::a_test"]);
    }

    #[test]
    fn trims_the_unwinder_frames_some_targets_render() {
        assert_eq!(trim(UNWINDER_FRAMES), ["app::hop", "app::a_test"]);
    }

    #[test]
    fn cli_capture_keeps_the_task_body_and_drops_pluto_main_below_the_runtime() {
        assert_eq!(
            trim(CLI_MAIN_THREAD),
            [
                "pluto::commands::enr::run",
                "pluto::run::{closure#0}",
                "pluto::main::{closure#0}",
            ]
        );
    }

    #[test]
    fn release_cli_capture_keeps_main_above_the_runtime_start() {
        assert_eq!(
            trim(CLI_RELEASE),
            [
                "pluto::commands::enr::run",
                "pluto::run::{closure#0}",
                "pluto::main::{closure#0}",
                "pluto::main",
            ]
        );
    }

    #[test]
    fn keeps_the_runtime_frames_when_no_caller_precedes_them() {
        assert_eq!(
            trim(RUNTIME_ONLY),
            [
                "tokio::task::coop::budget::<...>",
                "<tokio::runtime::runtime::Runtime>::block_on::<...>",
            ]
        );
    }

    #[test]
    fn keeps_a_lone_call_shim_when_trimming_would_drop_every_frame() {
        assert_eq!(
            trim(INLINED_RELEASE),
            ["<app::a_test as core::ops::function::FnOnce<()>>::call_once"]
        );
    }

    /// A build without debug info yields frames carrying only a symbol, so this
    /// asserts nothing about `file` or `line`.
    #[test]
    fn parses_a_real_capture() {
        let backtrace = Backtrace::force_capture();
        let frames = parse(&backtrace).expect("force_capture is always captured");

        assert!(
            frames
                .iter()
                .any(|frame| frame.func.contains("parses_a_real_capture")),
            "{frames:?}"
        );
    }

    #[test]
    fn parses_frames_with_braces_in_the_symbol_name() {
        let debug =
            r#"Backtrace [{ fn: "a::b::{{closure}}", file: "src/a.rs", line: 7 }, { fn: "c::d" }]"#;
        let frames = parse_debug_str(debug).expect("two frames");

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].func, "a::b::{{closure}}");
        assert_eq!(frames[0].file, "src/a.rs");
        assert_eq!(frames[0].line, 7);
        assert_eq!(frames[1].func, "c::d");
        assert_eq!(frames[1].file, "");
        assert_eq!(frames[1].line, 0);
    }

    #[test]
    fn parses_symbols_that_contain_a_field_key() {
        let debug = concat!(
            r#"Backtrace [{ fn: "pluto_core::deadline::sleep", file: "crates/core/src/deadline.rs", line: 42 }, "#,
            r#"{ fn: "pluto_app::profile::Profile::new", file: "crates/app/src/profile.rs", line: 7 }]"#
        );
        let frames = parse_debug_str(debug).expect("two frames");

        assert_eq!(frames[0].func, "pluto_core::deadline::sleep");
        assert_eq!(frames[0].file, "crates/core/src/deadline.rs");
        assert_eq!(frames[0].line, 42);
        assert_eq!(frames[1].func, "pluto_app::profile::Profile::new");
        assert_eq!(frames[1].file, "crates/app/src/profile.rs");
        assert_eq!(frames[1].line, 7);
    }

    #[test]
    fn parses_a_frame_whose_symbol_is_unresolved() {
        let frames = parse_debug_str(r#"Backtrace [{ fn: <unknown> }]"#).expect("one frame");

        assert_eq!(frames[0].func, "<unknown>");
    }

    #[test]
    fn normalize_drops_capture_machinery_frames() {
        let debug = concat!(
            r#"Backtrace [{ fn: "<pluto_stacktrace::located_error::LocatedError<app::Leaf> as core::convert::From<app::Leaf>>::from", file: "l.rs", line: 2 }, "#,
            r#"{ fn: "app::main", file: "m.rs", line: 3 }]"#
        );
        let mut frames = parse_debug_str(debug).expect("two frames");
        normalize(&mut frames);

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].func, "app::main");
    }

    #[test]
    fn rejects_input_that_is_not_a_backtrace_rendering() {
        assert!(parse_debug_str("<disabled>").is_none());
        assert!(parse_debug_str("Backtrace []").is_none());
    }
}
