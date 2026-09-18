//! Parser turning the `Debug` rendering of a [`Backtrace`] into structured
//! frames, trimmed to the ones worth reading.

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

    /// Drops leading conversion machinery, everything from the first runtime or
    /// harness boundary onwards, and trailing call shims.
    ///
    /// A step that would leave no frames at all is skipped.
    fn normalize(&mut self) {
        let genuine = self
            .frames
            .iter()
            .position(|frame| !is_conversion_machinery(&frame.func));
        if let Some(genuine) = genuine {
            self.frames.drain(..genuine);
        }

        let boundary = self
            .frames
            .iter()
            .position(|frame| is_runtime_boundary(&frame.func));
        if let Some(boundary) = boundary
            && boundary > 0
        {
            self.frames.truncate(boundary);
        }

        let last = self
            .frames
            .iter()
            .rposition(|frame| !is_call_shim(&frame.func));
        if let Some(last) = last {
            self.frames.truncate(last.saturating_add(1));
        }
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

/// Frames the `?` conversion itself pushes above the raise site.
fn is_conversion_machinery(func: &str) -> bool {
    func.contains("pluto_stacktrace::located_error")
        || (func.contains("as core::convert::From<") && func.ends_with(">::from"))
        || (func.contains("as core::convert::Into<") && func.ends_with(">::into"))
        || func.ends_with("::from_residual")
        || func.starts_with("std::backtrace")
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

    /// Frames libtest and `std` push below every `#[test]` body.
    const LIBTEST_TAIL: &[&str] = &[
        "test::__rust_begin_short_backtrace::<core::result::Result<(), alloc::string::String>, fn() -> core::result::Result<(), alloc::string::String>>",
        "test::run_test_in_process::{closure#0}",
        "<core::panic::unwind_safe::AssertUnwindSafe<test::run_test_in_process::{closure#0}> as core::ops::function::FnOnce<()>>::call_once",
        "std::panicking::catch_unwind::do_call::<...>",
        "std::panicking::catch_unwind::<...>",
        "std::panic::catch_unwind::<...>",
        "test::run_test_in_process",
        "test::run_test::{closure#0}",
        "test::run_test::{closure#1}",
        "std::sys::backtrace::__rust_begin_short_backtrace::<test::run_test::{closure#1}, ()>",
        "std::thread::lifecycle::spawn_unchecked::<test::run_test::{closure#1}, ()>::{closure#1}::{closure#0}",
        "<core::panic::unwind_safe::AssertUnwindSafe<...> as core::ops::function::FnOnce<()>>::call_once",
        "std::panicking::catch_unwind::do_call::<...>",
        "std::panicking::catch_unwind::<...>",
        "std::panic::catch_unwind::<...>",
        "std::thread::lifecycle::spawn_unchecked::<test::run_test::{closure#1}, ()>::{closure#1}",
        "<std::thread::lifecycle::spawn_unchecked<test::run_test::{closure#1}, ()>::{closure#1} as core::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}",
        "<alloc::boxed::Box<dyn core::ops::function::FnOnce<(), Output = ()> + core::marker::Send> as core::ops::function::FnOnce<()>>::call_once",
        "<std::sys::thread::unix::Thread>::new::thread_start",
        "start_thread",
        "__GI___clone3",
    ];

    /// `?` inside `hop1`, called straight from a `#[test]` body, debug profile.
    const PLAIN_TEST_HEAD: &[&str] = &[
        "<pluto_stacktrace::located_error::LocatedError<measured::Leaf> as core::convert::From<measured::Leaf>>::from",
        "<measured::Wrapper as core::convert::From<measured::Leaf>>::from",
        "<core::result::Result<(), measured::Wrapper> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible, measured::Leaf>>>::from_residual",
        "measured::hop1",
        "measured::plain_test",
        "measured::plain_test::{closure#0}",
        "<measured::plain_test::{closure#0} as core::ops::function::FnOnce<()>>::call_once",
        "<fn() -> core::result::Result<(), alloc::string::String> as core::ops::function::FnOnce<()>>::call_once",
    ];

    /// The same raise under `#[tokio::test(flavor = "multi_thread")]`, debug
    /// profile.
    const TOKIO_TEST_HEAD: &[&str] = &[
        "<pluto_stacktrace::located_error::LocatedError<measured::Leaf> as core::convert::From<measured::Leaf>>::from",
        "<measured::Wrapper as core::convert::From<measured::Leaf>>::from",
        "<core::result::Result<(), measured::Wrapper> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible, measured::Leaf>>>::from_residual",
        "measured::hop1",
        "measured::tokio_multi_thread_test::{closure#0}",
        "<core::pin::Pin<&mut dyn core::future::future::Future<Output = ()>> as core::future::future::Future>::poll",
        "<tokio::runtime::park::CachedParkThread>::block_on::<...>::{closure#0}",
        "tokio::task::coop::with_budget::<...>",
        "tokio::task::coop::budget::<...>",
        "<tokio::runtime::park::CachedParkThread>::block_on::<...>",
        "<tokio::runtime::context::blocking::BlockingRegionGuard>::block_on::<...>",
        "<tokio::runtime::scheduler::multi_thread::MultiThread>::block_on::<...>::{closure#0}",
        "tokio::runtime::context::runtime::enter_runtime::<...>",
        "<tokio::runtime::scheduler::multi_thread::MultiThread>::block_on::<...>",
        "<tokio::runtime::runtime::Runtime>::block_on_inner::<...>",
        "<tokio::runtime::runtime::Runtime>::block_on::<...>",
        "measured::tokio_multi_thread_test",
        "measured::tokio_multi_thread_test::{closure#0}",
        "<measured::tokio_multi_thread_test::{closure#0} as core::ops::function::FnOnce<()>>::call_once",
        "<fn() -> core::result::Result<(), alloc::string::String> as core::ops::function::FnOnce<()>>::call_once",
    ];

    /// `Runtime::block_on` driving a bare `futures_util` combinator chain, so
    /// no workspace frame survives the runtime cut. Debug profile.
    const FUTURES_ONLY_HEAD: &[&str] = &[
        "<pluto_stacktrace::located_error::LocatedError<measured::Leaf> as core::convert::From<measured::Leaf>>::from",
        "<measured::Wrapper as core::convert::From<measured::Leaf>>::from",
        "<measured::Leaf as core::convert::Into<measured::Wrapper>>::into",
        "<futures_util::fns::IntoFn<measured::Wrapper> as futures_util::fns::FnOnce1<measured::Leaf>>::call_once",
        "<futures_util::fns::MapErrFn<futures_util::fns::IntoFn<measured::Wrapper>> as futures_util::fns::FnOnce1<core::result::Result<(), measured::Leaf>>>::call_once::{closure#0}",
        "<core::result::Result<(), measured::Leaf>>::map_err::<measured::Wrapper, ...>",
        "<futures_util::fns::MapErrFn<futures_util::fns::IntoFn<measured::Wrapper>> as futures_util::fns::FnOnce1<core::result::Result<(), measured::Leaf>>>::call_once",
        "<futures_util::future::future::map::Map<...> as core::future::future::Future>::poll",
        "<futures_util::future::future::Map<...> as core::future::future::Future>::poll",
        "<futures_util::future::try_future::MapErr<...> as core::future::future::Future>::poll",
        "<futures_util::future::try_future::ErrInto<...> as core::future::future::Future>::poll",
        "<core::pin::Pin<&mut futures_util::future::try_future::ErrInto<...>> as core::future::future::Future>::poll",
        "<tokio::runtime::scheduler::current_thread::CoreGuard>::block_on::<...>::{closure#0}::{closure#0}::{closure#0}",
        "tokio::task::coop::with_budget::<...>",
        "tokio::task::coop::budget::<...>",
        "<tokio::runtime::scheduler::current_thread::CoreGuard>::block_on::<...>::{closure#0}::{closure#0}",
        "<tokio::runtime::scheduler::current_thread::Context>::enter::<...>",
        "<tokio::runtime::scheduler::current_thread::CoreGuard>::block_on::<...>::{closure#0}",
        "<tokio::runtime::scheduler::current_thread::CoreGuard>::enter::<...>::{closure#0}",
        "<tokio::runtime::context::scoped::Scoped<tokio::runtime::scheduler::Context>>::set::<...>",
        "tokio::runtime::context::set_scheduler::<...>::{closure#0}",
        "<std::thread::local::LocalKey<tokio::runtime::context::Context>>::try_with::<...>",
        "<std::thread::local::LocalKey<tokio::runtime::context::Context>>::with::<...>",
        "tokio::runtime::context::set_scheduler::<...>",
        "<tokio::runtime::scheduler::current_thread::CoreGuard>::enter::<...>",
        "<tokio::runtime::scheduler::current_thread::CoreGuard>::block_on::<...>",
        "<tokio::runtime::scheduler::current_thread::CurrentThread>::block_on::<...>::{closure#0}",
        "tokio::runtime::context::runtime::enter_runtime::<...>",
        "<tokio::runtime::scheduler::current_thread::CurrentThread>::block_on::<...>",
        "<tokio::runtime::runtime::Runtime>::block_on_inner::<...>",
        "<tokio::runtime::runtime::Runtime>::block_on::<...>",
        "measured::futures_only",
        "measured::futures_only::{closure#0}",
        "<measured::futures_only::{closure#0} as core::ops::function::FnOnce<()>>::call_once",
        "<fn() -> core::result::Result<(), alloc::string::String> as core::ops::function::FnOnce<()>>::call_once",
    ];

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

    /// The same `pluto enr` failure built with `--release`: no `.debug_*`
    /// sections, so every frame carries an empty file and line `0`.
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

    /// The plain `#[test]` raise built with `--release`, where inlining leaves
    /// a single call shim above the harness.
    const RELEASE_PLAIN_TEST: &[&str] = &[
        "<measured::plain_test::{closure#0} as core::ops::function::FnOnce<()>>::call_once",
        "test::__rust_begin_short_backtrace::<core::result::Result<(), alloc::string::String>, fn() -> core::result::Result<(), alloc::string::String>>",
        "test::run_test::{closure#0}",
        "std::sys::backtrace::__rust_begin_short_backtrace::<test::run_test::{closure#1}, ()>",
        "<std::thread::lifecycle::spawn_unchecked<test::run_test::{closure#1}, ()>::{closure#1} as core::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}",
        "<std::sys::thread::unix::Thread>::new::thread_start",
        "start_thread",
        "__GI___clone3",
    ];

    fn frames(funcs: &[&str]) -> Vec<StackTraceFrame> {
        funcs
            .iter()
            .map(|func| StackTraceFrame {
                func: (*func).to_owned(),
                file: String::new(),
                line: 0,
            })
            .collect()
    }

    fn trim(funcs: &[&str]) -> Vec<String> {
        let mut stacktrace = StackTrace {
            frames: frames(funcs),
        };
        stacktrace.normalize();

        stacktrace
            .frames
            .into_iter()
            .map(|frame| frame.func)
            .collect()
    }

    #[test]
    fn trims_a_plain_test_capture_to_the_raising_body() {
        let capture = [PLAIN_TEST_HEAD, LIBTEST_TAIL].concat();
        assert_eq!(capture.len(), 29);

        assert_eq!(
            trim(&capture),
            [
                "measured::hop1",
                "measured::plain_test",
                "measured::plain_test::{closure#0}",
            ]
        );
    }

    #[test]
    fn trims_a_tokio_test_capture_at_the_runtime_boundary() {
        let capture = [TOKIO_TEST_HEAD, LIBTEST_TAIL].concat();
        assert_eq!(capture.len(), 41);

        assert_eq!(
            trim(&capture),
            [
                "measured::hop1",
                "measured::tokio_multi_thread_test::{closure#0}",
            ]
        );
    }

    #[test]
    fn cli_capture_keeps_the_task_body_and_drops_pluto_main_below_the_runtime() {
        assert_eq!(CLI_MAIN_THREAD.len(), 34);

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
    fn trims_a_release_capture_that_carries_no_debug_info() {
        let mut stacktrace = StackTrace {
            frames: frames(CLI_RELEASE),
        };
        stacktrace.normalize();

        assert!(
            stacktrace
                .frames
                .iter()
                .all(|frame| frame.file.is_empty() && frame.line == 0)
        );
        assert_eq!(
            stacktrace
                .frames
                .iter()
                .map(|frame| frame.func.as_str())
                .collect::<Vec<_>>(),
            [
                "pluto::commands::enr::run",
                "pluto::run::{closure#0}",
                "pluto::main::{closure#0}",
                "pluto::main",
            ]
        );
    }

    #[test]
    fn keeps_the_combinator_chain_when_no_workspace_frame_precedes_the_runtime() {
        let capture = [FUTURES_ONLY_HEAD, LIBTEST_TAIL].concat();
        assert_eq!(capture.len(), 56);

        assert_eq!(
            trim(&capture),
            [
                "<futures_util::fns::IntoFn<measured::Wrapper> as futures_util::fns::FnOnce1<measured::Leaf>>::call_once",
                "<futures_util::fns::MapErrFn<futures_util::fns::IntoFn<measured::Wrapper>> as futures_util::fns::FnOnce1<core::result::Result<(), measured::Leaf>>>::call_once::{closure#0}",
                "<core::result::Result<(), measured::Leaf>>::map_err::<measured::Wrapper, ...>",
                "<futures_util::fns::MapErrFn<futures_util::fns::IntoFn<measured::Wrapper>> as futures_util::fns::FnOnce1<core::result::Result<(), measured::Leaf>>>::call_once",
                "<futures_util::future::future::map::Map<...> as core::future::future::Future>::poll",
                "<futures_util::future::future::Map<...> as core::future::future::Future>::poll",
                "<futures_util::future::try_future::MapErr<...> as core::future::future::Future>::poll",
                "<futures_util::future::try_future::ErrInto<...> as core::future::future::Future>::poll",
            ]
        );
    }

    #[test]
    fn keeps_the_last_non_empty_result_when_a_step_would_drop_every_frame() {
        assert_eq!(
            trim(RELEASE_PLAIN_TEST),
            ["<measured::plain_test::{closure#0} as core::ops::function::FnOnce<()>>::call_once"]
        );

        let runtime_only = &CLI_MAIN_THREAD[6..17];
        assert_eq!(trim(runtime_only), runtime_only);
    }

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
