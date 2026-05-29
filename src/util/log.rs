//! Minimal leveled logger — no external crate.
//!
//! Lines are timestamped (UTC) and tagged with a level. Warnings and errors go
//! to stderr, informational and debug lines to stdout, so runtime noise can be
//! separated from diagnostics. The active level is a process-global set once at
//! startup from `--quiet`/`--verbose`.

use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};

use super::time;

/// Severity, ordered most to least important. `set_level` enables a level and
/// everything more important than it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Set the most verbose level that will be emitted: quiet → `Warn`, default →
/// `Info`, verbose → `Debug`.
pub fn set_level(level: Level) {
    MAX_LEVEL.store(level as u8, Ordering::Relaxed);
}

fn enabled(level: Level) -> bool {
    level as u8 <= MAX_LEVEL.load(Ordering::Relaxed)
}

/// Write one preformatted line. Prefer the `log_*!` macros, which build the
/// arguments lazily and skip the call entirely when the level is disabled.
pub fn emit(level: Level, args: fmt::Arguments) {
    if !enabled(level) {
        return;
    }
    let ts = time::format_utc(time::now());
    let tag = match level {
        Level::Error => "ERROR",
        Level::Warn => "WARN",
        Level::Info => "INFO",
        Level::Debug => "DEBUG",
    };
    if level <= Level::Warn {
        eprintln!("{ts} [{tag}] {args}");
    } else {
        println!("{ts} [{tag}] {args}");
    }
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        $crate::util::log::emit($crate::util::log::Level::Error, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        $crate::util::log::emit($crate::util::log::Level::Warn, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        $crate::util::log::emit($crate::util::log::Level::Info, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        $crate::util::log::emit($crate::util::log::Level::Debug, format_args!($($arg)*))
    };
}
