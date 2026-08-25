use std::{cmp, fmt, sync::LazyLock};

type Result<T> = std::result::Result<T, SemVerError>;

/// Errors that can occur when parsing or handling semantic versions.
#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum SemVerError {
    /// Invalid version format when parsing a semantic version.
    #[error("Invalid version format")]
    InvalidFormat,
}

/// The branch version of the codebase.
///     - Main branch: v0.X-dev
///     - Release branch: v0.Y-rc
pub static VERSION: LazyLock<SemVer> = LazyLock::new(|| {
    let str = env!("CARGO_PKG_VERSION");

    SemVer::parse(format!("v{}", str)).expect("invalid semantic version")
});

/// Supported minor versions in order of precedence.
pub const SUPPORTED: &[SemVer] = {
    const fn v(major: usize, minor: usize) -> SemVer {
        SemVer {
            sem_ver_type: SemVerType::Minor,
            major,
            minor,
            patch: 0,
            pre_release: String::new(),
        }
    }

    &[
        v(1, 7),
        v(1, 6),
        v(1, 5),
        v(1, 4),
        v(1, 3),
        v(1, 2),
        v(1, 1),
        v(1, 0),
    ]
};

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

/// Git commit hash and timestamp from build info.
pub fn git_commit() -> (String, String) {
    let hash = option_env!("GIT_COMMIT_HASH_SHORT")
        .or(built_info::GIT_COMMIT_HASH_SHORT)
        .unwrap_or("unknown")
        .into();

    let timestamp = chrono::DateTime::parse_from_rfc2822(built_info::BUILT_TIME_UTC)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|_| "unknown".into());

    (hash, timestamp)
}

/// Placeholder short git hash used when no valid build hash is available. Seven
/// lowercase-hex chars so it satisfies Charon's peerinfo git-hash validation.
const GIT_HASH_FALLBACK: &str = "0000000";

/// Short git commit hash coerced into the `^[0-9a-f]{7}$` form Charon requires
/// in the peerinfo protocol.
///
/// Charon validates every peer's git hash against that regex and drops the
/// peer's *entire* peerinfo record (version, uptime, clock offset, ...) when it
/// fails. Release builds stamp a real 7-char hex hash, but builds without git
/// metadata (e.g. Docker builds lacking a `.git` dir) yield `""` or `"unknown"`
/// — both of which Charon rejects, hiding pluto peers from the cluster
/// dashboard. This normalises whatever the build produced (lowercasing, keeping
/// hex digits, and truncating to seven) and falls back to `GIT_HASH_FALLBACK`
/// so pluto always advertises a well-formed hash and interoperates with Charon
/// normally.
pub fn git_commit_hash_short() -> String {
    let (raw, _) = git_commit();
    coerce_git_hash(&raw)
}

/// Coerces a raw build git hash into Charon's `^[0-9a-f]{7}$` form: lowercase,
/// keep hex digits, truncate to seven, else [`GIT_HASH_FALLBACK`].
fn coerce_git_hash(raw: &str) -> String {
    let normalized: String = raw
        .to_ascii_lowercase()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(7)
        .collect();

    if normalized.len() == 7 {
        normalized
    } else {
        GIT_HASH_FALLBACK.to_owned()
    }
}

/// Logs pluto version information along with the provided message.
pub fn log_info(msg: &str) {
    let (git_hash, git_timestamp) = git_commit();
    tracing::info!(
        version = %*VERSION,
        git_commit_hash = git_hash,
        git_commit_time = git_timestamp,
        "{msg}"
    );
}

/// Dependency list from build info in `name v{version}` format.
pub fn dependencies() -> Vec<String> {
    let mut deps: Vec<String> = built_info::DEPENDENCIES
        .iter()
        .map(|(name, version)| format!("{name} v{version}"))
        .collect();
    deps.sort_unstable();
    deps
}

/// The type of semantic version, i.e., minor, patch, or pre-release.
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum SemVerType {
    /// Only major and minor version present, e.g., v1.2
    Minor,
    /// Major, minor, and patch version present, e.g., v1.2.3
    Patch,
    /// Pre-release version present, e.g., v1.2.3-rc
    PreRelease,
}

/// Represents a semantic version. A valid [`SemVer`] contains a major and minor
/// version and optionally either a patch version or a pre-release label,
/// i.e., v1.2 or v1.2.3 or v1.2-rc.
#[derive(Clone, Debug)]
pub struct SemVer {
    sem_ver_type: SemVerType,
    major: usize,
    minor: usize,
    patch: usize,
    pre_release: String,
}

static SEMVER_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^v(\d+)\.(\d+)(?:\.(\d+))?(?:-(.+))?$").expect("invalid regex")
});

impl SemVer {
    /// Returns true if the [`SemVer`] represents a tag for a pre-release.
    pub fn is_pre_release(&self) -> bool {
        self.sem_ver_type == SemVerType::PreRelease
    }

    /// Produces the minor version of the semantic version.
    /// It strips the `patch` version and `pre_release` label if
    /// present.
    pub const fn to_minor(&self) -> SemVer {
        Self {
            sem_ver_type: SemVerType::Minor,
            major: self.major,
            minor: self.minor,
            patch: 0,
            pre_release: String::new(),
        }
    }

    /// Try to parse a semantic version from a string.
    pub fn parse<T: AsRef<str>>(value: T) -> Result<SemVer> {
        let matches = SEMVER_REGEX
            .captures(value.as_ref())
            .filter(|matches| matches.len() == 5)
            .ok_or(SemVerError::InvalidFormat)?;

        // The regex guarantees these capture groups are non-empty ASCII digits,
        // so the only possible parse failure is integer overflow (e.g. a very
        // long digit run from a malicious peer). Fail closed with InvalidFormat
        // rather than panicking. NB: this is an intentional, safe divergence
        // from Charon's Parse (app/version/version.go @ v1.7.1), which discards
        // the strconv.Atoi error and silently yields 0 on overflow.
        let major = matches[1].parse().map_err(|_| SemVerError::InvalidFormat)?;
        let minor = matches[2].parse().map_err(|_| SemVerError::InvalidFormat)?;

        let mut patch = 0;
        let mut pre_release = "";
        let mut sem_ver_type = SemVerType::Minor;

        if let Some(m) = matches.get(3) {
            patch = m.as_str().parse().map_err(|_| SemVerError::InvalidFormat)?;
            sem_ver_type = SemVerType::Patch;
        }

        if let Some(m) = matches.get(4) {
            pre_release = m.as_str();
            sem_ver_type = SemVerType::PreRelease;
        }

        Ok(SemVer {
            major,
            minor,
            patch,
            pre_release: pre_release.to_string(),
            sem_ver_type,
        })
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.sem_ver_type {
            SemVerType::Minor => write!(f, "v{}.{}", self.major, self.minor),
            SemVerType::Patch => write!(f, "v{}.{}.{}", self.major, self.minor, self.patch),
            SemVerType::PreRelease => {
                write!(
                    f,
                    "v{}.{}.{}-{}",
                    self.major, self.minor, self.patch, self.pre_release
                )
            }
        }
    }
}

impl Eq for SemVer {}

impl Ord for SemVer {
    // Only major and minor versions are used for comparison, unless both self and
    // other have patch versions, in which case the patch version is also used.
    // Pre-release labels are ignored.
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        if self.major != other.major {
            if self.major < other.major {
                return cmp::Ordering::Less;
            }

            return cmp::Ordering::Greater;
        }

        if self.minor != other.minor {
            if self.minor < other.minor {
                return cmp::Ordering::Less;
            }

            return cmp::Ordering::Greater;
        }

        if self.sem_ver_type != SemVerType::Patch || other.sem_ver_type != SemVerType::Patch {
            return cmp::Ordering::Equal;
        }

        if self.patch == other.patch {
            return cmp::Ordering::Equal;
        } else if self.patch < other.patch {
            return cmp::Ordering::Less;
        }

        cmp::Ordering::Greater
    }
}

impl PartialEq for SemVer {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == cmp::Ordering::Equal
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use crate::version::{SUPPORTED, SemVer, SemVerError, SemVerType, VERSION};
    use std::{cmp, panic};

    #[test]
    fn compare() {
        let tc = vec![
            ("v0.1.0", "v0.1.0", cmp::Ordering::Equal),
            ("v0.1.0", "v0.1.1", cmp::Ordering::Less),
            ("v0.1.1", "v0.1.0", cmp::Ordering::Greater),
            ("v0.1.1", "v0.1", cmp::Ordering::Equal),
            ("v0.2.1", "v0.1", cmp::Ordering::Greater),
            ("v0.1", "v0.1-dev", cmp::Ordering::Equal),
            ("v0.1-dev", "v0.2", cmp::Ordering::Less),
        ];

        for (a, b, expected) in tc {
            let ver_a = SemVer::parse(a).unwrap();
            let ver_b = SemVer::parse(b).unwrap();
            assert_eq!(ver_a.partial_cmp(&ver_b).unwrap(), expected);
        }
    }

    #[test]
    fn coerce_git_hash_normalizes_and_falls_back() {
        use super::{GIT_HASH_FALLBACK, coerce_git_hash};

        // A valid short hash passes through unchanged.
        assert_eq!(coerce_git_hash("749d2d7"), "749d2d7");
        // Uppercase is lowered.
        assert_eq!(coerce_git_hash("ABCDEF0"), "abcdef0");
        // A full-length hash is truncated to seven.
        assert_eq!(coerce_git_hash("749d2d7abcdef0123456"), "749d2d7");
        // Non-hex sentinels and empty strings fall back.
        assert_eq!(coerce_git_hash(""), GIT_HASH_FALLBACK);
        assert_eq!(coerce_git_hash("unknown"), GIT_HASH_FALLBACK);
        // Too few hex digits also falls back (must be exactly seven).
        assert_eq!(coerce_git_hash("abc"), GIT_HASH_FALLBACK);
        // The fallback itself is a valid 7-char lowercase-hex string.
        assert_eq!(GIT_HASH_FALLBACK.len(), 7);
        assert!(GIT_HASH_FALLBACK.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn is_pre_release() {
        let pre_release = SemVer::parse("v0.17.1-rc1").unwrap();
        assert!(pre_release.is_pre_release());

        let release = SemVer::parse("v0.17.1").unwrap();
        assert!(!release.is_pre_release());
    }

    #[test]
    fn current_in_supported() {
        assert_eq!(*VERSION, SUPPORTED[0]);
    }

    #[test]
    fn supported_are_minors() {
        for v in SUPPORTED {
            assert_eq!(*v, v.to_minor());
        }
    }

    #[test]
    #[allow(clippy::const_is_empty, reason = "SUPPORTED should never be empty")]
    fn multi_supported() {
        assert!(!SUPPORTED.is_empty());
    }

    #[test]
    fn valid_version() {
        let result = panic::catch_unwind(|| VERSION.clone());
        assert!(result.is_ok());
    }

    struct ParseTestCase {
        name: &'static str,
        version: &'static str,
        expected: super::Result<SemVer>,
    }

    #[test]
    fn parse() {
        let tc = vec![
            ParseTestCase {
                name: "Patch",
                version: "v1.2.3",
                expected: Ok(SemVer {
                    major: 1,
                    minor: 2,
                    patch: 3,
                    pre_release: String::new(),
                    sem_ver_type: SemVerType::Patch,
                }),
            },
            ParseTestCase {
                name: "PreRelease",
                version: "v0.17-dev",
                expected: Ok(SemVer {
                    major: 0,
                    minor: 17,
                    patch: 0,
                    pre_release: "dev".to_string(),
                    sem_ver_type: SemVerType::PreRelease,
                }),
            },
            ParseTestCase {
                name: "Minor",
                version: "v0.1",
                expected: Ok(SemVer {
                    major: 0,
                    minor: 1,
                    patch: 0,
                    pre_release: String::new(),
                    sem_ver_type: SemVerType::Minor,
                }),
            },
            ParseTestCase {
                name: "Empty",
                version: "",
                expected: Err(SemVerError::InvalidFormat),
            },
            ParseTestCase {
                name: "Invalid 1",
                version: "invalid",
                expected: Err(SemVerError::InvalidFormat),
            },
            ParseTestCase {
                name: "No v prefix",
                version: "1.2.3",
                expected: Err(SemVerError::InvalidFormat),
            },
            ParseTestCase {
                name: "Invalid 2",
                version: "12-dev",
                expected: Err(SemVerError::InvalidFormat),
            },
            ParseTestCase {
                name: "Overflow major",
                // 30 nines: far exceeds usize::MAX on any target, must not panic.
                version: "v999999999999999999999999999999.0",
                expected: Err(SemVerError::InvalidFormat),
            },
        ];

        for test in tc {
            let actual = SemVer::parse(test.version);
            assert_eq!(actual, test.expected, "parse: `{}`", test.name);
        }
    }

    #[test]
    fn parse_overflow_is_fail_closed() {
        // Long digit runs that overflow usize must return Err, never panic.
        let overflow = "9".repeat(40);
        for version in [
            format!("v{overflow}.0"),       // major overflow
            format!("v0.{overflow}"),       // minor overflow
            format!("v0.0.{overflow}"),     // patch overflow
            format!("v0.0.{overflow}-rc1"), // patch overflow with pre-release
        ] {
            assert_eq!(
                SemVer::parse(&version),
                Err(SemVerError::InvalidFormat),
                "expected fail-closed for `{version}`"
            );
        }
    }
}
