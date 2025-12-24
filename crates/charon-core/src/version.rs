use std::{cmp, fmt, str, sync::LazyLock};

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
    let str = option_env!("CHARON_VERSION").unwrap_or("v0.1.0-dev");

    SemVer::try_from(str).unwrap()
});

/// Supported minor versions in order of precedence.
pub const SUPPORTED: &'static [SemVer] = {
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

/// Git commit hash and timestamp from build info.
pub fn git_commit() -> (String, String) {
    mod built_info {
        include!(concat!(env!("OUT_DIR"), "/built.rs"));
    }

    let hash = built_info::GIT_COMMIT_HASH.unwrap_or("unknown").into();
    let timestamp = chrono::DateTime::parse_from_rfc2822(built_info::BUILT_TIME_UTC)
        .map(|dt| dt.timestamp().to_string())
        .unwrap_or("unknown".into());

    (hash, timestamp)
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

static SEMVER_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^v(\d+)\.(\d+)(?:\.(\d+))?(?:-(.+))?$").unwrap());

impl SemVer {
    /// Returns true if the [`SemVer`] represents a tag for a pre-release.
    pub fn is_pre_release(&self) -> bool {
        self.sem_ver_type == SemVerType::PreRelease
    }

    /// Produces the minor version of the semantic version.
    /// It strips the [`patch`] version and [`pre_release`] label if present.
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
    pub fn parse(value: &str) -> Result<SemVer> {
        let matches = SEMVER_REGEX
            .captures(value)
            .filter(|matches| !(matches.len() == 0 || matches.len() != 5))
            .ok_or(SemVerError::InvalidFormat)?;

        let major = matches[1].parse().expect("regex ensures number");
        let minor = matches[2].parse().expect("regex ensures number");

        let mut patch = 0;
        let mut pre_release = "";
        let mut sem_ver_type = SemVerType::Minor;

        if let Some(m) = matches.get(3) {
            patch = m.as_str().parse().expect("regex ensures number");
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

impl PartialEq for SemVer {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other).unwrap() == cmp::Ordering::Equal
    }
}

impl PartialOrd for SemVer {
    // Only major and minor versions are used for comparison, unless both self and
    // other have patch versions, in which case the patch version is also used.
    // Pre-release labels are ignored.
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        if self.major != other.major {
            if self.major < other.major {
                return Some(cmp::Ordering::Less);
            }

            return Some(cmp::Ordering::Greater);
        }

        if self.minor != other.minor {
            if self.minor < other.minor {
                return Some(cmp::Ordering::Less);
            }

            return Some(cmp::Ordering::Greater);
        }

        if self.sem_ver_type != SemVerType::Patch || other.sem_ver_type != SemVerType::Patch {
            return Some(cmp::Ordering::Equal);
        }

        if self.patch == other.patch {
            return Some(cmp::Ordering::Equal);
        } else if self.patch < other.patch {
            return Some(cmp::Ordering::Less);
        }

        return Some(cmp::Ordering::Greater);
    }
}

impl TryFrom<&str> for SemVer {
    type Error = SemVerError;

    fn try_from(value: &str) -> Result<Self> {
        SemVer::parse(value)
    }
}

impl str::FromStr for SemVer {
    type Err = SemVerError;

    fn from_str(s: &str) -> Result<Self> {
        SemVer::parse(s)
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
            let ver_a = SemVer::try_from(a).unwrap();
            let ver_b = SemVer::try_from(b).unwrap();
            assert_eq!(ver_a.partial_cmp(&ver_b).unwrap(), expected);
        }
    }

    #[test]
    fn is_pre_release() {
        let pre_release = SemVer::try_from("v0.17.1-rc1").unwrap();
        assert!(pre_release.is_pre_release());

        let release = SemVer::try_from("v0.17.1").unwrap();
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
    fn multi_supported() {
        assert!(SUPPORTED.len() >= 1);
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
        ];

        for test in tc {
            let actual = SemVer::parse(test.version);
            assert_eq!(actual, test.expected, "parse: `{}`", test.name);
        }
    }
}
