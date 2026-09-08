//! # Verify PR
//!
//! Verifies a GitHub pull request against the contribution template: a
//! `package[/subpackage]: subject` title plus a body carrying `category:`,
//! `ticket:` and optional `feature_flag:` tags.
//!
//! The PR is read as JSON from the `GITHUB_PR` env variable, which is how the
//! GitHub Actions `pull_request` event payload is handed to the tool.

use std::{env, sync::LazyLock};

use pluto_featureset::{Config, Feature, FeatureSet, FeaturesetError, Status};
use regex::Regex;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// The env variable carrying the PR as JSON.
const PR_ENV: &str = "GITHUB_PR";

/// The maximum length of a PR title.
const MAX_TITLE_LEN: usize = 60;

/// The minimum length of the title suffix, the `: subject` part.
const MIN_TITLE_SUFFIX_LEN: usize = 5;

/// The values accepted by the `category:` body tag.
const CATEGORIES: [&str; 7] = [
    "feature", "bug", "refactor", "docs", "test", "fixbuild", "misc",
];

/// The `category:` body tag.
const CAT_TAG: &str = "category:";

/// The `ticket:` body tag.
const TICKET_TAG: &str = "ticket:";

/// The `feature_flag:` body tag.
const FEATURE_TAG: &str = "feature_flag:";

/// Matches the `package[/subpackage]` title prefix.
///
/// The `\w` class is spelled out since Go's `regexp` treats it as ASCII-only
/// while Rust's `regex` treats it as Unicode.
static TITLE_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[*0-9A-Za-z_]+(/[*0-9A-Za-z_]+)?$").expect("invalid regex"));

/// Errors returned when a PR doesn't match the template.
#[derive(Debug, Error)]
pub enum Error {
    /// The env variable carrying the PR isn't set, or is blank.
    #[error("env variable not set: {var}")]
    EnvVarNotSet {
        /// Name of the missing env variable.
        var: &'static str,
    },

    /// The PR JSON couldn't be deserialised.
    #[error("unmarshal PR body")]
    UnmarshalPr(#[source] serde_json::Error),

    /// One of the required PR fields is empty.
    #[error("pr field not set")]
    PrFieldNotSet,

    /// The feature set couldn't be resolved.
    #[error(transparent)]
    Featureset(#[from] FeaturesetError),

    /// The title exceeds the maximum length.
    #[error("title too long: max {max}, actual {actual}")]
    TitleTooLong {
        /// Maximum allowed title length.
        max: usize,
        /// Length of the offending title.
        actual: usize,
    },

    /// The title has no `package[/subpackage]:` prefix.
    #[error("title isn't prefixed with 'package[/subpackage]:'")]
    TitleNotPrefixed,

    /// The title prefix isn't a `package[/subpackage]` pair.
    #[error("title prefix doesn't match regex")]
    TitlePrefixRegex,

    /// The title suffix is shorter than the minimum length.
    #[error("title suffix too short")]
    TitleSuffixTooShort,

    /// The colon after the title prefix isn't followed by a space.
    #[error("title prefix not followed by space")]
    TitleNotFollowedBySpace,

    /// The title suffix starts with a capital.
    #[error("title suffix shouldn't start with a capital")]
    TitleSuffixCapital,

    /// The title suffix ends with punctuation.
    #[error("title suffix shouldn't end with punctuation")]
    TitleSuffixPunctuation,

    /// The body is empty.
    #[error("body empty")]
    BodyEmpty,

    /// The body still carries the template's markdown comments.
    #[error("instructions not deleted (markdown comments present)")]
    InstructionsNotDeleted,

    /// The first body line is empty.
    #[error("first line empty")]
    FirstLineEmpty,

    /// The body carries more than one `category:` line.
    #[error("multiple category tag lines")]
    MultipleCategoryTags,

    /// The `category:` line isn't preceded by an empty line.
    #[error("category tag not preceded by empty line")]
    CategoryTagNotPrecededByEmptyLine,

    /// The `category:` tag has no value.
    #[error("category tag empty")]
    CategoryTagEmpty,

    /// The `category:` value isn't one of the accepted categories.
    #[error("invalid category: {category}, allows: {allows}")]
    InvalidCategory {
        /// The rejected category.
        category: String,
        /// The accepted categories.
        allows: String,
    },

    /// The body carries more than one `ticket:` line.
    #[error("multiple ticket tag lines")]
    MultipleTicketTags,

    /// The `ticket:` tag has no value.
    #[error("ticket tag empty")]
    TicketTagEmpty,

    /// The `ticket:` value is still the template's placeholder.
    #[error("invalid #000 ticket")]
    InvalidPlaceholderTicket,

    /// The `ticket:` value isn't a valid URL.
    #[error("ticket tag invalid url")]
    TicketTagInvalidUrl,

    /// The `ticket:` value isn't a GitHub issue reference.
    #[error("ticket tag not a valid github link, #123")]
    TicketTagNotGithubLink,

    /// The `ticket:` value is neither a URL, `none`, nor `#123`.
    #[error("invalid ticket tag")]
    InvalidTicketTag,

    /// The body is missing the `category:` tag.
    #[error("missing category tag")]
    MissingCategoryTag,

    /// The body is missing the `ticket:` tag.
    #[error("missing ticket tag")]
    MissingTicketTag,

    /// The body carries more than one `feature_flag:` line.
    #[error("multiple feature_flag tag lines")]
    MultipleFeatureFlagTags,

    /// The `feature_flag:` tag has no value.
    #[error("feature_flag tag empty")]
    FeatureFlagTagEmpty,

    /// The `feature_flag:` value is still the template's placeholder.
    #[error("invalid ? feature_flag")]
    InvalidPlaceholderFeatureFlag,

    /// The `feature_flag:` value isn't snake case.
    #[error("feature flags are snake case, see crates/featureset/src/lib.rs")]
    FeatureFlagNotSnakeCase,

    /// The `feature_flag:` value isn't a known, enabled feature.
    #[error("unknown feature flag, see crates/featureset/src/lib.rs")]
    UnknownFeatureFlag,
}

/// Result alias for PR verification.
pub type Result<T> = std::result::Result<T, Error>;

/// A GitHub pull request.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Pr {
    /// The PR title.
    #[serde(default)]
    pub title: String,
    /// The PR body.
    #[serde(default)]
    pub body: String,
    /// The PR node ID.
    #[serde(default, rename = "node_id")]
    pub id: String,
}

impl Pr {
    /// Returns the PR parsed from the `GITHUB_PR` env variable.
    pub fn from_env() -> Result<Self> {
        let pr_json = env::var(PR_ENV).map_err(|_| Error::EnvVarNotSet { var: PR_ENV })?;

        if pr_json.trim().is_empty() {
            return Err(Error::EnvVarNotSet { var: PR_ENV });
        }

        let pr: Self = serde_json::from_str(&pr_json).map_err(Error::UnmarshalPr)?;

        if pr.title.is_empty() || pr.body.is_empty() || pr.id.is_empty() {
            return Err(Error::PrFieldNotSet);
        }

        Ok(pr)
    }
}

/// Returns an error if the PR in the `GITHUB_PR` env variable doesn't match the
/// template.
pub fn verify() -> Result<()> {
    let features = FeatureSet::from_config(Config {
        min_status: Status::Alpha,
        ..Default::default()
    })?;

    let pr = Pr::from_env()?;

    // Skip dependabot PRs.
    if pr.title.contains("build(deps)") && pr.body.contains("dependabot") {
        return Ok(());
    }

    // Skip Renovate PRs.
    if pr.title.contains("chore(deps)") && pr.body.contains("Renovate") {
        return Ok(());
    }

    tracing::info!(title = %pr.title, "Verifying PR against template");
    tracing::info!("## PR body:\n{}\n####", pr.body);

    verify_title(&pr.title)?;
    verify_body(&pr.body, &features)?;

    Ok(())
}

/// Returns an error if the PR title doesn't match the template.
pub fn verify_title(title: &str) -> Result<()> {
    if title.len() > MAX_TITLE_LEN {
        return Err(Error::TitleTooLong {
            max: MAX_TITLE_LEN,
            actual: title.len(),
        });
    }

    let Some((prefix, suffix)) = title.split_once(':') else {
        return Err(Error::TitleNotPrefixed);
    };

    if !TITLE_PREFIX.is_match(prefix) {
        return Err(Error::TitlePrefixRegex);
    }

    if suffix.len() < MIN_TITLE_SUFFIX_LEN {
        return Err(Error::TitleSuffixTooShort);
    }

    let Some(suffix) = suffix.strip_prefix(' ') else {
        return Err(Error::TitleNotFollowedBySpace);
    };

    if suffix.chars().next().is_some_and(char::is_uppercase) {
        return Err(Error::TitleSuffixCapital);
    }

    if suffix.chars().next_back().is_some_and(is_punct) {
        return Err(Error::TitleSuffixPunctuation);
    }

    Ok(())
}

/// Returns an error if the PR body doesn't match the template.
///
/// `features` resolves the `feature_flag:` tag; a flag naming a feature that
/// isn't enabled there is rejected.
pub fn verify_body(body: &str, features: &FeatureSet) -> Result<()> {
    if body.trim().is_empty() {
        return Err(Error::BodyEmpty);
    }

    if body.contains("<!--") {
        return Err(Error::InstructionsNotDeleted);
    }

    let mut prev_line_empty = false;
    let mut found_category = false;
    let mut found_ticket = false;
    let mut found_feature = false;

    for (i, line) in body.split('\n').enumerate() {
        if i == 0 && line.trim().is_empty() {
            return Err(Error::FirstLineEmpty);
        }

        if let Some(cat) = line.strip_prefix(CAT_TAG) {
            if found_category {
                return Err(Error::MultipleCategoryTags);
            }

            if !prev_line_empty {
                return Err(Error::CategoryTagNotPrecededByEmptyLine);
            }

            let cat = cat.trim();

            if cat.is_empty() {
                return Err(Error::CategoryTagEmpty);
            }

            if !CATEGORIES.contains(&cat) {
                return Err(Error::InvalidCategory {
                    category: cat.to_owned(),
                    allows: CATEGORIES.join(", "),
                });
            }

            found_category = true;
        }

        if let Some(ticket) = line.strip_prefix(TICKET_TAG) {
            if found_ticket {
                return Err(Error::MultipleTicketTags);
            }

            let ticket = ticket.trim();

            match ticket {
                "" => return Err(Error::TicketTagEmpty),
                "#000" => return Err(Error::InvalidPlaceholderTicket),
                _ => {}
            }

            if ticket.starts_with("https://") {
                if !is_ticket_url(ticket) {
                    return Err(Error::TicketTagInvalidUrl);
                }
                // URL is fine.
            } else if ticket == "none" {
                // None is also fine.
            } else if let Some(number) = ticket.strip_prefix('#') {
                if number.parse::<i64>().is_err() {
                    return Err(Error::TicketTagNotGithubLink);
                }
                // Link is also fine.
            } else {
                return Err(Error::InvalidTicketTag);
            }

            found_ticket = true;
        }

        if let Some(flag) = line.strip_prefix(FEATURE_TAG) {
            if found_feature {
                return Err(Error::MultipleFeatureFlagTags);
            }

            let flag = flag.trim();

            match flag {
                "" => return Err(Error::FeatureFlagTagEmpty),
                "?" => return Err(Error::InvalidPlaceholderFeatureFlag),
                _ => {}
            }

            if flag.contains(' ') || flag.contains('-') || flag.to_lowercase() != flag {
                return Err(Error::FeatureFlagNotSnakeCase);
            }

            if !Feature::try_from(flag).is_ok_and(|feature| features.enabled(feature)) {
                return Err(Error::UnknownFeatureFlag);
            }

            found_feature = true;
        }

        prev_line_empty = line.trim().is_empty();
    }

    if !found_category {
        return Err(Error::MissingCategoryTag);
    }

    if !found_ticket {
        return Err(Error::MissingTicketTag);
    }

    Ok(())
}

/// Reports whether `c` is in Unicode category P (punctuation).
///
/// Only ASCII is considered. The ASCII symbols `$ + < = > ^ ` | ~` are in
/// category S (symbol), so they are not punctuation.
fn is_punct(c: char) -> bool {
    c.is_ascii_punctuation() && !matches!(c, '$' | '+' | '<' | '=' | '>' | '^' | '`' | '|' | '~')
}

/// Reports whether an `https://` ticket tag is an absolute URL with a path.
///
/// `Url` normalises a missing path to `/`, so the presence of a path component
/// is checked against the raw string.
fn is_ticket_url(ticket: &str) -> bool {
    if Url::parse(ticket).is_err() {
        return false;
    }

    // Drop the scheme, then the query and fragment; a "/" in what is left of
    // the authority means a path component follows it.
    ticket
        .strip_prefix("https://")
        .and_then(|rest| rest.split(['?', '#']).next())
        .is_some_and(|authority| authority.contains('/'))
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    /// Returns a feature set enabling every alpha feature, matching the set
    /// [`verify`] resolves.
    fn features() -> FeatureSet {
        FeatureSet::from_config(Config {
            min_status: Status::Alpha,
            ..Default::default()
        })
        .expect("alpha config should be valid")
    }

    #[test_case("this: is ok" ; "package")]
    #[test_case("this/is: also ok" ; "subpackage")]
    #[test_case("*: wildcard is ok" ; "wildcard")]
    #[test_case("*/*: wildcards are also ok" ; "wildcards")]
    fn title_ok(title: &str) {
        verify_title(title).expect("title should match the template");
    }

    #[test_case("", "title isn't prefixed" ; "empty")]
    #[test_case("missing_colon", "title isn't prefixed" ; "missing colon")]
    #[test_case("no space: allowed", "doesn't match regex" ; "space in prefix")]
    #[test_case("no: punctuation.", "shouldn't end with punctuation" ; "trailing punctuation")]
    #[test_case("short: too", "title suffix too short" ; "short suffix")]
    #[test_case("missing:space", "not followed by space" ; "missing space")]
    #[test_case("avoid: Sentence case", "shouldn't start with a capital" ; "sentence case")]
    #[test_case(
        "foo/bar: this title is too long, the max length is 60 characters",
        "title too long" ;
        "too long"
    )]
    fn title_err(title: &str, want: &str) {
        let err = verify_title(title)
            .expect_err("title should be rejected")
            .to_string();

        assert!(
            err.contains(want),
            "expected error to contain {want:?}, got: {err}"
        );
    }

    #[test_case("Foo\nbar\n\ncategory: bug\nticket: #123" ; "category and ticket")]
    #[test_case("Foo\n\ncategory: bug\nticket: none\nfeature_flag: mock_alpha" ; "feature flag")]
    #[test_case("Foo\n\ncategory: bug\nticket: none\nfeature_flag: quic" ; "other feature flag")]
    #[test_case("Foo\n\ncategory: bug\nticket: https://github.com/foo/bar/issues/1" ; "ticket url")]
    fn body_ok(body: &str) {
        verify_body(body, &features()).expect("body should match the template");
    }

    #[test_case("", "body empty" ; "empty")]
    #[test_case("\nFoo", "first line empty" ; "first line empty")]
    #[test_case("Foo\ncategory: bar", "not preceded by empty line" ; "category not preceded")]
    #[test_case("Foo\nbar\n\ncategory: bar", "invalid category" ; "invalid category")]
    #[test_case("Foo\nbar\n\ncategory:", "empty" ; "category empty")]
    #[test_case("Foo", "missing category tag" ; "missing category")]
    #[test_case("Foo\n\ncategory: bug", "missing ticket tag" ; "missing ticket")]
    #[test_case("Foo\n\ncategory: bug\nticket:123", "invalid ticket tag" ; "ticket not a link")]
    #[test_case("Foo\n\ncategory: bug\nticket:https://s", "ticket tag invalid url" ; "ticket url without path")]
    #[test_case(
        "<!--\n\ncategory: bug\nticket: none",
        "instructions not deleted (markdown comments present)" ;
        "instructions not deleted"
    )]
    #[test_case("Foo\n\ncategory: bug\nticket: #000", "invalid #000 ticket" ; "placeholder ticket")]
    #[test_case(
        "Foo\n\ncategory: bug\nticket: none\nfeature_flag: ?",
        "invalid ? feature_flag" ;
        "placeholder feature flag"
    )]
    #[test_case(
        "Foo\n\ncategory: bug\nticket: none\nfeature_flag: CAPS",
        "feature flags are snake case" ;
        "feature flag not snake case"
    )]
    #[test_case(
        "Foo\n\ncategory: bug\nticket: none\nfeature_flag: unknown",
        "unknown feature flag" ;
        "unknown feature flag"
    )]
    fn body_err(body: &str, want: &str) {
        let err = verify_body(body, &features())
            .expect_err("body should be rejected")
            .to_string();

        assert!(
            err.contains(want),
            "expected error to contain {want:?}, got: {err}"
        );
    }
}
