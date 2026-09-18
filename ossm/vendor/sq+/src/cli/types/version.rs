use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;

use serde::Serialize;

use crate::Result;

/// A value parser for the version string.
///
/// This parser always emits an error that the argument is at the
/// wrong place.
#[derive(Clone, Debug, Default)]
pub struct VersionInvalidPositionValueParser {}

impl clap::builder::TypedValueParser for VersionInvalidPositionValueParser {
    type Value = Version;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> std::result::Result<Self::Value, clap::error::Error> {
        let mut err = clap::Error::new(clap::error::ErrorKind::UnknownArgument)
            .with_cmd(cmd);
        if let Some(arg) = arg {
            err.insert(
                clap::error::ContextKind::InvalidArg,
                clap::error::ContextValue::String(arg.to_string()));
        }
        err.insert(
            clap::error::ContextKind::InvalidValue,
            clap::error::ContextValue::String(
                String::from_utf8_lossy(value.as_encoded_bytes()).to_string()));
        err.insert(
            clap::error::ContextKind::Suggested,
            clap::error::ContextValue::StyledStrs(vec![
                "--cli-version must be the very first argument".to_string().into()
            ]));

        Err(err)
    }
}

/// A semver version string.
///
/// As `sq` evolves, the machine-readable output format may need to
/// change. Consumers should be able to know what version of the output
/// format has been produced. This is expressed using a three-part
/// version number, which is always included in the output, similar to
/// [Semantic Versions][]. The parts are known as "major", "minor",
/// and "patch", and have the following semantics:
///
/// * patch: incremented if there are no semantic changes
/// * minor: one or more fields were added
/// * major: one or more fields were dropped
///
/// [Semantic Version]: https://semver.org/
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct Version {
    major: usize,
    minor: usize,
    patch: usize,
}

impl Version {
    /// Create a new version number from constituent parts.
    pub const fn new(major: usize, minor: usize, patch: usize) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Does this version fulfill the needs of the version that is requested?
    pub fn is_acceptable_for<V>(&self, wanted: V) -> bool
    where V: Borrow<Self>
    {
        let wanted = wanted.borrow();

        self.major == wanted.major &&
            (self.minor > wanted.minor ||
             (self.minor == wanted.minor && self.patch >= wanted.patch))
    }
}

impl FromStr for Version {
    type Err = anyhow::Error;

    fn from_str(v: &str) -> Result<Self> {
        let ints = parse_ints(v)?;
        match ints.len() {
            0 => Err(anyhow!("doesn't look like a version: {}", v)),
            1 => Ok(Self::new(ints[0], 0, 0)),
            2 => Ok(Self::new(ints[0], ints[1], 0)),
            3 => Ok(Self::new(ints[0], ints[1], ints[2])),
            _ => Err(anyhow!("too many components in version (at most three allowed): {}", v)),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialEq<Version> for &Version {
    fn eq(&self, other: &Version) -> bool {
        self.major == other.major &&
            self.minor == other.minor &&
            self.patch == other.patch
    }
}

fn parse_ints(s: &str) -> Result<Vec<usize>> {
    let mut ints = vec![];
    let mut v = s;
    while !v.is_empty() {
        if let Some(i) = v.find('.') {
            ints.push(parse_component(&v[..i])?);
            v = &v[i+1..];
            if v.is_empty() {
                return Err(anyhow!("trailing dot in version: {}", s));
            }
        } else {
            ints.push(parse_component(v)?);
            v = "";
        }
    }
    Ok(ints)
}

fn parse_component(s: &str) -> Result<usize> {
    Ok(FromStr::from_str(s)?)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use super::Version;

    #[test]
    fn empty_string() {
        assert!(Version::from_str("").is_err());
    }

    #[test]
    fn not_int() {
        assert!(Version::from_str("foo").is_err());
    }

    #[test]
    fn not_int2() {
        assert!(Version::from_str("1.foo").is_err());
    }

    #[test]
    fn leading_dot() {
        assert!(Version::from_str(".1").is_err());
    }

    #[test]
    fn trailing_dot() {
        assert!(Version::from_str("1.").is_err());
    }

    #[test]
    fn one_int() {
        assert_eq!(Version::from_str("1").unwrap(), Version::new(1, 0, 0));
    }

    #[test]
    fn two_ints() {
        assert_eq!(Version::from_str("1.2").unwrap(), Version::new(1, 2, 0));
    }

    #[test]
    fn three_ints() {
        assert_eq!(Version::from_str("1.2.3").unwrap(), Version::new(1, 2, 3));
    }

    #[test]
    fn four_ints() {
        assert!(Version::from_str("1.2.3.4").is_err());
    }

    #[test]
    fn acceptable_if_same() {
        let a = Version::new(0, 0, 0);
        assert!(a.is_acceptable_for(a));
    }

    #[test]
    fn acceptable_if_newer_patch() {
        let wanted = Version::new(0, 0, 0);
        let actual = Version::new(0, 0, 1);
        assert!(actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_older_patch() {
        let wanted = Version::new(0, 0, 1);
        let actual = Version::new(0, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }

    #[test]
    fn acceptable_if_newer_minor() {
        let wanted = Version::new(0, 0, 0);
        let actual = Version::new(0, 1, 0);
        assert!(actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_older_minor() {
        let wanted = Version::new(0, 1, 0);
        let actual = Version::new(0, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_newer_major() {
        let wanted = Version::new(0, 0, 0);
        let actual = Version::new(1, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_older_major() {
        let wanted = Version::new(1, 0, 0);
        let actual = Version::new(0, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }
}
