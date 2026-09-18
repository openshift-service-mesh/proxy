use std::fmt::Display;
use std::fmt::Formatter;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use chrono::DateTime;
use chrono::Utc;

use clap::builder::IntoResettable;
use clap::builder::OsStr;
use clap::builder::Resettable;

use typenum::Unsigned;

use crate::Result;
use crate::cli::KEY_ROTATE_RETIRE_IN_DURATION;
use crate::cli::THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION;
use crate::cli::config;
use crate::cli::pki::vouch::CERTIFICATION_EXPIRATION;
use crate::cli::types::Time;

// Argument parser options.

/// Expiration argument kind specialization.
pub enum ExpirationKind {
    Default,
    Certification,
    RetireIn,
}

impl From<usize> for ExpirationKind {
    fn from(v: usize) -> ExpirationKind {
        match v {
            0 => {
                debug_assert_eq!(0, DefaultKind::to_usize());
                ExpirationKind::Default
            },

            1 => {
                debug_assert_eq!(1, CertificationKind::to_usize());
                ExpirationKind::Certification
            },

            2 => {
                debug_assert_eq!(2, RetireInKind::to_usize());
                ExpirationKind::RetireIn
            },

            _ => unreachable!(),
        }
    }
}

impl ExpirationKind {
    fn name(&self) -> &'static str {
        match self {
            ExpirationKind::Default => "expiration",
            ExpirationKind::Certification => "expiration",
            ExpirationKind::RetireIn => "retire-in",
        }
    }
}

/// Default expiration parameter.
pub type DefaultKind = typenum::U0;

/// Specialization for third-party certifications.
pub type CertificationKind = typenum::U1;

/// Specialization for `sq key rotate --retire-in`.
pub type RetireInKind = typenum::U2;

#[derive(Debug)]
pub struct ExpirationArg<Kind = DefaultKind> {
    expiration: Expiration,

    /// Argument parser specializations.
    arguments: std::marker::PhantomData<Kind>,
}

impl<Kind> Deref for ExpirationArg<Kind> {
    type Target = Expiration;

    fn deref(&self) -> &Self::Target {
        &self.expiration
    }
}

impl<Kind> ExpirationArg<Kind> {
    /// Returns the expiration time.
    pub fn value(&self) -> Expiration {
        self.expiration.clone()
    }
}

impl<Kind> clap::Args for ExpirationArg<Kind>
where
    Kind: typenum::Unsigned,
{
    fn augment_args(cmd: clap::Command) -> clap::Command {
        let kind: ExpirationKind = Kind::to_usize().into();

        const EXPIRATION_LONG_HELP: &str = "\
Sets the expiration time

EXPIRATION is either an ISO 8601 formatted date with an optional time \
or a custom duration.  A duration takes the form `N[ymwds]`, where the \
letters stand for years, months, weeks, days, and seconds, respectively. \
Alternatively, the keyword `never` does not set an expiration time.";

        const RETIRE_IN_LONG_HELP: &str = "\
Sets the time at which the certificate should be retired

TIME is either an ISO 8601 formatted date with an optional time \
or a custom duration.  A duration takes the form `N[ymwds]`, where the \
letters stand for years, months, weeks, days, and seconds, respectively. \
Alternatively, the keyword `never` skips the certification of a \
revocation certificate.";

        let name = kind.name();

        cmd.arg(
            clap::Arg::new(name)
                .long(name)
                .allow_hyphen_values(true)
                .value_name(match kind {
                    ExpirationKind::Default => "EXPIRATION",
                    ExpirationKind::Certification => "EXPIRATION",
                    ExpirationKind::RetireIn => "TIME",
                })
                .value_parser(Expiration::new)
                .default_value(match kind {
                    ExpirationKind::Default => Expiration::Never,
                    ExpirationKind::Certification =>
                        Expiration::from_duration(
                            THIRD_PARTY_CERTIFICATION_VALIDITY_DURATION),
                    ExpirationKind::RetireIn =>
                        Expiration::from_duration(
                            KEY_ROTATE_RETIRE_IN_DURATION),
                })
                .help(match kind {
                    ExpirationKind::Default | ExpirationKind::Certification =>
                        "Sets the expiration time",
                    ExpirationKind::RetireIn =>
                        "Sets the time at which the certificate should be retired",
                })
                .long_help(match kind {
                    ExpirationKind::Default => EXPIRATION_LONG_HELP.into(),
                    ExpirationKind::Certification =>
                        config::augment_help(CERTIFICATION_EXPIRATION,
                                             EXPIRATION_LONG_HELP),
                    ExpirationKind::RetireIn => RETIRE_IN_LONG_HELP.into(),
                })
        )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

impl<Kind> clap::FromArgMatches for ExpirationArg<Kind>
where
    Kind: typenum::Unsigned
{
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches)
                               -> clap::error::Result<()>
    {
        let kind: ExpirationKind = Kind::to_usize().into();

        if let Some(v) = matches.get_one::<Expiration>(kind.name()) {
            self.expiration = v.clone();
        }

        Ok(())
    }

    fn from_arg_matches(matches: &clap::ArgMatches)
                        -> clap::error::Result<Self>
    {
        let mut expiration = ExpirationArg {
            expiration: Expiration::Never,
            arguments: Default::default(),
        };

        expiration.update_from_arg_matches(matches)?;
        Ok(expiration)
    }
}

/// Expiration information
///
/// This enum tracks expiry information either in the form of a timestamp or
/// a duration.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Expiration {
    /// An expiry timestamp
    Timestamp(Time),
    /// There is no expiry
    Never,
}

impl Expiration {
    /// Create a new Expiration in a Result
    ///
    /// If `expiry` ends with `"y"`, `"m"`, `"w"`, `"w"`, `"d"` or `"s"` it
    /// is treated as a duration, which is parsed using `parse_duration()` and
    /// returned in an `Expiration::Duration`.
    /// If the special keyword `"never"` is provided as `expiry`,
    /// `Expiration::Never` is returned.
    /// If `expiry` is an ISO 8601 compatible string it is returned as
    /// `cli::types::Time` in an `Expiration::Timestamp`.
    pub fn new(expiry: &str) -> Result<Self> {
        match expiry {
            "never" => Ok(Expiration::Never),
            _ => Ok(Expiration::Timestamp(Time::from_str(expiry)?)),
        }
    }

    /// Create a new Expiration from a `Duration`.
    pub fn from_duration(duration: Duration) -> Self {
        Expiration::Timestamp(Time::from_duration(duration))
    }

    /// Return the expiry as an optional Duration in a Result
    ///
    /// This method returns an Error if the reference time is later than the
    /// time provided in an `Expiration::Timestamp(Time)`.
    ///
    /// If self is `Expiration::Timestamp(Time)`, `reference` is used as the start
    /// of a period, `Some(Time - reference)` is returned.
    /// If self is `Expiration::Duration(duration)`, `Some(duration)` is returned.
    /// If self is `Expiration::Never`, `None` is returned.
    pub fn as_duration(
        &self,
        reference: DateTime<Utc>,
    ) -> Result<Option<Duration>> {
        match self {
            Expiration::Timestamp(time) => {
                Ok(Some(time.duration_since(reference.into())?))
            }
            Expiration::Never => Ok(None),
        }
    }

    /// Return the expiry as absolute time.
    pub fn to_system_time(&self, now: SystemTime) -> Result<Option<SystemTime>> {
        match self {
            Expiration::Timestamp(t) => Ok(Some(t.to_system_time(now)?)),
            Expiration::Never => Ok(None),
        }
    }
}

impl FromStr for Expiration {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Expiration> {
        Expiration::new(s)
    }
}

impl Display for Expiration {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Expiration::Timestamp(time) => write!(f, "{}", time),
            Expiration::Never => write!(f, "never"),
        }
    }
}

impl IntoResettable<OsStr> for Expiration {
    fn into_resettable(self) -> Resettable<OsStr> {
        Resettable::Value(format!("{}", self).into()).into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::SECONDS_IN_YEAR;

    #[test]
    fn test_expiry() {
        assert_eq!(
            Expiration::new("1y").unwrap(),
            Expiration::from_duration(Duration::new(SECONDS_IN_YEAR, 0)),
        );
        assert_eq!(
            Expiration::new("2023-05-15T20:00:00Z").unwrap(),
            Expiration::Timestamp(Time::from_str("2023-05-15T20:00:00Z").unwrap()),
        );
        assert_eq!(
            Expiration::new("never").unwrap(),
            Expiration::Never,
        );
    }

    #[test]
    fn test_expiry_as_duration() {
        let reference = DateTime::from_timestamp(1, 0).unwrap();

        let expiry = Expiration::Timestamp(
            Time::try_from(DateTime::from_timestamp(2, 0).unwrap())
                .expect("valid"));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(1, 0)),
        );

        let expiry = Expiration::from_duration(Duration::new(2, 0));
        assert_eq!(
            expiry.as_duration(reference).unwrap(),
            Some(Duration::new(2, 0)),
        );

        let expiry = Expiration::Never;
        assert_eq!(expiry.as_duration(reference).unwrap(), None);
    }

    #[test]
    fn test_expiry_as_duration_errors() {
        let reference = DateTime::from_timestamp(2, 0).unwrap();
        let expiry = Expiration::Timestamp(
            Time::try_from(DateTime::from_timestamp(1, 0).unwrap())
                .expect("valid"));
        assert!(expiry.as_duration(reference).is_err());
    }
}
