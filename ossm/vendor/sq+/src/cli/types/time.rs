use std::fmt::Display;
use std::fmt::Formatter;
use std::time::Duration;
use std::time::SystemTime;

use anyhow::Context;

use chrono::offset::Utc;
use chrono::DateTime;
use chrono::TimeZone;

use sequoia_openpgp as openpgp;
use openpgp::types::Timestamp;

use crate::cli::SECONDS_IN_YEAR;
use crate::cli::SECONDS_IN_DAY;

use crate::Result;

/// A signed offset (in seconds).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Offset {
    /// Whether the offset is negative (strictly less than and not equal to 0).
    negative: bool,
    /// The number of seconds.
    seconds: u64,
}

/// A thin wrapper around `openpgp::types::Timestamp`.
///
/// Recall: an OpenPGP timestamp has a whole second resolution, and
/// uses a 32-bit quantity to represent the number of seconds since
/// the UNIX epoch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Time {
    Timestamp(Timestamp),
    Offset(Offset),
}

impl std::str::FromStr for Time {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Time> {
        let s = s.trim();

        if Time::is_offset(s) {
            Ok(Self::parse_offset(s)?)
        } else {
            let time =
                Time::parse_iso8601(s, chrono::NaiveTime::from_hms_opt(0, 0, 0)
                                    .unwrap())?;
            Ok(Time::try_from(SystemTime::from(time))?)
        }
    }
}

impl TryFrom<SystemTime> for Time {
    type Error = anyhow::Error;

    fn try_from(time: SystemTime) -> Result<Self> {
        Ok(Self::Timestamp(Timestamp::try_from(time)?))
    }
}

impl TryFrom<DateTime<Utc>> for Time {
    type Error = anyhow::Error;

    fn try_from(time: DateTime<Utc>) -> Result<Self> {
        Self::try_from(SystemTime::try_from(time)?)
    }
}

impl Time {
    /// Returns the current time.
    #[allow(dead_code)]
    pub fn now() -> Self {
        Time::Timestamp(Timestamp::now())
    }

    /// Returns a relative time in the future.
    pub fn from_duration(duration: Duration) -> Self {
        Time::Offset(Offset {
            negative: false,
            seconds: duration.as_secs(),
        })
    }

    /// Parses the given string depicting a ISO 8601 timestamp.
    fn parse_iso8601(
        s: &str,
        pad_date_with: chrono::NaiveTime,
    ) -> anyhow::Result<DateTime<Utc>> {
        // If you modify this function this function, synchronize the
        // changes with the copy in sqv.rs!
        for f in &[
            "%Y-%m-%dT%H:%M:%S%#z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M%#z",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%dT%H%#z",
            "%Y-%m-%dT%H",
            "%Y%m%dT%H%M%S%#z",
            "%Y%m%dT%H%M%S",
            "%Y%m%dT%H%M%#z",
            "%Y%m%dT%H%M",
            "%Y%m%dT%H%#z",
            "%Y%m%dT%H",
        ] {
            if f.ends_with("%#z") {
                if let Ok(d) = DateTime::parse_from_str(s, *f) {
                    return Ok(d.into());
                }
            } else if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(Utc.from_utc_datetime(&d));
            }
        }
        for f in &["%Y-%m-%d", "%Y-%m", "%Y-%j", "%Y%m%d", "%Y%m", "%Y%j", "%Y"]
        {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
                return Ok(Utc.from_utc_datetime(&d.and_time(pad_date_with)));
            }
        }
        Err(anyhow::anyhow!("Malformed timestamp: {}.\n\
                             Try: YYYY-MM-DD[Thh:mm[:ss][[+|-]hh[:mm]]] \
                             or [+|-|]N[ymdhs]", s))
    }

    const OFFSET_SUFFIXES: &'static [char] = &['y', 'm', 'w', 'd', 's'];

    /// Whether the string appears to be an offset (e.g., 1y).
    fn is_offset(s: &str) -> bool {
        s.trim_end().ends_with(Self::OFFSET_SUFFIXES)
    }

    /// Parse a string as an offset.
    ///
    /// `offset` must be at least two chars long, and consist of an
    /// optional + or -, digits, and a trailing factor identifier (one
    /// of `"y"`, `"m"`, `"w"`, `"d"`, `"s"` for year, month, week,
    /// day, and second, respectively).
    pub fn parse_offset(offset: &str) -> Result<Self> {
        if offset.len() < 2 {
            return Err(anyhow::anyhow!(
                "Value must contain at least one digit and one factor."
            ));
        }

        let (negative, seconds) = match offset.strip_suffix(Self::OFFSET_SUFFIXES) {
            Some(digits) => {
                let (negative, count) = match digits.parse::<i64>() {
                    Ok(count) => {
                        (count.is_negative(), count.unsigned_abs())
                    }
                    Err(err) => return Err(err).context(
                        format!("Value '{}' is out of range", digits)
                    ),
                };

                let factor = match offset.chars().last() {
                    Some('y') => SECONDS_IN_YEAR,
                    Some('m') => SECONDS_IN_YEAR / 12,
                    Some('w') => 7 * SECONDS_IN_DAY,
                    Some('d') => SECONDS_IN_DAY,
                    Some('s') => 1,
                    _ => unreachable!(
                        "Value without 'y', 'm', 'w', 'd' or 's' \
                         suffix impossible since checked for it."
                    ),
                };

                (negative, count * factor)
            }
            None => {
                return Err(anyhow::anyhow!(
                    if let Some(suffix) = offset.chars().last() {
                        format!(
                            "Invalid suffix '{}' in '{}' \
                             (try <digits><{}>, e.g. '1y')",
                            suffix,
                            offset,
                            Self::OFFSET_SUFFIXES.iter().map(|c| c.to_string())
                                .collect::<Vec<String>>()
                                .join("|"))
                    } else {
                        format!(
                            "Invalid value: {} \
                             (try <digits><{}>, e.g. '1y')",
                            offset,
                            Self::OFFSET_SUFFIXES.iter().map(|c| c.to_string())
                                .collect::<Vec<String>>()
                                .join("|"))
                    }
                ))
            }
        };

        Ok(Time::Offset(Offset {
            negative,
            seconds,
        }))
    }

    /// Returns the time as an absolute time.
    pub fn to_system_time(&self, now: SystemTime) -> Result<SystemTime> {
        match self {
            Time::Timestamp(ts) => Ok(ts.clone().try_into()?),
            Time::Offset(offset) => {
                if offset.negative {
                    Ok(now - Duration::new(offset.seconds, 0))
                } else {
                    Ok(now + Duration::new(offset.seconds, 0))
                }
            }
        }
    }

    /// Returns the time since the specified time.
    ///
    /// Returns an error if `t` is in the future relative to the time.
    pub fn duration_since(&self, t: SystemTime) -> Result<Duration> {
        Ok(self.to_system_time(t)?.duration_since(t)?)
    }

}

impl Display for Time {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Time::Timestamp(time) => write!(f, "{}", time),
            Time::Offset(offset) => {
                if offset.negative {
                    write!(f, "-")?;
                }

                let seconds = offset.seconds;
                if seconds % SECONDS_IN_YEAR == 0 {
                    write!(f, "{}y", seconds / SECONDS_IN_YEAR)
                } else if seconds % (SECONDS_IN_YEAR / 12) == 0 {
                    write!(f, "{}m", seconds / (SECONDS_IN_YEAR / 12))
                } else if seconds % (SECONDS_IN_DAY * 7) == 0 {
                    write!(f, "{}w", seconds / (SECONDS_IN_DAY * 7))
                } else if seconds % SECONDS_IN_DAY == 0 {
                    write!(f, "{}d", seconds / SECONDS_IN_DAY)
                } else {
                    write!(f, "{}s", seconds)
                }
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_iso8601() -> anyhow::Result<()> {
        let z = chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap();
        Time::parse_iso8601("2017-03-04T13:25:35Z", z)?;
        Time::parse_iso8601("2017-03-04T13:25:35+08:30", z)?;
        Time::parse_iso8601("2017-03-04T13:25:35", z)?;
        Time::parse_iso8601("2017-03-04T13:25Z", z)?;
        Time::parse_iso8601("2017-03-04T13:25", z)?;
        // CliTime::parse_iso8601("2017-03-04T13Z", z)?; // XXX: chrono doesn't like
        // CliTime::parse_iso8601("2017-03-04T13", z)?; // ditto
        Time::parse_iso8601("2017-03-04", z)?;
        // CliTime::parse_iso8601("2017-03", z)?; // ditto
        Time::parse_iso8601("2017-031", z)?;
        Time::parse_iso8601("20170304T132535Z", z)?;
        Time::parse_iso8601("20170304T132535+0830", z)?;
        Time::parse_iso8601("20170304T132535", z)?;
        Time::parse_iso8601("20170304T1325Z", z)?;
        Time::parse_iso8601("20170304T1325", z)?;
        // CliTime::parse_iso8601("20170304T13Z", z)?; // ditto
        // CliTime::parse_iso8601("20170304T13", z)?; // ditto
        Time::parse_iso8601("20170304", z)?;
        // CliTime::parse_iso8601("201703", z)?; // ditto
        Time::parse_iso8601("2017031", z)?;
        // CliTime::parse_iso8601("2017", z)?; // ditto
        Ok(())
    }

    #[test]
    fn test_parse_offset() {
        assert_eq!(
            Time::parse_offset("1y").unwrap(),
            Time::from_duration(Duration::new(SECONDS_IN_YEAR, 0)),
        );
        assert_eq!(
            Time::parse_offset("+1y").unwrap(),
            Time::from_duration(Duration::new(SECONDS_IN_YEAR, 0)),
        );
        assert_eq!(
            Time::parse_offset("-1y").unwrap(),
            Time::Offset(Offset { negative: true, seconds: SECONDS_IN_YEAR }),
        );
        assert!(Time::parse_offset("f").is_err());
        assert!(Time::parse_offset("foo").is_err());
        assert!(Time::parse_offset("1o").is_err());
    }
}
