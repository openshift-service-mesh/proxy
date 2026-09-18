//! A type for absolute paths or default paths, and a clap parser.

use std::path::PathBuf;

use anyhow::{Result, anyhow};

/// Either an absolute path, or a default path.
///
/// Even though this type is homomorphic to [`Option<PathBuf>`], we
/// need a new type for this, because clap handles [`Option`]s
/// differently, and we cannot return [`Option<PathBuf>`] from
/// `TypedValueParser::parse_ref`.
#[derive(Clone, Debug)]
pub enum StateDirectory {
    /// An absolute path.
    Absolute(PathBuf),

    /// The default path.
    Default,

    /// Explicitly disable this state.
    None,
}

impl StateDirectory {
    /// Returns whether this state has been disabled.
    #[allow(dead_code)]
    pub fn is_none(&self) -> bool {
        matches!(self, StateDirectory::None)
    }

    /// Returns the absolute path, or `None` if the default path is to
    /// be used.
    pub fn path(&self) -> Result<Option<PathBuf>> {
        match self {
            StateDirectory::Absolute(p) => Ok(Some(p.clone())),
            StateDirectory::Default => Ok(None),
            StateDirectory::None => Err(anyhow!("state is disabled")),
        }
    }
}

/// A value parser for absolute directories with explicit default.
///
/// If `default` is given, this parses to `StateDirectory::Default`.
/// If `none` is given, this parses to `StateDirectory::None`.  If an
/// empty path is given, a hint is displayed to give `default`
/// instead.
///
/// If a relative path is given, a hint is displayed to use an
/// absolute path instead.
#[derive(Clone, Default)]
pub struct StateDirectoryValueParser {}

impl clap::builder::TypedValueParser for StateDirectoryValueParser {
    type Value = StateDirectory;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::error::Error> {
        use clap::error::*;

        if value == "default" {
            return Ok(StateDirectory::Default);
        }

        if value == "none" {
            return Ok(StateDirectory::None);
        }

        if value.is_empty() {
            let mut err = Error::new(ErrorKind::InvalidValue)
                .with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(ContextKind::InvalidArg,
                           ContextValue::String(arg.to_string()));
            }
            err.insert(ContextKind::InvalidValue,
                       ContextValue::String("".into()));
            err.insert(ContextKind::SuggestedValue,
                       ContextValue::String("default".into()));
            err.insert(ContextKind::Suggested,
                       ContextValue::StyledStrs(vec![
                           "to use the default directory, use 'default'".into(),
                       ]));
            return Err(err);
        }

        let p = PathBuf::from(value);

        // Expand `~/foo` to `/home/user/foo`.
        let p = expand_tilde(p)?;

        if ! p.is_absolute() {
            let mut err = Error::new(ErrorKind::InvalidValue)
                .with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(ContextKind::InvalidArg,
                           ContextValue::String(arg.to_string()));
            }
            err.insert(ContextKind::InvalidValue,
                       ContextValue::String(p.display().to_string()));
            err.insert(ContextKind::Suggested,
                       ContextValue::StyledStrs(vec![
                           "must be an absolute path".into(),
                       ]));
            return Err(err);
        }

        Ok(StateDirectory::Absolute(p))
    }
}

/// Expands tilde in paths.
///
/// There are at least two crates that do this, shellexpand and
/// tilde-expand, but both operate on strings, which is the wrong data
/// type.
///
/// Currently, we only handle `~`, not `~user`.  At least shellexpand
/// doesn't either.
fn expand_tilde(p: PathBuf) -> clap::error::Result<PathBuf> {
    if p.components().next().map(|c| c.as_os_str() == "~").unwrap_or(false) {
        Ok(dirs::home_dir().ok_or_else(
            || {
                use clap::error;

                // Not great, but we cannot return a rich error here.
                eprintln!("Error: no home directory known for this platform");
                error::Error::new(error::ErrorKind::Io)
            })?
           .join(p.components().skip(1).collect::<PathBuf>()))
    } else {
        Ok(p)
    }
}
