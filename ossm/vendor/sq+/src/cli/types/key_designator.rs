use std::str::FromStr;

use anyhow::Result;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;

// Argument parser options.

pub type DefaultOptions = typenum::U0;

/// Normally it is possible to designate multiple keys.  This errors
/// out if there is more than one value.
pub type OneValue = typenum::U1;

/// Normally it is possible to designate primary keys.  This errors
/// out if the primary key is used.
pub type OnlySubkeys = typenum::U2;

pub trait AdditionalDocs {
    /// Text to be added to the help text.
    // XXX: This should return a Cow<'static, str>, but there is no
    // implementation of From<Cow<'static, str>> for StyledStr,
    // see https://github.com/clap-rs/clap/issues/5785
    fn help(_arg: &'static str, help: &'static str) -> clap::builder::StyledStr {
        help.into()
    }
}

/// No additional documentation.
pub struct NoDoc(());
impl AdditionalDocs for NoDoc {}

/// A user ID designator.
#[derive(Debug)]
pub enum KeyDesignator {
    KeyHandle(KeyHandle),
}

/// A data structure that can be flattened into a clap `Command`, and
/// adds arguments to address key IDs.
///
/// `Options` are the set of options to the argument parser.  By
/// default, at least one key designator must be specified.
pub struct KeyDesignators<Options=typenum::U0, Doc=NoDoc>
{
    /// The set of key designators.
    pub designators: Vec<KeyDesignator>,

    arguments: std::marker::PhantomData<(Options, Doc)>,
}

impl<Options, Doc> std::fmt::Debug for KeyDesignators<Options, Doc>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyDesignators")
            .field("designators", &self.designators)
            .finish()
    }
}

#[allow(dead_code)]
impl KeyDesignators<DefaultOptions, NoDoc> {
    pub fn none() -> Option<Self> {
        None
    }
}

#[allow(dead_code)]
impl<Options, Doc> KeyDesignators<Options, Doc> {
    /// Like `Vec::push`.
    pub fn push(&mut self, designator: KeyDesignator) {
        self.designators.push(designator)
    }

    /// Like `Vec::is_empty`.
    pub fn is_empty(&self) -> bool {
        self.designators.is_empty()
    }

    /// Like `Vec::len`.
    pub fn len(&self) -> usize {
        self.designators.len()
    }

    /// Iterates over the user ID designators.
    pub fn iter(&self) -> impl Iterator<Item=&KeyDesignator> {
        self.designators.iter()
    }
}

impl<Options, Doc> clap::Args for KeyDesignators<Options, Doc>
where
    Options: typenum::Unsigned,
    Doc: AdditionalDocs,
{
    fn augment_args(mut cmd: clap::Command) -> clap::Command
    {
        let options = Options::to_usize();
        let one_value = (options & OneValue::to_usize()) > 0;

        let group = format!("key-designator-{:X}", options);
        let mut arg_group = clap::ArgGroup::new(&group);

        arg_group = arg_group.required(true);

        if one_value {
            arg_group = arg_group.multiple(false);
        } else {
            arg_group = arg_group.multiple(true);
        }

        let action = if one_value {
            clap::ArgAction::Set
        } else {
            clap::ArgAction::Append
        };

        // Converts a string to a valid `KeyHandle`.
        //
        // Note: `<KeyHandle as FromStr>::from_str` is not enough, as
        // we also want to bail if the fingerprint format is unknown.
        // That is, KeyHandle will happily parse a 24 character hex
        // string, but v4 fignerprints are 20 characters, and v6
        // fingerprints are 32 characters.
        fn parse_as_key_handle(s: &str) -> Result<KeyHandle> {
            let kh = KeyHandle::from_str(s)?;
            if kh.is_invalid() {
                Err(anyhow::anyhow!(
                    "{:?} is not a valid fingerprint or key ID \
                     (hint: v4 fingerprints are 20 hex characters, \
                     key IDs are 16 hex characters, you provided {} \
                     characters)",
                    s, s.chars().count()))
            } else {
                Ok(kh)
            }
        }

        let full_name = "key";
        cmd = cmd.arg(
            clap::Arg::new(&full_name)
                .long(&full_name)
                .value_name("FINGERPRINT|KEYID")
                .value_parser(parse_as_key_handle)
                .action(action.clone())
                .help(Doc::help(
                    "doc",
                    "Use the key with the specified \
                     fingerprint or key ID")));
        arg_group = arg_group.arg(full_name);

        cmd = cmd.group(arg_group);

        cmd
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command
    {
        Self::augment_args(cmd)
    }
}

impl<Options, Doc> clap::FromArgMatches for KeyDesignators<Options, Doc>
where
    Options: typenum::Unsigned,
{
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches)
        -> Result<(), clap::Error>
    {
        // eprintln!("matches: {:#?}", matches);

        let mut designators = Vec::new();

        if let Ok(Some(keys)) = matches.try_get_many::<KeyHandle>("key")
        {
            for key in keys.cloned() {
                designators.push(
                    KeyDesignator::KeyHandle(key));
            }
        }

        self.designators = designators;
        Ok(())
    }

    fn from_arg_matches(matches: &clap::ArgMatches)
        -> Result<Self, clap::Error>
    {
        let mut designators = Self {
            designators: Vec::new(),
            arguments: std::marker::PhantomData,
        };

        // The way we use clap, this is never called.
        designators.update_from_arg_matches(matches)?;
        Ok(designators)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Check that flattening KeyDesignators works as expected.
    #[test]
    fn key_designators() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub keys: KeyDesignators,
        }

        let command = CLI::command();

        // Check if --key is recognized.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--key", "0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
            "--key", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.keys.designators.len(), 2);
    }

    #[test]
    fn key_designators_one() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub keys: KeyDesignators<OneValue>,
        }

        let command = CLI::command();

        // Check if --key is recognized.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--key", "0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.keys.designators.len(), 1);

        // Make sure that we can't give it twice.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--key", "0D45C6A756A038670FDFD85CB1C82E8D27DB23A1",
            "--key", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
        ]);
        assert!(m.is_err());

        // Make sure that we can't give it zero times.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
        ]);
        assert!(m.is_err());
    }
}
