use anyhow::Context;
use anyhow::Result;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;

use crate::cli::escape_for_shell;

// Whether to enable the --name parameters.  Currently disabled.
// See https://gitlab.com/sequoia-pgp/sequoia-sq/-/issues/487 .
const ENABLE_NAME: bool = false;

/// Adds a `--all` argument.
pub type AllUserIDsArg = typenum::U1;

/// Adds `--userid` `--email`, and `--name` arguments.
///
/// For `UserIDDesignator::resolve`, the value must match on a
/// self-signed user ID, but returns the value as is.  That is, if
/// there is a self-signed user ID "Alice <alice@example.org>",
/// "--email alice@example.org" matches and returns the user ID
/// "<alice@example.org>".
pub type ExactArgs = typenum::U2;

/// Adds `--userid`, `--userid-by-email`, and `--userid-by-name`
/// arguments.
///
/// For `UserIDDesignator::resolve`, the value must correspond to a
/// self-signed user ID.  That is, if there is a self-signed user ID
/// "Alice <alice@example.org>", "--email alice@example.org" matches
/// and returns the matching user ID, i.e., "Alice
/// <alice@example.org>".
pub type ByArgs = typenum::U4;

/// Adds a `--add-userid`, `--add-email`, and `--add-name` argument.
///
/// For `UserIDDesignator::resolve`, acts like `ExactArgs`, but if
/// there is no matching self-signed user ID, creates one from the
/// value.
pub type AddArgs = typenum::U8;


/// Requires ByArgs, conflicts with ExactArgs.  Renames ByArgs'
/// arguments to `--userid`, `--email`, and `--name`.
pub type PlainIsBy = typenum::U16;

/// Requires AddArgs, conflicts with ExactArgs.  Renames AddArgs'
/// arguments to `--userid`, `--email`, and `--name`.
pub type PlainIsAdd = typenum::U32;


pub type PlainByArgs
    = <ByArgs as std::ops::BitOr<PlainIsBy>>::Output;

pub type PlainAddArgs
    = <AddArgs as std::ops::BitOr<PlainIsAdd>>::Output;

pub type ExactAndAddArgs
    = <ExactArgs as std::ops::BitOr<AddArgs>>::Output;

pub type ExactByAndAddArgs
    = <ByArgs as std::ops::BitOr<ExactAndAddArgs>>::Output;

pub type AllExactByAndAddArgs
    = <AllUserIDsArg as std::ops::BitOr<ExactByAndAddArgs>>::Output;

pub type PlainAddAndByArgs
    = <ByArgs as std::ops::BitOr<PlainAddArgs>>::Output;

pub type AllPlainAddAndByArgs
    = <AllUserIDsArg as std::ops::BitOr<PlainAddAndByArgs>>::Output;

// Argument parser options.

/// Normally it is possible to designate multiple certificates.  This
/// errors out if there is more than one value.
pub type OneValue = typenum::U1;

/// Normally a certificate designator is required, and errors out if
/// there isn't at least one value.  This makes the cert designator
/// completely optional.
pub type OptionalValue = typenum::U2;

/// Doesn't lint new (non-self signed) user IDs.  This also suppresses
/// the `--allow-non-canonical-userid` flag.
pub type NoLinting = typenum::U4;

/// Makes --all match non-self signed user IDs.
pub type AllMatchesNonSelfSigned = typenum::U8;

pub type OneValueNoLinting
    = <OneValue as std::ops::BitOr<NoLinting>>::Output;

pub type AllMatchesNonSelfSignedNoLinting
    = <AllMatchesNonSelfSigned as std::ops::BitOr<NoLinting>>::Output;


/// The documentation.
pub trait Documentation {
    /// Returns the help text to display.
    fn help(typ: UserIDDesignatorType,
            plain: bool,
            semantics: UserIDDesignatorSemantics)
        -> (&'static str, Option<&'static str>);
}

/// Documentation for user ID designators when the designator selects
/// a self-signed user ID in a certificate.
///
/// This is for commands like `sq key userid revoke`.
#[derive(Debug, Clone)]
pub struct SelfSignedDocumentation(());

impl Documentation for SelfSignedDocumentation {
    fn help(typ: UserIDDesignatorType,
            plain: bool,
            semantics: UserIDDesignatorSemantics)
        -> (&'static str, Option<&'static str>)
    {
        use UserIDDesignatorType::*;
        use UserIDDesignatorSemantics::*;
        match (typ, semantics) {
            (UserID, Exact | By) => {
                ("Use the specified self-signed user ID",
                 Some("\
Use the specified self-signed user ID

The specified user ID must be self signed."))
            }
            (UserID, Add) => {
                ("Use the specified user ID",
                 if plain {
                     Some("\
Use the specified user ID

The specified user ID does not need to be self signed.")
                 } else {
                     Some("\
Use the specified user ID

The specified user ID does not need to be self signed.

Because using a user ID that is not self-signed is often a mistake, \
you need to use this option to explicitly opt in.")
                 })
            }
            (Email, Exact) => {
                ("\
Use a user ID consisting of just the email address, if the email address \
occurs in a self-signed user ID",
                 None)
            }
            (Email, By) => {
                ("Use the self-signed user ID with the specified email address",
                 None)
            }
            (Email, Add) => {
                ("Use a user ID with the specified email address",
                 Some("\
Use a user ID with the specified email address

The user ID consists of just the email address.  The email address does not \
have to appear in a self-signed user ID."))
            }
            (Name, Exact) => {
                ("\
Use a user ID consisting of just the display name, if the display name \
occurs in a self-signed user ID",
                 None)
            }
            (Name, By) => {
                ("Use the self-signed user ID with the specified display name",
                 None)
            }
            (Name, Add) => {
                ("Use a user ID with the specified display name",
                 Some("\
Use a user ID with the specified display name

The user ID consists of just the display named.  The display name does not \
have to appear in a self-signed user ID."))
            }
        }
    }
}

/// The designator type.
pub enum UserIDDesignatorType {
    /// --userid.
    UserID,
    /// --email.
    Email,
    /// --name.
    Name,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserIDDesignatorSemantics {
    /// For `UserIDDesignator::resolve`, the value must match on a
    /// self-signed user ID, but returns the value.  That is, if there
    /// is a self-signed user ID "Alice <alice@example.org>", "--email
    /// alice@example.org" matches and returns the user ID
    /// "<alice@example.org>".
    Exact,

    /// For `UserIDDesignator::resolve`, the value must correspond to
    /// a self-signed user ID.  That is, if there is a self-signed
    /// user ID "Alice <alice@example.org>", "--email
    /// alice@example.org" matches and returns the matching user ID,
    /// i.e., "Alice <alice@example.org>".
    By,

    /// `UserIDDesignator::resolve`, acts like `ExactArgs`, but if
    /// there is no matching self-signed user ID, creates one from the
    /// value.
    Add,
}

#[allow(unused)]
impl UserIDDesignatorSemantics {
    /// If `self` is `UserIDDesignatorSemantics::Exact`.
    fn is_exact(&self) -> bool {
        matches!(self, &UserIDDesignatorSemantics::Exact)
    }

    /// If `self` is `UserIDDesignatorSemantics::By`.
    fn is_by(&self) -> bool {
        matches!(self, &UserIDDesignatorSemantics::By)
    }

    /// If `self` is `UserIDDesignatorSemantics::Add`.
    fn is_add(&self) -> bool {
        matches!(self, &UserIDDesignatorSemantics::Add)
    }
}

/// A user ID designator.
#[derive(Debug, Clone)]
pub enum UserIDDesignator {
    /// A user ID.
    UserID(UserIDDesignatorSemantics, String),

    /// An email address.
    Email(UserIDDesignatorSemantics, String),

    /// A display name.
    Name(UserIDDesignatorSemantics, String),
}

#[allow(dead_code)]
impl UserIDDesignator {
    /// Whether the designator is a user ID.
    pub fn is_userid(&self) -> bool {
        use UserIDDesignator::*;
        match self {
            UserID(_, _) => true,
            Email(_, _) => false,
            Name(_, _) => false,
        }
    }

    /// Whether the designator is an email address.
    pub fn is_email(&self) -> bool {
        use UserIDDesignator::*;
        match self {
            UserID(_, _) => false,
            Email(_, _) => true,
            Name(_, _) => false,
        }
    }

    /// Whether the designator is a display name.
    pub fn is_name(&self) -> bool {
        use UserIDDesignator::*;
        match self {
            UserID(_, _) => false,
            Email(_, _) => false,
            Name(_, _) => true,
        }
    }

    /// Returns the semantics.
    fn semantics(&self) -> &UserIDDesignatorSemantics {
        use UserIDDesignator::*;
        match self {
            UserID(s, _) | Email(s, _) | Name(s, _) => {
                s
            }
        }
    }

    /// If `self` is `UserIDDesignatorSemantics::Exact`.
    pub fn is_exact(&self) -> bool {
        self.semantics().is_exact()
    }

    /// If `self` is `UserIDDesignatorSemantics::By`.
    fn is_by(&self) -> bool {
        self.semantics().is_by()
    }

    /// If `self` is `UserIDDesignatorSemantics::Add`.
    pub fn is_add(&self) -> bool {
        self.semantics().is_add()
    }

    /// Returns the argument's value.
    pub fn value(&self) -> &str {
        use UserIDDesignator::*;
        match self {
            UserID(_, s) | Email(_, s) | Name(_, s) => s,
        }
    }

    /// Returns the argument's name.
    pub fn argument_name<Arguments>(&self) -> String
    where Arguments: Unsigned
    {
        let arguments = Arguments::to_usize();
        let _all_arg = (arguments & AllUserIDsArg::to_usize()) > 0;
        let exact_args = (arguments & ExactArgs::to_usize()) > 0;
        let by_args = (arguments & ByArgs::to_usize()) > 0;
        let add_args = (arguments & AddArgs::to_usize()) > 0;

        let plain_is_by = (arguments & PlainIsBy::to_usize()) > 0;
        let plain_is_add = (arguments & PlainIsAdd::to_usize()) > 0;

        // Can't use PlainIsBy or PlainIsAdd with ExactArgs or with
        // each other.
        assert!(! (exact_args && plain_is_by));
        assert!(! (exact_args && plain_is_add));
        assert!(! (plain_is_by && plain_is_add));
        // If plain_is_xxx is set, then by_xxx must be set.
        if plain_is_by {
            assert!(by_args);
        }
        if plain_is_add {
            assert!(add_args);
        }

        use UserIDDesignator::*;
        let thing = match self {
            UserID(_, _) => {
                "userid"
            }
            Email(_, _) => {
                "email"
            }
            Name(_, _) => {
                "name"
            }
        };

        let semantics = match self {
            UserID(semantics, _) | Email(semantics, _) | Name(semantics, _) => {
                semantics
            }
        };

        use UserIDDesignatorSemantics::*;
        match semantics {
            Exact => format!("--{}", thing),
            By if plain_is_by => format!("--{}", thing),
            Add if plain_is_add => format!("--{}", thing),
            By => {
                if self.is_userid() {
                    format!("--userid")
                } else {
                    format!("--userid-by-{}", thing)
                }
            }
            Add => {
                format!("--add-{}", thing)
            }
        }
    }

    /// Returns the argument's value.
    ///
    /// The returned string is escaped.
    pub fn argument_value(&self) -> String
    {
        use UserIDDesignator::*;
        let value = match self {
            UserID(_, userid) => userid,
            Email(_, email) => email,
            Name(_, name) => name,
        };

        escape_for_shell(value).to_string()
    }

    /// Returns the argument, e.g., `--email=alice@example.org`
    pub fn argument<Arguments>(&self) -> String
    where Arguments: Unsigned
    {
        format!("{} {}",
                self.argument_name::<Arguments>(),
                self.argument_value())
    }

    /// Resolves to the specified user IDs.
    pub fn resolve_to(&self, userid: UserID) -> ResolvedUserID {
        ResolvedUserID {
            designator: Some(self.clone()),
            userid,
        }
    }

    /// Resolves to the designated user ID.
    ///
    /// If an email or a name, first converts them to a user ID in the
    /// usual manner.
    pub fn resolve_to_self(&self) -> ResolvedUserID {
        use UserIDDesignator::*;
        let userid = match self {
            UserID(_, userid) =>
                openpgp::packet::UserID::from(&userid[..]),
            Email(_, email) =>
                openpgp::packet::UserID::from(&format!("<{}>", email)[..]),
            Name(_, name) =>
                openpgp::packet::UserID::from(&name[..]),
        };

        ResolvedUserID {
            designator: Some(self.clone()),
            userid,
        }
    }
}

/// A data structure that can be flattened into a clap `Command`, and
/// adds arguments to address user IDs.
///
/// Depending on `Arguments`, it adds zero or more arguments to the
/// subcommand.  If `ExistingUserIDArg` is selected, for instance,
/// then a `--userid` argument is added.
///
/// `Options` are the set of options to the argument parser.  By
/// default, at least one user ID designator must be specified.
pub struct UserIDDesignators<Arguments,
                             Options=typenum::U0,
                             Documentation=SelfSignedDocumentation>
{
    /// The set of certificate designators.
    pub designators: Vec<UserIDDesignator>,

    /// Use all self-signed user IDs.
    pub all: Option<bool>,

    /// Whether --all should match non-self signed user IDs.
    all_matches_non_self_signed: bool,

    /// Whether --allow-non-canonical-userids was passed.
    pub allow_non_canonical_userids: bool,

    arguments: std::marker::PhantomData<(Arguments, Options, Documentation)>,
}

impl<Arguments, Options, Documentation> std::fmt::Debug
    for UserIDDesignators<Arguments, Options, Documentation>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserIDDesignators")
            .field("designators", &self.designators)
            .field("all", &self.all)
            .finish()
    }
}

#[allow(dead_code)]
impl<Arguments, Options, Documentation>
    UserIDDesignators<Arguments, Options, Documentation>
{
    /// Like `Vec::push`.
    pub fn push(&mut self, designator: UserIDDesignator) {
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
    pub fn iter(&self) -> impl Iterator<Item=&UserIDDesignator> {
        self.designators.iter()
    }

    /// Returns whether the all flag was set.
    ///
    /// If the flag was not enabled, returns `None`.
    pub fn all(&self) -> Option<bool> {
        self.all
    }

    /// Returns whether --all should match non-self signed user IDs.
    pub fn all_matches_non_self_signed(&self) -> bool {
        self.all_matches_non_self_signed
    }

    /// Returns whether the allow-non-canonical-userids flag was set.
    pub fn allow_non_canonical_userids(&self) -> bool {
        self.allow_non_canonical_userids
    }
}

impl<Arguments, Options, Docs> clap::Args
    for UserIDDesignators<Arguments, Options, Docs>
where
    Arguments: typenum::Unsigned,
    Options: typenum::Unsigned,
    Docs: Documentation + std::fmt::Debug,
{
    fn augment_args(mut cmd: clap::Command) -> clap::Command
    {
        let arguments = Arguments::to_usize();
        let all_arg = (arguments & AllUserIDsArg::to_usize()) > 0;
        let exact_args = (arguments & ExactArgs::to_usize()) > 0;
        let by_args = (arguments & ByArgs::to_usize()) > 0;
        let add_args = (arguments & AddArgs::to_usize()) > 0;

        let plain_is_by = (arguments & PlainIsBy::to_usize()) > 0;
        let plain_is_add = (arguments & PlainIsAdd::to_usize()) > 0;

        // Can't use PlainIsBy or PlainIsAdd with ExactArgs or with
        // each other.
        assert!(! (exact_args && plain_is_by));
        assert!(! (exact_args && plain_is_add));
        assert!(! (plain_is_by && plain_is_add));
        // If plain_is_xxx is set, then by_xxx must be set.
        if plain_is_by {
            assert!(by_args);
        }
        if plain_is_add {
            assert!(add_args);
        }

        let options = Options::to_usize();
        let one_value = (options & OneValue::to_usize()) > 0;
        let optional_value = (options & OptionalValue::to_usize()) > 0;
        let no_linting = (options & NoLinting::to_usize()) > 0;

        let group = format!("userid-designator-{:X}-{:X}",
                            arguments,
                            options);
        let mut arg_group = clap::ArgGroup::new(&group);
        if one_value {
            arg_group = arg_group.multiple(false);
        } else {
            arg_group = arg_group.multiple(true);
        }

        if optional_value {
            arg_group = arg_group.required(false);
        } else {
            arg_group = arg_group.required(true);
        }

        let action = if one_value {
            clap::ArgAction::Set
        } else {
            clap::ArgAction::Append
        };

        fn parse_as_email(s: &str) -> Result<String> {
            let userid = openpgp::packet::UserID::from(format!("<{}>", s));
            match userid.email_normalized() {
                Ok(Some(email)) => {
                    Ok(email)
                }
                Ok(None) => {
                    Err(anyhow::anyhow!(
                        "{:?} is not a valid email address", s))
                }
                Err(err) => {
                    Err(err).context(format!(
                        "{:?} is not a valid email address", s))
                }
            }
        }

        if all_arg {
            let full_name = "all";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .action(clap::ArgAction::SetTrue)
                    .help("\
Use all self-signed user IDs"));
            arg_group = arg_group.arg(full_name);
        }

        use UserIDDesignatorType::*;
        use UserIDDesignatorSemantics::*;
        if exact_args || plain_is_by {
            let full_name = "userid";
            let (help, long_help) = Docs::help(
                UserID, true, if plain_is_by { By } else { Exact });

            let mut arg = clap::Arg::new(&full_name)
                .long(&full_name)
                .value_name("USERID")
                .action(action.clone())
                .help(help);
            if let Some(long_help) = long_help {
                arg = arg.long_help(long_help);
            }
            if all_arg {
                arg = arg.conflicts_with("all");
            }
            cmd = cmd.arg(arg);

            arg_group = arg_group.arg(full_name);
        }

        if add_args {
            let full_name = if plain_is_add {
                "userid"
            } else {
                "add-userid"
            };

            let (help, long_help) = Docs::help(UserID, false, Add);
            let mut arg = clap::Arg::new(&full_name)
                .long(&full_name)
                .value_name("USERID")
                .action(action.clone())
                .help(help);
            if let Some(long_help) = long_help {
                arg = arg.long_help(long_help);
            }
            if all_arg {
                arg = arg.conflicts_with("all");
            }
            cmd = cmd.arg(arg);

            arg_group = arg_group.arg(full_name);
        }

        if by_args {
            let full_name = if plain_is_by {
                "email"
            } else {
                "userid-by-email"
            };

            let (help, long_help) = Docs::help(Email, plain_is_by, By);

            let mut arg = clap::Arg::new(&full_name)
                .long(&full_name)
                .value_name("EMAIL")
                .value_parser(parse_as_email)
                .action(action.clone())
                .help(help);
            if let Some(long_help) = long_help {
                arg = arg.long_help(long_help);
            }
            if all_arg {
                arg = arg.conflicts_with("all");
            }
            cmd = cmd.arg(arg);

            arg_group = arg_group.arg(full_name);
        }

        // plain_is_by is handled below.  This improves the ordering.
        let render_by_name = |mut cmd: clap::Command,
                              mut arg_group: clap::ArgGroup|
        {
            if ENABLE_NAME {
                let full_name = if plain_is_by {
                    "name"
                } else {
                    "userid-by-name"
                };

                let (help, long_help) = Docs::help(Name, plain_is_by, By);

                let mut arg = clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("DISPLAY_NAME")
                    .action(action.clone())
                    .help(help);
                if let Some(long_help) = long_help {
                    arg = arg.long_help(long_help);
                }
                if all_arg {
                    arg = arg.conflicts_with("all");
                }
                cmd = cmd.arg(arg);

                arg_group = arg_group.arg(full_name);
            }

            (cmd, arg_group)
        };
        if by_args && ! plain_is_by {
            (cmd, arg_group) = render_by_name(cmd, arg_group);
        }

        if exact_args {
            let full_name = "email";
            let (help, long_help) = Docs::help(Email, true, Exact);
            let mut arg = clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("EMAIL")
                    .value_parser(parse_as_email)
                    .action(action.clone())
                    .help(help);
            if let Some(long_help) = long_help {
                arg = arg.long_help(long_help);
            }
            if all_arg {
                arg = arg.conflicts_with("all");
            }
            cmd = cmd.arg(arg);

            arg_group = arg_group.arg(full_name);
        }

        if add_args {
            let full_name = if plain_is_add {
                "email"
            } else {
                "add-email"
            };
            let (help, long_help) = Docs::help(Email, plain_is_add, Add);
            let mut arg = clap::Arg::new(&full_name)
                .long(&full_name)
                .value_name("EMAIL")
                .value_parser(parse_as_email)
                .action(action.clone())
                .help(help);
            if let Some(long_help) = long_help {
                arg = arg.long_help(long_help);
            }
            if all_arg {
                arg = arg.conflicts_with("all");
            }
            cmd = cmd.arg(arg);

            arg_group = arg_group.arg(full_name);
        }

        if exact_args {
            if ENABLE_NAME {
                let full_name = "name";
                let (help, long_help) = Docs::help(Name, true, Exact);
                let mut arg = clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("DISPLAY_NAME")
                    .action(action.clone())
                    .help(help);
                if let Some(long_help) = long_help {
                    arg = arg.long_help(long_help);
                }
                if all_arg {
                    arg = arg.conflicts_with("all");
                }
                cmd = cmd.arg(arg);

                arg_group = arg_group.arg(full_name);
            }
        }

        if by_args && plain_is_by {
            (cmd, arg_group) = render_by_name(cmd, arg_group);
        }

        if add_args {
            if ENABLE_NAME {
                let full_name = if plain_is_add {
                    "name"
                } else {
                    "add-name"
                };
                let (help, long_help) = Docs::help(Name, plain_is_add, Add);
                let mut arg = clap::Arg::new(&full_name)
                    .long(&full_name)
                    .value_name("DISPLAY_NAME")
                    .action(action.clone())
                    .help(help);
                if let Some(long_help) = long_help {
                    arg = arg.long_help(long_help);
                }
                if all_arg {
                    arg = arg.conflicts_with("all");
                }
                cmd = cmd.arg(arg);

                arg_group = arg_group.arg(full_name);
            }
        }

        if ! no_linting && add_args {
            let full_name = "allow-non-canonical-userids";
            cmd = cmd.arg(
                clap::Arg::new(&full_name)
                    .long(&full_name)
                    .action(clap::ArgAction::SetTrue)
                    .help("\
Don't reject new user IDs that are not in canonical form")
                    .long_help("\
Don't reject new user IDs that are not in canonical form

Canonical user IDs are of the form `Name (Comment) \
<localpart@example.org>`."));
        }

        cmd = cmd.group(arg_group);

        cmd
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command
    {
        Self::augment_args(cmd)
    }
}

impl<Arguments, Options, Documentation> clap::FromArgMatches
    for UserIDDesignators<Arguments, Options, Documentation>
where
    Arguments: typenum::Unsigned,
    Options: typenum::Unsigned,
    Documentation: std::fmt::Debug,
{
    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches)
        -> Result<(), clap::Error>
    {
        // eprintln!("matches: {:#?}", matches);

        let arguments = Arguments::to_usize();
        let all_arg = (arguments & AllUserIDsArg::to_usize()) > 0;
        let exact_args = (arguments & ExactArgs::to_usize()) > 0;
        let by_args = (arguments & ByArgs::to_usize()) > 0;
        let add_args = (arguments & AddArgs::to_usize()) > 0;

        let plain_is_by = (arguments & PlainIsBy::to_usize()) > 0;
        let plain_is_add = (arguments & PlainIsAdd::to_usize()) > 0;

        // Can't use PlainIsBy or PlainIsAdd with ExactArgs or with
        // each other.
        assert!(! (exact_args && plain_is_by));
        assert!(! (exact_args && plain_is_add));
        assert!(! (plain_is_by && plain_is_add));
        // If plain_is_xxx is set, then by_xxx must be set.
        if plain_is_by {
            assert!(by_args);
        }
        if plain_is_add {
            assert!(add_args);
        }

        let options = Options::to_usize();
        let no_linting = (options & NoLinting::to_usize()) > 0;
        let all_matches_non_self_signed =
            (options & AllMatchesNonSelfSigned::to_usize()) > 0;

        let mut designators = Vec::new();

        self.all = if all_arg {
            if matches.get_flag("all") {
                Some(true)
            } else {
                Some(false)
            }
        } else {
            None
        };
        self.all_matches_non_self_signed = all_matches_non_self_signed;

        use UserIDDesignatorSemantics::*;
        if exact_args {
            if let Ok(Some(userids)) = matches.try_get_many::<String>("userid") {
                for userid in userids.cloned() {
                    designators.push(
                        UserIDDesignator::UserID(Exact, userid));
                }
            }
            if let Ok(Some(emails)) = matches.try_get_many::<String>("email") {
                for email in emails.cloned() {
                    designators.push(
                        UserIDDesignator::Email(Exact, email));
                }
            }
            if let Ok(Some(names)) = matches.try_get_many::<String>("name") {
                for name in names.cloned() {
                    designators.push(
                        UserIDDesignator::Name(Exact, name));
                }
            }
        }

        if by_args {
            if plain_is_by {
                if let Ok(Some(userids)) = matches.try_get_many::<String>("userid") {
                    for userid in userids.cloned() {
                        designators.push(
                            UserIDDesignator::UserID(By, userid));
                    }
                }
            }
            if let Ok(Some(emails))
                = matches.try_get_many::<String>(
                    if plain_is_by { "email" } else { "userid-by-email" })
            {
                for email in emails.cloned() {
                    designators.push(
                        UserIDDesignator::Email(By ,email));
                }
            }
            if let Ok(Some(names))
                = matches.try_get_many::<String>(
                    if plain_is_by { "name" } else { "userid-by-name" })
            {
                for name in names.cloned() {
                    designators.push(
                        UserIDDesignator::Name(By, name));
                }
            }
        }

        if add_args {
            if let Ok(Some(userids))
                = matches.try_get_many::<String>(
                    if plain_is_add { "userid" } else { "add-userid" }) {
                for userid in userids.cloned() {
                    designators.push(
                        UserIDDesignator::UserID(Add, userid));
                }
            }
            if let Ok(Some(emails))
                = matches.try_get_many::<String>(
                    if plain_is_add { "email" } else { "add-email" })
            {
                for email in emails.cloned() {
                    designators.push(
                        UserIDDesignator::Email(Add, email));
                }
            }
            if let Ok(Some(names))
                = matches.try_get_many::<String>(
                    if plain_is_add { "name" } else { "add-name" })
            {
                for name in names.cloned() {
                    designators.push(
                        UserIDDesignator::Name(Add, name));
                }
            }
        }

        if no_linting {
            self.allow_non_canonical_userids = true;
        } else if add_args {
            self.allow_non_canonical_userids
                = matches.get_flag("allow-non-canonical-userids");
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
            all: None,
            all_matches_non_self_signed: false,
            allow_non_canonical_userids: false,
        };

        // The way we use clap, this is never called.
        designators.update_from_arg_matches(matches)?;
        Ok(designators)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedUserID {
    designator: Option<UserIDDesignator>,
    userid: UserID,
}

impl From<UserID> for ResolvedUserID {
    fn from(userid: UserID) -> Self {
        ResolvedUserID {
            designator: None,
            userid,
        }
    }
}

use crate::cli::types::MyAsRef;
impl MyAsRef<UserID> for &ResolvedUserID {
    fn as_ref(&self) -> &UserID {
        &self.userid
    }
}

impl ResolvedUserID {
    /// Return a new implicitly resolved user ID (i.e., it was
    /// resolved via `--add`).
    pub fn implicit(userid: UserID)
        -> Self
    {
        Self {
            designator: None,
            userid,
        }
    }

    /// Return implicitly resolved user IDs for all user IDs
    /// associated with a certificate.
    #[allow(dead_code)]
    pub fn implicit_for_cert(cert: &Cert) -> Vec<Self> {
        cert.userids()
            .map(|ua| Self::implicit(ua.userid().clone()))
            .collect::<Vec<_>>()
    }

    /// Return implicitly resolved user IDs for of a certificate's
    /// self-signed user IDs.
    #[allow(dead_code)]
    pub fn implicit_for_valid_cert(vc: &ValidCert) -> Vec<Self> {
        vc.userids()
            .map(|ua| Self::implicit(ua.userid().clone()))
            .collect::<Vec<_>>()
    }

    /// The user ID designator.
    ///
    /// The designator is what the user provided.  If the user ID was
    /// not explicitly designator (i.e., it was resolved via `--all`),
    /// this is `None`.
    #[allow(unused)]
    pub fn designator(&self) -> Option<&UserIDDesignator> {
        self.designator.as_ref()
    }

    /// The resolved user ID.
    pub fn userid(&self) -> &UserID {
        &self.userid
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Check that flattening UserIDDesignators works as expected.
    #[test]
    fn userid_designators() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        macro_rules! check {
            ($t:ty,
             $plain:expr, $by:expr, $add:expr) =>
            {{
                #[derive(Parser, Debug)]
                #[clap(name = "prog")]
                struct CLI {
                    #[command(flatten)]
                    pub userids: UserIDDesignators<$t>,
                }

                let command = CLI::command();

                let plain: Option<UserIDDesignatorSemantics> =
                    $plain.into();

                // Check if --userid is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog", "--userid", "alice", "--userid", "bob",
                ]);
                if let Some(plain) = plain.as_ref() {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| {
                        d.semantics() == plain
                    }));
                } else {
                    assert!(m.is_err());
                }


                // Check if --email is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--email", "alice@example.org",
                    "--email", "bob@example.org",
                ]);
                if let Some(plain) = plain.as_ref() {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| {
                        d.semantics() == plain
                    }));
                } else {
                    assert!(m.is_err());
                }

                // Check if --name is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--name", "alice",
                    "--name", "bob",
                ]);
                if let (Some(plain), true) = (plain.as_ref(), ENABLE_NAME) {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| {
                        d.semantics() == plain
                    }));
                } else {
                    assert!(m.is_err());
                }

                // Check if --userid-by-email is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--userid-by-email", "alice@example.org",
                    "--userid-by-email", "bob@example.org",
                ]);
                if $by {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| d.is_by()));
                } else {
                    assert!(m.is_err());
                }

                // Check if --userid-by-name is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--userid-by-name", "alice",
                    "--userid-by-name", "bob",
                ]);
                if $by && ENABLE_NAME {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| d.is_by()));
                } else {
                    assert!(m.is_err());
                }

                // Either --email is unknown, or the --email's value
                // is invalid.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--email", "alice@invalid@example.org",
                ]);
                assert!(m.is_err());

                // Check if --add-userid is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--add-userid", "alice",
                    "--add-userid", "bob",
                ]);
                if $add {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| d.is_add()));
                } else {
                    assert!(m.is_err());
                }

                // Check if --add-email is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--add-email", "alice@example.org",
                    "--add-email", "bob@example.org",
                ]);
                if $add {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| d.is_add()));
                } else {
                    assert!(m.is_err());
                }

                // Check if --add-name is recognized.
                let m = command.clone().try_get_matches_from(vec![
                    "prog",
                    "--add-name", "alice",
                    "--add-name", "bob",
                ]);
                if $add && ENABLE_NAME {
                    let m = m.expect("valid arguments");
                    let c = CLI::from_arg_matches(&m).expect("ok");
                    assert_eq!(c.userids.designators.len(), 2);
                    assert!(c.userids.designators.iter().all(|d| d.is_add()));
                } else {
                    assert!(m.is_err());
                }
            }}
        }

        use UserIDDesignatorSemantics::*;
        //                              plain,    by,   add
        check!(typenum::U0,              None, false, false);
        check!(ExactArgs,               Exact, false, false);
        check!(ByArgs,                   None,  true, false);
        check!(AddArgs,                  None, false, true);
        check!(PlainByArgs,                By, false, false);
        check!(PlainAddArgs,              Add, false, false);
        check!(ExactAndAddArgs,         Exact, false,  true);
        check!(ExactByAndAddArgs,       Exact,  true,  true);
        check!(AllExactByAndAddArgs,    Exact,  true,  true);
        check!(PlainAddAndByArgs,         Add,  true, false);
        check!(AllPlainAddAndByArgs,      Add,  true, false);
    }

    #[test]
    fn userid_designators_one() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub userids: UserIDDesignators<ExactArgs, OneValue>,
        }

        let command = CLI::command();

        // Check if --userid is recognized.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "userid",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 1);

        // Make sure that we can't give it twice.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
            "--userid", "bob",
        ]);
        assert!(m.is_err());

        // Make sure that we can't give it zero times.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
        ]);
        assert!(m.is_err());

        // Mixing is also not allowed.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "carol",
            "--email", "localpart@example.org",
        ]);
        assert!(m.is_err());
    }

    #[test]
    fn userid_designators_optional() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub userids: UserIDDesignators<ExactArgs,
                                           OptionalValue>,
        }

        let command = CLI::command();

        // Check if --userid is recognized.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 1);

        // Make sure that we can give it twice.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
            "--userid", "bob",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 2);

        // Make sure that we can give it zero times.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 0);

        // Make sure mixing is allowed.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
            "--email", "localpart@example.org",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 2);
    }

    #[test]
    fn userid_designators_all() {
        use clap::Parser;
        use clap::CommandFactory;
        use clap::FromArgMatches;

        #[derive(Parser, Debug)]
        #[clap(name = "prog")]
        struct CLI {
            #[command(flatten)]
            pub userids: UserIDDesignators<AllExactByAndAddArgs>,
        }

        let command = CLI::command();

        // Sanity check.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--userid", "alice",
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 1);
        assert_eq!(c.userids.all(), Some(false));

        // Make sure --all by itself is accepted.
        let m = command.clone().try_get_matches_from(vec![
            "prog",
            "--all"
        ]);
        let m = m.expect("valid arguments");
        let c = CLI::from_arg_matches(&m).expect("ok");
        assert_eq!(c.userids.designators.len(), 0);
        assert_eq!(c.userids.all(), Some(true));

        // Can't combine --all with any other designator.
        for (arg, value) in &[
            ("--userid", "foo"),
            ("--userid-by-email", "foo@example.org"),
            ("--userid-by-name", "foo"),
            ("--add-userid", "foo"),
            ("--email", "foo@example.org"),
            ("--add-email", "foo@example.org"),
            ("--name", "foo"),
            ("--add-name", "foo"),
        ]
        {
            if ! ENABLE_NAME && arg.contains("-name") {
                continue;
            }

            // Make sure the arg/value are recognized.
            eprintln!("Testing {} {}", arg, value);
            let m = command.clone().try_get_matches_from(vec![
                "prog",
                arg, value,
            ]);
            let m = m.expect("valid arguments");
            let c = CLI::from_arg_matches(&m).expect("ok");
            assert_eq!(c.userids.designators.len(), 1);
            assert_eq!(c.userids.all(), Some(false));

            // Make sure adding --all causes it to fail.
            eprintln!("Testing {} {} --all", arg, value);
            let m = command.clone().try_get_matches_from(vec![
                "prog",
                arg, value,
                "--all",
            ]);
            assert!(m.is_err());
        }
    }
}
