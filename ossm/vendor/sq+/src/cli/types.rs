//! Types used in the command-line parser.

use std::fmt::Display;
use std::fmt::Formatter;
use std::io::Read;
use std::io::stdin;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;

use buffered_reader::BufferedReader;
use buffered_reader::File;
use buffered_reader::Generic;

/// Common types for arguments of sq.
use clap::ValueEnum;

use sequoia_openpgp as openpgp;
use openpgp::fmt::hex;
use openpgp::KeyHandle;
use openpgp::packet::UserID;
use openpgp::parse::Cookie;
use openpgp::types::KeyFlags;
use openpgp::types::SymmetricAlgorithm;

pub mod cert_designator;
pub use cert_designator::CertDesignators;
mod encryption_algorithm;
pub use encryption_algorithm::EncryptionAlgorithm;
pub mod key_designator;
pub use key_designator::KeyDesignators;
pub mod paths;
pub mod userid_designator;
pub use userid_designator::UserIDDesignators;
pub mod expiration;
pub use expiration::Expiration;
pub use expiration::ExpirationArg;
pub mod profile;
pub use profile::Profile;
pub mod signature_notations;
pub use signature_notations::SignatureNotationsArg;
mod signing_algorithm;
pub use signing_algorithm::SigningAlgorithm;
pub mod special_names;
pub use special_names::SpecialName;
pub mod time;
pub use time::Time;
pub mod version;
pub use version::Version;

// A local copy of the standard library's AsRef trait.
//
// We need a local copy of AsRef, as we need to implement AsRef for
// UserID, but due to the orphan rule, we can't.  Instead we have to
// make a local copy of AsRef or UserID.  Copying AsRef is less
// invasive.
pub trait MyAsRef<T>
where
    T: ?Sized,
{
    fn as_ref(&self) -> &T;
}

impl MyAsRef<UserID> for UserID {
    fn as_ref(&self) -> &UserID {
        self
    }
}

impl MyAsRef<UserID> for &UserID {
    fn as_ref(&self) -> &UserID {
        self
    }
}

/// A trait to provide const &str for clap annotations for custom structs
pub trait ClapData {
    /// The clap value name.
    const VALUE_NAME: &'static str;

    /// The clap help text for required arguments.
    ///
    /// Use this as the default help text if the value must be given.
    const HELP_REQUIRED: &'static str;

    /// The clap help text for optional arguments.
    ///
    /// Use this as the default help text if the value must not be
    /// given, because either:
    ///
    ///   - there is a default value, or
    ///   - the type is an `Option<T>`.
    const HELP_OPTIONAL: &'static str;
}

/// Reads from stdin, and prints a warning to stderr if no input is
/// read within a certain amount of time.
pub struct StdinWarning {
    do_warn: bool,
    /// The thing that is being waited for.  See `StdinWarning::emit`.
    thing: &'static str,
}

/// Print a warning if we don't get any input after this amount of
/// time.
const STDIN_TIMEOUT: Duration = std::time::Duration::new(2, 0);

impl StdinWarning {
    /// Emit a custom warning if no input is received.
    pub fn new(thing: &'static str) -> Self {
        Self {
            do_warn: true,
            thing,
        }
    }

    /// Emit a warning that a certificate is expected if no input is
    /// received.
    pub fn openpgp() -> Self {
        Self::new("OpenPGP data")
    }

    /// Emit a warning that certificates are expected if no input is
    /// received.
    pub fn certs() -> Self {
        Self::new("OpenPGP certificates")
    }

    pub fn emit(&self) {
        eprintln!("Waiting for {} on stdin...", self.thing);
    }
}

impl Read for StdinWarning {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if self.do_warn {
            if buf.len() == 0 {
                return Ok(0);
            }

            // We may warn the user.  We don't want to print the
            // warning if we read anything.  If we try to read two
            // bytes, we might read one byte, block, print the
            // warning, and then later read a second byte.  That's not
            // great.  Thus, we don't read more than a single byte.
            buf = &mut buf[..1];

            // Don't warn again.
            self.do_warn = false;

            thread::scope(|s| {
                let (sender, receiver) = mpsc::channel::<()>();

                s.spawn(move || {
                    if let Err(mpsc::RecvTimeoutError::Timeout)
                        = receiver.recv_timeout(STDIN_TIMEOUT)
                    {
                        self.emit();
                    }
                });

                let result = stdin().read(buf);
                // Force the thread to exit now.
                drop(sender);
                result
            })
        } else {
            stdin().read(buf)
        }
    }
}

/// A type wrapping an optional PathBuf to use as stdin or file input
///
/// When creating `FileOrStdin` from `&str`, providing a `"-"` is interpreted
/// as `None`, i.e. read from stdin. Providing other strings is interpreted as
/// `Some(PathBuf)`, i.e. read from file.
/// Use this if a CLI should allow input from a file and if unset from stdin.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         default_value_t = FileOrStdin::default(),
///         help = FileOrStdin::HELP_OPTIONAL,
///         value_name = FileOrStdin::VALUE_NAME,
///     )]
///     pub input: FileOrStdin,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdin(Option<PathBuf>);

impl ClapData for FileOrStdin {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_OPTIONAL: &'static str =
        "Read from FILE or stdin if FILE is '-'";
    const HELP_REQUIRED: &'static str =
        "Read from FILE or stdin if omitted";
}

impl FileOrStdin {
    pub fn new(path: Option<PathBuf>) -> Self {
        FileOrStdin(path)
    }

    /// Return a reference to the inner type
    pub fn inner(&self) -> Option<&PathBuf> {
        self.0.as_ref()
    }

    /// Returns `None` if `self.0` is `None`, otherwise calls f with the wrapped
    /// value and returns the result
    pub fn and_then<U, F>(self, f: F) -> Option<U>
    where
        F: FnOnce(PathBuf) -> Option<U>,
    {
        self.0.and_then(|x| f(x))
    }

    /// Get a boxed BufferedReader for the FileOrStdin
    ///
    /// Opens a file if there is Some(PathBuf), else opens stdin.
    ///
    /// `thing` is the thing that we expect to read, e.g., "OpenPGP
    /// certificates" or "a signed message".
    pub fn open<'a>(&self, thing: &'static str)
        -> Result<Box<dyn BufferedReader<Cookie> + 'a>>
    {
        if let Some(path) = self.inner() {
            Ok(Box::new(
                File::with_cookie(path, Default::default())
                .with_context(|| format!("Failed to open {}", self))?))
        } else {
            Ok(Box::new(
                Generic::with_cookie(
                    StdinWarning::new(thing), None, Default::default())))
        }
    }

    /// Return a reference to the optional PathBuf.
    pub fn path(&self) -> Option<&PathBuf> {
        self.0.as_ref()
    }
}

impl Default for FileOrStdin {
    fn default() -> Self {
        FileOrStdin(None)
    }
}

impl From<PathBuf> for FileOrStdin {
    fn from(value: PathBuf) -> Self {
        if value == PathBuf::from("-") {
            FileOrStdin::default()
        } else {
            FileOrStdin::new(Some(value))
        }
    }
}

impl From<Option<PathBuf>> for FileOrStdin {
    fn from(value: Option<PathBuf>) -> Self {
        if let Some(path) = value {
            FileOrStdin::from(path)
        } else {
            FileOrStdin::default()
        }
    }
}

impl From<&Path> for FileOrStdin {
    fn from(value: &Path) -> Self {
        if Path::new("-") == value {
            FileOrStdin::default()
        } else {
            FileOrStdin::from(value.to_owned())
        }
    }
}

impl From<Option<&Path>> for FileOrStdin {
    fn from(value: Option<&Path>) -> Self {
        if let Some(path) = value {
            FileOrStdin::from(path)
        } else {
            FileOrStdin::default()
        }
    }
}

impl FromStr for FileOrStdin {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if "-" == s {
            Ok(FileOrStdin(None))
        } else {
            Ok(FileOrStdin(Some(PathBuf::from(s))))
        }
    }
}

impl Display for FileOrStdin {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match &self.0 {
            None => write!(f, "-"),
            Some(path) => write!(f, "{}", path.display()),
        }
    }
}

/// A type providing const strings for output to certstore by default
///
/// This struct is empty and solely used to provide strings to clap.
/// Use this in combination with a [`FileOrStdout`] if a CLI should allow output
/// to a file and if unset output to a cert store.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         help = FileOrCertStore::HELP_OPTIONAL,
///         long,
///         value_name = FileOrCertStore::VALUE_NAME,
///     )]
///     pub output: Option<FileOrStdout>,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrCertStore{}

impl ClapData for FileOrCertStore {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_REQUIRED: &'static str
        = "Write to FILE (or stdout if FILE is '-') instead of \
          importing into the certificate store";
    const HELP_OPTIONAL: &'static str
        = "Write to FILE (or stdout when omitted) instead of \
          importing into the certificate store";
}

/// Designates a certificate by path, by stdin, or by key handle.
///
/// Use [`Sq::lookup_one`] to read the certificate.
#[derive(Clone, Debug)]
pub enum FileStdinOrKeyHandle {
    FileOrStdin(FileOrStdin),
    KeyHandle(KeyHandle),
}

impl From<FileOrStdin> for FileStdinOrKeyHandle {
    fn from(file: FileOrStdin) -> Self {
        FileStdinOrKeyHandle::FileOrStdin(file)
    }
}

impl From<&str> for FileStdinOrKeyHandle {
    fn from(path: &str) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<&Path> for FileStdinOrKeyHandle {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<PathBuf> for FileStdinOrKeyHandle {
    fn from(path: PathBuf) -> Self {
        FileStdinOrKeyHandle::FileOrStdin(path.into())
    }
}

impl From<&KeyHandle> for FileStdinOrKeyHandle {
    fn from(kh: &KeyHandle) -> Self {
        FileStdinOrKeyHandle::KeyHandle(kh.clone())
    }
}

impl From<KeyHandle> for FileStdinOrKeyHandle {
    fn from(kh: KeyHandle) -> Self {
        FileStdinOrKeyHandle::KeyHandle(kh)
    }
}

impl FileStdinOrKeyHandle {
    /// Returns whether this contains a `FileOrStdin`.
    pub fn is_file(&self) -> bool {
        match self {
            FileStdinOrKeyHandle::FileOrStdin(_) => true,
            FileStdinOrKeyHandle::KeyHandle(_) => false,
        }
    }

    /// Returns whether this contains a `KeyHandle`.
    pub fn is_key_handle(&self) -> bool {
        match self {
            FileStdinOrKeyHandle::FileOrStdin(_) => false,
            FileStdinOrKeyHandle::KeyHandle(_) => true,
        }
    }
}

/// A type wrapping an optional PathBuf to use as stdout or file output
///
/// When creating `FileOrStdout` from `&str`, providing a `"-"` is interpreted
/// as `None`, i.e. output to stdout. Providing other strings is interpreted as
/// `Some(PathBuf)`, i.e. output to file.
/// Use this if a CLI should allow output to a file and if unset output to
/// stdout.
///
/// ## Examples
/// ```
/// use clap::Args;
///
/// #[derive(Debug, Args)]
/// #[clap(name = "example", about = "an example")]
/// pub struct Example {
///     #[clap(
///         default_value_t = FileOrStdout::default(),
///         help = FileOrStdout::HELP_OPTIONAL,
///         long,
///         value_name = FileOrStdout::VALUE_NAME,
///     )]
///     pub output: FileOrStdout,
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileOrStdout {
    path: Option<PathBuf>,

    /// If set, secret keys may be written to this sink.
    for_secrets: bool,
}

impl ClapData for FileOrStdout {
    const VALUE_NAME: &'static str = "FILE";
    const HELP_REQUIRED: &'static str =
        "Write to FILE or stdout if FILE is '-'";
    const HELP_OPTIONAL: &'static str =
        "Write to FILE or stdout if omitted";
}

impl FileOrStdout {
    pub fn new(path: Option<PathBuf>) -> Self {
        FileOrStdout {
            path,
            ..Default::default()
        }
    }

    /// Indicates that we will emit secrets.
    ///
    /// Use this to mark outputs where we intend to emit secret keys.
    pub fn for_secrets(mut self) -> Self {
        self.for_secrets = true;
        self
    }

    /// Queries whether we are configured to emit secrets.
    pub fn is_for_secrets(&self) -> bool {
        self.for_secrets
    }

    /// Return a reference to the optional PathBuf
    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

}

impl Default for FileOrStdout {
    fn default() -> Self {
        FileOrStdout {
            path: None,
            for_secrets: false,
        }
    }
}

impl From<PathBuf> for FileOrStdout {
    fn from(value: PathBuf) -> Self {
        if value == PathBuf::from("-") {
            FileOrStdout::default()
        } else {
            FileOrStdout::new(Some(value))
        }
    }
}

impl From<Option<PathBuf>> for FileOrStdout {
    fn from(value: Option<PathBuf>) -> Self {
        if let Some(path) = value {
            FileOrStdout::from(path)
        } else {
            FileOrStdout::default()
        }
    }
}

impl FromStr for FileOrStdout {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if "-" == s {
            Ok(FileOrStdout::default())
        } else {
            Ok(FileOrStdout::new(Some(PathBuf::from(s))))
        }
    }
}

impl Display for FileOrStdout {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}", path.display()),
            None => write!(f, "-"),
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum ArmorKind {
    Auto,
    Message,
    #[clap(name = "cert")]
    PublicKey,
    #[clap(name = "key")]
    SecretKey,
    #[clap(name = "sig")]
    Signature,
    File,
}

impl From<ArmorKind> for Option<openpgp::armor::Kind> {
    fn from(c: ArmorKind) -> Self {
        match c {
            ArmorKind::Auto => None,
            ArmorKind::Message => Some(openpgp::armor::Kind::Message),
            ArmorKind::PublicKey => Some(openpgp::armor::Kind::PublicKey),
            ArmorKind::SecretKey => Some(openpgp::armor::Kind::SecretKey),
            ArmorKind::Signature => Some(openpgp::armor::Kind::Signature),
            ArmorKind::File => Some(openpgp::armor::Kind::File),
        }
    }
}

/// Describes the purpose of the encryption.
#[derive(ValueEnum, Clone, Debug)]
pub enum EncryptPurpose {
    /// Selects subkeys marked as suitable for transport encryption.
    Transport,

    /// Selects those for encrypting data at rest.
    Storage,

    /// Selects all encryption-capable subkeys.
    Universal,
}

impl From<EncryptPurpose> for KeyFlags {
    fn from(p: EncryptPurpose) -> Self {
        match p {
            EncryptPurpose::Storage => {
                KeyFlags::empty().set_storage_encryption()
            }
            EncryptPurpose::Transport => {
                KeyFlags::empty().set_transport_encryption()
            }
            EncryptPurpose::Universal => KeyFlags::empty()
                .set_storage_encryption()
                .set_transport_encryption(),
        }
    }
}

/// Describes the purpose of the encryption.
#[derive(Copy, Clone, Debug)]
pub enum TrustAmount<T> {
    /// No trust.
    None,

    /// Partial trust.
    Partial,

    /// Full trust.
    Full,

    /// Double trust.
    Double,

    /// Other trust amount.
    Other(T),
}

impl<T: Copy + From<u8>> TrustAmount<T> {
    /// Returns the trust amount as numeric value.
    pub fn amount(&self) -> T {
        match self {
            TrustAmount::None => 0.into(),
            // See section 5.2.3.13. Trust Signature of RFC4880 for
            // the values of partial and full trust.
            TrustAmount::Partial => 60.into(),
            TrustAmount::Full => 120.into(),
            TrustAmount::Double => 240.into(),
            TrustAmount::Other(a) => *a,
        }
    }
}

impl<T: Display + FromStr> FromStr for TrustAmount<T>
where
    <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<TrustAmount<T>> {
        if s.eq_ignore_ascii_case("none") {
            Ok(TrustAmount::None)
        } else if s.eq_ignore_ascii_case("partial") {
            Ok(TrustAmount::Partial)
        } else if s.eq_ignore_ascii_case("full") {
            Ok(TrustAmount::Full)
        } else if s.eq_ignore_ascii_case("double") {
            Ok(TrustAmount::Double)
        } else {
            Ok(TrustAmount::Other(s.parse()?))
        }
    }
}

impl<T: Display + FromStr> Display for TrustAmount<T> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            TrustAmount::None => f.write_str("none"),
            TrustAmount::Partial => f.write_str("partial"),
            TrustAmount::Full => f.write_str("full"),
            TrustAmount::Double => f.write_str("double"),
            TrustAmount::Other(a) => write!(f, "{}", a),
        }
    }
}

/// Holds a session key as parsed from the command line, with an optional
/// algorithm specifier.
///
/// This struct does not implement [`Display`] to prevent accidental leaking
/// of key material. If you are sure you want to print a session key, use
/// [`display_sensitive`].
///
/// [`Display`]: std::fmt::Display
/// [`display_sensitive`]: SessionKey::display_sensitive
#[derive(Debug, Clone)]
pub struct SessionKey {
    pub session_key: openpgp::crypto::SessionKey,
    pub symmetric_algo: Option<SymmetricAlgorithm>,
}

impl std::str::FromStr for SessionKey {
    type Err = anyhow::Error;

    /// Parse a session key. The format is: an optional prefix specifying the
    /// symmetric algorithm as a number, followed by a colon, followed by the
    /// session key in hexadecimal representation.
    fn from_str(sk: &str) -> anyhow::Result<Self> {
        let result = if let Some((algo, sk)) = sk.split_once(':') {
            let algo = SymmetricAlgorithm::from(algo.parse::<u8>()?);
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: Some(algo),
            }
        } else {
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: None,
            }
        };
        Ok(result)
    }
}

impl SessionKey {
    /// Returns an object that implements Display for explicitly opting into
    /// printing a `SessionKey`.
    pub fn display_sensitive(&self) -> SessionKeyDisplay {
        SessionKeyDisplay { csk: self }
    }
}

/// Helper struct for intentionally printing session keys with format! and {}.
///
/// This struct implements the `Display` trait to print the session key. This
/// construct requires the user to explicitly call
/// [`SessionKey::display_sensitive`]. By requiring the user to opt-in, this
/// will hopefully reduce that the chance that the session key is inadvertently
/// leaked, e.g., in a log that may be publicly posted.
pub struct SessionKeyDisplay<'a> {
    csk: &'a SessionKey,
}

/// Print the session key without prefix in hexadecimal representation.
impl<'a> std::fmt::Display for SessionKeyDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let sk = self.csk;
        write!(f, "{}", hex::encode(&sk.session_key))
    }
}
