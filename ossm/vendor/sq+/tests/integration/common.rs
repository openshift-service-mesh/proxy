#![allow(unused)]

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use anyhow::anyhow;
use anyhow::Context;

use assert_cmd::Command;

use chrono::DateTime;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::CertParser;
use openpgp::packet::Signature;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;

use tempfile::TempDir;

pub const STANDARD_POLICY: &StandardPolicy = &StandardPolicy::new();
pub const NULL_POLICY: &NullPolicy = unsafe { &NullPolicy::new() };

pub fn artifact(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests").join("data").join(filename)
}

pub fn artifact_s(filename: &str) -> String {
    artifact(filename).display().to_string()
}

// Returns the power set excluding the empty set.
pub fn power_set<T: Clone>(set: &[T]) -> Vec<Vec<T>> {
    let mut power_set: Vec<Vec<T>> = Vec::new();
    for element in set.iter() {
        power_set.extend(
            power_set.clone().into_iter().map(|mut v: Vec<T>| {
                v.push(element.clone());
                v
            }));
        power_set.push(vec![ element.clone() ]);
    }
    power_set
}

/// Returns the time formatted as an ISO 8106 string.
pub fn time_as_string(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Extracts fingerprints from human readable output and returns a map
/// from fingerprint to count.
pub fn extract_fingerprints(output: &str) -> BTreeMap<Fingerprint, usize> {
    use regex::Regex;

    // v6 and v4 fingerprints without spaces.
    let re = Regex::new(r"(\b[A-F0-9]{64}\b)|(\b[A-F0-9]{40}\b)").unwrap();

    let mut fprs: Vec<(Fingerprint, usize)> = re
        .captures_iter(output).map(|c| c.extract())
        .map(|(_, [fpr])| {
            (fpr.parse::<Fingerprint>().expect("valid fingerprint"), 1)
        })
        .collect();

    fprs.sort();
    fprs.dedup_by(|a, b| {
            if a.0 == b.0 {
                // a is removed
                b.1 += a.1;
                true
            } else {
                false
            }
        });

    fprs.into_iter().collect()
}

pub fn check_fingerprints<B>(output: &str,
                             expected: B)
where B: Into<BTreeMap<Fingerprint, usize>>
{
    let expected = expected.into();

    let got = extract_fingerprints(output);

    if got == expected {
        return;
    }

    let mut bad = false;
    for (fpr, got_count) in got.iter() {
        let expected_count = expected.get(fpr).unwrap_or(&0);
        if got_count != expected_count {
            eprintln!("Got {} {} times, but expected it {} times",
                      fpr, got_count, expected_count);
            bad = true;
        }
    }
    for (fpr, expected_count) in expected.iter() {
        let got_count = got.get(fpr).unwrap_or(&0);
        if *got_count == 0 && *expected_count > 0 {
            eprintln!("Got {} {} times, but expected it {} times",
                      fpr, got_count, expected_count);
            bad = true;
        }
    }

    if bad {
        eprintln!("Output is:\n{}", output);
        panic!("Fingerprint mismatch");
    }
}

pub fn check_certifications(
    certs: &[Cert],
    expected_certifications: &[
        // Certifier, cert, user ID, trust amount, count.
        (Fingerprint, Fingerprint, &str, usize, usize)
    ])
{
    let got: Vec<(&Cert, UserID, Signature)> = certs.into_iter()
        .flat_map(|cert| {
            cert.userids()
                .flat_map(|ua| {
                    ua.certifications()
                        .map(|certification| {
                            (cert,
                             ua.userid().clone(),
                             certification.clone())
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect();
    eprintln!("Have {} certifications", got.len());

    let certs: BTreeMap<Fingerprint, &Cert> = certs
        .into_iter()
        .map(|cert| {
            (cert.fingerprint(), cert)
        })
        .collect();

    let mut got: Vec<_> = got
        .into_iter()
        .map(|(cert, userid, sig)| {
            let issuers = sig.get_issuers();
            for issuer in issuers.iter() {
                let fpr = match issuer {
                    KeyHandle::Fingerprint(fpr) => fpr,
                    KeyHandle::KeyID(keyid) => {
                        eprintln!("Skipping key ID: {}", keyid);
                        continue;
                    }
                };

                if let Some(certifier) = certs.get(fpr) {
                    if let Ok(_) = sig.verify_userid_binding(
                        certifier.primary_key().key(),
                        cert.primary_key().key(),
                        &userid)
                    {
                        return (certifier, cert, userid, sig);
                    }
                }
            }

            panic!("Unable to find certifier for certification of {}, {}; \
                    alleged issuers: {}",
                   cert.fingerprint(),
                   String::from_utf8_lossy(userid.value()),
                   issuers
                       .iter()
                       .map(|i| i.to_string())
                       .collect::<Vec<String>>()
                       .join(", "));
        })
        .map(|(certifier, cert, userid, sig)| {
            // Get it in to a similar form as expected.
            let (_depth, amount) = sig.trust_signature()
                .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

            eprintln!("Certification: {} on {}, {}; amount: {}",
                      certifier.fingerprint(),
                      cert.fingerprint(),
                      String::from_utf8_lossy(userid.value()),
                      amount);

            (certifier.fingerprint(),
             cert.fingerprint(),
             String::from_utf8_lossy(userid.value()).to_string(),
             amount as usize,
             // Count.
             1)
        })
        .collect();

    got.sort();
    got.dedup_by(
        |(a_certifier, a_cert, a_userid, a_amount, a_count),
         (b_certifier, b_cert, b_userid, b_amount, b_count)|
        {
            if a_certifier == b_certifier
                && a_cert == b_cert
                && a_userid == b_userid
                && a_amount == b_amount
            {
                *b_count += *a_count;
                true
            } else {
                false
            }
        });
    let got = BTreeSet::from_iter(got.into_iter());

    let expected = BTreeSet::from_iter(
        expected_certifications.iter()
            .map(|(certifier, cert, userid, amount, count)| {
                (certifier.clone(),
                 cert.clone(),
                 userid.to_string(),
                 *amount,
                 *count)
            }));

    eprintln!();

    let mut bad = false;
    for (certifier, cert, userid, amount, count) in expected.difference(&got) {
        let certifier_uid = certs.get(certifier).unwrap()
            .userids().map(|ua| ua.userid()).next().unwrap().clone();

        eprintln!("Expected {} certification(s) by {}, {} for {}, {}, amount: {}",
                  count,
                  certifier,
                  String::from_utf8_lossy(certifier_uid.value()),
                  cert, userid, amount);
        bad = true;
    }
    for (certifier, cert, userid, amount, count) in got.difference(&expected) {
        let certifier_uid = certs.get(certifier).unwrap()
            .userids().map(|ua| ua.userid()).next().unwrap().clone();

        eprintln!("Unexpectedly got {} certification(s) by {}, {} for {}, {}, amount: {}",
                  count,
                  certifier,
                  String::from_utf8_lossy(certifier_uid.value()),
                  cert, userid, amount);
        bad = true;
    }

    if bad {
        panic!("Certification mismatch.");
    }
}

/// Designates a certificate by path, or by key handle.
#[derive(Clone, Debug)]
pub enum FileOrKeyHandle {
    FileOrStdin(PathBuf),
    KeyHandle((KeyHandle, OsString)),
}

impl From<&str> for FileOrKeyHandle {
    fn from(path: &str) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<String> for FileOrKeyHandle {
    fn from(path: String) -> Self {
        PathBuf::from(path).into()
    }
}

impl From<&Path> for FileOrKeyHandle {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<&PathBuf> for FileOrKeyHandle {
    fn from(path: &PathBuf) -> Self {
        path.clone().into()
    }
}

impl From<PathBuf> for FileOrKeyHandle {
    fn from(path: PathBuf) -> Self {
        FileOrKeyHandle::FileOrStdin(path.into())
    }
}

impl From<&KeyHandle> for FileOrKeyHandle {
    fn from(kh: &KeyHandle) -> Self {
        FileOrKeyHandle::KeyHandle((kh.clone(), kh.to_string().into()))
    }
}

impl From<KeyHandle> for FileOrKeyHandle {
    fn from(kh: KeyHandle) -> Self {
        let s = kh.to_string().into();
        FileOrKeyHandle::KeyHandle((kh, s))
    }
}

impl From<&Fingerprint> for FileOrKeyHandle {
    fn from(fpr: &Fingerprint) -> Self {
        KeyHandle::from(fpr).into()
    }
}

impl From<Fingerprint> for FileOrKeyHandle {
    fn from(fpr: Fingerprint) -> Self {
        KeyHandle::from(fpr).into()
    }
}

impl From<&FileOrKeyHandle> for FileOrKeyHandle {
    fn from(h: &FileOrKeyHandle) -> Self {
        h.clone()
    }
}

impl AsRef<OsStr> for FileOrKeyHandle {
    fn as_ref(&self) -> &OsStr {
        match self {
            FileOrKeyHandle::FileOrStdin(file) => file.as_os_str(),
            FileOrKeyHandle::KeyHandle((kh, s)) => s.as_os_str(),
        }
    }
}

impl FileOrKeyHandle {
    /// Returns whether this contains a `FileOrStdin`.
    pub fn is_file(&self) -> bool {
        match self {
            FileOrKeyHandle::FileOrStdin(_) => true,
            FileOrKeyHandle::KeyHandle(_) => false,
        }
    }

    /// Returns whether this contains a `KeyHandle`.
    pub fn is_key_handle(&self) -> bool {
        match self {
            FileOrKeyHandle::FileOrStdin(_) => false,
            FileOrKeyHandle::KeyHandle(_) => true,
        }
    }
}

/// Designates data by path, or bytes (which are fed to stdin).
#[derive(Clone, Debug)]
pub enum FileOrBytes {
    FileOrStdin(PathBuf),
    Bytes(Vec<u8>),
}

impl From<&[u8]> for FileOrBytes {
    fn from(s: &[u8]) -> Self {
        FileOrBytes::Bytes(s.to_vec())
    }
}

impl From<Vec<u8>> for FileOrBytes {
    fn from(s: Vec<u8>) -> Self {
        FileOrBytes::Bytes(s)
    }
}

impl From<&Vec<u8>> for FileOrBytes {
    fn from(s: &Vec<u8>) -> Self {
        FileOrBytes::Bytes(s.clone())
    }
}

impl From<&Path> for FileOrBytes {
    fn from(path: &Path) -> Self {
        path.to_path_buf().into()
    }
}

impl From<&PathBuf> for FileOrBytes {
    fn from(path: &PathBuf) -> Self {
        path.clone().into()
    }
}

impl From<PathBuf> for FileOrBytes {
    fn from(path: PathBuf) -> Self {
        FileOrBytes::FileOrStdin(path.into())
    }
}

impl From<&FileOrBytes> for FileOrBytes {
    fn from(h: &FileOrBytes) -> Self {
        h.clone()
    }
}

impl FileOrBytes {
    /// Returns whether this contains a `FileOrStdin`.
    pub fn is_file(&self) -> bool {
        match self {
            FileOrBytes::FileOrStdin(_) => true,
            FileOrBytes::Bytes(_) => false,
        }
    }

    /// Returns whether this contains bytes.
    pub fn is_bytes(&self) -> bool {
        match self {
            FileOrBytes::FileOrStdin(_) => false,
            FileOrBytes::Bytes(_) => true,
        }
    }
}

/// An enum for user ID arguments.
#[derive(Debug, Clone)]
pub enum UserIDArg<'a> {
    UserID(&'a str),
    Email(&'a str),
    Name(&'a str),
    AddUserID(&'a str),
    AddEmail(&'a str),
    ByEmail(&'a str),
}

impl<'a> From<&'a str> for UserIDArg<'a> {
    fn from(userid: &'a str) -> Self {
        UserIDArg::UserID(userid)
    }
}

impl<'a> From<&'a &'a str> for UserIDArg<'a> {
    fn from(userid: &'a &'a str) -> Self {
        UserIDArg::UserID(userid)
    }
}

impl<'a> From<&'a String> for UserIDArg<'a> {
    fn from(userid: &'a String) -> Self {
        UserIDArg::UserID(&userid)
    }
}

impl UserIDArg<'_> {
    /// Return the raw string.
    pub fn raw(&self) -> &str {
        match self {
            UserIDArg::UserID(s)
                | UserIDArg::Email(s)
                | UserIDArg::Name(s)
                | UserIDArg::AddUserID(s)
                | UserIDArg::AddEmail(s)
                | UserIDArg::ByEmail(s) =>
            {
                s
            }
        }
    }

    /// Add the argument to a `Command`.
    pub fn as_arg(&self, cmd: &mut Command) {
        match self {
            UserIDArg::UserID(userid) =>
                cmd.arg("--userid").arg(userid),
            UserIDArg::Email(email) =>
                cmd.arg("--email").arg(email),
            UserIDArg::Name(name) =>
                cmd.arg("--name").arg(name),
            UserIDArg::AddUserID(userid) =>
                cmd.arg("--add-userid").arg(userid),
            UserIDArg::AddEmail(email) =>
                cmd.arg("--add-email").arg(email),
            UserIDArg::ByEmail(email) =>
                cmd.arg("--userid-by-email").arg(email),
        };
    }

    /// Add the argument to a `Command` as a cert designator.
    ///
    /// Note: only a subset of user ID arguments are expressible as
    /// cert designators.
    pub fn as_cert_designator(&self, cmd: &mut Command) {
        match self {
            UserIDArg::UserID(userid) =>
                cmd.arg("--cert-userid").arg(userid),
            UserIDArg::Email(email) =>
                cmd.arg("--cert-email").arg(email),
            UserIDArg::Name(name) =>
                unreachable!(),
            UserIDArg::AddUserID(userid) =>
                unreachable!(),
            UserIDArg::AddEmail(email) =>
                unreachable!(),
            UserIDArg::ByEmail(userid) =>
                unreachable!(),
        };
    }
}

impl std::fmt::Display for UserIDArg<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> std::result::Result<(), std::fmt::Error>
    {
        write!(f, "{}", self.raw())
    }
}

/// An enum for user ID arguments.
#[derive(Debug, Clone)]
pub enum CertArg<'a> {
    Stdin(),
    File(PathBuf),
    Cert(KeyHandle),
    UserID(&'a str),
    Email(&'a str),
    Domain(&'a str),
    Grep(&'a str),
    Special(&'a str),
    Self_(),
}

impl From<PathBuf> for CertArg<'_> {
    fn from(path: PathBuf) -> Self {
        CertArg::File(path)
    }
}

impl<'a> From<&'a Path> for CertArg<'_> {
    fn from(path: &'a Path) -> Self {
        CertArg::File(path.to_path_buf())
    }
}

impl From<KeyHandle> for CertArg<'_> {
    fn from(kh: KeyHandle) -> Self {
        CertArg::Cert(kh)
    }
}

impl<'a> From<&'a KeyHandle> for CertArg<'_> {
    fn from(kh: &'a KeyHandle) -> Self {
        CertArg::Cert(kh.clone())
    }
}

impl From<Fingerprint> for CertArg<'_> {
    fn from(fpr: Fingerprint) -> Self {
        CertArg::Cert(fpr.into())
    }
}

impl<'a> From<&'a Fingerprint> for CertArg<'_> {
    fn from(fpr: &'a Fingerprint) -> Self {
        CertArg::Cert(fpr.into())
    }
}

impl<'a> From<&'a Cert> for CertArg<'_> {
    fn from(cert: &'a Cert) -> Self {
        CertArg::Cert(cert.key_handle())
    }
}

impl CertArg<'_> {
    /// Add the argument to a `Command`.
    pub fn as_arg<'a, P>(&self, cmd: &mut Command, prefix: P)
    where P: Into<Option<&'a str>>
    {
        cmd.args(self.raw(prefix));
    }

    pub fn raw<'a, P>(&self, prefix: P) -> Vec<String>
    where P: Into<Option<&'a str>>
    {
        let prefix = prefix.into();

        let s;
        let (suffix, value) = match self {
            CertArg::Stdin() => (Some("file"), Some("-")),
            CertArg::File(p) => {
                s = p.display().to_string();
                (Some("file"), Some(&s[..]))
            }
            CertArg::Cert(kh) => {
                s = kh.to_string();
                if prefix.is_none() {
                    (Some("cert"), Some(&s[..]))
                } else {
                    (None, Some(&s[..]))
                }
            }
            CertArg::UserID(userid) => (Some("userid"), Some(*userid)),
            CertArg::Email(email) => (Some("email"), Some(*email)),
            CertArg::Domain(domain) => (Some("domain"), Some(*domain)),
            CertArg::Grep(pattern) => (Some("grep"), Some(*pattern)),
            CertArg::Special(special) => (Some("special"), Some(*special)),
            CertArg::Self_() => (Some("self"), None),
        };

        let arg = match (prefix, suffix) {
            (Some(prefix), Some(suffix)) => {
                format!("--{}-{}", prefix, suffix)
            }
            (None, Some(suffix)) => {
                format!("--{}", suffix)
            }
            (Some(prefix), None) => {
                format!("--{}", prefix)
            }
            (None, None) => panic!("No prefix and no suffix specified"),
        };

        if let Some(value) = value {
            vec![ arg, value.to_string() ]
        } else {
            vec![ arg ]
        }
    }
}

impl std::fmt::Display for CertArg<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> std::result::Result<(), std::fmt::Error>
    {
        write!(f, "{}", self.raw(None).join(" "))
    }
}

// When calling a function like `Sq::key_generate` that has an `&[U]
// where U: Into<UserIDArg` parameter, we can't pass `&[]`, because
// rust can't infer a type for `U`.  Instead, we can use this.
pub const NO_USERIDS: &[UserIDArg] = &[];

pub struct Sq {
    base: TempDir,
    // Whether to preserve the directory on exit.  Normally we clean
    // it up, but preserving it can simplify debugging when a test
    // fails.
    preserve: bool,
    home: PathBuf,

    /// The working directory to invoke commands in.
    working_dir: PathBuf,

    policy: PathBuf,
    certd: PathBuf,
    now: std::time::SystemTime,
    scratch: AtomicUsize,
}

impl Drop for Sq {
    fn drop(&mut self) {
        if self.preserve {
            self.preserve = false;

            match TempDir::new() {
                Ok(tmp) => {
                    let base = std::mem::replace(&mut self.base, tmp);
                    let path = base.into_path();
                    eprintln!("Preserving state in {}", path.display());
                }
                Err(err) => {
                    eprintln!("Error preserving state in {}: {}",
                              self.base.path().display(), err);
                }
            }
        }
    }
}

impl Sq {
    /// Creates a new Sq context in a new, emphemeral home directory.
    /// The clock is set to the specified time.
    pub fn at_str(t: &str) -> Self {
        if let Ok(d) = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S") {
            return Self::at(Utc.from_utc_datetime(&d).into());
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d") {
            let pad_date_with = chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap();
            return Self::at(Utc.from_utc_datetime(&d.and_time(pad_date_with)).into());
        }
        panic!("Invalid timestamp, must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS");
    }

    /// Creates a new Sq context in a new, emphemeral home directory.
    /// The clock is set to the specified time.
    pub fn at(now: std::time::SystemTime) -> Self {
        let base = TempDir::new()
            .expect("can create a temporary directory");
        let home = base.path().join("home");

        let working_dir = base.path().join("working-dir");
        std::fs::create_dir_all(&working_dir).unwrap();

        // Create an empty policy configuration file.  We use this
        // instead of the system-wide policy configuration file, which
        // might be more strict than what our test vectors expect.
        let policy = base.path().join("empty-policy.toml");
        std::fs::write(&policy, "").unwrap();

        let certd = home.join("data").join("pgp.cert.d");

        Sq {
            base,
            preserve: false,
            home,
            working_dir,
            policy,
            certd,
            now,
            scratch: 0.into(),
        }
    }

    /// Creates a new Sq context in a new, emphemeral home directory.
    /// The clock is set to the current time.
    pub fn new() -> Self {
        // The current time.
        let mut now = std::time::SystemTime::now();
        let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
        now = now - std::time::Duration::new(0, since_epoch.subsec_nanos());

        Self::at(now)
    }

    /// Preserves the files on exit.
    ///
    /// Normally we clean delete all files and directories.  This
    /// suppresses that behavior.  Preserving the state can facilitate
    /// debugging.  Normally, you'll only enable this to debug a test,
    /// and then disable it again.
    pub fn preserve(&mut self) {
        self.preserve = true;
    }

    /// Returns the base directory.
    ///
    /// The sequoia home directory is under the `home` subdirectory.
    /// The rest can be used as scratch space.
    pub fn base(&self) -> &Path {
        self.base.path()
    }

    /// Returns the home directory.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Returns the working directory.
    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    /// Returns the path to the cert.d.
    pub fn certd(&self) -> &Path {
        &self.certd
    }

    /// Returns the path to the test data.
    pub fn test_data(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests").join("data")
    }

    /// Returns the scratch directory.
    pub fn scratch_dir(&self) -> PathBuf {
        let dir = self.home.join("scratch");
        std::fs::create_dir_all(&dir)
            .expect("can create scratch directory");
        dir
    }

    /// Returns a new scratch file.
    ///
    /// The file is guaranteed to not exist, but it isn't actually
    /// created.
    pub fn scratch_file<'a, S>(&self, name: S) -> PathBuf
        where S: Into<Option<&'a str>>
    {
        let name = name.into();

        let name_;
        let name = if let Some(name) = name {
            name_ = name.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>();
            &name_
        } else {
            name.unwrap_or("scratch-file")
        };

        let dir = self.scratch_dir();
        loop {
            let i = self.scratch.fetch_add(1, Ordering::Relaxed);
            let file = dir.join(format!("{}-{}", i, name));
            if ! file.exists() {
                return file;
            }
        }
    }

    /// Returns the current time.
    pub fn now(&self) -> std::time::SystemTime {
        self.now
    }

    /// Returns the current time formatted as an ISO 8106 string.
    pub fn now_as_string(&self) -> String {
        time_as_string(self.now.into())
    }

    /// Advances the clock by `sec` number of seconds.
    pub fn tick(&mut self, secs: u64)
    {
        self.now += std::time::Duration::new(secs, 0);
    }

    /// Rewinds the clock by `sec` number of seconds.
    pub fn rewind(&mut self, secs: u64)
    {
        self.now -= std::time::Duration::new(secs, 0);
    }

    /// Returns a command that is set to run `sq`.  The home directory
    /// and time are already set.
    pub fn command(&self) -> Command {
        self.command_args(&[])
    }

    /// Returns a command that is set to run `sq`.  The home directory
    /// and time are already set.  The arguments in `pre` are added at
    /// the beginning of the command line.
    pub fn command_args(&self, pre: &[&str]) -> Command {
        let mut cmd = Command::cargo_bin("sq")
            .expect("can run sq");
        cmd.current_dir(&self.working_dir);
        cmd.env("RUST_BACKTRACE", "1");
        cmd.env("RUST_LOG", "trace");
        cmd.env("SEQUOIA_CRYPTO_POLICY", &self.policy);
        for arg in pre {
            cmd.arg(arg);
        }
        cmd.arg("--batch");
        cmd.arg("--home").arg(self.home());
        cmd.arg("--time").arg(&self.now_as_string());

        cmd
    }

    /// Runs the command.  If `expect` is `Some`, asserts that the
    /// command succeeds or fails as per the boolean.
    pub fn run<E>(&self, mut cmd: Command, expect: E) -> Output
        where E: Into<Option<bool>>
    {
        eprintln!("Running: {}",
                  std::iter::once(cmd.get_program())
                  .chain(cmd.get_args())
                  .map(|arg| {
                      let arg = arg.to_string_lossy();
                      if arg.contains(" ") {
                          format!("{:?}", arg)
                      } else {
                          arg.into_owned()
                      }
                  })
                  .collect::<Vec<_>>()
                  .join(" "));

        let output = cmd.output().expect("can run command");
        let expect = expect.into();
        match (output.status.success(), expect) {
            (true, Some(true)) | (false, Some(false)) | (_, None) => {
                eprintln!("Exit status:");

                let dump = |id, stream| {
                    let limit = 4096;

                    let data = String::from_utf8_lossy(stream)
                        .chars()
                        .collect::<Vec<_>>();

                    if data.is_empty() {
                        eprintln!("{}: empty", id);
                    } else {
                        eprintln!("{}: {}{}",
                                  id,
                                  data.iter().take(limit).collect::<String>(),
                                  if data.len() > limit {
                                      format!("... {} more bytes",
                                              data.len() - limit)
                                  } else {
                                      "".to_string()
                                  });
                    }
                };

                dump("stdout", &output.stdout);
                dump("stderr", &output.stderr);
            }
            (got, expected) => {
                let expected = expect.unwrap();

                panic!(
                    "Running {:?}: {}, but should have {}:\n\
                     stdout: {}\n\
                     stderr: {}",
                    cmd,
                    if got { "succeeded" } else { "failed" },
                    if expected { "succeeded" } else { "failed" },
                    &String::from_utf8_lossy(&output.stdout),
                    &String::from_utf8_lossy(&output.stderr));
            }
        }
        output
    }

    // A helper function that handles a command's output when the
    // output is a certificate.
    //
    // If the command fails, returns an error.
    //
    // If `output_file` is `Some`, then reads the key or certificate
    // from stdin or the specified file, and returns it.  Otherwise,
    // exports the key or certificate, and returns it.
    //
    // `is_key` is whether the returned certificate is expected to
    // include secret key material.  If `is_key` is `None`, then it
    // may or may not (e.g., `sq key subkey delete`, which may delete
    // the last bit of secret key material, or not).
    fn handle_cert_output<'a, O, K>(&self, output: Output,
                                    cert: FileOrKeyHandle, output_file: O,
                                    is_key: K)
        -> Result<Cert>
    where
        O: Into<Option<&'a Path>>,
        K: Into<Option<bool>>
    {
        let output_file = output_file.into();
        let is_key = is_key.into();

        if output.status.success() {
            let cert = match (output_file, cert) {
                (Some(output_file), _) => {
                    // An output file was specified.
                    if output_file == &PathBuf::from("-") {
                        Cert::from_bytes(&output.stdout)
                            .with_context(|| {
                                format!("Importing result from stdout")
                            })
                            .expect("can parse certificate")
                    } else {
                        Cert::from_file(output_file)
                            .with_context(|| {
                                format!("Importing result from the file {}",
                                        output_file.display())
                            })
                            .expect("can parse certificate")
                    }
                }
                (None, FileOrKeyHandle::KeyHandle((kh, _s))) => {
                    // No output file was specified, input was read
                    // from the certificate store => the updated
                    // certificate is written to the certificate
                    // store.
                    match is_key {
                        None => {
                            // Try the key store, and then fallback to
                            // the cert store.
                            self.key_export_maybe(kh.clone())
                                .unwrap_or_else(|_| self.cert_export(kh))
                        }
                        Some(true) => self.key_export(kh),
                        Some(false) => self.cert_export(kh),
                    }
                }
                (None, FileOrKeyHandle::FileOrStdin(_path)) => {
                    // No output file was specified, input was read
                    // from a file => the certificate is written to
                    // stdout.
                    Cert::from_bytes(&output.stdout)
                        .with_context(|| {
                            format!("Importing result from stdout")
                        })
                        .expect("can parse certificate")
                }
            };

            if let Some(is_key) = is_key {
                assert_eq!(cert.is_tsk(), is_key);
            }

            Ok(cert)
        } else {
            Err(anyhow::anyhow!(format!(
                "Failed (expected):\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }


    /// Decrypts a message.
    pub fn decrypt<M>(&self, args: &[&str], msg: M) -> Vec<u8>
    where M: Into<FileOrBytes>,
    {
        self.decrypt_maybe(args, msg).expect("can decrypt")
    }

    /// Decrypts a message.
    pub fn decrypt_maybe<M>(&self, args: &[&str], msg: M) -> Result<Vec<u8>>
    where M: Into<FileOrBytes>,
    {
        let mut cmd = self.command();
        cmd.args([ "decrypt" ]);
        for arg in args {
            cmd.arg(arg);
        }

        match msg.into() {
            FileOrBytes::FileOrStdin(path) => {
                cmd.arg(path);
            }
            FileOrBytes::Bytes(bytes) => {
                cmd.write_stdin(bytes);
            }
        }

        let output = self.run(cmd, None);

        if output.status.success() {
            Ok(output.stdout.to_vec())
        } else {
            Err(anyhow::anyhow!("sq decrypt returned an error"))
        }
    }

    /// Encrypts a message.
    pub fn encrypt<A, M>(&self, args: &[A], msg: M) -> Vec<u8>
    where A: AsRef<str>,
          M: Into<FileOrBytes>,
    {
        self.encrypt_maybe(args, msg).expect("can encrypt")
    }

    /// Encrypts a message.
    pub fn encrypt_maybe<A, M>(&self, args: &[A], msg: M) -> Result<Vec<u8>>
    where A: AsRef<str>,
          M: Into<FileOrBytes>,
    {
        let mut cmd = self.command();
        cmd.args([ "encrypt" ]);
        for arg in args {
            cmd.arg(arg.as_ref());
        }

        if ! args.iter().any(|a| a.as_ref().starts_with("--signer")) {
            cmd.arg("--without-signature");
        }

        match msg.into() {
            FileOrBytes::FileOrStdin(path) => {
                cmd.arg(path);
            }
            FileOrBytes::Bytes(bytes) => {
                cmd.write_stdin(bytes);
            }
        }

        let output = self.run(cmd, None);

        if output.status.success() {
            Ok(output.stdout.to_vec())
        } else {
            Err(anyhow::anyhow!("sq encrypt returned an error"))
        }
    }

    /// Generates a new key.
    ///
    /// The certificate is not imported into the cert store or key
    /// store, but saved in a file.
    ///
    /// Returns the certificate, the certificate's filename, and the
    /// revocation certificate's filename.
    pub fn key_generate<'a, U>(&self,
                               extra_args: &[&str],
                               userids: &[U])
        -> (Cert, PathBuf, PathBuf)
    where U: Into<UserIDArg<'a>> + Clone
    {
        let userids: Vec<UserIDArg> = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect();

        let mut cmd = self.command();
        cmd.args([ "key", "generate", "--own-key" ]);

        if ! extra_args.contains(&"--new-password-file") {
            cmd.arg("--without-password");
        }

        for arg in extra_args {
            cmd.arg(arg);
        }

        let any_userids = ! userids.is_empty()
            || extra_args.iter().any(|a| a.starts_with("--name")
                                     || a.starts_with("--email")
                                     || a.starts_with("--userid"));
        if ! any_userids {
            cmd.arg("--no-userids");
        } else {
            for userid in userids.iter() {
                userid.as_arg(&mut cmd);
            }
        }

        let cert_filename = self.scratch_file(
            userids.get(0).map(|u| format!("{}-cert", u.raw())).as_deref());
        cmd.arg("--output").arg(&cert_filename);

        let rev_filename = self.scratch_file(
            userids.get(0).map(|u| format!("{}-rev", u.raw())).as_deref());
        cmd.arg("--rev-cert").arg(&rev_filename);

        let output = self.run(cmd, Some(true));

        let cert = Cert::from_file(&cert_filename)
            .expect("can parse certificate");
        assert!(cert.is_tsk());

        (cert, cert_filename, rev_filename)
    }

    /// Run `sq key rotate`.
    ///
    /// If `output_file` is not `None`, then it is parsed and
    /// returned.  Otherwise, an empty vector is returned.
    pub fn try_key_rotate<'a, O>(&self, extra_args: &[&str],
                                 cert: CertArg,
                                 output_file: O)
        -> Result<Vec<Cert>>
    where O: Into<Option<&'a Path>>,
    {
        let mut cmd = self.command();
        cmd.args([ "key", "rotate" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        if ! extra_args.contains(&"--new-password-file") {
            cmd.arg("--without-password");
        }
        if let Some(cert) = cert.into() {
            cert.as_arg(&mut cmd, "cert");
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            if let Some(output_file) = output_file.into() {
                let parser = if PathBuf::from("-").as_path() == output_file {
                    CertParser::from_bytes(&output.stdout)
                        .expect("can parse certificate")
                } else {
                    CertParser::from_file(&output_file)
                        .expect("can parse certificate")
                };
                parser.collect::<Result<Vec<_>>>()
            } else {
                // We don't try to figure out what was certificated,
                // but just return an empty vector.
                Ok(Vec::new())
            }
        } else {
            Err(anyhow::anyhow!(
                "Failed: {}",
                String::from_utf8_lossy(&output.stderr).to_string()))
        }
    }

    /// Run `sq key rotate`.
    ///
    /// If `output_file` is not `None`, then it is parsed and
    /// returned.  Otherwise, an empty vector is returned.
    pub fn key_rotate<'a, O>(&self, extra_args: &[&str],
                             cert: CertArg,
                             output_file: O)
        -> Vec<Cert>
    where O: Into<Option<&'a Path>>,
    {
        self.try_key_rotate(extra_args, cert, output_file)
            .expect("success")
    }

    /// Run `sq inspect` and return stdout.
    pub fn inspect<H>(&self, handle: H) -> String
    where H: Into<FileOrKeyHandle>
    {
        let mut cmd = self.command();
        cmd.arg("inspect");
        match handle.into() {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
            }
        };

        let output = self.run(cmd, Some(true));
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    /// Delete the specified key.
    pub fn try_key_delete<'a, H, Q>(&self,
                                    cert_handle: H,
                                    output_file: Q)
        -> Result<Cert>
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("delete");

        match &cert_handle {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--cert-file").arg(path);
                if let Some(output_file) = output_file {
                    cmd.arg("--output").arg(output_file);
                } else {
                    cmd.arg("--output").arg("-");
                }
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
                if let Some(output_file) = output_file {
                    cmd.arg("--output").arg(output_file);
                }
            }
        };

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert_handle, output_file, None)
    }

    /// Delete the specified key.
    pub fn key_delete<'a, H, Q>(&self,
                                cert_handle: H,
                                output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        self.try_key_delete(cert_handle, output_file)
            .expect("success")
    }

    /// Run `sq key revoked` and return the revocation certificate.
    pub fn key_revoke<'a, H, I, Q>(&self,
                                cert_handle: H,
                                revoker_handle: I,
                                reason: &str,
                                message: &str,
                                revocation_time: Option<DateTime<Utc>>,
                                notations: &[(&str, &str)],
                                output_file: Q)
        -> Cert
        where H: Into<FileOrKeyHandle>,
              I: Into<Option<FileOrKeyHandle>>,
              Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let revoker_handle = revoker_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("revoke")
            .arg("--reason").arg(reason)
            .arg("--message").arg(message);

        match &cert_handle {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--cert-file").arg(path);
                assert!(output_file.is_some());
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
            }
        };
        match revoker_handle.as_ref() {
            Some(FileOrKeyHandle::FileOrStdin(path)) => {
                cmd.arg("--revoker-file").arg(path);
            }
            Some(FileOrKeyHandle::KeyHandle((_kh, s))) => {
                cmd.arg("--revoker").arg(&s);
            }
            None => (),
        };

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        for (k, v) in notations {
            cmd.args(["--signature-notation", k, v]);
        }

        if let Some(time) = revocation_time {
            cmd.args([
                "--time",
                &time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ]);
        }

        let output = self.run(cmd, Some(true));
        assert!(output.status.success());
        self.handle_cert_output(output, cert_handle, output_file, false)
            .expect("can parse certificate")
    }

    /// Imports the specified key into the keystore.
    pub fn key_import<P>(&self, path: P)
    where P: AsRef<Path>
    {
        let mut cmd = self.command();
        cmd.arg("key").arg("import").arg(path.as_ref());
        self.run(cmd, Some(true));
    }

    /// Runs `sq key list` with the supplied arguments.
    pub fn try_key_list(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = self.command();
        cmd.arg("key").arg("list");
        for arg in args {
            cmd.arg(arg);
        }
        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(anyhow::anyhow!("sq cert list returned an error"))
        }
    }

    /// Runs `sq key list` with the supplied arguments.
    pub fn key_list(&self, args: &[&str]) -> Vec<u8> {
        self.try_key_list(args).expect("success")
    }

    /// Exports the specified key.
    pub fn key_export(&self, kh: KeyHandle) -> Cert {
        self.key_export_maybe(kh)
            .expect("can export key")
    }

    /// Exports the specified key from the key store.
    ///
    /// Returns an error if `sq key export` fails.  This happens if
    /// the certificate is known, but the key store doesn't manage any
    /// of its secret key material.
    pub fn key_export_maybe(&self, kh: KeyHandle) -> Result<Cert> {
        let mut cmd = self.command();
        cmd.args([ "key", "export", "--cert", &kh.to_string() ]);
        let output = self.run(cmd, None);

        if output.status.success() {
            Ok(Cert::from_bytes(&output.stdout).expect("can parse certificate"))
        } else {
            Err(anyhow::anyhow!("sq key export returned an error"))
        }
    }

    /// Change the key's password.
    pub fn try_key_password<'a, H, Q>(&self,
                                      cert_handle: H,
                                      old_password_file: Option<&'a Path>,
                                      new_password_file: Option<&'a Path>,
                                      output_file: Q)
        -> Result<Cert>
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("password");

        if cert_handle.is_file() {
            cmd.arg("--cert-file").arg(&cert_handle);
            if output_file.is_none() {
                cmd.arg("--output").arg("-");
            }
        } else {
            cmd.arg("--cert").arg(&cert_handle);
        };

        if let Some(p) = old_password_file {
            cmd.arg("--password-file").arg(p);
        }

        if let Some(p) = new_password_file {
            cmd.arg("--new-password-file").arg(p);
        } else {
            cmd.arg("--clear-password");
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert_handle, output_file, true)
    }

    /// Change the key's password.
    pub fn key_password<'a, H, Q>(&self,
                                  cert_handle: H,
                                  old_password_file: Option<&'a Path>,
                                  new_password_file: Option<&'a Path>,
                                  output_file: Q)
        -> Cert
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        self.try_key_password(
            cert_handle, old_password_file, new_password_file, output_file)
            .expect("success")
    }

    /// Calls `sq key bind`.
    ///
    /// `keyrings` are a list of files to pass to `--keyring`.  They
    /// usually contain the key to bind.
    ///
    /// `target` is the certificate that will bind the key.
    ///
    /// `keys` is the set of keys to bind.
    ///
    /// The resulting certificate is NOT imported into the key store
    /// or the cert store.
    pub fn key_subkey_bind_maybe<P, T, K, Q>(&self,
                                             extra_args: &[&str],
                                             keyrings: Vec<P>,
                                             target: T,
                                             keys: Vec<K>,
                                             output_file: Q)
        -> Result<Cert>
    where
        P: AsRef<Path>,
        T: Into<FileOrKeyHandle>,
        K: Into<KeyHandle>,
        Q: AsRef<Path>,
    {
        let target = target.into();
        let output_file = output_file.as_ref();

        let mut cmd = self.command();
        cmd.arg("key").arg("subkey").arg("bind");

        for arg in extra_args {
            cmd.arg(arg);
        }

        for k in keyrings.into_iter() {
            cmd.arg("--keyring").arg(k.as_ref());
        }

        if target.is_file() {
            cmd.arg("--cert-file").arg(&target);
        } else {
            cmd.arg("--cert").arg(&target);
        };

        assert!(! keys.is_empty());
        for k in keys.into_iter() {
            let k: KeyHandle = k.into();
            cmd.arg("--key").arg(k.to_string());
        }

        cmd.arg("--output").arg(&output_file);

        let output = self.run(cmd, None);
        self.handle_cert_output(output, target, output_file, None)
    }

    /// Calls `sq key bind`.
    ///
    /// `keyrings` are a list of files to pass to `--keyring`.  They
    /// usually contain the key to bind.
    ///
    /// `target` is the certificate that will bind the key.
    ///
    /// `keys` is the set of keys to bind.
    ///
    /// The resulting certificate is NOT imported into the key store
    /// or the cert store.
    ///
    /// This version panics if `sq key bind` fails.
    pub fn key_subkey_bind<P, T, K, Q>(&self,
                                       extra_args: &[&str],
                                       keyrings: Vec<P>,
                                       target: T,
                                       keys: Vec<K>,
                                       output_file: Q)
        -> Cert
    where
        P: AsRef<Path>,
        T: Into<FileOrKeyHandle>,
        K: Into<KeyHandle>,
        Q: AsRef<Path>,
    {
        self.key_subkey_bind_maybe(
            extra_args, keyrings, target, keys, output_file)
            .expect("sq key subkey bind succeeds")
    }

    pub fn try_key_approvals_list<'a, H, U>(&self,
                                            args: &[&str],
                                            cert: H,
                                            userids: &[U])
        -> Result<Vec<u8>>
    where H: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
    {
        let cert = cert.into();
        let userids: Vec<UserIDArg> = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect();

        let mut cmd = self.command();
        cmd.arg("key").arg("approvals").arg("list");

        cmd.args(args);

        match &cert {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--cert-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(s);
            }
        }

        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(anyhow::anyhow!("sq key approvals list returned an error"))
        }
    }

    pub fn key_approvals_list<'a, H, U>(&self,
                                        args: &[&str],
                                        cert: H,
                                        userids: &[U])
        -> Vec<u8>
    where H: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
    {
        self.try_key_approvals_list(args, cert, userids)
            .expect("success")
    }

    pub fn try_key_approvals_update<'a, H, U, Q>(&self,
                                                 args: &[&str],
                                                 cert: H,
                                                 userids: &[U],
                                                 output_file: Q)
        -> Result<Cert>
    where H: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
          Q: Into<Option<&'a Path>>,
    {
        let cert = cert.into();
        let userids: Vec<UserIDArg> = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("approvals").arg("update");

        cmd.args(args);

        match &cert {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--cert-file").arg(file);
                assert!(output_file.is_some());
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(s);
            }
        }

        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert, output_file, None)
    }

    pub fn key_approvals_update<'a, H, U, Q>(&self,
                                             args: &[&str],
                                             cert: H,
                                             userids: &[U],
                                             output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
          Q: Into<Option<&'a Path>>,
    {
        self.try_key_approvals_update(args, cert, userids, output_file)
            .expect("success")
    }

    /// Change the certificate's expiration.
    pub fn key_expire<'a, H, Q>(&self,
                                cert_handle: H,
                                expire: &str,
                                password_file: Option<&'a Path>,
                                output_file: Q,
                                success: bool)
        -> Result<Cert>
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("expire")
            .arg("--expiration").arg(expire);

        if cert_handle.is_file() {
            cmd.arg("--cert-file").arg(&cert_handle);
            assert!(output_file.is_some());
        } else {
            cmd.arg("--cert").arg(&cert_handle);
        };

        if let Some(p) = password_file {
            cmd.arg("--password-file").arg(p);
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(success));
        self.handle_cert_output(output, cert_handle, output_file, None)
    }

    /// Exports the specified keys.
    pub fn key_subkey_export<H1, H2>(&self, cert: H1, khs: Vec<H2>)
        -> Cert
    where H1: Into<KeyHandle>,
          H2: Into<KeyHandle>
    {
        self.key_subkey_export_maybe(cert, khs)
            .expect("can export key")
    }

    /// Exports the specified keys from the key store.
    ///
    /// Returns an error if `sq key subkey export` fails.  This
    /// happens if the key is known, but the key store doesn't manage
    /// any of its secret key material.
    pub fn key_subkey_export_maybe<H1, H2>(&self, cert: H1, khs: Vec<H2>)
        -> Result<Cert>
    where H1: Into<KeyHandle>,
          H2: Into<KeyHandle>,
    {
        let cert = cert.into();

        let mut cmd = self.command();
        cmd.args([ "key", "subkey", "export" ]);
        cmd.arg("--cert").arg(cert.to_string());
        for kh in khs.into_iter() {
            let kh: KeyHandle = kh.into();
            cmd.arg("--key").arg(kh.to_string());
        }
        let output = self.run(cmd, None);
        self.handle_cert_output(
            output, cert.into(), Some(PathBuf::from("-").as_path()), true)
    }

    /// Run `sq key subkey revoke` and return the revocation certificate.
    pub fn key_subkey_revoke<'a, H, I, Q>(&self,
                                          cert_handle: H,
                                          key_handles: &[KeyHandle],
                                          revoker_handle: I,
                                          reason: &str,
                                          message: &str,
                                          revocation_time: Option<DateTime<Utc>>,
                                          notations: &[(&str, &str)],
                                          output_file: Q)
        -> Cert
        where H: Into<FileOrKeyHandle>,
              I: Into<Option<FileOrKeyHandle>>,
              Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let revoker_handle = revoker_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("subkey").arg("revoke")
            .arg("--reason").arg(reason)
            .arg("--message").arg(message);

        for key in key_handles {
            cmd.arg("--key").arg(key.to_string());
        }

        match &cert_handle {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--cert-file").arg(path);
                assert!(output_file.is_some());
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
            }
        };
        match revoker_handle.as_ref() {
            Some(FileOrKeyHandle::FileOrStdin(path)) => {
                cmd.arg("--revoker-file").arg(path);
            }
            Some(FileOrKeyHandle::KeyHandle((_kh, s))) => {
                cmd.arg("--revoker").arg(&s);
            }
            None => (),
        };

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        for (k, v) in notations {
            cmd.args(["--signature-notation", k, v]);
        }

        if let Some(time) = revocation_time {
            cmd.args([
                "--time",
                &time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ]);
        }

        let output = self.run(cmd, Some(true));
        self.handle_cert_output(output, cert_handle, output_file, false)
            .expect("can parse certificate")
    }

    /// Delete the specified keys.
    pub fn try_key_subkey_delete<'a, H, Q>(&self,
                                           cert_handle: H,
                                           key_handles: &[KeyHandle],
                                           output_file: Q)
        -> Result<Cert>
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("subkey").arg("delete");

        match &cert_handle {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--cert-file").arg(path);
                if let Some(output_file) = output_file {
                    cmd.arg("--output").arg(output_file);
                } else {
                    cmd.arg("--output").arg("-");
                }
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(&s);
                if let Some(output_file) = output_file {
                    cmd.arg("--output").arg(output_file);
                }
            }
        };

        for kh in key_handles {
            cmd.arg("--key").arg(kh.to_string());
        }

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert_handle, output_file, None)
    }

    /// Delete the specified keys.
    pub fn key_subkey_delete<'a, H, Q>(&self,
                                       cert_handle: H,
                                       key_handles: &[KeyHandle],
                                       output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        self.try_key_subkey_delete(cert_handle, key_handles, output_file)
            .expect("success")
    }

    /// Change the key's password.
    pub fn try_key_subkey_password<'a, H, Q>(
        &self,
        cert_handle: H,
        keys: &[KeyHandle],
        old_password_file: Option<&'a Path>,
        new_password_file: Option<&'a Path>,
        output_file: Q)
        -> Result<Cert>
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("subkey").arg("password");

        if cert_handle.is_file() {
            cmd.arg("--cert-file").arg(&cert_handle);
            if let Some(output_file) = output_file {
                cmd.arg("--output").arg(output_file);
            } else {
                cmd.arg("--output").arg("-");
            }
        } else {
            cmd.arg("--cert").arg(&cert_handle);
            if let Some(output_file) = output_file {
                cmd.arg("--output").arg(output_file);
            }
        };

        for key in keys.iter() {
            cmd.arg("--key").arg(key.to_string());
        }

        if let Some(p) = old_password_file {
            cmd.arg("--password-file").arg(p);
        }

        if let Some(p) = new_password_file {
            cmd.arg("--new-password-file").arg(p);
        } else {
            cmd.arg("--clear-password");
        }

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert_handle, output_file, None)
    }

    /// Change the key's password.
    pub fn key_subkey_password<'a, H, Q>(&self,
                                         cert_handle: H,
                                         keys: &[KeyHandle],
                                         old_password_file: Option<&'a Path>,
                                         new_password_file: Option<&'a Path>,
                                         output_file: Q)
                                         -> Cert
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        self.try_key_subkey_password(
            cert_handle, keys,
            old_password_file, new_password_file,
            output_file)
            .expect("success")
    }

    /// Change the key's expiration.
    pub fn key_subkey_expire<'a, H, Q>(&self,
                                       cert_handle: H,
                                       keys: &[KeyHandle],
                                       expire: &str,
                                       password_file: Option<&'a Path>,
                                       output_file: Q,
                                       success: bool)
        -> Result<Cert>
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        let cert_handle = cert_handle.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("key").arg("subkey").arg("expire")
            .arg("--expiration").arg(expire);

        if cert_handle.is_file() {
            cmd.arg("--cert-file").arg(&cert_handle);
            assert!(output_file.is_some());
        } else {
            cmd.arg("--cert").arg(&cert_handle);
        };

        for key in keys.iter() {
            cmd.arg("--key").arg(key.to_string());
        }

        if let Some(p) = password_file {
            cmd.arg("--password-file").arg(p);
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, Some(success));
        self.handle_cert_output(output, cert_handle, output_file, None)
    }

    /// Adds user IDs to the given key.
    pub fn key_userid_add<'a, U>(&self, args: &[&str],
                                 key: Cert, userids: &[U])
        -> Result<Cert>
        where U: Into<UserIDArg<'a>> + Clone
    {
        let userids = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect::<Vec<_>>();

        let mut cmd = self.command();
        cmd.args(["key", "userid", "add"]);
        for arg in args {
            cmd.arg(arg);
        }

        let in_filename = self.scratch_file(None);
        key.as_tsk().serialize(&mut File::create(&in_filename)?)?;
        cmd.arg("--cert-file").arg(&in_filename);

        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        let out_filename = self.scratch_file(None);
        cmd.arg("--output").arg(&out_filename);

        let output = self.run(cmd, Some(true));

        let out_key = Cert::from_file(&out_filename)?;
        assert!(out_key.is_tsk());
        Ok(out_key)
    }

    /// Revokes a user ID.
    pub fn key_userid_revoke_maybe<'a, 'b, C, O, U>(&self, args: &[&str],
                                                    cert: C, userid: U,
                                                    reason: &str,
                                                    message: &str,
                                                    output_file: O)
        -> Result<Cert>
    where C: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>>,
          O: Into<Option<&'b Path>>,
    {
        let cert = cert.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([
            "key", "userid", "revoke",
            "--reason", reason,
            "--message", message,
        ]);
        for arg in args {
            cmd.arg(arg);
        }

        match &cert {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--cert-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(s);
            }
        }
        userid.into().as_arg(&mut cmd);

        if let Some(output_file) = output_file {
            cmd.arg("--overwrite").arg("--output").arg(output_file);
        }

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert, output_file, false)
    }

    pub fn key_userid_revoke<'a, 'b, C, O, U>(&self, args: &[&str],
                                              cert: C, userid: U,
                                              reason: &str,
                                              message: &str,
                                              output_file: O)
        -> Cert
    where C: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>>,
          O: Into<Option<&'b Path>>,
    {
        self.key_userid_revoke_maybe(args, cert, userid, reason, message, output_file)
            .expect("succeeds")
    }

    /// Runs `sq cert list` with the supplied arguments.
    pub fn cert_list_maybe(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = self.command();
        cmd.arg("cert").arg("list");
        for arg in args {
            cmd.arg(arg);
        }
        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(anyhow::anyhow!("sq cert list returned an error"))
        }
    }

    /// Runs `sq cert list` with the supplied arguments.
    pub fn cert_list(&self, args: &[&str]) -> Vec<u8> {
        self.cert_list_maybe(args).expect("success")
    }

    /// Imports the specified certificate into the keystore.
    pub fn cert_import_maybe<P>(&self, path: P) -> Result<()>
    where P: AsRef<Path>
    {
        let mut cmd = self.command();
        cmd.arg("cert").arg("import").arg(path.as_ref());
        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("sq cert import returned an error"))
        }
    }

    /// Imports the specified certificate into the keystore.
    pub fn cert_import<P>(&self, path: P)
    where P: AsRef<Path>
    {
        self.cert_import_maybe(path)
            .expect("succeeds")
    }

    /// Exports the specified certificate.
    pub fn cert_export<H>(&self, kh: H) -> Cert
    where
        H: Borrow<KeyHandle>,
    {
        let mut cmd = self.command();
        cmd.args([ "cert", "export", "--cert", &kh.borrow().to_string() ]);
        let output = self.run(cmd, Some(true));

        Cert::from_bytes(&output.stdout)
            .expect("can parse certificate")
    }

    pub fn cert_export_all(&self) -> Vec<Cert>
    {
        let mut cmd = self.command();
        cmd.args([ "cert", "export", "--all" ]);
        let output = self.run(cmd, Some(true));

        CertParser::from_bytes(&output.stdout)
            .expect("can parse certificate")
            .collect::<Result<Vec<Cert>>>()
            .expect("can export")
    }

    /// Try to certify the user ID binding.
    ///
    /// If `output_file` is `Some`, then the output is written to that
    /// file.  Otherwise, the default behavior is followed.
    pub fn try_pki_vouch_add<'a, 'b, H, C, U, Q>(
        &self, extra_args: &[&str],
        certifier: H,
        cert: C, userids: &[U],
        output_file: Q)
        -> Result<Cert>
    where H: Into<FileOrKeyHandle>,
          C: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
          Q: Into<Option<&'b Path>>,
    {
        let certifier = certifier.into();
        let cert = cert.into();
        let userids = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect::<Vec<_>>();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([ "pki", "vouch", "add" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        match &certifier {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--certifier-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--certifier").arg(s);
            }
        }
        match &cert {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--cert-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(s);
            }
        }
        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        if let Some(output_file) = output_file {
            cmd.arg("--overwrite").arg("--output").arg(output_file);
        }

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert, output_file, false)
    }

    /// Certify the user ID binding.
    pub fn pki_vouch_add<'a, 'b, H, C, U, Q>(
        &self, extra_args: &[&str],
        certifier: H,
        cert: C, userids: &[U],
        output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          C: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
          Q: Into<Option<&'b Path>>,
    {
        self.try_pki_vouch_add(
            extra_args, certifier, cert, userids, output_file)
            .expect("success")
    }

    /// Try to make an authorization.
    ///
    /// If `output_file` is `Some`, then the output is written to that
    /// file.  Otherwise, the default behavior is followed.
    pub fn try_pki_vouch_authorize<'a, 'b, H, C, U, Q>(
        &self, extra_args: &[&str],
        certifier: H,
        cert: C, userids: &[U],
        output_file: Q)
        -> Result<Cert>
    where H: Into<FileOrKeyHandle>,
          C: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
          Q: Into<Option<&'b Path>>,
    {
        let certifier = certifier.into();
        let cert = cert.into();
        let userids = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect::<Vec<_>>();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([ "pki", "vouch", "authorize" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        match &certifier {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--certifier-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--certifier").arg(s);
            }
        }
        match &cert {
            FileOrKeyHandle::FileOrStdin(file) => {
                cmd.arg("--cert-file").arg(file);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--cert").arg(s);
            }
        }
        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        if let Some(output_file) = output_file {
            cmd.arg("--overwrite").arg("--output").arg(output_file);
        }

        let output = self.run(cmd, None);
        self.handle_cert_output(output, cert, output_file, false)
    }

    /// Authorize a certificate.
    pub fn pki_vouch_authorize<'a, 'b, H, C, U, Q>(
        &self, extra_args: &[&str],
        certifier: H,
        cert: C, userids: &[U],
        output_file: Q)
        -> Cert
    where H: Into<FileOrKeyHandle>,
          C: Into<FileOrKeyHandle>,
          U: Into<UserIDArg<'a>> + Clone,
          Q: Into<Option<&'b Path>>,
    {
        self.try_pki_vouch_authorize(
            extra_args, certifier, cert, userids, output_file)
            .expect("success")
    }

    /// List certifications made by certifier.
    pub fn try_pki_vouch_list<'a, C1, C2>(&self, extra_args: &[&str],
                                          certifier: C1, cert: C2)
        -> Result<String>
    where C1: Into<Option<CertArg<'a>>>,
          C2: Into<Option<CertArg<'a>>>
    {
        let mut cmd = self.command();
        cmd.args([ "pki", "vouch", "list" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        if let Some(certifier) = certifier.into() {
            certifier.as_arg(&mut cmd, "certifier");
        }
        if let Some(cert) = cert.into() {
            cert.as_arg(&mut cmd, "cert");
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(anyhow::anyhow!(
                "Failed: {}",
                String::from_utf8_lossy(&output.stderr).to_string()))
        }
    }

    /// List certifications made by certifier.
    pub fn pki_vouch_list<'a, C1, C2>(&self, extra_args: &[&str],
                                      certifier: C1, cert: C2)
        -> String
    where C1: Into<Option<CertArg<'a>>>,
          C2: Into<Option<CertArg<'a>>>
    {
        self.try_pki_vouch_list(extra_args, certifier, cert)
            .expect("success")
    }

    /// Replays active certifications made by `source` using `target`.
    ///
    /// If `output_file` is not `None`, then the output is parsed and
    /// returned.  If `output_file` is `None`, then an empty vector is
    /// returned.
    pub fn try_pki_vouch_replay<'a, O>(&self, extra_args: &[&str],
                                       source: CertArg,
                                       target: CertArg,
                                       output_file: O)
        -> Result<Vec<Cert>>
    where O: Into<Option<&'a Path>>,
    {
        let mut cmd = self.command();
        cmd.args([ "pki", "vouch", "replay" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        if let Some(source) = source.into() {
            source.as_arg(&mut cmd, "source");
        }
        if let Some(target) = target.into() {
            target.as_arg(&mut cmd, "target");
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            if let Some(output_file) = output_file.into() {
                let parser = if PathBuf::from("-").as_path() == output_file {
                    CertParser::from_bytes(&output.stdout)
                        .expect("can parse certificate")
                } else {
                    CertParser::from_file(&output_file)
                        .expect("can parse certificate")
                };
                parser.collect::<Result<Vec<_>>>()
            } else {
                // We don't try to figure out what was certificated,
                // but just return an empty vector.
                Ok(Vec::new())
            }
        } else {
            Err(anyhow::anyhow!(
                "Failed: {}",
                String::from_utf8_lossy(&output.stderr).to_string()))
        }
    }

    /// Replays active certifications made by `source` using `target`.
    ///
    /// If `output_file` is not `None`, then the output is parsed and
    /// returned.  If `output_file` is `None`, then an empty vector is
    /// returned.
    pub fn pki_vouch_replay<'a, O>(&self, extra_args: &[&str],
                                   source: CertArg,
                                   target: CertArg,
                                   output_file: O)
        -> Vec<Cert>
    where O: Into<Option<&'a Path>>,
    {
        self.try_pki_vouch_replay(extra_args, source, target, output_file)
            .expect("success")
    }

    /// Add a link for the binding.
    pub fn pki_link_add_maybe<'a, U>(&self, extra_args: &[&str],
                                     cert: KeyHandle, userids: &[U])
        -> Result<()>
        where U: Into<UserIDArg<'a>> + Clone,
    {
        let userids = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect::<Vec<_>>();

        let mut cmd = self.command();
        cmd.args([ "pki", "link", "add" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        cmd.arg("--cert").arg(cert.to_string());
        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!(
                "Command failed:\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Add a link for the binding.
    pub fn pki_link_add<'a, U>(&self, args: &[&str],
                               cert: KeyHandle, userids: &[U])
        where U: Into<UserIDArg<'a>> + Clone,
    {
        self.pki_link_add_maybe(args, cert, userids).expect("success")
    }

    /// Add a link for the binding.
    pub fn pki_link_retract_maybe<'a, U>(&self, extra_args: &[&str],
                                         cert: KeyHandle,
                                         userids: &[U])
        -> Result<()>
        where U: Into<UserIDArg<'a>> + Clone,
    {
        let userids = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect::<Vec<_>>();

        let mut cmd = self.command();
        cmd.args([ "pki", "link", "retract" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        cmd.arg("--cert").arg(cert.to_string());
        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!(
                "Command failed:\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Add a link for the binding.
    pub fn pki_link_retract<'a, U>(&self, args: &[&str],
                                   cert: KeyHandle, userids: &[U])
        where U: Into<UserIDArg<'a>> + Clone,
    {
        self.pki_link_retract_maybe(args, cert, userids)
            .expect("success")
    }

    /// Add a link for the binding.
    pub fn pki_link_authorize_maybe<'a, U>(&self, extra_args: &[&str],
                                           cert: KeyHandle,
                                           userids: &[U])
        -> Result<()>
        where U: Into<UserIDArg<'a>> + Clone,
    {
        let userids = userids.iter()
            .cloned()
            .map(|u| u.into())
            .collect::<Vec<_>>();

        let mut cmd = self.command();
        cmd.args([ "pki", "link", "authorize" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        cmd.arg("--cert").arg(cert.to_string());
        for userid in userids.iter() {
            userid.as_arg(&mut cmd);
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!(
                "Command failed:\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Add a link for the binding.
    pub fn pki_link_authorize<'a, U>(&self, args: &[&str],
                                     cert: KeyHandle, userids: &[U])
        where U: Into<UserIDArg<'a>> + Clone,
    {
        self.pki_link_authorize_maybe(args, cert, userids)
            .expect("success")
    }

    /// Runs `sq pki link list` with the supplied arguments.
    pub fn try_pki_link_list(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut cmd = self.command();
        cmd.arg("pki").arg("link").arg("list");
        for arg in args {
            cmd.arg(arg);
        }
        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(anyhow::anyhow!("sq cert list returned an error"))
        }
    }

    /// Runs `sq pki link list` with the supplied arguments.
    pub fn pki_link_list(&self, args: &[&str]) -> Vec<u8> {
        self.try_pki_link_list(args).expect("success")
    }

    /// Authenticate a binding.
    pub fn pki_authenticate<'a, U>(&self, extra_args: &[&str],
                                   cert: &str, userid: U)
        -> Result<()>
        where U: Into<UserIDArg<'a>>,
    {
        let mut cmd = self.command();
        cmd.args([ "pki", "authenticate", "--show-paths" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        cmd.arg("--cert").arg(cert);
        userid.into().as_arg(&mut cmd);

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!(
                "Command failed:\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    /// Lookup a binding.
    pub fn pki_lookup<'a, U>(&self, extra_args: &[&str],
                             userid: U)
        -> Result<()>
        where U: Into<UserIDArg<'a>>,
    {
        let mut cmd = self.command();
        cmd.args([ "pki", "lookup", "--show-paths" ]);
        for arg in extra_args {
            cmd.arg(arg);
        }
        userid.into().as_arg(&mut cmd);

        let output = self.run(cmd, None);
        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(format!(
                "Command failed:\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    pub fn sign<'a, H, Q>(&self,
                          signer: H,
                          password_file: Option<&Path>,
                          input_file: &Path,
                          output_file: Q)
        -> Vec<u8>
    where H: Into<FileOrKeyHandle>,
          Q: Into<Option<&'a Path>>,
    {
        self.sign_args(&[], signer, password_file, input_file, output_file)
    }

    pub fn sign_args<'a, H, Q>(&self,
                               args: &[&str],
                               signer: H,
                               password_file: Option<&Path>,
                               input_file: &Path,
                               output_file: Q)
                               -> Vec<u8>
    where
        H: Into<FileOrKeyHandle>,
        Q: Into<Option<&'a Path>>,
    {
        let signer = signer.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.arg("sign").arg("--message");
        cmd.args(args);

        match &signer {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--signer-file").arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--signer").arg(&s);
            }
        };

        if let Some(password_file) = password_file {
            cmd.arg("--password-file").arg(password_file);
        }

        cmd.arg(input_file);

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        };

        let output = self.run(cmd, Some(true));
        assert!(output.status.success());

        if let Some(output_file) = output_file {
            std::fs::read(output_file).expect("can read file")
        } else {
            output.stdout
        }
    }

    pub fn sign_detached<'a, H, O>(&self,
                                   args: &[&str],
                                   signer: H,
                                   input_file: &Path,
                                   output_file: O)
        -> Vec<u8>
    where H: Into<FileOrKeyHandle>,
          O: Into<Option<&'a Path>>,
    {
        self.try_sign_detached(args, signer, input_file, output_file)
            .unwrap()
    }

    pub fn try_sign_detached<'a, H, O>(&self,
                                       args: &[&str],
                                       signer: H,
                                       input_file: &Path,
                                       output_file: O)
                                       -> Result<Vec<u8>>
    where
        H: Into<FileOrKeyHandle>,
        O: Into<Option<&'a Path>>,
    {
        let signer = signer.into();
        let output_file = output_file.into();

        let mut cmd = self.command();
        let stdout: PathBuf = "-".into();
        cmd.arg("sign")
            .arg("--signature-file").arg(output_file.unwrap_or(&stdout));

        for arg in args {
            cmd.arg(arg);
        }

        match &signer {
            FileOrKeyHandle::FileOrStdin(path) => {
                cmd.arg("--signer-file").arg(path);
            }
            FileOrKeyHandle::KeyHandle((_kh, s)) => {
                cmd.arg("--signer").arg(&s);
            }
        };

        cmd.arg(input_file);

        let output = self.run(cmd, None);
        if output.status.success() {
            if let Some(output_file) = output_file {
                Ok(std::fs::read(output_file).expect("can read file"))
            } else {
                Ok(output.stdout)
            }
        } else {
            Err(anyhow::anyhow!("{}", String::from_utf8_lossy(&output.stderr)))
        }
    }

    pub fn verify_maybe<'a, P, Q>(&self,
                                  args: &[&str],
                                  op: Verify,
                                  input: P,
                                  output_file: Q)
        -> Result<Vec<u8>>
    where P: AsRef<Path>,
          Q: Into<Option<&'a Path>>,
    {
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([ "verify" ]);
        for arg in args {
            cmd.arg(arg);
        }
        op.apply(&mut cmd);
        cmd.arg(input.as_ref());
        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, None);
        if output.status.success() {
            if let Some(output_file) = output_file {
                if output_file != &PathBuf::from("-") {
                    return Ok(std::fs::read(output_file)?);
                }
            }

            Ok(output.stdout)
        } else {
            Err(anyhow::anyhow!(format!(
                "Command failed:\n{}",
                String::from_utf8_lossy(&output.stderr))))
        }
    }

    pub fn verify<'a, P, Q>(&self,
                            args: &[&str],
                            op: Verify,
                            input: P,
                            output_file: Q)
        -> Vec<u8>
    where P: AsRef<Path>,
          Q: Into<Option<&'a Path>>,
    {
        self.verify_maybe(args, op, input, output_file)
            .expect("success")
    }

    // Merges the certificates.
    pub fn keyring_merge_maybe<'a, P, Q>(&self,
                                         input_files: &[P],
                                         input_bytes: Option<&[u8]>,
                                         output_file: Q)
        -> Result<Vec<Cert>>
    where P: AsRef<Path>,
          Q: Into<Option<&'a Path>>,
    {
        let output_file = output_file.into();

        let mut cmd = self.command();
        cmd.args([ "keyring", "merge" ]);

        for input_file in input_files.into_iter() {
            cmd.arg(input_file.as_ref());
        }
        if let Some(input_bytes) = input_bytes {
            cmd.arg("-");
            cmd.write_stdin(input_bytes);
        }

        if let Some(output_file) = output_file {
            cmd.arg("--output").arg(output_file);
        }

        let output = self.run(cmd, None);

        if output.status.success() {
            let mut parser = None;
            if let Some(output_file) = output_file {
                if PathBuf::from("-").as_path() != output_file {
                    parser = Some(CertParser::from_file(&output_file)
                                  .expect("can parse certificate"));
                }
            }
            let parser = if let Some(parser) = parser {
                parser
            } else {
                // Read from stdout.
                CertParser::from_bytes(&output.stdout)
                    .expect("can parse certificate")
            };

            parser.collect::<Result<Vec<_>>>()
        } else {
            Err(anyhow::anyhow!("sq key export returned an error"))
        }
    }

    // Merges the certificates.
    pub fn keyring_merge<'a, P, Q>(&self,
                                   input_files: &[P],
                                   input_bytes: Option<&[u8]>,
                                   output_file: Q)
        -> Vec<Cert>
    where P: AsRef<Path>,
          Q: Into<Option<&'a Path>>,
    {
        self.keyring_merge_maybe(input_files, input_bytes, output_file)
            .expect("success")
    }
}

pub enum Verify {
    Message,
    SignatureFile(PathBuf),
    Cleartext,
}

impl Verify {
    fn apply(self, cmd: &mut Command) {
        match self {
            Verify::Message => cmd.arg("--message"),
            Verify::SignatureFile(f) => cmd.arg("--signature-file").arg(f),
            Verify::Cleartext => cmd.arg("--cleartext"),
        };
    }
}

/// Ensure notations can be found in a Signature
///
/// ## Errors
///
/// Returns an error if a notation can not be found in the Signature
pub fn compare_notations(
    signature: &Signature,
    notations: &[(&str, &str)],
) -> Result<()> {
    if ! notations.is_empty() {
        let found_notations: Vec<(&str, String)> = signature
            .notation_data()
            .map(|n| (n.name(), String::from_utf8_lossy(n.value()).into()))
            .collect();

        for (key, value) in notations {
            if !found_notations.contains(&(key, String::from(*value))) {
                return Err(anyhow!(format!(
                    "Expected notation \"{}: {}\" in {:?}",
                    key, value, found_notations
                )));
            }
        }
    }
    Ok(())
}
