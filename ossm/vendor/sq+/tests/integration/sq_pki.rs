use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fmt::Result as FMTResult;
use std::path;
use std::time;

use regex::bytes::Regex;

use sequoia_openpgp as openpgp;

use openpgp::Fingerprint;
use openpgp::Result;
use openpgp::packet::UserID;

use super::common::Sq;
use super::common::UserIDArg;

const HR_OK: &'static str = "[ ✓ ]";
const HR_NOT_OK: &'static str = "[ 0/120 ]";
const HR_NOT_OK_EMPTY: &'static str = "[ ]";
const HR_PATH: &'static str = "◯ ";

fn no_output() -> &'static HashMap::<OutputFormat, Vec<(usize, Regex)>> {
    use std::sync::OnceLock;
    static NO_OUTPUT: OnceLock<HashMap::<OutputFormat, Vec<(usize, Regex)>>>
        = OnceLock::new();
    NO_OUTPUT.get_or_init(|| Default::default())
}

/// Supported output types
///
/// These need to be synced with the ones in src/cli.rs
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
enum OutputFormat {
    /// output in human readable format
    HumanReadable,
}

impl OutputFormat {
    pub fn iterator() -> impl Iterator<Item = &'static OutputFormat> {
        static FORMATS: [OutputFormat; 1] =
            [OutputFormat::HumanReadable];
        FORMATS.iter()
    }
}

impl Display for OutputFormat {
    fn fmt(&self, f: &mut Formatter) -> FMTResult {
        write!(
            f,
            "{}",
            match self {
                OutputFormat::HumanReadable => "human-readable",
            }
        )
    }
}

fn dir() -> path::PathBuf {
    path::Path::new("tests").join("data").join("keyrings")
}

fn regexify(needle: &str) -> Regex {
    Regex::new(
        &regex::escape(needle).replace(char::is_whitespace, "[\\s\\n─┬│└]*"))
        .unwrap()
}

/// Create a HashMap, containing per OutputFormat lists of occurrences
/// of strings
fn output_map<S>(
    human: &[(usize, S)],
) -> HashMap<OutputFormat, Vec<(usize, Regex)>>
where S: AsRef<str>,
{
    let mut output = HashMap::<OutputFormat, Vec<(usize, Regex)>>::new();
    output.insert(OutputFormat::HumanReadable,
                  human.iter().map(|(c, n)| (*c, regexify(n.as_ref()))).collect());
    output
}

fn test<'a, R, U>(
    keyring: &str,
    trust_root: R,
    sqwot_args: &[&str],
    command: &str,
    args: &[&str],
    amount: usize,
    userid: U,
    target: Option<&Fingerprint>,
    success: bool,
    output: &HashMap<OutputFormat, Vec<(usize, Regex)>>,
) -> Result<()>
where
    R: Into<Option<&'a Fingerprint>>,
    U: Into<Option<&'a UserIDArg<'a>>>,
{
    let sq = Sq::new();
    let trust_root = trust_root.into();
    let userid = userid.into();

    for outputformat in OutputFormat::iterator() {
        let mut cmd = sq.command();
        cmd.current_dir(&dir())
            .args(&["--keyring", keyring]);
        if let Some(trust_root) = trust_root {
            cmd.args(&["--trust-root", &trust_root.to_string()]);
        }
        cmd
            .arg(if command == "list" { "cert" } else { "pki" })
            .arg(command)
            .args(sqwot_args);
        // We test the verbose output.  Enable it (when appropriate).
        if ["authenticate", "lookup", "identify", "list"].contains(&command) {
            cmd.arg("--show-paths");
        }
        if let Some(target) = target {
            if ["authenticate", "identify"].contains(&command) {
                cmd.arg("--cert");
            }
            cmd.arg(&target.to_string());
        }
        if let Some(userid) = userid {
            if command == "list" {
                userid.as_cert_designator(&mut cmd);
            } else {
                userid.as_arg(&mut cmd);
            }
        }
        for arg in args {
            cmd.arg(arg);
        }
        cmd.args(&["--amount", &format!("{}", amount)]);

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

        if success {
            let assertion = cmd.assert();
            let assertion = assertion.success();

            if let Some(output) = output.get(outputformat) {
                for (expected_occurrences, s) in output {
                    let haystack = &assertion.get_output().stdout;
                    let occurrences =
                        s.find_iter(haystack.as_ref()).count();

                    assert_eq!(
                        occurrences, *expected_occurrences,
                        "Failed to find: '{}' {} times \
                         in output:\n\n\
                         {}",
                        s, expected_occurrences,
                        String::from_utf8_lossy(haystack),
                    );
                }
            }
        } else {
            let assertion = cmd.assert();
            let assertion = assertion.failure();

            if let Some(output) = output.get(outputformat) {
                for (expected_occurrences, s) in output {
                    let haystack = &assertion.get_output().stdout;
                    let occurrences =
                        s.find_iter(haystack.as_ref()).count();

                    assert_eq!(
                        occurrences, *expected_occurrences,
                        "Failed to find: '{}' {} times \
                         in output:\n\n\
                         {}",
                        s, expected_occurrences,
                        String::from_utf8_lossy(haystack),
                    );
                }
            }
            // TODO: check stderr?
        }
    }

    Ok(())
}

// Test authenticating a binding (User ID and certificate).
#[test]
    #[allow(unused)]
fn authenticate() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserIDArg::UserID("<ellen@example.org>");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    // defaults
    let keyring = "simple.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "authenticate";
    let args = &[];

    let human_output =
        [(1, format!("- {} {}", HR_OK, &dave_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_uid),
        Some(&dave_fpr),
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&dave_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );

    // Not enough depth.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_uid),
        Some(&ellen_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&ellen_uid),
        Some(&ellen_fpr),
        false,
        no_output(),
    );

    // No such User ID on dave's key.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&ellen_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );

    Ok(())
}

// Test authenticating bindings where we match on just the email
// address, not the whole User ID.
#[test]
#[allow(unused)]
fn authenticate_email() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    // Yes, UserIDArg::Email, not UserIDArg::UserID.  We're testing
    // what --email matches!
    let alice_uid
        = UserIDArg::Email("<alice@example.org>");

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    // Yes, UserIDArg::Email, not UserIDArg::UserID.
    let dave_uid
        = UserIDArg::Email("<dave@example.org>");
    let dave_email = UserIDArg::Email("dave@example.org");
    let dave_email_uc1 = UserIDArg::Email("DAVE@example.org");
    let dave_email_uc2 = UserIDArg::Email("DAVE@EXAMPLE.ORG");

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    // Yes, UserIDArg::Email, not UserIDArg::UserID.
    let ellen_uid
        = UserIDArg::Email("<ellen@example.org>");
    let ellen_email = UserIDArg::Email("ellen@example.org");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    // defaults
    let keyring = "simple.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "authenticate";
    let args = &[];

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &dave_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_email),
        Some(&dave_fpr),
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&dave_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&dave_email),
        Some(&dave_fpr),
        false,
        no_output(),
    );

    // Not enough depth.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_uid),
        Some(&ellen_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_email),
        Some(&ellen_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&ellen_uid),
        Some(&ellen_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&ellen_email),
        Some(&ellen_fpr),
        false,
        no_output(),
    );

    // No such User ID on dave's key.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_email),
        Some(&dave_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&ellen_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&ellen_email),
        Some(&dave_fpr),
        false,
        no_output(),
    );

    // Normalized.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_email_uc1),
        Some(&dave_fpr),
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_email_uc2),
        Some(&dave_fpr),
        true,
        &output_map(&human_output),
    );

    // Puny code and case normalization.
    let alice_fpr: Fingerprint =
        "B8DA8B318149B1C8C0CBD1ECB1CEC6D3CD00E69D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");
    let alice_email
        = UserIDArg::Email("alice@example.org");

    let hans_fpr: Fingerprint =
        "74767C4F2B15F57F3394FCA99DE867E6CA6A2756"
        .parse().expect("valid fingerprint");
    let hans_uid
        = UserIDArg::UserID("<hÄNS@bücher.tld>");
    // Certified by: B8DA8B318149B1C8C0CBD1ECB1CEC6D3CD00E69D

    let hans_email
        = UserIDArg::Email("hÄNS@bücher.tld");
    let hans_email_lowercase
        = UserIDArg::Email("häns@bücher.tld");
    let hans_email_punycode
        = UserIDArg::Email("hÄNS@xn--bcher-kva.tld");
    let hans_email_punycode_lowercase
        = UserIDArg::Email("häns@xn--bcher-kva.tld");

    let carol_fpr: Fingerprint =
        "7432C123761B94EC50D50CF6562B9ADEE7F789F6"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 74767C4F2B15F57F3394FCA99DE867E6CA6A2756

    let carol_email
        = UserIDArg::Email("carol@example.org");

    // defaults
    let keyring = "puny-code.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "authenticate";
    let args = &[];

    let human_output =
        [(1, format!("- {} {}", HR_OK, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&alice_email),
        Some(&alice_fpr),
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &hans_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&hans_email),
        Some(&hans_fpr),
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&hans_email_lowercase),
        Some(&hans_fpr),
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&hans_email_punycode),
        Some(&hans_fpr),
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&hans_email_punycode_lowercase),
        Some(&hans_fpr),
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&carol_email),
        Some(&carol_fpr),
        true,
        &output_map(&human_output),
    );

    Ok(())
}

// Test looking up a certificate by User ID.
#[test]
#[allow(unused)]
fn lookup() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid = UserIDArg::UserID("<alice@example.org>");
    let alice_uid_uppercase = UserIDArg::UserID("<ALICE@EXAMPLE.ORG>");
    let alice_uid_uppercase2 = UserIDArg::UserID("<alice@EXAMPLE.ORG>");

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid = UserIDArg::UserID("<dave@example.org>");
    let dave_uid_uppercase = UserIDArg::UserID("<DAVE@EXAMPLE.ORG>");
    let dave_uid_uppercase2 = UserIDArg::UserID("<dave@EXAMPLE.ORG>");

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserIDArg::UserID("<ellen@example.org>");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    // defaults
    let keyring = "simple.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "lookup";
    let args = &[];

    let human_output =
        [(1, format!("- {} {}", HR_OK, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&alice_uid),
        None,
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&alice_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output = [
        (1, format!("- {} {}", HR_OK, &dave_uid)),
        (1, format!("{}{} ({})", HR_PATH, &alice_fpr, &alice_uid)),
    ];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_uid),
        None,
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&dave_uid),
        None,
        false,
        no_output(),
    );

    // Not enough depth.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_uid),
        None,
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&ellen_uid),
        None,
        false,
        no_output(),
    );

    // No such User ID.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        &UserIDArg::UserID("Gary <gary@some.org>"),
        None,
        false,
        no_output(),
    );

    // We need an exact match.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&alice_uid_uppercase),
        None,
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&alice_uid_uppercase2),
        None,
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_uid_uppercase),
        None,
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&dave_uid_uppercase2),
        None,
        false,
        no_output(),
    );

    Ok(())
}

// Test looking up a certificate by email address.
#[test]
#[allow(unused)]
fn lookup_email() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid = UserIDArg::UserID("<alice@example.org>");
    let alice_email = UserIDArg::Email("alice@example.org");

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid = UserIDArg::UserID("<dave@example.org>");
    let dave_email = UserIDArg::Email("dave@example.org");

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserIDArg::UserID("<ellen@example.org>");
    let ellen_email = UserIDArg::Email("ellen@example.org");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    // defaults for test() call
    let keyring = "simple.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = [];
    let command = "lookup";
    let args = [];
    let target = None;

    let human_output =
        [(1, format!("- {} {}", HR_OK, &alice_uid))];
    test(
        keyring,
        trust_root,
        &sqwot_args,
        command,
        &args,
        100,
        Some(&alice_email),
        target,
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        &sqwot_args,
        command,
        &args,
        120,
        &alice_email,
        target,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, dave_uid))];
    test(
        keyring,
        trust_root,
        &sqwot_args,
        command,
        &args,
        100,
        &dave_email,
        target,
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        &sqwot_args,
        command,
        &args,
        120,
        &dave_email,
        target,
        false,
        no_output(),
    );

    // Not enough depth.
    test(
        keyring,
        trust_root,
        &sqwot_args,
        command,
        &args,
        100,
        &ellen_email,
        target,
        false,
        no_output(),
    );
    test(
        keyring,
        trust_root,
        &sqwot_args,
        command,
        &args,
        120,
        &ellen_email,
        target,
        false,
        no_output(),
    );

    // No such User ID.
    test(
        keyring,
        trust_root,
        &sqwot_args,
        command,
        &args,
        100,
        &UserIDArg::Email("gary@some.org"),
        target,
        false,
        no_output(),
    );

    Ok(())
}

// Test identifying a certificate.
#[test]
#[allow(unused)]
fn identify() -> Result<()> {
    let alice_fpr: Fingerprint =
        "2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserID::from("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "03182611B91B1E7E20B848E83DFC151ABFAD85D5"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserID::from("<bob@other.org>");
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA
    let bob_some_org_uid
        = UserID::from("<bob@some.org>");
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA

    let carol_fpr: Fingerprint =
        "9CA36907B46FE7B6B9EE9601E78064C12B6D7902"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserID::from("<carol@example.org>");
    // Certified by: 03182611B91B1E7E20B848E83DFC151ABFAD85D5

    let dave_fpr: Fingerprint =
        "C1BC6794A6C6281B968A6A41ACE2055D610CEA03"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserID::from("<dave@other.org>");
    // Certified by: 9CA36907B46FE7B6B9EE9601E78064C12B6D7902

    // defaults for test() call
    let keyring = "multiple-userids-1.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "identify";
    let args = &[];
    let userid = None;

    let userids = &[&alice_uid];
    let human_output = userids
        .iter()
        .map(|userid| {
            (
                1,
                format!("- {} {}", HR_OK, userid)
                    .to_string(),
            )
        })
        .chain(vec![(userids.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        userid,
        Some(&alice_fpr),
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        userid,
        Some(&alice_fpr),
        true,
        &output_map(&human_output),
    );

    let userids = &[&dave_uid];
    let human_output = userids
        .iter()
        .map(|userid| {
            (
                1,
                format!("- {} {}", HR_OK, userid).to_string(),
            )
        })
        .chain(vec![(userids.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        50,
        userid,
        Some(&dave_fpr),
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        userid,
        Some(&dave_fpr),
        false,
        no_output(),
    );

    let userids = &[&bob_uid, &bob_some_org_uid];
    let human_output = userids
        .iter()
        .map(|userid| {
            (
                1,
                format!("- {} {}", HR_OK, userid).to_string(),
            )
        })
        .chain(vec![(userids.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        50,
        userid,
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        userid,
        Some(&bob_fpr),
        false,
        no_output(),
    );

    Ok(())
}

// List all authenticated bindings.
#[test]
#[allow(unused)]
fn list() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserID::from("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "39A479816C934B9E0464F1F4BC1DCFDEADA4EE90"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserID::from("<bob@example.org>");
    // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

    let carol_fpr: Fingerprint =
        "43530F91B450EDB269AA58821A1CF4DC7F500F04"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserID::from("<carol@example.org>");
    // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserID::from("<dave@example.org>");
    // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserID::from("<ellen@example.org>");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    let frank_fpr: Fingerprint =
        "2693237D2CED0BB68F118D78DC86A97CD2C819D9"
        .parse().expect("valid fingerprint");
    let frank_uid
        = UserID::from("<frank@example.org>");

    // defaults for test() call
    let keyring = "simple.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "list";
    let args = &[];
    let userid = None;
    let target = None;

    let bindings = &[(&alice_uid, &alice_fpr)];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        userid,
        target,
        true,
        &output_map(&human_output),
    );

    let bindings = &[
        (&alice_uid, &alice_fpr),
        (&bob_uid, &bob_fpr),
        (&carol_uid, &carol_fpr),
        (&dave_uid, &dave_fpr),
    ];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        50,
        userid,
        target,
        true,
        &output_map(&human_output),
    );

    Ok(())
}

// List all authenticated bindings matching a pattern.
#[test]
#[allow(unused)]
fn list_pattern() -> Result<()> {
    let alice_fpr: Fingerprint =
        "2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserID::from("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "03182611B91B1E7E20B848E83DFC151ABFAD85D5"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserID::from("<bob@other.org>");
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA
    let bob_some_org_uid
        = UserID::from("<bob@some.org>");
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA

    let carol_fpr: Fingerprint =
        "9CA36907B46FE7B6B9EE9601E78064C12B6D7902"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserID::from("<carol@example.org>");
    // Certified by: 03182611B91B1E7E20B848E83DFC151ABFAD85D5

    let dave_fpr: Fingerprint =
        "C1BC6794A6C6281B968A6A41ACE2055D610CEA03"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserID::from("<dave@other.org>");
    // Certified by: 9CA36907B46FE7B6B9EE9601E78064C12B6D7902

    // defaults
    let keyring = "multiple-userids-1.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "list";

    let bindings = &[(&bob_uid, &bob_fpr), (&bob_some_org_uid, &bob_fpr)];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["bob"],
        50,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["BOB"],
        50,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    let bindings = &[(&alice_uid, &alice_fpr), (&carol_uid, &carol_fpr)];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["@example.org"],
        50,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["@EXAMPLE.ORG"],
        50,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    let bindings = &[(&bob_uid, &bob_fpr), (&dave_uid, &dave_fpr)];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["@OTHER.ORG"],
        50,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    let bindings = &[
        (&alice_uid, &alice_fpr),
        (&bob_uid, &bob_fpr),
        (&bob_some_org_uid, &bob_fpr),
        (&carol_uid, &carol_fpr),
        (&dave_uid, &dave_fpr),
    ];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["ORG"],
        50,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    // Puny code.
    let alice_fpr: Fingerprint = "B8DA8B318149B1C8C0CBD1ECB1CEC6D3CD00E69D"
        .parse()
        .expect("valid fingerprint");
    let alice_uid = UserID::from("<alice@example.org>");
    let alice_email = UserID::from("alice@example.org");

    let hans_fpr: Fingerprint = "74767C4F2B15F57F3394FCA99DE867E6CA6A2756"
        .parse()
        .expect("valid fingerprint");
    let hans_uid = UserID::from("<hÄNS@bücher.tld>");
    // Certified by: B8DA8B318149B1C8C0CBD1ECB1CEC6D3CD00E69D

    let hans_email = "hÄNS@bücher.tld";
    let hans_email_punycode = "hÄNS@xn--bcher-kva.tld";
    let hans_email_punycode_lowercase = "häns@xn--bcher-kva.tld";

    let carol_fpr: Fingerprint = "7432C123761B94EC50D50CF6562B9ADEE7F789F6"
        .parse()
        .expect("valid fingerprint");
    let carol_uid = UserID::from("<carol@example.org>");
    // Certified by: 74767C4F2B15F57F3394FCA99DE867E6CA6A2756

    let carol_email
        = UserID::from("carol@example.org");

    // defaults
    let keyring = "puny-code.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "list";

    let bindings = &[(&hans_uid, &hans_fpr)];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();

    // If we don't provide --email, then we only case
    // insensitively match on the raw User ID; we don't perform
    // puny code normalization.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["bücher.tld"],
        100,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["BÜCHER.TLD"],
        100,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[hans_email],
        100,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[&format!("<{}>", hans_email)],
        100,
        None,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[hans_email_punycode],
        100,
        None,
        None,
        false,
        no_output(),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[hans_email_punycode_lowercase],
        100,
        None,
        None,
        false,
        no_output(),
    );

    Ok(())
}

// List all authenticated bindings where the email address matches
// a pattern.
#[test]
#[allow(unused)]
fn list_email_pattern() -> Result<()> {
    // Puny code and case normalization.
    let alice_fpr: Fingerprint =
        "B8DA8B318149B1C8C0CBD1ECB1CEC6D3CD00E69D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserID::from("<alice@example.org>");
    let alice_email
        = UserID::from("alice@example.org");

    let hans_fpr: Fingerprint =
        "74767C4F2B15F57F3394FCA99DE867E6CA6A2756"
        .parse().expect("valid fingerprint");
    let hans_uid
        = UserID::from("<hÄNS@bücher.tld>");
    // Certified by: B8DA8B318149B1C8C0CBD1ECB1CEC6D3CD00E69D

    let hans_email = UserIDArg::Email("hÄNS@bücher.tld");
    let hans_email_bad = UserIDArg::Email("<hÄNS@bücher.tld>");
    let hans_email_punycode
        = UserIDArg::Email("hÄNS@xn--bcher-kva.tld");
    let hans_email_punycode_lowercase
        = UserIDArg::Email("häns@xn--bcher-kva.tld");

    let carol_fpr: Fingerprint =
        "7432C123761B94EC50D50CF6562B9ADEE7F789F6"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserID::from("<carol@example.org>");
    // Certified by: 74767C4F2B15F57F3394FCA99DE867E6CA6A2756

    let carol_email
        = UserID::from("carol@example.org");

    // defaults
    let keyring = "puny-code.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "list";

    let bindings = &[(&hans_uid, &hans_fpr)];
    let human_output = bindings
        .iter()
        .map(|(userid, target)| {
            (1, format!("- {} {}", HR_OK, userid).to_string())
        })
        .chain(vec![(bindings.len(), HR_OK.to_string())].into_iter())
        .collect::<Vec<_>>();

    // --email has to match the whole email, not a substring.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        100,
        &UserIDArg::Email("bücher.tld"),
        None,
        false,
        no_output(),
    );

    // --email has to match the whole email, not a substring.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        100,
        &UserIDArg::Email("BÜCHER.TLD"),
        None,
        false,
        no_output(),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        100,
        &hans_email,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        100,
        &hans_email_bad,
        None,
        false,
        no_output(),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        100,
        &hans_email_punycode,
        None,
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        100,
        &hans_email_punycode_lowercase,
        None,
        true,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn path_simple() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "39A479816C934B9E0464F1F4BC1DCFDEADA4EE90"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

    let carol_fpr: Fingerprint =
        "43530F91B450EDB269AA58821A1CF4DC7F500F04"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserIDArg::UserID("<ellen@example.org>");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    let frank_fpr: Fingerprint =
        "2693237D2CED0BB68F118D78DC86A97CD2C819D9"
        .parse().expect("valid fingerprint");
    let frank_uid
        = UserIDArg::UserID("<frank@example.org>");

    // defaults
    let keyring = "simple.pgp";
    let trust_root = None; // No trust root for path.
    let sqwot_args = &[];
    let command = "path";

    // Alice certifies Bob at trust amount = 100. (120 required).
    let human_output =
        [(1, format!("{} {} {}", HR_NOT_OK_EMPTY, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        120,
        Some(&bob_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output = [(1, format!("{} {} {}", HR_OK, bob_fpr, bob_uid))];
    // As above, but we only require 100.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        100,
        Some(&bob_uid),
        None,
        true,
        &output_map(&human_output),
    );

    // Alice makes Bob a level 2 trusted introducer.
    // Bob certificates Carol, but for Bob.
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        100,
        Some(&bob_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}", HR_OK, carol_fpr, carol_uid))];
    // Alice makes Bob a level 2 trusted introducer.
    // Bob certificates Carol.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        100,
        Some(&carol_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}", HR_OK, dave_fpr, dave_uid))];
    // Alice makes Bob a level 2 trusted introducer.
    // Bob makes Carol a level 1 trust introducer.
    // Carol certifies Dave.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
        ],
        100,
        Some(&dave_uid),
        None,
        true,
        &output_map(&human_output),
    );

    // Alice makes Bob a level 2 trusted introducer (require level 3).
    // Bob makes Carol a level 1 trusted introducer (require level 2).
    // Carol makes Dave a level 1 trusted introducer.
    // Dave certifies Ellen.
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &ellen_fpr, &ellen_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
            &ellen_fpr.to_string(),
        ],
        100,
        Some(&ellen_uid),
        None,
        false,
        &output_map(&human_output),
    );

    // Alice makes Bob a level 2 trusted introducer.
    // Bob does *not* certify Dave.
    // Dave certifies Ellen.
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &ellen_fpr, &ellen_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &dave_fpr.to_string(),
            &ellen_fpr.to_string(),
        ],
        100,
        Some(&ellen_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn path_missing_certs() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "39A479816C934B9E0464F1F4BC1DCFDEADA4EE90"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

    let carol_fpr: Fingerprint =
        "43530F91B450EDB269AA58821A1CF4DC7F500F04"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserIDArg::UserID("<ellen@example.org>");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    let frank_fpr: Fingerprint =
        "2693237D2CED0BB68F118D78DC86A97CD2C819D9"
        .parse().expect("valid fingerprint");
    let frank_uid
        = UserIDArg::UserID("<frank@example.org>");

    let missing_fpr: Fingerprint =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        .parse().expect("valid fingerprint");

    // defaults
    let keyring = "simple.pgp";
    let trust_root = None; // No trust root for path.
    let sqwot_args = &[];
    let command = "path";

    let human_output =
        [(1, format!("{} {} {}", HR_OK, carol_fpr, carol_uid))];
    // Alice tsigns Bob at depth = 2, trust amount = 100.
    // Bob certifies Carol, trust amount = 100.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        100,
        Some(&carol_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &missing_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        100,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &missing_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        100,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &missing_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &missing_fpr.to_string(),
        ],
        100,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn path_singleton() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "39A479816C934B9E0464F1F4BC1DCFDEADA4EE90"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

    let carol_fpr: Fingerprint =
        "43530F91B450EDB269AA58821A1CF4DC7F500F04"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserIDArg::UserID("<ellen@example.org>");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    let frank_fpr: Fingerprint =
        "2693237D2CED0BB68F118D78DC86A97CD2C819D9"
        .parse().expect("valid fingerprint");
    let frank_uid
        = UserIDArg::UserID("<frank@example.org>");

    let missing_fpr: Fingerprint =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        .parse().expect("valid fingerprint");

    // defaults
    let keyring = "simple.pgp";
    let trust_root = None; // No trust root for path.
    let sqwot_args = &[];
    let command = "path";

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &alice_fpr, &alice_uid))];
    // A self signed User ID.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
        ],
        120,
        Some(&alice_uid),
        None,
        true,
        &output_map(&human_output),
    );

    // A User ID that is not self signed.
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &alice_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
        ],
        120,
        Some(&bob_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn path_multiple_userids_1() -> Result<()> {
    let alice_fpr: Fingerprint =
        "2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "03182611B91B1E7E20B848E83DFC151ABFAD85D5"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@other.org>");
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA
    let bob_some_org_uid
        = UserIDArg::UserID("<bob@some.org>");
    // Certified by: 2A2A4A23A7EEC119BC0B46642B3825DC02A05FEA

    let carol_fpr: Fingerprint =
        "9CA36907B46FE7B6B9EE9601E78064C12B6D7902"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 03182611B91B1E7E20B848E83DFC151ABFAD85D5

    let dave_fpr: Fingerprint =
        "C1BC6794A6C6281B968A6A41ACE2055D610CEA03"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@other.org>");
    // Certified by: 9CA36907B46FE7B6B9EE9601E78064C12B6D7902

    // defaults
    let keyring = "multiple-userids-1.pgp";
    let trust_root = None; // No trust root for path.
    let sqwot_args = &[];
    let command = "path";

    // Alice certifies Bob as:
    //   a level 2 trusted introducer, amount = 50
    //   a level 1 trusted introducer, amount = 70
    // Bob certifies Carol as a level 2 trusted introducer
    // Carol certifies Dave
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &dave_fpr, &dave_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
        ],
        70,
        Some(&dave_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}", HR_OK, dave_fpr, dave_uid))];
    // As above, but
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
        ],
        50,
        Some(&dave_uid),
        None,
        true,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn path_multiple_users_2() -> Result<()> {
    // Note: this also tests regular expressions.

    let alice_fpr: Fingerprint =
        "F1C99C4019837703DD17C45440F8A0141DF278EA"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "5528B9E5DAFC519ED2E37F0377B332E4111456CB"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@other.org>");
    // Certified by: F1C99C4019837703DD17C45440F8A0141DF278EA
    let bob_some_org_uid
        = UserIDArg::UserID("<bob@some.org>");
    // Certified by: F1C99C4019837703DD17C45440F8A0141DF278EA

    let carol_fpr: Fingerprint =
        "6F8291428420AB53576BAB4BEFF6477D3E348D71"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 5528B9E5DAFC519ED2E37F0377B332E4111456CB

    let dave_fpr: Fingerprint =
        "62C57D90DAD253DEA01D5A86C7382FD6285C18F0"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@other.org>");
    // Certified by: 6F8291428420AB53576BAB4BEFF6477D3E348D71

    let ed_fpr: Fingerprint =
        "0E974D0ACBA0C4D8F51D7CF68F048FF83B173504"
        .parse().expect("valid fingerprint");
    let ed_uid
        = UserIDArg::UserID("<ed@example.org>");
    // Certified by: 6F8291428420AB53576BAB4BEFF6477D3E348D71

    let frank_fpr: Fingerprint =
        "5BEE3D41F85B2FCBC300DE4E18CB2BDA65465F03"
        .parse().expect("valid fingerprint");
    let frank_uid
        = UserIDArg::UserID("<frank@other.org>");
    // Certified by: 5528B9E5DAFC519ED2E37F0377B332E4111456CB

    // defaults
    let keyring = "multiple-userids-2.pgp";
    let trust_root = None; // No trust root for path.
    let sqwot_args = &[];
    let command = "path";

    let human_output = [(1, format!("{} {}", HR_OK, frank_fpr))];
    // Alice certifies Bob as:
    //   a level 255 trusted introducer, amount = 70 for other.org
    //   a level 1 trusted introducer, amount = 50
    // Bob certifies Frank@other.org
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &frank_fpr.to_string(),
        ],
        70,
        Some(&frank_uid),
        None,
        true,
        &output_map(&human_output),
    );

    // Alice certifies Bob as:
    //   a level 255 trusted introducer, amount = 70 for other.org
    //   a level 1 trusted introducer, amount = 50
    // Bob certifies Carol@example.org
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        70,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}", HR_OK, carol_fpr, carol_uid))];
    // As above, but reduce the required trust amount to 50.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        50,
        Some(&carol_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}", HR_OK, dave_fpr, dave_uid))];
    // Alice certifies Bob as:
    //   a level 255 trusted introducer, amount = 70 for other.org
    //   a level 1 trusted introducer, amount = 50
    // Bob certifies carol as a level 2 trusted introducer
    // Carol certifies dave@other.org
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
        ],
        70,
        Some(&dave_uid),
        None,
        true,
        &output_map(&human_output),
    );

    // Alice certifies Bob as:
    //   a level 255 trusted introducer, amount = 70 for other.org
    //   a level 1 trusted introducer, amount = 50
    // Bob certifies carol as a level 2 trusted introducer
    // Carol certifies ed@example.org
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &ed_fpr, &ed_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &ed_fpr.to_string(),
        ],
        70,
        Some(&ed_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn path_sha1() -> Result<()> {
    let alice_fpr: Fingerprint =
        "B5FA089BA76FE3E17DC11660960E53286738F94C"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "231BC4AB9D8CAB86D1622CE02C0CE554998EECDB"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: B5FA089BA76FE3E17DC11660960E53286738F94C
    // Certified by: B5FA089BA76FE3E17DC11660960E53286738F94C

    let carol_fpr: Fingerprint =
        "FABA8485B2D4D5BF1582AA963A8115E774FA9852"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 231BC4AB9D8CAB86D1622CE02C0CE554998EECDB
    // Certified by: 231BC4AB9D8CAB86D1622CE02C0CE554998EECDB

    // defaults
    let keyring = "sha1.pgp";
    let trust_root = None; // No trust root for path.
    let sqwot_args = &[ "--time", "2023-01-10T15:07:01" ];
    let command = "path";

    // Alice certifies Bob as
    //   a level 1 trusted introducer, amount = 120 using sha1
    //   a level 1 trusted introducer, amount = 60 using sha512 (future)
    // Bob certifies carol as a
    //   a level 1 trusted introducer, amount = 120 using sha1
    //   a level 1 trusted introducer, amount = 60 using sha512 (future)
    //
    // The valid signatures won't be used because they are from
    // the future (after the reference time).
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        120,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    // Again, but this time only require a trust amount of 60.
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        60,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    // set sq-wot args again
    let sqwot_args = &[];

    // Again, after the SHA256 certificates are valid.  But with a
    // trust amount of 120.
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        120,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}", HR_OK, carol_fpr, carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        60,
        Some(&carol_uid),
        None,
        true,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn authenticate_certification_network_simple() -> Result<()> {
    let alice_fpr: Fingerprint =
        "85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "39A479816C934B9E0464F1F4BC1DCFDEADA4EE90"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 85DAB65713B2D0ABFC5A4F28BC10C9CE4A699D8D

    let carol_fpr: Fingerprint =
        "43530F91B450EDB269AA58821A1CF4DC7F500F04"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 39A479816C934B9E0464F1F4BC1DCFDEADA4EE90

    let dave_fpr: Fingerprint =
        "329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: 43530F91B450EDB269AA58821A1CF4DC7F500F04

    let ellen_fpr: Fingerprint =
        "A7319A9B166AB530A5FBAC8AB43CA77F7C176AF4"
        .parse().expect("valid fingerprint");
    let ellen_uid
        = UserIDArg::UserID("<ellen@example.org>");
    // Certified by: 329D5AAF73DC70B4E3DD2D11677CB70FFBFE1281

    let frank_fpr: Fingerprint =
        "2693237D2CED0BB68F118D78DC86A97CD2C819D9"
        .parse().expect("valid fingerprint");
    let frank_uid
        = UserIDArg::UserID("<frank@example.org>");

    // defaults
    let keyring = "simple.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "authenticate";
    let args = &[];

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_uid),
        Some(&ellen_fpr),
        false,
        no_output(),
    );

    let sqwot_args = &["--certification-network"];
    let human_output =
        [(1, format!("- {} {}", HR_OK, &ellen_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        100,
        Some(&ellen_uid),
        Some(&ellen_fpr),
        true,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn authenticate_certification_network() -> Result<()> {
    let alice_fpr: Fingerprint =
        "B2B371214EF71AFD16E42C62D81360B4C0489225"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");
    // Certified by: 9A1AE937B5CB8BC46048AB63023CC01973ED9DF3

    let bob_fpr: Fingerprint =
        "A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: B2B371214EF71AFD16E42C62D81360B4C0489225

    let carol_fpr: Fingerprint =
        "AB9EF1C89631519842ED559697557DD147D99C97"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05

    let dave_fpr: Fingerprint =
        "9A1AE937B5CB8BC46048AB63023CC01973ED9DF3"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: AB9EF1C89631519842ED559697557DD147D99C97

    // defaults
    let keyring = "certification-network.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "authenticate";
    let args = &[];

    let human_output =
        [(1, format!("- {} {}", HR_OK, &bob_uid))];
    // Alice does not make Bob a trusted introducer.  So without
    // --certificate-network, she can only authenticate Bob, but
    // not Carol or Dave.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&carol_uid),
        Some(&carol_fpr),
        false,
        no_output(),
    );

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&dave_uid),
        Some(&dave_fpr),
        false,
        no_output(),
    );

    // With --certification-network, she can authenticate them all.
    let sqwot_args = &["--certification-network"];
    let human_output =
        [(1, format!("- {} {}", HR_OK, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&carol_uid),
        Some(&carol_fpr),
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &dave_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&dave_uid),
        Some(&dave_fpr),
        true,
        &output_map(&human_output),
    );

    let sqwot_args = &[];
    let trust_root = &dave_fpr;
    // dave authenticates alice for 60 of 120.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&alice_uid),
        Some(&alice_fpr),
        false,
        no_output(),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        60,
        Some(&alice_uid),
        Some(&alice_fpr),
        true,
        &output_map(&human_output),
    );

    // use --certification-network
    let sqwot_args = &["--certification-network"];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&alice_uid),
        Some(&alice_fpr),
        false,
        no_output(),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        60,
        Some(&alice_uid),
        Some(&alice_fpr),
        true,
        &output_map(&human_output),
    );

    let sqwot_args = &[];
    // use carol as trust root
    let trust_root = &carol_fpr;
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        60,
        Some(&alice_uid),
        Some(&alice_fpr),
        false,
        no_output(),
    );

    // use --certification-network
    let sqwot_args = &["--certification-network"];
    let human_output =
        [(1, format!("- {} {}", HR_OK, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        60,
        Some(&alice_uid),
        Some(&alice_fpr),
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("- {} {}", HR_OK, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn path_certification_network() -> Result<()> {
    let alice_fpr: Fingerprint =
        "B2B371214EF71AFD16E42C62D81360B4C0489225"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");
    // Certified by: 9A1AE937B5CB8BC46048AB63023CC01973ED9DF3

    let bob_fpr: Fingerprint =
        "A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: B2B371214EF71AFD16E42C62D81360B4C0489225

    let carol_fpr: Fingerprint =
        "AB9EF1C89631519842ED559697557DD147D99C97"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05

    let dave_fpr: Fingerprint =
        "9A1AE937B5CB8BC46048AB63023CC01973ED9DF3"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: AB9EF1C89631519842ED559697557DD147D99C97

    // defaults
    let keyring = "certification-network.pgp";
    let trust_root = &alice_fpr;
    let sqwot_args = &[];
    let command = "path";

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &bob_fpr, &bob_uid))];
    // Alice does not make Bob a trusted introducer.  So without
    // --certificate-network, she can only authenticate Bob, but
    // not Carol or Dave.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        120,
        Some(&bob_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}:", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        120,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &dave_fpr, &dave_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
        ],
        120,
        Some(&dave_uid),
        None,
        false,
        &output_map(&human_output),
    );

    // change sq-wot args
    let sqwot_args = &["--certification-network"];

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &bob_fpr, &bob_uid))];
    // With --certification-network, she can authenticate them all.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        120,
        Some(&bob_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &carol_fpr, &carol_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        120,
        Some(&carol_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &dave_fpr, &dave_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
        ],
        120,
        Some(&dave_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &carol_fpr, &carol_uid))];
    // But invalid paths should stay invalid.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &carol_fpr.to_string(),
        ],
        120,
        Some(&carol_uid),
        None,
        false,
        &output_map(&human_output),
    );

    // set dave as trust root
    let trust_root = &dave_fpr;
    // reset sq-wot args again
    let sqwot_args = &[];
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &alice_fpr, &alice_uid))];
    // dave authenticates alice for 60 of 120.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &dave_fpr.to_string(),
            &alice_fpr.to_string(),
        ],
        120,
        Some(&alice_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &alice_fpr, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &dave_fpr.to_string(),
            &alice_fpr.to_string(),
        ],
        60,
        Some(&alice_uid),
        None,
        true,
        &output_map(&human_output),
    );

    // set sq-wot args to use certification network
    let sqwot_args = &["--certification-network"];
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &alice_fpr, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &dave_fpr.to_string(),
            &alice_fpr.to_string(),
        ],
        120,
        Some(&alice_uid),
        None,
        false,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &alice_fpr, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &dave_fpr.to_string(),
            &alice_fpr.to_string(),
        ],
        60,
        Some(&alice_uid),
        None,
        true,
        &output_map(&human_output),
    );

    // set carol as trust root
    let trust_root = &carol_fpr;
    // reset sq-wot args again
    let sqwot_args = &[];
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &alice_fpr, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
            &alice_fpr.to_string(),
        ],
        60,
        Some(&alice_uid),
        None,
        false,
        &output_map(&human_output),
    );

    // set sq-wot args to use certification network
    let sqwot_args = &["--certification-network"];

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &alice_fpr, &alice_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
            &alice_fpr.to_string(),
        ],
        60,
        Some(&alice_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &carol_fpr.to_string(),
            &dave_fpr.to_string(),
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        true,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn gossip_certification_network() -> Result<()> {
    let alice_fpr: Fingerprint =
        "B2B371214EF71AFD16E42C62D81360B4C0489225"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");
    // Certified by: 9A1AE937B5CB8BC46048AB63023CC01973ED9DF3

    let bob_fpr: Fingerprint =
        "A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: B2B371214EF71AFD16E42C62D81360B4C0489225

    let carol_fpr: Fingerprint =
        "AB9EF1C89631519842ED559697557DD147D99C97"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: A68DF00EB82F9C49C27CC7723C5F5BBE6B790C05

    let dave_fpr: Fingerprint =
        "9A1AE937B5CB8BC46048AB63023CC01973ED9DF3"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: AB9EF1C89631519842ED559697557DD147D99C97

    // defaults
    let keyring = "certification-network.pgp";
    let trust_root = None;
    let sqwot_args = &["--gossip"];
    let command = "authenticate";
    let args = &[];

    let human_output =
        [(1, format!("- {} {}", HR_NOT_OK, &bob_uid))];
    // Alice certified Bob.  Although the path is unauthenticated (the
    // path is not from a trust root), we should print it: the user
    // asked for gossip.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    let trust_root = &alice_fpr;
    // Even when we specify --gossip, paths are authenticated as much
    // as possible.
    let human_output =
        [(1, format!("- {} {}", HR_OK, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        120,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn target_cert_expired() -> Result<()> {
    let alice_fpr: Fingerprint =
        "1FA62523FB7C06E71EEFB82BB5159F3FC3EB3AC9"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "B166B31AE5F95600B3F7184FE74C6CE62821686F"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 1FA62523FB7C06E71EEFB82BB5159F3FC3EB3AC9

    let carol_fpr: Fingerprint =
        "81CD118AC5BD9156DC113772626222D76ACDFFCF"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: B166B31AE5F95600B3F7184FE74C6CE62821686F

    // $ date '+%s' -d 20200202
    // 1580598000
    let t1 = std::time::UNIX_EPOCH + time::Duration::new(1580598000, 0);
    // $ date '+%s' -d 20200302
    // 1583103600
    let t2 = std::time::UNIX_EPOCH + time::Duration::new(1583103600, 0);
    // $ date '+%s' -d 20200402
    // 1585778400
    let t3 = std::time::UNIX_EPOCH + time::Duration::new(1585778400, 0);

    // At t1, Alice certifies Bob (amount = 60).
    // At t2, Bob's certificate expires.

    // defaults
    let keyring = "cert-expired.pgp";
    let trust_root: Option<&Fingerprint> = Some(&alice_fpr);
    let sqwot_args = &[];
    let command = "authenticate";

    let human_output =
        [(1, format!("- {} {}", HR_OK, &bob_uid))];
    // Bob's certificate is not yet expired.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["--time", "20200214"],
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    let trust_root = None; // no trust root for path
    let command = "path";
    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            "--time",
            "20200214",
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let trust_root = Some(&alice_fpr);
    let command = "authenticate";
    // Bob's certificate is expired.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &["--time", "20200216"],
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        false,
        no_output(),
    );

    let trust_root = None;
    let command = "path";
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            "--time",
            "20200216",
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn target_cert_hard_revoked() -> Result<()> {
    let alice_fpr: Fingerprint =
        "219AAB661C8AAF4526DBC31AA751A7A0532863BA"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "90E02BFB03FAA04714D1D3D87543157EF3B12BE9"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA
    // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA

    let carol_fpr: Fingerprint =
        "BF680710128E6BCCB2268154569F5F6BFB95C544"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 219AAB661C8AAF4526DBC31AA751A7A0532863BA

    let dave_fpr: Fingerprint =
        "46945292F8F643F0573AF71183F9C1A4759A16D6"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: 90E02BFB03FAA04714D1D3D87543157EF3B12BE9
    // Certified by: BF680710128E6BCCB2268154569F5F6BFB95C544
    // Certified by: 90E02BFB03FAA04714D1D3D87543157EF3B12BE9

    // defaults
    let keyring = "cert-revoked-hard.pgp";
    let trust_root: Option<&Fingerprint> = Some(&alice_fpr);
    let sqwot_args = &[];
    let command = "authenticate";

    // Bob's certificate is hard revoked.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        false,
        no_output(),
    );

    let trust_root: Option<&Fingerprint> = None;
    let command = "path";
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn target_cert_soft_revoked() -> Result<()> {
    let alice_fpr: Fingerprint =
        "66037F98B444BBAFDFE98E871738DFAB86878262"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "4CD8737F76C2B897C4F058DBF28C47540FA2C3B3"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 66037F98B444BBAFDFE98E871738DFAB86878262

    let carol_fpr: Fingerprint =
        "AB4E3F8EE8BBD3459754D75ACE570F9B8C7DC75D"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: 66037F98B444BBAFDFE98E871738DFAB86878262

    let dave_fpr: Fingerprint =
        "DF6A440ED9DE723B0EBC7F50E24FBB1B9FADC999"
        .parse().expect("valid fingerprint");
    let dave_uid
        = UserIDArg::UserID("<dave@example.org>");
    // Certified by: 4CD8737F76C2B897C4F058DBF28C47540FA2C3B3
    // Certified by: AB4E3F8EE8BBD3459754D75ACE570F9B8C7DC75D
    // Certified by: 4CD8737F76C2B897C4F058DBF28C47540FA2C3B3

    // defaults
    let keyring = "cert-revoked-soft.pgp";
    let trust_root: Option<&Fingerprint> = Some(&alice_fpr);
    let sqwot_args = &["--time", "20200228"];
    let command = "authenticate";
    let args = &[];

    let human_output =
        [(1, format!("- {} {}", HR_OK, &bob_uid))];
    // Bob's certificate is soft revoked on 20200301.  If the
    // reference time is before that, we should be able to
    // authenticate Bob.  After that and we should fail to do so.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        args,
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    let trust_root: Option<&Fingerprint> = None; // no trust root for binding
    let command = "path";
    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let trust_root: Option<&Fingerprint> = Some(&alice_fpr);
    let command = "authenticate";
    let sqwot_args = &["--time", "20200302"]; // setting time again

    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        false,
        no_output(),
    );

    let command = "path";
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}

#[test]
#[allow(unused)]
fn target_userid_revoked() -> Result<()> {
    let alice_fpr: Fingerprint =
        "01672BB67E4B4047E5A4EC0A731CEA092C465FC8"
        .parse().expect("valid fingerprint");
    let alice_uid
        = UserIDArg::UserID("<alice@example.org>");

    let bob_fpr: Fingerprint =
        "EA479A77CD074458EAFE56B4861BF42FF490C581"
        .parse().expect("valid fingerprint");
    let bob_uid
        = UserIDArg::UserID("<bob@example.org>");
    // Certified by: 01672BB67E4B4047E5A4EC0A731CEA092C465FC8
    // Certified by: 01672BB67E4B4047E5A4EC0A731CEA092C465FC8

    let carol_fpr: Fingerprint =
        "212873BB9C4CC49F8E5A6FEA78BC5397470BA7F0"
        .parse().expect("valid fingerprint");
    let carol_uid
        = UserIDArg::UserID("<carol@example.org>");
    // Certified by: EA479A77CD074458EAFE56B4861BF42FF490C581
    // Certified by: EA479A77CD074458EAFE56B4861BF42FF490C581

    // defaults
    let keyring = "userid-revoked.pgp";
    let trust_root = Some(&alice_fpr);
    let sqwot_args = &["--time", "20200228"];
    let command = "authenticate";

    let human_output =
        [(1, format!("- {} {}", HR_OK, &bob_uid))];
    // Bob's User ID is soft revoked on 20200301.  If the
    // reference time is before that, we should be able to
    // authenticate Bob.  After that and we should fail to do so.
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        true,
        &output_map(&human_output),
    );

    let trust_root = None;
    let command = "path";
    let human_output =
        [(1, format!("{} {} {}: ", HR_OK, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        true,
        &output_map(&human_output),
    );

    let trust_root = Some(&alice_fpr);
    let sqwot_args = &["--time", "20200302"];
    let command = "authenticate";
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[],
        60,
        Some(&bob_uid),
        Some(&bob_fpr),
        false,
        no_output(),
    );

    let trust_root = None;
    let command = "path";
    let human_output =
        [(1, format!("{} {} {}: ", HR_NOT_OK_EMPTY, &bob_fpr, &bob_uid))];
    test(
        keyring,
        trust_root,
        sqwot_args,
        command,
        &[
            &alice_fpr.to_string(),
            &bob_fpr.to_string(),
        ],
        60,
        Some(&bob_uid),
        None,
        false,
        &output_map(&human_output),
    );

    Ok(())
}
