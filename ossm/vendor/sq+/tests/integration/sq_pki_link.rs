use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::{Mutex, OnceLock};

use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::Cert;
use openpgp::parse::Parse;

use super::common::FileOrKeyHandle;
use super::common::NO_USERIDS;
use super::common::Sq;
use super::common::STANDARD_POLICY;
use super::common::UserIDArg;
use super::common::artifact;

// We are going to replace certifications, and we want to make sure
// that the newest one is the active one.  This means ensuring that
// the newer one has a newer timestamp.  To avoid sleeping for a
// second, the resolution of the time stamp, we pass an explicit time
// to each operation.
//
// This function drives the clock forward, and ensures that every
// operation "happens" at a different point in time.
static TIME: OnceLock<Mutex<chrono::DateTime<chrono::Utc>>> = OnceLock::new();

fn tick() -> String {
    let t = TIME.get_or_init(|| Mutex::new(chrono::Utc::now()));
    let mut t = t.lock().unwrap();
    *t = *t + chrono::Duration::seconds(10);
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// Returns the "current" time.
fn now() -> chrono::DateTime<chrono::Utc> {
    *TIME.get_or_init(|| Mutex::new(chrono::Utc::now())).lock().unwrap()
}

// Verifies a signed message.
fn sq_verify(sq: &Sq,
             time: Option<chrono::DateTime<chrono::Utc>>,
             trust_roots: &[&str],
             signer_files: &[&str],
             msg_pgp: &str,
             authenticated_sigs: usize, unauthenticated_sigs: usize)
{
    let mut cmd = sq.command();
    for trust_root in trust_roots {
        cmd.args(&["--trust-root", trust_root]);
    }
    let time = if let Some(time) = time {
        time.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        tick()
    };
    cmd.args(["verify", "--message", "--time", &time]);
    for signer_file in signer_files {
        cmd.args(&["--signer-file", signer_file]);
    }
    cmd.arg(msg_pgp);
    eprintln!("{:?}", cmd);
    let output = sq.run(cmd, None);

    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if authenticated_sigs > 0 {
        assert!(status.success(),
                "\nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
        assert!(stderr.contains(&format!("{} authenticated signature",
                                         authenticated_sigs)),
                "stdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    } else {
        assert!(! status.success(),
                "\nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    }

    if unauthenticated_sigs > 0 {
        assert!(stderr.contains(&format!("{} unauthenticated signature",
                                         unauthenticated_sigs)),
                "stdout:\n{}\nstderr:\n{}", stdout, stderr);
    }
}

// Links a User ID and a certificate.
fn sq_link(sq: &Sq,
           cert: &str, userids: &[&str], emails: &[&str], more_args: &[&str],
           success: bool)
    -> (ExitStatus, String, String)
{
    let mut cmd = sq.command();
    cmd.args(&["pki", "link", "add", "--time", &tick()]);
    cmd.arg("--cert").arg(cert);
    for userid in userids {
        cmd.arg("--userid").arg(userid);
    }
    for email in emails {
        cmd.arg("--email").arg(email);
    }
    cmd.args(more_args);
    let output = sq.run(cmd, None);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if success {
        assert!(output.status.success(),
                "'sq pki link add' failed unexpectedly\
                 \nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    } else {
        assert!(! output.status.success(),
                "'sq pki link add' succeeded unexpectedly\
                 \nstdout:\n{}\nstderr:\n{}",
                stdout, stderr);
    }

    (output.status, stdout, stderr)
}

fn sq_retract(sq: &Sq, cert: &str, userids: &[&str], emails: &[&str])
    -> (ExitStatus, String, String)
{
    let mut cmd = sq.command();
    cmd.args(&["pki", "link", "retract", "--time", &tick(), "--cert", cert]);
    for userid in userids {
        cmd.arg("--userid").arg(userid);
    }
    for email in emails {
        cmd.arg("--email").arg(email);
    }
    if userids.is_empty() && emails.is_empty() {
        cmd.arg("--all");
    }
    eprintln!("{:?}", cmd);
    let output = sq.run(cmd, true);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (output.status, stdout, stderr)
}

// Certifies a binding.
//
// The certification is imported into the cert store.
fn sq_certify(sq: &Sq,
              certifier: &Path, cert: &str, userid: &str,
              trust_amount: Option<usize>)
{
    let mut extra_args = Vec::new();
    let trust_amount_;
    if let Some(trust_amount) = trust_amount {
        extra_args.push("--amount");
        trust_amount_ = format!("{}", trust_amount);
        extra_args.push(&trust_amount_);
    }

    let certification = sq.scratch_file(Some(&format!(
        "certification {} {} by {}", cert, userid,
        PathBuf::from(certifier.file_name().unwrap()).display())[..]));

    let cert = if let Ok(kh) = cert.parse::<KeyHandle>() {
        kh.into()
    } else {
        FileOrKeyHandle::FileOrStdin(cert.into())
    };

    sq.pki_vouch_add(&extra_args, certifier, cert, &[userid],
                         Some(certification.as_path()));
    sq.cert_import(&certification);
}

fn sq_authorize(sq: &Sq,
                certifier: &Path, cert: &str, userid: &str,
                trust_amount: Option<usize>, depth: Option<usize>)
{
    let mut extra_args = vec![ "--unconstrained" ];
    let trust_amount_;
    if let Some(trust_amount) = trust_amount {
        extra_args.push("--amount");
        trust_amount_ = format!("{}", trust_amount);
        extra_args.push(&trust_amount_);
    }
    let depth_;
    if let Some(depth) = depth {
        extra_args.push("--depth");
        depth_ = format!("{}", depth);
        extra_args.push(&depth_);
    }

    let certification = sq.scratch_file(Some(&format!(
        "certification {} {} by {}", cert, userid,
        PathBuf::from(certifier.file_name().unwrap()).display())[..]));

    let cert = if let Ok(kh) = cert.parse::<KeyHandle>() {
        kh.into()
    } else {
        FileOrKeyHandle::FileOrStdin(cert.into())
    };

    sq.pki_vouch_authorize(&extra_args, certifier, cert, &[userid],
                           Some(certification.as_path()));
    sq.cert_import(&certification);
}

// Verify signatures using the acceptance machinery.
#[test]
fn sq_pki_link_add_retract() -> Result<()> {
    let sq = Sq::new();
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    struct Data {
        key_file: PathBuf,
        cert: Cert, // unused
        sig_file: String,
    }

    // Four certificates.
    let alice_userid = "<alice@example.org>";
    let (alice, alice_pgp, _) = sq.key_generate(&[], &[alice_userid]);
    sq.cert_import(&alice_pgp);
    let alice = Data {
        key_file: alice_pgp,
        cert: alice,
        sig_file: dir.path().join("alice.sig").display().to_string(),
    };
    let alice_fpr = alice.cert.fingerprint().to_string();

    let bob_userid = "<bob@example.org>";
    let (bob, bob_pgp, _) = sq.key_generate(&[], &[bob_userid]);
    sq.cert_import(&bob_pgp);
    let bob = Data {
        key_file: bob_pgp,
        cert: bob,
        sig_file: dir.path().join("bob.sig").display().to_string(),
    };
    let bob_fpr = bob.cert.fingerprint().to_string();

    let carol_userid =  "<carol@example.org>";
    let (carol, carol_pgp, _) = sq.key_generate(&[], &[carol_userid]);
    sq.cert_import(&carol_pgp);
    let carol = Data {
        key_file: carol_pgp,
        cert: carol,
        sig_file: dir.path().join("carol.sig").display().to_string(),
    };
    let carol_fpr = carol.cert.fingerprint().to_string();

    let dave_userid =  "<dave@other.org>";
    let (dave, dave_pgp, _) = sq.key_generate(&[], &[dave_userid]);
    sq.cert_import(&dave_pgp);
    let dave = Data {
        key_file: dave_pgp,
        cert: dave,
        sig_file: dir.path().join("dave.sig").display().to_string(),
    };
    let dave_fpr = dave.cert.fingerprint().to_string();

    let data: &[&Data] = &[ &alice, &bob, &carol, &dave ][..];

    // Have each certificate sign a message.
    for data in data.iter() {
        sq.sign_args(
            &["--time", &tick()],
            &data.key_file, None,
            &artifact("messages/a-cypherpunks-manifesto.txt"),
            PathBuf::from(data.sig_file.clone()).as_path());
    }

    // None of the certificates can be authenticated so verifying the
    // messages should fail.
    for data in data.iter() {
        sq_verify(&sq, None, &[], &[], &data.sig_file, 0, 1);
    }

    // Have Alice certify Bob as a trusted introducer and have Bob
    // certify Carol.
    sq_authorize(&sq, &alice.key_file,
                 &bob.cert.fingerprint().to_string(), bob_userid,
                 None, Some(1));
    sq_certify(&sq, &bob.key_file,
               &carol.cert.fingerprint().to_string(), carol_userid,
               None);

    // We should be able to verify Alice's, Bob's and Carol's
    // signatures Alice as the trust root.  And Bob's and Carols' with
    // Bob as the trust root.

    sq_verify(&sq, None, &[&alice_fpr], &[], &alice.sig_file, 1, 0);
    sq_verify(&sq, None, &[&alice_fpr], &[], &bob.sig_file, 1, 0);
    sq_verify(&sq, None, &[&alice_fpr], &[], &carol.sig_file, 1, 0);
    sq_verify(&sq, None, &[&alice_fpr], &[], &dave.sig_file, 0, 1);

    sq_verify(&sq, None, &[&bob_fpr], &[], &alice.sig_file, 0, 1);
    sq_verify(&sq, None, &[&bob_fpr], &[], &bob.sig_file, 1, 0);
    sq_verify(&sq, None, &[&bob_fpr], &[], &carol.sig_file, 1, 0);
    sq_verify(&sq, None, &[&bob_fpr], &[], &dave.sig_file, 0, 1);

    sq_verify(&sq, None, &[&carol_fpr], &[], &alice.sig_file, 0, 1);
    sq_verify(&sq, None, &[&carol_fpr], &[], &bob.sig_file, 0, 1);
    sq_verify(&sq, None, &[&carol_fpr], &[], &carol.sig_file, 1, 0);
    sq_verify(&sq, None, &[&carol_fpr], &[], &dave.sig_file, 0, 1);

    sq_verify(&sq, None, &[&dave_fpr], &[], &alice.sig_file, 0, 1);
    sq_verify(&sq, None, &[&dave_fpr], &[], &bob.sig_file, 0, 1);
    sq_verify(&sq, None, &[&dave_fpr], &[], &carol.sig_file, 0, 1);
    sq_verify(&sq, None, &[&dave_fpr], &[], &dave.sig_file, 1, 0);

    // Let's accept Alice, but not (yet) as a trusted introducer.  We
    // should now be able to verify Alice's signature, but not Bob's.
    sq_link(&sq, &alice_fpr, &[ &alice_userid ], &[], &[], true);

    sq_verify(&sq, None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &bob.sig_file, 0, 1);

    // Accept Alice as a trusted introducer.  We should be able to
    // verify Alice, Bob, and Carol's signatures.
    sq.pki_link_authorize(&["--time", &tick(), "--unconstrained"],
                          alice.cert.key_handle(),
                          &[ &alice_userid ]);

    sq_verify(&sq, None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &dave.sig_file, 0, 1);

    // Retract the acceptance for Alice.  If we don't specify a trust
    // root, none of the signatures should verify.
    sq_retract(&sq, &alice_fpr, &[ &alice_userid ], &[]);

    for data in data.iter() {
        sq_verify(&sq, None, &[], &[], &data.sig_file, 0, 1);
    }

    // Accept Alice as a trusted introducer again.  We should be able
    // to verify Alice, Bob, and Carol's signatures.
    sq.pki_link_authorize(&["--time", &tick(), "--unconstrained"],
                          alice.cert.key_handle(),
                          &[ &alice_userid ]);

    sq_verify(&sq, None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &dave.sig_file, 0, 1);

    // Have Bob certify Dave.  Now Dave's signature should also
    // verify.
    sq_certify(&sq, &bob.key_file,
               &dave.cert.fingerprint().to_string(), dave_userid,
               None);

    sq_verify(&sq, None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &dave.sig_file, 1, 0);

    // Change Alice's acceptance to just be a normal certification.
    // We should only be able to verify her signature.
    sq_link(&sq, &alice_fpr, &[ &alice_userid ], &[], &[], true);

    sq_verify(&sq, None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &bob.sig_file, 0, 1);
    sq_verify(&sq, None, &[], &[], &carol.sig_file, 0, 1);
    sq_verify(&sq, None, &[], &[], &dave.sig_file, 0, 1);

    // Change Alice's acceptance to be a ca, but only for example.org,
    // i.e., not for Dave.
    sq.pki_link_authorize(&["--time", &tick(), "--domain", "example.org"],
                          alice.cert.key_handle(),
                          &[ &alice_userid ]);

    sq_verify(&sq, None, &[], &[], &alice.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &bob.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &carol.sig_file, 1, 0);
    sq_verify(&sq, None, &[], &[], &dave.sig_file, 0, 1);



    // A fifth certificate.
    let (ed, ed_pgp, _) = sq.key_generate(
        &["--allow-non-canonical-userids"],
        &[
            "Ed <ed@example.org>",
            "Eddie <ed@example.org>",
            // This is not considered to be an email address as
            // it is not wrapped in angle brackets.
            "ed@some.org",
            // But this is.
            "<ed@other.org>",
        ]);
    sq.cert_import(&ed_pgp);
    let ed_fpr = ed.fingerprint().to_string();
    let ed_sig_file = dir.path().join("ed.sig");

    sq.sign_args(
        &["--time", &tick()],
        &ed_pgp, None,
        &artifact("messages/a-cypherpunks-manifesto.txt"),
        ed_sig_file.as_path());

    // If we don't use --petname, than a self-signed User ID must
    // exist.
    sq_link(&sq, &ed_fpr, &[ "bob@example.com" ], &[], &[], false);
    let ed_sig_file = ed_sig_file.display().to_string();
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 0, 1);

    sq_link(&sq, &ed_fpr, &[], &[ "bob@example.com" ], &[], false);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 0, 1);

    // We should only create links if all the supplied User IDs are
    // valid.
    sq_link(&sq, &ed_fpr, &["ed@some.org", "bob@example.com"], &[], &[], false);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 0, 1);

    sq_link(&sq, &ed_fpr, &["ed@some.org"], &["bob@example.com"], &[], false);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 0, 1);

    // Pass an email address to --userid.  This shouldn't match
    // either.
    sq_link(&sq, &ed_fpr, &["ed@other.org"], &[], &[], false);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 0, 1);

    // Link all User IDs individually.
    sq_link(&sq, &ed_fpr,
            &["ed@some.org", "Ed <ed@example.org>", "Eddie <ed@example.org>"],
            &["ed@other.org"],
            &[], true);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 1, 0);

    // Retract the links one at a time.
    sq_retract(&sq, &ed_fpr, &[], &[ "ed@other.org" ]);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 1, 0);

    sq_retract(&sq, &ed_fpr, &[ "Ed <ed@example.org>" ], &[]);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 1, 0);

    sq_retract(&sq, &ed_fpr, &[ "Eddie <ed@example.org>" ], &[]);
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 1, 0);

    sq_retract(&sq, &ed_fpr, &[ "ed@some.org" ], &[]);
    // Now the certificate should no longer be authenticated.
    sq_verify(&sq, None, &[], &[], &ed_sig_file, 0, 1);

    Ok(())
}

// Set the different parameters.  When the parameters are the same,
// make sure no certifications are written; when they are different
// make sure the file changed.
#[test]
fn sq_pki_link_update_detection() -> Result<()> {
    let sq = Sq::new();

    let alice_userid = "<alice@example.org>";
    let (alice, alice_pgp, _) = sq.key_generate(&[], &[alice_userid]);
    sq.cert_import(&alice_pgp);
    let alice_fpr = alice.fingerprint().to_string();
    let alice_cert_pgp = sq.certd()
        .join(&alice_fpr[0..2].to_ascii_lowercase())
        .join(&alice_fpr[2..].to_ascii_lowercase());

    // Reads and returns file.  Asserts that old and the new contexts
    // are the same (or not).
    let compare = |old: Vec<u8>, file: &Path, same: bool| -> Vec<u8> {
        let new = std::fs::read(file).unwrap();
        if same {
            assert_eq!(old, new, "file unexpectedly changed");
        } else {
            assert_ne!(old, new, "file unexpectedly stayed the same");
        }
        new
    };
    let bytes = std::fs::read(&alice_cert_pgp).unwrap();

    // Retract it.  There is nothing to retract (but this doesn't fail).
    let output = sq_retract(&sq, &alice_fpr, &[], &[]);
    assert!(output.1.contains("never certified"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Link it.
    sq_link(&sq, &alice_fpr, &[], &[], &["--all"], true);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    // As no parameters changed, this should succeeded, but no
    // certification should be written.
    let output = sq_link(&sq, &alice_fpr, &[], &[], &["--all"], true);
    assert!(output.1.contains("certification parameters are unchanged"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Make Alice a CA.
    sq.pki_link_authorize(&["--time", &tick(), "--unconstrained", "--all"],
                          alice.key_handle(),
                          NO_USERIDS);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    sq.pki_link_authorize(&["--time", &tick(), "--unconstrained", "--all"],
                          alice.key_handle(),
                          NO_USERIDS);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Make her a partially trusted CA.
    let output = sq_link(&sq, &alice_fpr, &[], &[],
                         &["--amount", "30", "--all"], true);
    assert!(output.1.contains("was previously"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&sq, &alice_fpr, &[], &[],
                         &["--amount", "30", "--all"], true);
    assert!(output.1.contains("certification parameters are unchanged"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Retract the link.
    let output = sq_retract(&sq, &alice_fpr, &[], &[]);
    assert!(output.1.contains("was previously"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_retract(&sq, &alice_fpr, &[], &[]);
    assert!(output.1.contains("certification parameters are unchanged"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);


    // Link it again.
    let output = sq_link(&sq, &alice_fpr, &[], &[],
                         &["--amount", "10", "--all"], true);
    assert!(output.1.contains("was retracted"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&sq, &alice_fpr, &[], &[],
                         &["--amount", "10", "--all"], true);
    assert!(output.1.contains("certification parameters are unchanged"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // Use a notation.
    let output = sq_link(&sq, &alice_fpr, &[], &[],
                         &["--signature-notation", "foo", "10", "--all"], true);
    assert!(output.1.contains("was previously"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&sq, &alice_fpr, &[], &[],
                         &["--signature-notation", "foo", "10", "--all"], true);
    assert!(output.1.contains("certification parameters are unchanged"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    // The default link again.
    let output = sq_link(&sq, &alice_fpr, &[], &[], &["--all"], true);
    assert!(output.1.contains("was previously"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    let output = sq_link(&sq, &alice_fpr, &[], &[], &["--all"], true);
    assert!(output.1.contains("certification parameters are unchanged"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, true);

    let _ = bytes;
    Ok(())
}

// Check that sq pki link add --temporary works.
#[test]
fn sq_pki_link_add_temporary() -> Result<()> {
    let sq = Sq::new();

    let alice_userid = "<alice@example.org>";
    let (alice, alice_pgp, _) = sq.key_generate(&[], &[alice_userid]);
    sq.cert_import(&alice_pgp);
    let alice_fpr = alice.fingerprint().to_string();
    let alice_cert_pgp = sq.certd()
        .join(&alice_fpr[0..2].to_ascii_lowercase())
        .join(&alice_fpr[2..].to_ascii_lowercase());

    let alice_sig_file = sq.base().join("alice.sig");
    sq.sign_args(
        &["--time", &tick()],
        &alice_pgp, None,
        &artifact("messages/a-cypherpunks-manifesto.txt"),
        alice_sig_file.as_path());

    // Reads and returns file.  Asserts that old and the new contexts
    // are the same (or not).
    let compare = |old: Vec<u8>, file: &Path, same: bool| -> Vec<u8> {
        let new = std::fs::read(file).unwrap();
        if same {
            assert_eq!(old, new, "file unexpectedly changed");
        } else {
            assert_ne!(old, new, "file unexpectedly stayed the same");
        }
        new
    };
    let bytes = std::fs::read(&alice_cert_pgp).unwrap();

    let alice_sig_file = alice_sig_file.display().to_string();
    sq_verify(&sq, None, &[], &[], &alice_sig_file, 0, 1);

    let output = sq_link(&sq, &alice_fpr, &[], &[], &["--temporary", "--all"], true);
    assert!(output.1.contains("certification created"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    // Now it is fully trusted.
    sq_verify(&sq, None, &[], &[], &alice_sig_file, 1, 0);

    // In 6 days, too.
    sq_verify(&sq,
              Some(now() + chrono::Duration::seconds(6 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 1, 0);

    // But in 8 days it will only be partially trusted.
    sq_verify(&sq,
              Some(now() + chrono::Duration::seconds(8 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 0, 1);


    // Now mark it as fully trusted.  It should be trusted now, in 6
    // days and in 8 days.
    let output = sq_link(&sq, &alice_fpr, &[], &[], &["--all"], true);
    assert!(output.1.contains("was previously"),
            "stdout:\n{}\nstderr:\n{}", output.1, output.2);
    eprintln!("{:?}", output);
    let bytes = compare(bytes, &alice_cert_pgp, false);

    sq_verify(&sq, None, &[], &[], &alice_sig_file, 1, 0);

    sq_verify(&sq,
              Some(now() + chrono::Duration::seconds(6 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 1, 0);

    sq_verify(&sq,
              Some(now() + chrono::Duration::seconds(8 * 24 * 60 * 60)),
              &[], &[], &alice_sig_file, 1, 0);

    let _bytes = bytes;

    Ok(())
}

#[test]
fn retract_non_self_signed() {
    // Make sure we can retract non-self signed user IDs.
    let mut sq = Sq::new();

    let alice_userid = "Alice <alice@example.org>";
    let (alice, alice_pgp, _) = sq.key_generate(&[], &[alice_userid]);
    sq.key_import(&alice_pgp);

    let petname = "Mon chouchou";

    let msg = artifact("messages/a-cypherpunks-manifesto.txt");
    let sig_msg = sq.scratch_file(None);
    let sig_msg = sig_msg.as_path();
    let sig_msg_str = sig_msg.display().to_string();
    sq.sign(alice.key_handle(), None, &msg, sig_msg);

    // Verifying should fail: alice's certificate is not linked at all.
    sq_verify(&sq, None, &[], &[], &sig_msg_str, 0, 1);

    // Link a non-self-signed user ID.
    sq.tick(1);
    sq.pki_link_add(&[], alice.key_handle(),
                    &[UserIDArg::AddUserID(petname)]);

    // Now it should work.
    sq_verify(&sq, None, &[], &[], &sig_msg_str, 1, 0);

    // Retract the link.
    sq.tick(1);
    sq_retract(&sq, &alice.fingerprint().to_string(), &[petname], &[]);

    // Now it should fail.
    sq_verify(&sq, None, &[], &[], &sig_msg_str, 0, 1);
}

#[test]
fn retract_weak() {
    // Make sure we can retract signed user IDs whose binding
    // signatures rely on weak cryptography from a valid certificate.
    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("sha1-userid-priv.pgp");
    sq.key_import(&cert_path);

    let cert = Cert::from_file(&cert_path).expect("can read");

    // Make sure the user ID is there and really uses SHA-1.
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");
    let valid_userids: BTreeSet<_> = vc.userids()
        .map(|ua| ua.userid())
        .collect();
    let all_userids: BTreeSet<_> = cert.userids()
        .map(|ua| ua.userid())
        .collect();

    assert!(valid_userids.len() < all_userids.len());

    let weak_userids: Vec<_>
        = all_userids.difference(&valid_userids)
        .map(|u| {
            String::from_utf8_lossy(u.value()).to_string()
        })
        .collect();
    let weak_userids: Vec<&String> = weak_userids.iter().collect();

    // The current policy doesn't allow SHA-1.
    assert!(
        sq.pki_link_add_maybe(&[], cert.key_handle(), &weak_userids)
            .is_err());

    // But the policy as of 2003 did.
    sq.pki_link_add(&["--policy-as-of", "2003-01-01"],
                    cert.key_handle(), &weak_userids);

    // Retract.
    sq.pki_link_retract(&[], cert.key_handle(), &weak_userids[..]);
}

#[test]
fn retract_all() {
    // Link all self-signed user IDs and a non-self-signed user ID.
    // When we retract all, make sure they are all retracted.
    let mut sq = Sq::new();

    let alice_userid = "Alice <alice@example.org>";
    let (alice, alice_pgp, _) = sq.key_generate(&[], &[alice_userid]);
    sq.key_import(&alice_pgp);

    let petname = "Mon chouchou";

    let msg = artifact("messages/a-cypherpunks-manifesto.txt");
    let sig_msg = sq.scratch_file(None);
    let sig_msg = sig_msg.as_path();
    let sig_msg_str = sig_msg.display().to_string();
    sq.sign(alice.key_handle(), None, &msg, sig_msg);

    // Verifying should fail: alice's certificate is not linked at all.
    sq_verify(&sq, None, &[], &[], &sig_msg_str, 0, 1);

    // Link a non-self-signed user ID.
    sq.tick(1);
    sq.pki_link_add(&[], alice.key_handle(), &[UserIDArg::AddUserID(petname)]);

    // Now it should work.
    sq_verify(&sq, None, &[], &[], &sig_msg_str, 1, 0);

    // Retract *all* links.
    sq.tick(1);
    sq_retract(&sq, &alice.fingerprint().to_string(), &[], &[]);

    // Now it should fail.
    sq_verify(&sq, None, &[], &[], &sig_msg_str, 0, 1);
}

#[test]
fn no_ambiguous_email() {
    // Check that we can't address self-signed user IDs by an
    // ambiguous email address.
    let mut sq = Sq::new();

    let alice_userids = &["Alice <alice@example.org>",
                         "Alice Lovelace <alice@example.org>"][..];
    let (alice, alice_pgp, _) = sq.key_generate(&[], alice_userids);
    sq.key_import(&alice_pgp);

    sq.tick(1);

    // --email links a user ID with the specified email address, if it
    // occurs in a self-signed user ID: Ambiguous is allowed.
    assert!(
        sq.pki_link_add_maybe(
            &[], alice.key_handle(), &[UserIDArg::Email("alice@example.org")])
            .is_ok());
    // --userid-by-email links the matching self-signed user ID:
    // Ambiguous is not allowed.
    assert!(
        sq.pki_link_add_maybe(
            &[], alice.key_handle(), &[UserIDArg::ByEmail("alice@example.org")])
            .is_err());
    // --add-email links a user ID with the email address:
    // Ambiguous is allowed.
    assert!(
        sq.pki_link_add_maybe(
            &[], alice.key_handle(), &[UserIDArg::AddEmail("alice@example.org")])
            .is_ok());

    // Not a self-signed user ID.
    assert!(
        sq.pki_link_add_maybe(
            &[], alice.key_handle(), &[UserIDArg::UserID("alice@example.org")])
            .is_err());

    // Fully qualified is okay.
    sq.pki_link_add(
        &[], alice.key_handle(),
        &[UserIDArg::UserID("Alice <alice@example.org>")]);

    // As well as adding a user ID.
    sq.pki_link_add(
        &[], alice.key_handle(),
        &[UserIDArg::AddUserID("<alice@example.org>")]);
}

#[test]
fn special_names() {
    // Check that --cert-special works.
    let sq = Sq::new();

    let check = |cmd: &str, args: &[&str], name: &str, success: bool| {
        let mut c = sq.command();
        c.args([ "pki", "link", cmd, "--cert-special", name ]);
        c.args(args);
        sq.run(c, Some(success));
    };

    const SPECIAL_STRINGS: &'static [&'static str] = &[
        "public-directories",
        "keys.openpgp.org",
        "keys.mailvelope.com",
        "proton.me",
        "wkd",
        "dane",
        "autocrypt",
        "web",
    ];

    for name in SPECIAL_STRINGS.iter() {
        check("add", &["--all"], name, true);
    }
    check("add", &["--all"], "xxx", false);

    for name in SPECIAL_STRINGS.iter() {
        check("retract", &["--all"], name, true);
    }
    check("retract", &["--all"], "xxx", false);

    for name in SPECIAL_STRINGS.iter() {
        check("authorize", &["--all", "--unconstrained"], name, true);
    }
    check("authorize", &["--all", "--unconstrained"], "xxx", false);

    for name in SPECIAL_STRINGS.iter() {
        check("retract", &["--all"], name, true);
    }
    check("retract", &["--all"], "xxx", false);
}

#[test]
fn link_userid_designators() {
    for authorize in [true, false] {
        let link_maybe = |sq: &mut Sq,
                          kh: KeyHandle, userid_arg: UserIDArg|
            -> Result<()>
        {
            sq.tick(1);
            if authorize {
                sq.pki_link_authorize_maybe(
                    &["--unconstrained"], kh, &[ userid_arg ])
            } else {
                sq.pki_link_add_maybe(&[], kh, &[ userid_arg ])
            }
        };

        let link = |sq: &mut Sq,
                    kh: KeyHandle, userid_arg: UserIDArg|
        {
            link_maybe(sq, kh, userid_arg)
                .expect("success")
        };

        let retract = |sq: &mut Sq, kh: KeyHandle| {
            sq.tick(1);
            sq.pki_link_retract(&[ "--all" ], kh.clone(), NO_USERIDS);
        };

        // Check that the different user ID designators work.
        let mut sq = Sq::new();

        let (cert, cert_path, _rev_path) = sq.key_generate(
            &[],
            &[
                "Alice <alice@example.org>",
                "Alice <alice@an.org>",
                "Alice <alice@third.org>",
            ]);
        let fpr = cert.fingerprint().to_string();
        sq.key_import(cert_path);


        // 1. Use --userid to link "Alice <alice@an.org>", which is a
        // self-signed user ID.
        link(&mut sq, cert.key_handle(),
             UserIDArg::UserID("Alice <alice@an.org>"));
        assert!(sq.pki_authenticate(
            &[], &fpr, UserIDArg::UserID("Alice <alice@an.org>")).is_ok());

        retract(&mut sq, cert.key_handle());

        // 2. Use --add-userid to link "Alice <alice@some.org>", which
        // is not a self-signed user ID.

        // This fails with --userid, because it expects a self-signed user ID.
        assert!(link_maybe(
            &mut sq, cert.key_handle(),
            UserIDArg::UserID("Alice <alice@some.org>")).is_err());

        // But it works with --add-userid.
        link(&mut sq, cert.key_handle(),
             UserIDArg::AddUserID("Alice <alice@some.org>"));
        assert!(sq.pki_authenticate(
            &[], &fpr, UserIDArg::UserID("Alice <alice@some.org>")).is_ok());


        retract(&mut sq, cert.key_handle());

        // 3. Use --email to link "<alice@example.org>", which is part
        // of a self-signed user ID.
        //
        // --email => the email address must be part of a self-signed
        // user ID, but uses a user ID with just email address.
        link(&mut sq, cert.key_handle(),
             UserIDArg::Email("alice@example.org"));

        assert!(sq.pki_authenticate(
            &[], &fpr, UserIDArg::UserID("<alice@example.org>")).is_ok());
        if ! authorize {
            // If '<alice@example.org>' is a trusted introducer, then
            // it is used to authenticate the self-signed user ID.
            assert!(sq.pki_authenticate(
                &[], &fpr,
                UserIDArg::UserID("Alice <alice@example.org>")).is_err());
        }


        retract(&mut sq, cert.key_handle());

        // 4. Use --userid-by-email to link "Alice
        // <alice@example.org>", which is a self signed user ID.
        //
        // --userid-by-email => use the matching self signed user ID.
        link(&mut sq, cert.key_handle(),
             UserIDArg::ByEmail("alice@example.org"));

        assert!(sq.pki_authenticate(
            &[], &fpr, UserIDArg::UserID("<alice@example.org>")).is_err());
        assert!(sq.pki_authenticate(
            &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_ok());

        retract(&mut sq, cert.key_handle());

        // 5. Use --add-email to link "<alice@example.com>", which is
        // not part of a self signed user ID.

        // This fails with --email, because it expects a self-signed
        // user ID.
        assert!(link_maybe(
            &mut sq, cert.key_handle(),
            UserIDArg::Email("alice@example.com")).is_err());

        // This fails with --userid-by-email, because there is no
        // self-signed user ID with the email address.
        assert!(link_maybe(
            &mut sq, cert.key_handle(),
            UserIDArg::ByEmail("alice@example.com")).is_err());

        // But it works with --email-or-add.
        link(&mut sq,
             cert.key_handle(), UserIDArg::AddEmail("alice@example.com"));
        assert!(sq.pki_authenticate(
            &[], &fpr, UserIDArg::UserID("<alice@example.com>")).is_ok());

        // Use --add-email to link "<alice@third.org>", which is
        // part of the self signed user ID "Alice <alice@third.org>".
        // This should link "<alice@third.org>", not the self-signed
        // user ID.
        link(&mut sq,
             cert.key_handle(), UserIDArg::AddEmail("alice@third.org"));
        assert!(sq.pki_authenticate(
            &[], &fpr, UserIDArg::UserID("<alice@third.org>")).is_ok());
        if ! authorize {
            // If '<alice@example.org>' is a trusted introducer, then
            // it is used to authenticate the self-signed user ID.
            assert!(sq.pki_authenticate(
                &[], &fpr, UserIDArg::UserID("Alice <alice@third.org>")).is_err());
        }
    }
}

#[test]
fn link_retract_userid_designators() {
    // Check that the different user ID designators work.
    let mut sq = Sq::new();

    let (cert, cert_path, _rev_path) = sq.key_generate(
        &[],
        &[
            "Alice <alice@example.org>",
            "<alice@some.org>",
        ]);
    let fpr = cert.fingerprint().to_string();
    sq.key_import(cert_path);

    // 1. Retract using --userid, which doesn't have to be
    // self-signed.

    // Link "Alice <alice@example.org>", which is self signed.
    sq.tick(1);
    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::UserID("Alice <alice@example.org>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_ok());

    // We can't retract using --email: it retracts "<alice@example.org>".
    sq.tick(1);
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::Email("alice@example.org") ]).is_err());

    sq.tick(1);
    sq.pki_link_retract(&[], cert.key_handle(),
                        &[ UserIDArg::UserID("Alice <alice@example.org>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_err());

    // Link "Alice <alice@example.com>", which is not self signed.
    sq.tick(1);
    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::AddUserID("Alice <alice@example.com>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.com>")).is_ok());

    // We can't retract using --email: it retracts "<alice@example.com>".
    sq.tick(1);
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::Email("alice@example.com") ]).is_err());

    // But we can retract using --user "Alice <alice@example.com>".
    sq.pki_link_retract(&[], cert.key_handle(),
                        &[ UserIDArg::UserID("Alice <alice@example.com>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.com>")).is_err());

    // 2. Retract using "--userid-by-email".

    // Link "Alice <alice@example.org>", which is a self signed user
    // ID.
    sq.tick(1);
    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::UserID("Alice <alice@example.org>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_ok());

    sq.tick(1);
    sq.pki_link_retract(&[], cert.key_handle(),
                        &[ UserIDArg::ByEmail("alice@example.org") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_err());


    // 3. Retract using "--email".  It uses a user ID with just the
    // email address.

    // Link "<alice@example.org>", which is NOT a self signed user
    // ID.
    sq.tick(1);
    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::AddUserID("<alice@example.org>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_err());
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("<alice@example.org>")).is_ok());

    // We can unlink it using --email, because that doesn't hvae to
    // match on self-signed user IDs.
    sq.tick(1);
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::Email("alice@example.org") ]).is_ok());
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_err());

    // Link "<alice@some.org>", which is a self signed user ID.
    sq.tick(1);
    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::UserID("<alice@some.org>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("<alice@some.org>")).is_ok());

    // We can unlink it using --email: that matchs on self-signed user
    // IDs.
    sq.tick(1);
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::Email("alice@some.org") ]).is_ok());
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("<alice@some.org>")).is_err());

    // Link "Alice <alice@example.org>", which is a self signed user
    // ID.
    sq.tick(1);
    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::AddUserID("Alice <alice@example.org>") ]);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_ok());

    // We can't use --email to retract it: that retracts , as that
    // "<alice@example.org>".
    sq.tick(1);
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::Email("alice@example.com") ]).is_err());
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_ok());
    // But we can use --userid-by-email
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::ByEmail("alice@example.org") ]).is_ok());
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID("Alice <alice@example.org>")).is_err());
}

#[test]
fn retract() {
    let mut sq = Sq::new();

    let (cert, cert_path, _rev_path) = sq.key_generate(
        &[], &["Alice <alice@example.org>" ]);
    sq.key_import(cert_path);

    // If a user ID was never linked, retract fails.

    // Check for a self-signed user ID.
    sq.tick(1);
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::UserID("Alice <alice@example.org>") ]).is_err());

    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::Email("alice@example.org") ]).is_err());

    // Check for a user ID that is not self signed.
    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::UserID("Alice <alice@example.com>") ]).is_err());

    assert!(sq.pki_link_retract_maybe(
        &[], cert.key_handle(),
        &[ UserIDArg::Email("alice@example.com") ]).is_err());

    // --all doesn't care.
    assert!(sq.pki_link_retract_maybe(
        &["--all"], cert.key_handle(), NO_USERIDS).is_ok());

    // Now create a link.  If we retract the same link multiple times,
    // we don't get an error, but the subsequent calls won't do
    // anything except emit the message "Certification parameters are
    // unchanged.")
    sq.tick(1);
    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::UserID("Alice <alice@example.org>") ]);

    for _ in 1..4 {
        sq.tick(1);
        sq.pki_link_retract(
            &[], cert.key_handle(),
            &[ UserIDArg::UserID("Alice <alice@example.org>") ]);

        sq.tick(1);
        // --email => "<alice@example.org>", which was not linked.
        assert!(sq.pki_link_retract_maybe(
            &[], cert.key_handle(),
            &[ UserIDArg::Email("alice@example.org") ]).is_err());
    }

    sq.pki_link_add(
        &[], cert.key_handle(),
        &[ UserIDArg::AddUserID("Alice <alice@example.com>") ]);

    for _ in 1..4 {
        sq.tick(1);
        sq.pki_link_retract(
            &[], cert.key_handle(),
            &[ UserIDArg::UserID("Alice <alice@example.com>") ]);

        // --email => "<alice@example.com>", which was not linked.
        sq.tick(1);
        assert!(sq.pki_link_retract_maybe(
            &[], cert.key_handle(),
            &[ UserIDArg::Email("alice@example.com") ]).is_err());
    }

    // --all doesn't care.
    assert!(sq.pki_link_retract_maybe(
        &["--all"], cert.key_handle(), NO_USERIDS).is_ok());
}
