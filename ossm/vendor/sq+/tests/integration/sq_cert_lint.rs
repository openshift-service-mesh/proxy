use std::path;

use predicates::prelude::*;

use sequoia_openpgp as openpgp;

use openpgp::Cert;
use openpgp::Packet;
use openpgp::parse::Parse;

use super::common::Sq;

fn dir() -> path::PathBuf {
    path::Path::new("tests").join("data").join("cert-lint")
}

const FROZEN_TIME: &str = "20220101";

// passwords: one '-p' option per element.
// required_fixes: the number of fixes (= new top-level signatures) needed.
// expected_fixes: the number of them that we can create.
fn t(base: &str, prv: Option<&str>, passwords: &[&str],
     required_fixes: usize, expected_fixes: usize)
{
    assert!(required_fixes >= expected_fixes);

    let sq = Sq::new();
    let dir = dir();
    let mut suffixes = vec![ "pub" ];
    if let Some(prv) = prv {
        suffixes.push(prv);
    }

    for suffix in suffixes.iter() {
        for keystore in [false, true] {
            // Lint it.
            let filename = &format!("{}-{}.pgp", base, suffix);
            eprintln!("Linting {}", filename);

            let cert = Cert::from_file(dir.join(filename))
                .expect(&format!("Can parse {}", filename));

            if keystore {
                // When using the keystore, we need to import the key.
                if suffix == &"pub" {
                    eprintln!("Import certificate from {}", filename);

                    let mut cmd = sq.command();
                    cmd
                        .current_dir(&dir)
                        .args([
                            "cert",
                            "import",
                            &filename,
                        ]);
                    let output = cmd.output().expect("can sq cert import");
                    if !output.status.success() {
                        panic!(
                            "sq exited with non-zero status code: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                } else {
                    eprintln!("Import key from {}", filename);

                    let mut cmd = sq.command();
                    cmd
                        .current_dir(&dir)
                        .args([
                            "key",
                            "import",
                            &filename,
                        ]);
                    let output = cmd.output().expect("can sq key import");
                    if !output.status.success() {
                        panic!(
                            "sq exited with non-zero status code: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }

            let mut cmd = sq.command();
            cmd
                .current_dir(&dir)
                .arg("cert").arg("lint")
                .arg("--time").arg(FROZEN_TIME);
            if keystore {
                cmd.arg("--cert").arg(&cert.fingerprint().to_string());
            } else {
                cmd.arg("--cert-file").arg(filename);
            }

            cmd
                .assert()
                .code(if required_fixes > 0 { 1 } else { 0 });


            // Fix it.
            let filename = &format!("{}-{}.pgp", base, suffix);
            eprint!("Fixing {}", filename);
            if passwords.len() > 0 {
                eprint!(" (passwords: ");
                for (i, p) in passwords.iter().enumerate() {
                    if i > 0 {
                        eprint!(", ");
                    }
                    eprint!("{:?}", p)
                }
                eprint!(")");
            }
            eprintln!(".");

            let expected_fixes = if suffix == &"pub" {
                // We only have public key material: we won't be able
                // to fix anything.
                0
            } else {
                expected_fixes
            };
            eprintln!("{} expected fixes, {} required fixes",
                      expected_fixes, required_fixes);

            let mut cmd = sq.command();
            let mut cmd = cmd.current_dir(&dir)
                .args(&[
                    "cert", "lint",
                    "--time", FROZEN_TIME,
                    "--fix",
                ]);
            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.args([
                    "--cert-file", &format!("{}-{}.pgp", base, suffix),
                ]);
            }
            for p in passwords.iter() {
                cmd = cmd.arg("-p").arg(p)
            }
            cmd.assert()
                // If not everything can be fixed, then --fix's exit code is 1.
                .code(if expected_fixes == required_fixes { 0 } else { 1 })
                .stdout(predicate::function(|output: &[u8]| -> bool {
                    if expected_fixes == 0 {
                        // If there are no fixes, nothing is printed.
                        output == b""
                    } else {
                        // Pass the result through the linter.
                        let mut cmd = sq.command();
                        cmd
                            .current_dir(&dir)
                            .arg("cert").arg("lint")
                            .arg("--time").arg(FROZEN_TIME);
                        if keystore {
                            cmd.arg("--cert")
                                .arg(&cert.fingerprint().to_string());
                        } else {
                            cmd.arg("--cert-file").arg("-")
                                .write_stdin(output);
                        }

                        cmd.assert()
                            .code(
                                if expected_fixes == required_fixes {
                                    // Everything should have been fixed.
                                    0
                                } else {
                                    // There are still issues.
                                    1
                                });

                        // Check that the number of new signatures equals
                        // the number of expected new signatures.
                        let orig_sigs: isize = cert
                            .clone()
                            .into_packets()
                            .map(|p| {
                                if let Packet::Signature(_) = p {
                                    1
                                } else {
                                    0
                                }
                            })
                            .sum();

                        let updated_cert = if keystore {
                            let mut cmd = sq.command();
                            let cmd = cmd.current_dir(&dir)
                                .args(&[
                                    "cert", "export",
                                    "--cert", &cert.fingerprint().to_string(),
                                ]);
                            let output = cmd.output()
                                .expect(&format!("Can run sq cert export"));
                            if !output.status.success() {
                                panic!(
                                    "sq exited with non-zero status code: {}",
                                    String::from_utf8_lossy(&output.stderr)
                                );
                            }
                            Cert::from_bytes(&output.stdout)
                        } else {
                            // When not using the keystore, `sq
                            // cert lint --fix` emits the fixed
                            // certificate on stdout.
                            Cert::from_bytes(output)
                        };

                        let fixed_sigs: isize = updated_cert
                            .map(|cert| {
                                cert.into_packets()
                                    .map(|p| {
                                        match p {
                                            Packet::Signature(_) => 1,
                                            Packet::SecretKey(_)
                                                | Packet::SecretSubkey(_) =>
                                                panic!("Secret key material \
                                                        should not be exported!"),
                                            _ => 0,
                                        }
                                    })
                                    .sum()
                            })
                            .map_err(|err| {
                                eprintln!("Parsing fixed certificate: {}", err);
                                0
                            })
                            .unwrap();

                        let fixes = fixed_sigs - orig_sigs;
                        if expected_fixes as isize != fixes {
                            eprintln!("Expected {} fixes, \
                                       found {} additional signatures",
                                      expected_fixes, fixes);
                            false
                        } else {
                            true
                        }
                    }
                }));
        }
    }
}

#[test]
fn known_good() {
    t("gnupg-rsa-normal", Some("priv"), &[], 0, 0);
    t("gnupg-ecc-normal", Some("priv"), &[], 0, 0);
}

#[test]
fn userid_certification() {
    // User ID: SHA256
    // User ID: SHA1
    // Enc Subkey: SHA256
    t("sha1-userid", Some("priv"), &[], 1, 1);
}

#[test]
fn revoked_userid_certification() {
    // A revoked User ID shouldn't be updated.

    // User ID: SHA256
    // User ID: SHA1 (revoked)
    // Enc Subkey: SHA256
    t("sha1-userid-revoked", Some("priv"), &[], 0, 0);
}

#[test]
fn signing_subkey_binding_signature() {
    // User ID: SHA256
    // Enc Subkey: SHA256
    // Sig Subkey: SHA1
    t("sha1-signing-subkey", Some("priv"), &[], 1, 1);
}

#[test]
fn encryption_subkey_binding_signature() {
    // User ID: SHA256
    // Enc Subkey: SHA256
    // Enc Subkey: SHA1
    t("sha1-encryption-subkey", Some("priv"), &[], 1, 1);
}

#[test]
fn subkey_backsig() {
    // User ID: SHA256
    // Enc Subkey: SHA256
    // Sig Subkey: SHA256, backsig: SHA1
    t("sha1-backsig-signing-subkey", Some("priv"), &[], 1, 1);
}

#[test]
fn all_bad() {
    // User ID: SHA1
    // Enc Subkey: SHA1
    t("only-sha1", Some("priv"), &[], 2, 2);

    // We don't fix MD5 signatures.
    //
    // User ID: MD5
    // Enc Subkey: MD5
    t("only-md5", Some("priv"), &[], 2, 0);
}

/// XXX: Disabled because there is no non-interactive way to feed
/// passwords to it.
#[allow(dead_code)]
fn passwords() {
    // User ID: SHA1
    // Enc Subkey: SHA1

    // Wrong password.
    t("all-sha1-password-Foobar", Some("priv"), &["foobar"], 2, 0);
    // Right password.
    t("all-sha1-password-Foobar", Some("priv"), &["Foobar"], 2, 2);

    // Try multiple passwords.
    t("all-sha1-password-Foobar", Some("priv"), &["Foobar", "bar"], 2, 2);
    t("all-sha1-password-Foobar", Some("priv"), &["bar", "Foobar"], 2, 2);
}

/// XXX: Disabled because there is no non-interactive way to feed
/// passwords to it.
#[allow(dead_code)]
fn multiple_passwords() {
    // The primary is encrypted with foo and the signing subkey
    // with bar.  We need to provide both, because the signing
    // subkey needs its backsig updated.

    // User ID: SHA256
    // Enc Subkey: SHA256
    // Enc Subkey: SHA1
    // Sig Subkey: SHA1

    // We only have the password for the signing subkey: we can't
    // update anything.
    t("multiple-passwords", Some("priv"), &["bar", "Foobar"], 2, 0);
    // We only have the password for the primary key: we can't
    // update the backsig.
    t("multiple-passwords", Some("priv"), &["foo", "Foobar"], 2, 1);
    // We have all passwords: we can fix everything.
    t("multiple-passwords", Some("priv"), &["bar", "Foobar", "foo"], 2, 2);
}

#[test]
fn offline_subkeys() {
    // The User ID, the encryption subkey, and the signing subkey
    // all need new signatures.  With just the primary key, we are
    // able to create two of the three required signatures.

    // User ID: SHA1
    // Enc Subkey: SHA1
    // Sig Subkey: SHA1

    // We can't update the backsig.
    t("sha1-offline-subkeys", Some("offline"), &[], 3, 2);
    // We can fix everything.
    t("sha1-offline-subkeys", Some("priv"), &[], 3, 3);
}

#[test]
fn sha1_authentication_subkey() {
    // User ID: SHA1
    // Enc Subkey: SHA1
    // Auth Subkey: SHA1
    t("sha1-authentication-subkey", Some("priv"), &[], 3, 3);
}

#[test]
fn authentication_subkey() {
    // An authentication subkey doesn't require a backsig.  Make
    // sure we don't flag a missing backsig as an error.

    // User ID: SHA512
    // Enc Subkey: SHA512
    // Auth Subkey: SHA512
    t("authentication-subkey", Some("priv"), &[], 0, 0);
}

#[test]
fn sha1_userid_sha256_subkeys() {
    // The User ID is protected with a SHA-1 signature, but two
    // subkeys are protected with SHA256.  Make sure the subkeys
    // don't get new binding signatures.

    // User ID: SHA1
    // Enc Subkey: SHA1
    // Sig Subkey: SHA256
    // Enc Subkey: SHA256
    t("sha1-userid-sha256-subkeys", Some("priv"), &[], 2, 2);
}

#[test]
fn no_backsig() {
    // If a key doesn't have a backsig and needs one, it won't be
    // detected as an issue, because it is not valid under
    // SHA1+SP.  That's okay.

    // User ID: SHA512
    // Sig Subkey: SHA512, no backsig.
    t("no-backsig", Some("priv"), &[], 0, 0);
}

#[test]
fn sha512_self_sig_sha1_revocation() {
    // Under the standard policy, SHA1 revocations are considered
    // bad.  We assume that SP+SHA-1 is strictly more liberal than
    // SP (i.e., it accepts at least everything that SP accepts).

    // User ID: SHA512, SHA-1 revocation.
    t("sha512-self-sig-sha1-revocation", None, &[], 0, 0);
}

#[test]
fn revoked_certificate() {
    // The certificate is only valid under SP+SHA1, and the
    // revocation certificate uses SHA1.  There is no need to
    // upgrade the certificate or the revocation certificate.

    // User ID: SHA1
    // Enc Subkey: SHA1
    // Revocation: SHA1
    t("sha1-cert-sha1-revocation", Some("priv"), &[], 0, 0);

    // The certificate is only valid under SP+SHA1, and the
    // revocation certificate uses SHA256.  There is no need to
    // upgrade the certificate or the revocation certificate.

    // User ID: SHA1
    // Enc Subkey: SHA1
    // Revocation: SHA256
    t("sha1-cert-sha256-revocation", Some("priv"), &[], 0, 0);

    // The certificate is valid under SP (the signatures use
    // SHA512), but there are two revocation certificates that use
    // SHA1.  Make sure we upgrade them.

    // User ID: SHA512
    // Enc Subkey: SHA512
    // Revocation: SHA1
    // Revocation: SHA1
    t("sha512-cert-sha1-revocation", Some("priv"), &[], 2, 2);

    // The certificate is valid under SP (the signatures use
    // SHA256), and it is revoked using a SHA256 revocation
    // certificate, which is also valid under SP.  It also has a
    // SHA-1 protected signing subkey.  Because the certificate is
    // revoked and the revocation certificate uses SHA256, we
    // don't need to fix the SHA-1 signature.  Make sure we don't.

    // User ID: SHA256
    // Enc Subkey: SHA256
    // Sig Subkey: SHA1
    // Revocation: SHA256
    t("sha256-cert-sha256-revocation", Some("priv"), &[], 0, 0);
}

#[test]
fn expired_certificates() {
    // User ID: SHA256 (expired)
    // Enc Subkey: SHA256
    t("sha256-expired", Some("priv"), &[], 0, 0);

    // User ID: SHA1 (expired)
    // Enc Subkey: SHA1
    t("sha1-expired", Some("priv"), &[], 0, 0);

    // User ID: SHA256 (old, expired), SHA1 (new, live)
    // Enc Subkey: SHA256
    t("sha256-expired-sha1-live", Some("priv"), &[], 1, 1);
}

#[test]
fn signature() {
    let sq = Sq::new();
    sq.command()
        .current_dir(&dir())
        .args(&[
            "cert", "lint",
            "--time", FROZEN_TIME,
            "--cert-file", "msg.sig",
        ])
        .assert()
        // If there are issues, the command fails.
        .failure();
}
