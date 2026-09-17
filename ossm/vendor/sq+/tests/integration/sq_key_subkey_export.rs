use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;
use openpgp::types::RevocationType;

use super::common::power_set;
use super::common::STANDARD_POLICY;
use super::common::Sq;

/// Check that invalid syntax is caught.
#[test]
fn sq_key_subkey_export_syntax() {
    let sq = Sq::new();

    let userid = "alice <alice@example.org>";
    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[userid]);
    sq.key_import(&cert_path);

    // A trivial test to make sure it works.
    sq.key_subkey_export(cert.key_handle(), vec![ cert.key_handle() ]);

    let fpr = cert.fingerprint().to_string();
    let subkey = cert.keys().subkeys().next().unwrap().key().fingerprint().to_string();

    // Make sure "--key" is required.
    let mut cmd = sq.command();
    cmd.args([
        "key", "subkey", "export",
        "--cert", &fpr,
    ]);
    sq.run(cmd, false);

    // Make sure "--cert" is specified at most once.
    let mut cmd = sq.command();
    cmd.args([
        "key", "subkey", "export",
        "--cert", &fpr,
        "--cert", &fpr,
        "--key", &fpr,
    ]);
    sq.run(cmd, false);

    // Make sure arguments from the "--cert" family are specified at
    // most once.
    let mut cmd = sq.command();
    cmd.args([
        "key", "subkey", "export",
        "--cert", &fpr,
        "--userid", userid,
        "--key", &fpr,
    ]);
    sq.run(cmd, false);

    // Make sure "--cert" is a primary key.
    let mut cmd = sq.command();
    cmd.args([
        "key", "subkey", "export",
        "--cert", &subkey,
        "--key", &fpr,
    ]);
    sq.run(cmd, false);
}

#[test]
fn by_email() {
    let mut sq = Sq::new();

    let userid = "alice <alice@example.org>";
    let (cert1, cert1_path, _rev_path)
        = sq.key_generate(&[], &[userid]);
    sq.key_import(&cert1_path);

    let (cert2, cert2_path, _rev_path)
        = sq.key_generate(&[], &[userid]);
    sq.key_import(&cert2_path);

    for i in [0, 1, 2] {
        let mut cmd = sq.command();
        cmd.args([
            "key", "subkey", "export",
            "--cert-email", "alice@example.org",
            "--key", &cert1.fingerprint().to_string(),
        ]);
        let output = sq.run(cmd, i == 1);
        match i {
            0 => {
                // Not linked.
                assert!(! output.status.success());

                // Link cert1.
                sq.tick(1);
                sq.pki_link_add(&[], cert1.key_handle(), &[userid]);
            }
            1 => {
                assert!(output.status.success());
                let cert = Cert::from_bytes(&output.stdout)
                    .expect("can read cert");
                assert!(cert.is_tsk());

                // Link cert2.
                sq.tick(1);
                sq.pki_link_add(&[], cert2.key_handle(), &[userid]);
            }
            2 => {
                // --email is now ambiguous.
                assert!(! output.status.success());
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn revoked_userid() {
    // Make sure we can export keys from a certificate where all user
    // IDs are revoked.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("retired-userid.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    let ua = vc.userids().next().expect("have a user ID");
    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
    } else {
        panic!("User ID should be revoked, but isn't.");
    };

    sq.key_import(&cert_path);

    let keys = cert.keys().map(|k| k.key().fingerprint()).collect::<Vec<_>>();
    for selection in power_set(&keys) {
        let exported = sq.key_subkey_export(
            vc.key_handle(), selection.clone());
        for k in exported.keys() {
            if selection.contains(&k.key().fingerprint()) {
                assert!(k.key().has_secret());
            } else {
                assert!(! k.key().has_secret());
            }
        }
    }
}

#[test]
fn hard_revoked_subkey() {
    // Make sure we can export subkeys that are hard revoked.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("hard-revoked-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    let mut hard_revoked_subkeys = 0;
    for ka in vc.keys() {
        if let RevocationStatus::Revoked(sigs) = ka.revocation_status() {
            for sig in sigs {
                let reason = sig.reason_for_revocation();
                let bad = if let Some((reason, _)) = reason {
                    reason.revocation_type() == RevocationType::Hard
                } else {
                    true
                };

                if bad {
                    hard_revoked_subkeys += 1;
                    break;
                }
            }
        }
    }
    assert_eq!(hard_revoked_subkeys, 1);

    sq.key_import(&cert_path);

    let keys = cert.keys().map(|k| k.key().fingerprint()).collect::<Vec<_>>();
    for selection in power_set(&keys) {
        let exported = sq.key_subkey_export(
            vc.key_handle(), selection.clone());
        for k in exported.keys() {
            if selection.contains(&k.key().fingerprint()) {
                assert!(k.key().has_secret());
            } else {
                assert!(! k.key().has_secret());
            }
        }
    }
}

#[test]
fn only_sha1() {
    // Make sure we can export subkeys that are not valid under the
    // standard policy.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("only-sha1-priv.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");

    // It shouldn't be valid under the standard policy.
    assert!(cert.with_policy(STANDARD_POLICY, sq.now()).is_err());

    sq.key_import(&cert_path);

    let keys = cert.keys().map(|k| k.key().fingerprint()).collect::<Vec<_>>();
    for selection in power_set(&keys) {
        let exported = sq.key_subkey_export(
            cert.key_handle(), selection.clone());
        for k in exported.keys() {
            if selection.contains(&k.key().fingerprint()) {
                assert!(k.key().has_secret());
            } else {
                assert!(! k.key().has_secret());
            }
        }
    }
}

#[test]
fn sha1_subkey() {
    // Make sure we can export subkeys that are not valid under the
    // standard policy.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("sha1-subkey-priv.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");

    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid under standard policy");
    assert!(cert.keys().count() > vc.keys().count());

    sq.key_import(&cert_path);

    let keys = cert.keys().map(|k| k.key().fingerprint()).collect::<Vec<_>>();
    for selection in power_set(&keys) {
        let exported = sq.key_subkey_export(
            cert.key_handle(), selection.clone());
        for k in exported.keys() {
            if selection.contains(&k.key().fingerprint()) {
                assert!(k.key().has_secret());
            } else {
                assert!(! k.key().has_secret());
            }
        }
    }
}
