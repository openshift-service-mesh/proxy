use std::collections::HashSet;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;

use super::common::FileOrKeyHandle;
use super::common::STANDARD_POLICY;
use super::common::Sq;

#[test]
fn sq_key_password() -> Result<()> {
    let mut sq = Sq::new();

    let (cert, cert_path, _rev_path) = sq.key_generate(&[], &["alice"]);

    let orig_password = sq.scratch_file("orig-password.txt");
    std::fs::write(&orig_password, "t00 ez").unwrap();

    let new_password = sq.scratch_file("new-password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let msg_txt = sq.scratch_file("msg.txt");
    std::fs::write(&msg_txt, "hello world").unwrap();


    for keystore in [false, true] {
        eprintln!("Keystore: {}", keystore);

        // Two days go by.
        sq.tick(2 * 24 * 60 * 60);

        if keystore {
            sq.key_import(&cert_path);
        }

        let cert_handle = if keystore {
            FileOrKeyHandle::from(cert.fingerprint())
        } else {
            cert_path.as_path().into()
        };

        // Sign a message.  No password should be required.
        sq.sign(&cert_handle, None, msg_txt.as_path(), None);

        // Change the key's password.
        eprintln!("Change the key's password.");
        let cert_updated = sq.scratch_file("cert-updated");
        let cert = sq.key_password(
            &cert_handle,
            None, Some(&new_password),
            if keystore { None } else { Some(cert_updated.as_path()) });
        assert!(cert.keys().all(|ka| {
            ka.key().has_secret()
                && ! ka.key().has_unencrypted_secret()
        }));

        let cert_handle = if keystore {
            FileOrKeyHandle::from(cert.fingerprint())
        } else {
            cert_updated.as_path().into()
        };

        // Sign a message.
        sq.sign(&cert_handle,
                Some(new_password.as_path()),
                msg_txt.as_path(), None);

        // Clear the key's password.
        eprintln!("Clear the key's password.");
        let cert_updated2 = sq.scratch_file("cert-updated2");

        let cert = sq.key_password(
            &cert_handle,
            Some(&new_password), None,
            if keystore { None } else { Some(cert_updated2.as_path()) });
        assert!(cert.keys().all(|ka| ka.key().has_unencrypted_secret()));

        let cert_handle = if keystore {
            FileOrKeyHandle::from(cert.fingerprint())
        } else {
            cert_updated2.as_path().into()
        };

        // Sign a message.
        sq.sign(&cert_handle, None, msg_txt.as_path(), None);
    }

    Ok(())
}

#[test]
fn unbound_subkey() {
    // Make sure we don't change the password for an unbound subkey.

    let sq = Sq::new();

    let new_password = sq.scratch_file("new-password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let cert_path = sq.test_data()
        .join("keys")
        .join("unbound-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // One subkey should be considered invalid.
    let bound: HashSet<Fingerprint>
        = HashSet::from_iter(vc.keys().map(|ka| ka.key().fingerprint()));
    let all: HashSet<Fingerprint>
        = HashSet::from_iter(cert.keys().map(|ka| ka.key().fingerprint()));
    assert!(bound.len() < all.len());


    let result = sq.key_password(
        &cert_path, None, Some(&new_password), None);

    // Make sure the password for the unbound key was not changed.
    for ka in result.keys() {
        if bound.contains(&ka.key().fingerprint()) {
            assert!(! ka.key().has_unencrypted_secret());
        } else {
            assert!(ka.key().has_unencrypted_secret());
        }
    }
}

#[test]
fn soft_revoked_subkey() {
    // Make sure we change the password for a soft revoked subkey.

    let sq = Sq::new();

    let new_password = sq.scratch_file("new-password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let cert_path = sq.test_data()
        .join("keys")
        .join("soft-revoked-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // Make sure the revoked key is there and is really revoked.
    let mut revoked = None;
    for k in vc.keys().subkeys() {
        if let RevocationStatus::Revoked(_) = k.revocation_status() {
            assert!(revoked.is_none(),
                    "Only expected a single revoked subkey");
            revoked = Some(k.key().key_handle());
        }
    }
    if revoked.is_none() {
        panic!("Expected a revoked subkey, but didn't fine one");
    }

    let updated = sq.key_password(
        cert_path, None, Some(new_password.as_path()), None);
    for ka in updated.keys() {
        assert!(! ka.key().has_unencrypted_secret());
    }
}

#[test]
fn hard_revoked_subkey() {
    // Make sure we can delete a hard revoked subkey.

    let sq = Sq::new();

    let new_password = sq.scratch_file("new-password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let cert_path = sq.test_data()
        .join("keys")
        .join("hard-revoked-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // Make sure the revoked key is there and is really revoked.
    let mut revoked = None;
    for k in vc.keys().subkeys() {
        if let RevocationStatus::Revoked(_) = k.revocation_status() {
            assert!(revoked.is_none(),
                    "Only expected a single revoked subkey");
            revoked = Some(k.key().key_handle());
        }
    }
    if revoked.is_none() {
        panic!("Expected a revoked subkey, but didn't fine one");
    }

    let updated = sq.key_password(
        cert_path, None, Some(new_password.as_path()), None);
    for ka in updated.keys() {
        assert!(! ka.key().has_unencrypted_secret());
    }
}

#[test]
fn sha1_subkey() {
    // Make sure we can change the password of keys that are bound
    // using SHA-1.

    let sq = Sq::new();

    let new_password = sq.scratch_file("new-password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let cert_path = sq.test_data()
        .join("keys")
        .join("sha1-subkey-priv.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // Make sure the subkey key is there and really uses SHA-1.
    let valid_subkeys: Vec<_> = vc.keys().subkeys()
        .map(|ka| ka.key().fingerprint())
        .collect();
    let all_subkeys: Vec<_> = cert.keys().subkeys()
        .map(|ka| ka.key().fingerprint())
        .collect();

    assert_eq!(valid_subkeys.len(), 0);
    assert_eq!(all_subkeys.len(), 1);

    let updated = sq.key_password(
        cert_path, None, Some(new_password.as_path()), None);
    for ka in updated.keys() {
        assert!(! ka.key().has_unencrypted_secret());
    }
}

#[test]
fn subkey_without_secret_key_material() {
    // Make sure we can change the password of keys where some of the
    // subkeys are missing secret key material.

    let sq = Sq::new();

    let new_password = sq.scratch_file("new-password.txt");
    std::fs::write(&new_password, "crazy passw0rd").unwrap();

    let (cert, cert_path, _rev_path) = sq.key_generate(&[], &["alice"]);

    // Delete some secret key material.
    let stripped = cert.keys().subkeys().next().unwrap().key();

    let update = sq.scratch_file(
        Some(&format!("delete-{}", stripped.fingerprint())[..]));
    sq.key_subkey_delete(
        cert_path, &[stripped.key_handle()], update.as_path());

    // Make sure it is stripped.
    let cert = Cert::from_file(&update).expect("can read");
    for ka in cert.keys() {
        if ka.key().fingerprint() == stripped.fingerprint() {
            assert!(! ka.key().has_secret(),
                    "{} still has secret key material", ka.key().fingerprint());
        } else {
            assert!(ka.key().has_secret());
        }
    }

    let updated = sq.key_password(
        &update, None, Some(new_password.as_path()), None);
    for ka in updated.keys() {
        assert!(! ka.key().has_unencrypted_secret());
    }
}
