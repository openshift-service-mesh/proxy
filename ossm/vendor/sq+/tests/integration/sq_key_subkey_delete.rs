use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;

use super::common::FileOrKeyHandle;
use super::common::power_set;
use super::common::Sq;
use super::common::STANDARD_POLICY;

fn check<'a, H>(
    sq: &Sq,
    cert_handle: H,
    to_delete: &[KeyHandle],
    success: bool)
where H: Into<FileOrKeyHandle>,
{
    let cert_handle = cert_handle.into();

    eprintln!("Deleting keys from {:?}:", cert_handle);
    for k in to_delete.iter() {
        eprintln!("  - {}", k);
    }

    // Delete the selection.
    let result = sq.try_key_subkey_delete(&cert_handle, to_delete, None);
    let got = match (success, result) {
        (true, Ok(cert)) => cert,
        (true, Err(err)) => {
            panic!("Failed, but should have succeeded: {}", err)
        }
        (false, Ok(_)) => {
            panic!("Succeded, but should have failed")
        }
        (false, Err(_)) => return,
    };

    // Make sure we got exactly what we asked for; no
    // more, no less.
    eprintln!("Result:");

    let mut deletions = 0;
    for got in got.keys().map(|ka| ka.key()) {
        eprintln!("  {} {} secret key material",
                  got.fingerprint(),
                  if got.has_secret() {
                      "has"
                  } else {
                      "doesn't have"
                  });

        let should_have_deleted
            = to_delete.iter().find(|kh| kh.aliases(got.key_handle())).is_some();

        if should_have_deleted {
            assert!(
                ! got.has_secret(),
                "got secret key material \
                 for a key we should have deleted ({})",
                got.fingerprint());

            deletions += 1;
        } else {
            assert!(
                got.has_secret(),
                "didn't get secret key material \
                 for a key we didn't delete ({})",
                got.fingerprint());
        }
    }
    assert_eq!(deletions, to_delete.len());
}

#[test]
fn sq_key_subkey_delete() -> Result<()>
{
    let sq = Sq::new();

    // Generate a key in a file.
    let (cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);
    assert!(cert.is_tsk());

    // Delete each non-empty subset of keys.

    eprintln!("Certificate:");
    for k in cert.keys() {
        eprintln!("  {}", k.key().fingerprint());
    }

    let keys: Vec<Key<_, _>> = cert.keys()
        .map(|k| {
            k.key().clone()
        })
        .collect();

    let key_ids = keys.iter().map(|k| k.fingerprint()).collect::<Vec<_>>();

    for (((i, to_delete), keystore), by_fpr) in power_set(&key_ids).into_iter()
        .enumerate()
        .flat_map(|x| [(x.clone(), false), (x.clone(), true)])
        .flat_map(|x| [(x.clone(), false), (x.clone(), true)])
    {
        eprintln!("Test #{}, by {}, from {}:",
                  i + 1,
                  if by_fpr { "fingerprint" } else { "key ID" },
                  if keystore {
                      "the key store".to_string()
                  } else {
                      cert_file.display().to_string()
                  });

        let to_delete: Vec<KeyHandle> = if by_fpr {
            to_delete.iter()
                .map(|fpr| KeyHandle::from(fpr))
                .collect()
        } else {
            to_delete.iter()
                .map(|fpr| KeyHandle::from(KeyID::from(fpr)))
                .collect()
        };

        if keystore {
            // Import it into the key store.
            sq.key_import(&cert_file);
            check(&sq, cert.key_handle(), &to_delete, true);
        } else {
            check(&sq, &cert_file, &to_delete, true);
        }
    }

    Ok(())
}

#[test]
fn unbound_subkey() {
    // Make sure we can't delete an unbound subkey.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("unbound-subkey.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");

    // One subkey should be considered invalid.
    assert!(vc.keys().count() < cert.keys().count());

    let unbound = "E992BF8BA7A27BB4FBB71D973857E47B14874045"
        .parse::<KeyHandle>().expect("valid");

    check(&sq, &cert_path, &[ unbound ], false);
}

#[test]
fn soft_revoked_subkey() {
    // Make sure we can delete a soft revoked subkey.

    let sq = Sq::new();

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
    let revoked = if let Some(revoked) = revoked {
        revoked
    } else {
        panic!("Expected a revoked subkey, but didn't fine one");
    };

    check(&sq, &cert_path, &[ revoked ], true);
}

#[test]
fn hard_revoked_subkey() {
    // Make sure we can delete a hard revoked subkey.

    let sq = Sq::new();

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
    let revoked = if let Some(revoked) = revoked {
        revoked
    } else {
        panic!("Expected a revoked subkey, but didn't fine one");
    };

    check(&sq, &cert_path, &[ revoked ], true);
}

#[test]
fn sha1_subkey() {
    // Make sure we can delete a subkey that is bound using SHA-1.

    let sq = Sq::new();

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

    let subkey = all_subkeys[0].clone();
    check(&sq, &cert_path, &[ KeyHandle::from(subkey) ], true);
}
