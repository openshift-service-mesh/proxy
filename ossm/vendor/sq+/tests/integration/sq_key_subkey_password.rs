use std::path::Path;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;

use super::common::power_set;
use super::common::Sq;
use super::common::STANDARD_POLICY;

fn check(
    sq: &Sq,
    cert_file: &Path,
    to_change: &[KeyHandle],
    success: bool)
{
    let cert = Cert::from_file(&cert_file).expect("can read");

    eprintln!("Changing password for {:?}:", cert_file);
    for k in to_change.iter() {
        eprintln!("  - {}", k);
    }

    let password = sq.scratch_file("password");
    std::fs::write(&password, "this is a super secret password")
        .expect("can write");

    for keystore in [false, true] {
        // Change the password for the selection.
        let result = if keystore {
            // Import it into the key store.
            sq.key_import(&cert_file);

            sq.try_key_subkey_password(
                cert.key_handle(), &to_change,
                None, Some(&password),
                None)
        } else {
            sq.try_key_subkey_password(
                cert_file, &to_change,
                None, Some(&password),
                None)
        };
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
        eprintln!("  Got:");

        let mut changes = 0;
        for got in got.keys().map(|ka| ka.key()) {
            eprintln!("    {} {} encrypted secret key material",
                      got.fingerprint(),
                      if got.has_unencrypted_secret() {
                          "doesn't have"
                      } else {
                          "has"
                      });

            let should_have_changed = to_change.iter()
                .find(|kh| kh.aliases(got.key_handle()))
                .is_some();

            if should_have_changed {
                assert!(
                    ! got.has_unencrypted_secret(),
                    "got unencrypted secret key material \
                     for a key whose password we changed ({})",
                    got.fingerprint());

                changes += 1;
            } else {
                assert!(
                    got.has_unencrypted_secret(),
                    "didn't get encrypted secret key material \
                     for a key whose password we changed ({})",
                    got.fingerprint());
            }
        }
        assert_eq!(changes, to_change.len());
    }
}


#[test]
fn sq_key_subkey_password_0() -> Result<()> {
    sq_key_subkey_password_mod(0)
}

#[test]
fn sq_key_subkey_password_1() -> Result<()> {
    sq_key_subkey_password_mod(1)
}

#[test]
fn sq_key_subkey_password_2() -> Result<()> {
    sq_key_subkey_password_mod(2)
}

#[test]
fn sq_key_subkey_password_3() -> Result<()> {
    sq_key_subkey_password_mod(3)
}

fn sq_key_subkey_password_mod(modulus: usize) -> Result<()>
{
    let sq = Sq::new();

    // Generate a key in a file.
    let (cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);
    assert!(cert.is_tsk());

    // Change the password each non-empty subset of keys.

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

    for ((i, to_change), by_fpr) in power_set(&key_ids).into_iter()
        .enumerate()
        .filter(|(i, _)| i % 4 == modulus)
        .flat_map(|x| [(x.clone(), false), (x.clone(), true)])
    {
        eprintln!("Test #{}, by {}, from {}:",
                  i + 1,
                  if by_fpr { "fingerprint" } else { "key ID" },
                  cert_file.display().to_string());
        eprintln!("  Changing the password for:");
        for k in to_change.iter() {
            eprintln!("    {}", k);
        }

        let to_change: Vec<KeyHandle> = if by_fpr {
            to_change.iter()
                .map(|fpr| KeyHandle::from(fpr))
                .collect()
        } else {
            to_change.iter()
                .map(|fpr| KeyHandle::from(KeyID::from(fpr)))
                .collect()
        };

        check(&sq, &cert_file, &to_change, true);
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
