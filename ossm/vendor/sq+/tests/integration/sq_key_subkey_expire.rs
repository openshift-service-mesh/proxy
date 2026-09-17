use std::time::Duration;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;

use super::common::STANDARD_POLICY;
use super::common::Sq;
use super::common::power_set;
use super::common::time_as_string;

#[test]
fn sq_key_subkey_expire() -> Result<()> {
    let mut sq = Sq::new();

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &["alice <alice@example.org>"]);
    let fpr = cert.fingerprint().to_string();

    let updated_path = sq.scratch_file("updated.pgp");
    let updated2_path = sq.scratch_file("updated2.pgp");

    let keys = cert.keys().map(|k| k.key().fingerprint()).collect::<Vec<_>>();

    // Two days go by.
    sq.tick(2 * 24 * 60 * 60);

    for expiring in power_set(&keys) {
        for keystore in [false, true] {
            let cert_expiring = expiring.contains(&cert.fingerprint());

            for (i, fpr) in keys.iter().enumerate() {
                eprintln!("  {}. {}: {}expiring",
                          i, fpr,
                          if expiring.contains(&fpr) {
                              ""
                          } else {
                              "NOT "
                          });
            }

            if keystore {
                sq.key_import(&cert_path);
            }

            // Change the key to expire in one day.
            let mut cmd = sq.command();
            cmd.args([
                "key", "subkey", "expire", "--expiration", "1d",
            ]);
            if keystore {
                cmd.args(["--cert", &fpr ]);
            } else {
                cmd
                    .arg("--overwrite")
                    .arg("--cert-file").arg(&cert_path)
                    .arg("--output").arg(&updated_path);
            }
            for k in expiring.iter() {
                cmd.args(["--key", &k.to_string()]);
            }
            sq.run(cmd, true);

            eprintln!("Updated keys at {} to expire in one day:\n{}",
                      sq.now_as_string(),
                      sq.inspect(&updated_path));

            let updated = if keystore {
                eprintln!("Updated certificate to expire in one day:\n{}",
                          sq.inspect(cert.key_handle()));

                sq.cert_export(cert.key_handle())
            } else {
                eprintln!("Updated certificate to expire in one day:\n{}",
                          sq.inspect(&updated_path));

                Cert::from_file(&updated_path).expect("valid cert")
            };

            // It should be alive now.
            let vc = updated.with_policy(STANDARD_POLICY, sq.now()).expect("valid");
            for k in vc.keys() {
                assert!(k.alive().is_ok());
            }

            // It should be alive in 1 day minus 1 second.
            let t = sq.now() + Duration::new(24 * 60 * 60 - 1, 0);
            eprintln!("Checking expiration status at {}", time_as_string(t.into()));
            let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
            for k in vc.keys() {
                assert!(k.alive().is_ok());
            }

            // But in exactly one day, it should be expired.
            let t = sq.now() + Duration::new(24 * 60 * 60, 0);
            eprintln!("Checking expiration status at {}", time_as_string(t.into()));
            let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
            for k in vc.keys() {
                assert_eq!(
                    cert_expiring || expiring.contains(&k.key().fingerprint()),
                    k.alive().is_err(),
                    "{} is {}alive",
                    k.key().fingerprint(),
                    if k.alive().is_ok() { "" } else { "NOT "});
            }

            // 12 hours go by.  Clear the expiration time.
            sq.tick(12 * 60 * 60);

            let mut cmd = sq.command();
            cmd.args([ "key", "subkey", "expire", "--expiration", "never" ]);
            if keystore {
                cmd.args([ "--cert", &fpr ]);
            } else {
                cmd
                    .arg("--overwrite")
                    .arg("--cert-file").arg(&updated_path)
                    .arg("--output").arg(&updated2_path);
            }
            for k in expiring.iter() {
                cmd.args(["--key", &k.to_string()]);
            }
            sq.run(cmd, true);

            let updated = if keystore {
                eprintln!("Updated certificate at {} to never expire:\n{}",
                          sq.now_as_string(),
                          sq.inspect(cert.key_handle()));

                sq.cert_export(cert.key_handle())
            } else {
                eprintln!("Updated certificate at {} to never expire:\n{}",
                          sq.now_as_string(),
                          sq.inspect(&updated2_path));

                Cert::from_file(&updated2_path).expect("valid cert")
            };

            // It should be alive now.
            let vc = updated.with_policy(STANDARD_POLICY, sq.now())
                .expect("valid");
            for k in vc.keys() {
                assert!(k.alive().is_ok());
            }

            // It should be alive in 1 day minus 1 second.
            let t = sq.now() + Duration::new(24 * 60 * 60 - 1, 0);
            eprintln!("Checking expiration status at {}", time_as_string(t.into()));
            let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
            for k in vc.keys() {
                eprintln!("  {} expires at {}",
                          k.key().fingerprint(),
                          if let Some(t) = k.key_expiration_time() {
                              time_as_string(t.into())
                          } else {
                              "never".to_string()
                          });
                if let Err(err) = k.alive() {
                    panic!("{} should be alive, but it's not: {}",
                           k.key().fingerprint(), err);
                }
            }

            // And in exactly one day...
            let t = sq.now() + Duration::new(24 * 60 * 60, 0);
            eprintln!("Checking expiration status at {}", time_as_string(t.into()));
            let vc = updated.with_policy(STANDARD_POLICY, t).expect("valid");
            for k in vc.keys() {
                eprintln!("  {} expires at {}",
                          k.key().fingerprint(),
                          if let Some(t) = k.key_expiration_time() {
                              time_as_string(t.into())
                          } else {
                              "never".to_string()
                          });
                if let Err(err) = k.alive() {
                    panic!("{} should be alive, but it's not: {}",
                           k.key().fingerprint(), err);
                }
            }
        }
    }

    Ok(())
}

#[test]
fn unbound_subkey() {
    // Make sure we can't extend the expiration time of an unbound
    // subkey.

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

    // Set it to expire in a day.
    let updated_path = sq.scratch_file("updated");
    let updated = sq.key_subkey_expire(cert_path,
                                       &[ unbound ],
                                       "1d",
                                       None,
                                       updated_path.as_path(),
                                       false);
    assert!(updated.is_err());
}

#[test]
fn soft_revoked_subkey() {
    // Make sure we can't extend the expiration time of a soft revoked
    // subkey.

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
            revoked = Some(k.key().fingerprint());
        }
    }
    let revoked = if let Some(revoked) = revoked {
        revoked
    } else {
        panic!("Expected a revoked subkey, but didn't fine one");
    };

    // Set it to expire in a day.
    let updated_path = sq.scratch_file("updated");
    let updated = sq.key_subkey_expire(cert_path,
                                       &[ revoked.clone().into() ],
                                       "1d",
                                       None,
                                       updated_path.as_path(),
                                       true)
        .expect("sq key expire should succeed");

    let vc = updated.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");
    let mut good = false;
    for k in vc.keys() {
        if k.key().fingerprint() == revoked {
            if let RevocationStatus::Revoked(_) = k.revocation_status() {
                panic!("{} shouldn't be revoked, but is.",
                       revoked);
            }

            let expiration = k.key_expiration_time();
            assert_eq!(expiration,
                       Some(sq.now()
                            + std::time::Duration::new(24 * 60 * 60, 0)));
            good = true;
            break;
        }
    }
    assert!(good);
}

#[test]
fn hard_revoked_subkey() {
    // Make sure we can't extend the expiration time of a hard revoked
    // subkey.

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
            revoked = Some(k.key().fingerprint());
        }
    }
    let revoked = if let Some(revoked) = revoked {
        revoked
    } else {
        panic!("Expected a revoked subkey, but didn't fine one");
    };

    // Set it to expire in a day.
    let updated_path = sq.scratch_file("updated");
    let result = sq.key_subkey_expire(cert_path,
                                       &[ revoked.clone().into() ],
                                       "1d",
                                       None,
                                       updated_path.as_path(),
                                       false);
    if result.is_ok() {
        panic!("Updated expiration of hard revoked subkey, but shouldn't have.");
    }
}

#[test]
fn sha1_subkey() {
    // Make sure we can't extend the expiration time of a subkey that
    // is bound using SHA-1.

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

    // Set it to expire in a day.
    let updated_path = sq.scratch_file("updated");
    let result = sq.key_subkey_expire(cert_path,
                                       &[ subkey.clone().into() ],
                                       "1d",
                                       None,
                                       updated_path.as_path(),
                                      false);
    assert!(result.is_err());
}
