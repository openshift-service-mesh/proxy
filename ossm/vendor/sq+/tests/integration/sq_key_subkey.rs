use std::time::Duration;

use sequoia_openpgp as openpgp;
use openpgp::packet::Key;
use openpgp::parse::Parse;
use openpgp::types::KeyFlags;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Result;

use super::common::NO_USERIDS;
use super::common::STANDARD_POLICY;
use super::common::Sq;
use super::common::UserIDArg;
use super::common::compare_notations;
use super::common::time_as_string;

#[test]
fn sq_key_subkey() -> Result<()> {
    let sq = Sq::new();

    for (arg, expected_key_flags, expected_count) in [
        ("--can-authenticate", KeyFlags::empty().set_authentication(), 2),
        ("--can-encrypt=universal", KeyFlags::empty().set_transport_encryption(), 2),
        ("--can-encrypt=universal", KeyFlags::empty().set_storage_encryption(), 2),
        ("--can-sign", KeyFlags::empty().set_signing(), 2),
    ] {
        for keystore in [false, true] {
            let (cert, cert_path, _rev_path)
                = sq.key_generate(&[], &["alice <alice@example.org>"]);

            let modified_cert_path = sq.scratch_file("new_key.pgp");

            if keystore {
                sq.key_import(&cert_path);
            }

            // Add the subkey.
            let mut cmd = sq.command();
            cmd.args([
                "key",
                "subkey",
                "add",
                "--without-password",
                arg,
            ]);

            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.args([
                    "--overwrite",
                    "--output",
                    &modified_cert_path.to_string_lossy(),
                    "--cert-file", &cert_path.to_string_lossy(),
                ]);
            }
            cmd.assert().success();

            let cert = if keystore {
                sq.cert_export(cert.key_handle())
            } else {
                Cert::from_file(&modified_cert_path)?
            };
            let valid_cert = cert.with_policy(STANDARD_POLICY, None)?;

            assert_eq!(
                valid_cert.keys().key_flags(&expected_key_flags).count(),
                expected_count
            );
        }
    }

    Ok(())
}

#[test]
fn sq_key_subkey_add_with_password() -> Result<()> {
    let sq = Sq::new();

    let password2 = "hunter2";
    let path2 = sq.base().join("password2");
    std::fs::write(&path2, password2)?;

    let (cert, cert_path, _) = sq.key_generate(&[
        "--cannot-sign",
        "--cannot-authenticate",
        "--cannot-encrypt",
        "--new-password-file", &path2.display().to_string(),
    ], NO_USERIDS);

    assert!(cert.is_tsk());
    assert_eq!(cert.keys().subkeys().count(), 0);
    let key = cert.primary_key().key();
    let secret = key.optional_secret().unwrap();
    assert!(secret.is_encrypted());
    assert!(secret.clone().decrypt(key, &password2.into()).is_ok());

    // Add the subkey.
    let password3 = "hunter3";
    let path3 = sq.base().join("password3");
    std::fs::write(&path3, password3)?;

    let output = sq.base().join("output");
    let mut cmd = sq.command();
    cmd.args([
        "key",
        "subkey",
        "add",
        "--can-authenticate",
        "--cert-file", &cert_path.display().to_string(),
        "--password-file", &path2.display().to_string(),
        "--new-password-file", &path3.display().to_string(),
        "--output", &output.display().to_string(),
    ]);
    sq.run(cmd, Some(true));

    let cert = Cert::from_file(output)?;

    assert!(cert.is_tsk());
    assert_eq!(cert.keys().subkeys().count(), 1);
    let key = cert.primary_key().key();
    let secret = key.optional_secret().unwrap();
    assert!(secret.is_encrypted());
    assert!(secret.clone().decrypt(key, &password2.into()).is_ok());

    let key = cert.keys().subkeys().next().unwrap().key();
    let secret = key.optional_secret().unwrap();
    assert!(secret.is_encrypted());
    assert!(secret.clone().decrypt(key, &password3.into()).is_ok());

    Ok(())
}

#[test]
fn sq_key_subkey_revoke() -> Result<()> {
    let sq = Sq::new();
    let time = sq.now();

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            &[][..],
            None,
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::KeyRetired, "retired", &[][..], None),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::KeySuperseded, "superseded", &[][..], None),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::Unspecified, "unspecified", &[][..], None),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
    ] {
        eprintln!("==========================");
        eprintln!("reason: {}, message: {}, notations: {:?}, time: {:?}",
                  reason, reason_str, notations, revocation_time);

        for keystore in [false, true].into_iter() {
            eprintln!("--------------------------");
            eprintln!("keystore: {}", keystore);

            let (cert, cert_path, _rev_path)
                = sq.key_generate(&[], &["alice <alice@example.org>"]);

            let valid_cert = cert.with_policy(STANDARD_POLICY, Some(time.into()))?;
            let fingerprint = valid_cert.clone().fingerprint();
            let subkey: Key<_, _> = valid_cert
                .with_policy(STANDARD_POLICY, Some(time.into()))
                .unwrap()
                .keys()
                .subkeys()
                .nth(0)
                .unwrap()
                .key()
                .clone();
            let subkey_fingerprint = subkey.fingerprint();
            let message = "message";

            let revocation = sq.scratch_file(Some(&*format!(
                "revocation_{}_{}_{}.rev",
                reason_str,
                if notations.is_empty() {
                    "no_notations"
                } else {
                    "notations"
                },
                if revocation_time.is_some() {
                    "time"
                } else {
                    "no_time"
                }
            )));

            if keystore {
                // When using the keystore, we need to import the key.
                sq.key_import(&cert_path);
            }

            let mut cmd = sq.command();
            cmd.args([
                "key",
                "subkey",
                "revoke",
                "--key", &subkey_fingerprint.to_string(),
                "--reason", reason_str,
                "--message", message,
            ]);

            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.arg("--output").arg(&revocation)
                    .arg("--cert-file").arg(&cert_path);
            }

            for (k, v) in notations {
                cmd.args(["--signature-notation", k, v]);
            }
            if let Some(time) = revocation_time {
                cmd.args([
                    "--time",
                    &time_as_string(time.into()),
                ]);
            }
            let output = cmd.output()?;
            if !output.status.success() {
                panic!("sq exited with non-zero status code: {}",
                       String::from_utf8_lossy(&output.stderr));
            }

            // whether we found a revocation signature
            let mut found_revoked = false;

            // read revocation cert
            let rev = if keystore {
                sq.cert_export(cert.key_handle())
            } else {
                Cert::from_file(&revocation)?
            };
            assert!(! rev.is_tsk());

            // and merge it into the certificate.
            let cert = cert.clone().merge_public(rev)?;
            let valid_cert =
                cert.with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;
            valid_cert
                .with_policy(STANDARD_POLICY, revocation_time.map(Into::into))
                .unwrap()
                .keys()
                .subkeys()
                .for_each(|x| {
                    if x.key().fingerprint() == subkey_fingerprint {
                        let status = x.bundle().revocation_status(
                            STANDARD_POLICY,
                            revocation_time.map(Into::into),
                        );

                        // the subkey is revoked
                        assert!(matches!(status, RevocationStatus::Revoked(_)));

                        if let RevocationStatus::Revoked(sigs) = status {
                            // there is only one signature packet
                            assert_eq!(sigs.len(), 1);
                            let sig = sigs.into_iter().next().unwrap();

                            // it is a subkey revocation
                            assert_eq!(sig.typ(), SignatureType::SubkeyRevocation);

                            // the issuer is the certificate owner
                            assert_eq!(
                                sig.get_issuers().into_iter().next().as_ref(),
                                Some(&fingerprint.clone().into())
                            );

                            // our reason for revocation and message matches
                            assert_eq!(
                                sig.reason_for_revocation(),
                                Some((reason, message.as_bytes()))
                            );

                            // the notations of the revocation match the ones
                            // we passed in
                            assert!(compare_notations(sig, notations).is_ok());

                            found_revoked = true;
                        }
                    }
                });

            if !found_revoked {
                panic!("the revoked subkey is not found in the revocation cert");
            }
        }
    }

    Ok(())
}

#[test]
fn sq_key_subkey_revoke_multiple() -> Result<()> {
    let sq = Sq::new();

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[UserIDArg::Email("alice@example.org")]);
    assert!(cert.keys().subkeys().count() > 0);
    sq.key_import(cert_path);

    let mut cmd = sq.command();
    cmd.args([
        "key", "subkey", "revoke",
        "--cert", &cert.fingerprint().to_string(),
    ]);

    for subkey in cert.keys().subkeys() {
        cmd.args(["--key", &subkey.key().fingerprint().to_string(),]);
    }

    cmd.args(["--reason", "retired", "--message", "rotation"]);
    sq.run(cmd, Some(true));

    let revoked = sq.cert_export(cert.key_handle());
    assert_eq!(cert.keys().subkeys().count(), revoked.keys().subkeys().count());

    let vrevoked = revoked.with_policy(STANDARD_POLICY, sq.now())?;
    for subkey in vrevoked.keys().subkeys() {
        use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
        assert!(matches!(subkey.revocation_status(),
                         RevocationStatus::Revoked(_)));
    }

    Ok(())
}


#[test]
fn sq_key_subkey_revoke_thirdparty() -> Result<()> {
    let sq = Sq::new();
    let time = sq.now();

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for (reason, reason_str, notations, revocation_time) in [
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            &[][..],
            None,
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::KeyCompromised,
            "compromised",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::KeyRetired, "retired", &[][..], None),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::KeyRetired,
            "retired",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::KeySuperseded, "superseded", &[][..], None),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::KeySuperseded,
            "superseded",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::Unspecified, "unspecified", &[][..], None),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[][..],
            Some(time + Duration::new(60 * 60, 0)),
        ),
        (
            ReasonForRevocation::Unspecified,
            "unspecified",
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
    ] {
        for keystore in [false, true].into_iter() {
            let (cert, cert_path, _rev_path)
                = sq.key_generate(&[], &["alice <alice@example.org>"]);

            let valid_cert = cert.with_policy(STANDARD_POLICY, Some(time.into()))?;
            let subkey: Key<_, _> = valid_cert
                .with_policy(STANDARD_POLICY, Some(time.into()))
                .unwrap()
                .keys()
                .subkeys()
                .nth(0)
                .unwrap()
                .key()
                .clone();
            let subkey_fingerprint = subkey.fingerprint();

            let (thirdparty_cert, thirdparty_path, _rev_path) =
                sq.key_generate(&[], &["bob <bob@example.org>"]);

            let thirdparty_valid_cert = thirdparty_cert
                .with_policy(STANDARD_POLICY, Some(time.into()))?;
            let thirdparty_fingerprint = thirdparty_valid_cert.clone().fingerprint();

            let message = "message";

            let revocation = sq.scratch_file(Some(&*format!(
                "revocation_{}_{}_{}.rev",
                reason_str,
                if ! notations.is_empty() {
                    "no_notations"
                } else {
                    "notations"
                },
                if revocation_time.is_some() {
                    "time"
                } else {
                    "no_time"
                }
            )));

            if keystore {
                // When using the keystore, we need to import the key.

                for path in &[ &cert_path, &thirdparty_path ] {
                    sq.key_import(path);
                }
            }

            let mut cmd = sq.command();
            cmd.args([
                "key",
                "subkey",
                "revoke",
                "--key", &subkey_fingerprint.to_string(),
                "--reason", reason_str,
                "--message", message,
            ]);

            if keystore {
                cmd.args([
                    "--cert", &cert.fingerprint().to_string(),
                    "--revoker", &thirdparty_cert.fingerprint().to_string(),
                ]);
            } else {
                cmd.arg("--output").arg(&revocation)
                    .arg("--cert-file").arg(&cert_path)
                    .arg("--revoker-file").arg(&thirdparty_path);
            }

            for (k, v) in notations {
                cmd.args(["--signature-notation", k, v]);
            }
            if let Some(time) = revocation_time {
                cmd.args([
                    "--time",
                    &time_as_string(time.into()),
                ]);
            }
            let output = cmd.output()?;
            if !output.status.success() {
                panic!("sq exited with non-zero status code: {}",
                       String::from_utf8_lossy(&output.stderr));
            }

            // read revocation cert
            let rev = if keystore {
                sq.cert_export(cert.key_handle())
            } else {
                Cert::from_file(&revocation)?
            };
            assert!(! rev.is_tsk());

            // and merge it into the certificate.
            let cert = cert.clone().merge_public(rev)?;
            let valid_cert =
                cert.with_policy(STANDARD_POLICY, revocation_time.map(Into::into))?;

            // whether we found a revocation signature
            let mut found_revoked = false;

            assert_eq!(valid_cert.userids().count(), 1);
            valid_cert
                .with_policy(STANDARD_POLICY, revocation_time.map(Into::into))
                .unwrap()
                .keys()
                .subkeys()
                .for_each(|x| {
                    if x.key().fingerprint() == subkey_fingerprint {
                        if let RevocationStatus::CouldBe(sigs) = x
                            .bundle()
                            .revocation_status(
                                STANDARD_POLICY,
                                revocation_time.map(Into::into),
                            )
                        {
                            // there is only one signature packet
                            assert_eq!(sigs.len(), 1);
                            let sig = sigs.into_iter().next().unwrap();

                            // it is a subkey revocation
                            assert_eq!(sig.typ(), SignatureType::SubkeyRevocation);

                            // the issuer is a thirdparty revoker
                            assert_eq!(
                                sig.get_issuers().into_iter().next().as_ref(),
                                Some(&thirdparty_fingerprint.clone().into())
                            );

                            // the revocation can be verified
                            if sig
                                .clone()
                                .verify_subkey_revocation(
                                    thirdparty_cert.primary_key().key(),
                                    cert.primary_key().key(),
                                    &subkey,
                                )
                                .is_err()
                            {
                                panic!("revocation is not valid")
                            }

                            // our reason for revocation and message matches
                            assert_eq!(
                                sig.reason_for_revocation(),
                                Some((reason, message.as_bytes()))
                            );

                            // the notations of the revocation match the ones
                            // we passed in
                            assert!(compare_notations(sig, notations).is_ok());

                            found_revoked = true;
                        } else {
                            panic!("there are no signatures in {:?}", x);
                        }
                    }
                });

            if !found_revoked {
                panic!("the revoked subkey is not found in the revocation cert");
            }
        }
    }

    Ok(())
}
