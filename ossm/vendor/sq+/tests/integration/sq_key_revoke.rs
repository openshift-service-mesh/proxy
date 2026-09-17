use std::time::Duration;

use openpgp::parse::Parse;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use super::common::artifact;
use super::common::compare_notations;
use super::common::FileOrKeyHandle;
use super::common::Sq;
use super::common::NULL_POLICY;
use super::common::STANDARD_POLICY;

#[test]
fn sq_key_revoke() -> Result<()> {
    let sq = Sq::new();

    let time = sq.now();

    let (_cert, cert_path, _cert_rev)
        = sq.key_generate(&[], &["alice"]);

    let message = "message";

    // revoke for various reasons, with or without notations added, or
    // with a revocation whose reference time is one hour after the
    // creation of the certificate
    for ((reason, reason_str, notations, revocation_time), cert_path) in [
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
            &[("foo", "bar"), ("hallo@sequoia-pgp.org", "VALUE")][..],
            None,
        ),
        (ReasonForRevocation::KeySuperseded, "superseded", &[][..], None),
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
    ].into_iter().flat_map(|test| {
        [
            // A normal key.
            (test, cert_path.clone()),
            // A key that uses SHA-1.
            (test, artifact("keys/only-sha1-priv.pgp")),
        ]
    })
    {
        eprintln!("==========================");
        eprintln!("reason: {}, message: {}, notations: {:?}, time: {:?}",
                  reason, reason_str, notations, revocation_time);

        let cert = Cert::from_file(&cert_path).expect("valid cert");

        for keystore in [false, true].into_iter() {
            eprintln!("--------------------------");
            eprintln!("keystore: {}", keystore);

            let revocation = sq.scratch_file(Some(&format!(
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
            )[..]));

            if keystore {
                // When using the keystore, we need to import the key.
                sq.key_import(&cert_path);
            }

            let updated = sq.key_revoke(
                if keystore {
                    FileOrKeyHandle::from(cert.key_handle())
                } else {
                    FileOrKeyHandle::from(&cert_path)
                },
                None,
                reason_str,
                message,
                None,
                notations,
                Some(revocation.as_path()));

            if let RevocationStatus::Revoked(sigs)
                = updated.revocation_status(STANDARD_POLICY, None)
            {
                assert_eq!(sigs.len(), 1);
                let sig = sigs.into_iter().next().unwrap();

                // the issuer is the certificate owner
                assert_eq!(
                    sig.get_issuers().into_iter().next(),
                    Some(cert.key_handle())
                );

                let revoked_cert =
                    cert.clone().insert_packets(sig.clone()).unwrap().0;
                let status = revoked_cert
                    .revocation_status(
                        STANDARD_POLICY,
                        revocation_time.map(Into::into));

                println!("{:?}", sig);
                println!("{:?}", status);
                // Verify the revocation.
                assert!(matches!(status, RevocationStatus::Revoked(_)));

                // it is a key revocation
                assert_eq!(sig.typ(), SignatureType::KeyRevocation);

                // our reason for revocation and message matches
                assert_eq!(
                    sig.reason_for_revocation(),
                    Some((reason, message.as_bytes()))
                );

                // the notations of the revocation match the ones
                // we passed in
                compare_notations(sig, notations)?;
            } else {
                panic!("Not revoked");
            }
        }
    }

    Ok(())
}

#[test]
fn sq_key_revoke_thirdparty() -> Result<()> {
    let sq = Sq::new();

    let time = sq.now();

    let (_cert, cert_path, _cert_rev)
        = sq.key_generate(&[], &["alice"]);

    let (_thirdparty_cert, thirdparty_path, _cert_rev)
        = sq.key_generate(&[], &["bob <bob@example.org>"]);

    let message = "message";

    // revoke for various reasons, with or without notations added, or with
    // a revocation whose reference time is one hour after the creation of the
    // certificate
    for ((reason, reason_str, notations, revocation_time), cert_path, thirdparty_path) in [
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
    ].into_iter().flat_map(|test| {
        [
            // Two valid keys.
            (test,
             cert_path.clone(),
             thirdparty_path.clone()),
            // The revokee is invalid (SHA-1).
            (test,
             artifact("keys/only-sha1-priv.pgp"),
             thirdparty_path.clone()),
            // The revoker is invalid (SHA-1).
            (test,
             cert_path.clone(),
             artifact("keys/only-sha1-priv.pgp")),
        ]
    }) {
        let cert = Cert::from_file(&cert_path).expect("valid cert");
        let thirdparty_cert
            = Cert::from_file(&thirdparty_path).expect("valid cert");

        let thirdparty_valid_cert = thirdparty_cert
            .with_policy(NULL_POLICY, Some(time.into()))?;
        let thirdparty_fingerprint
            = &thirdparty_valid_cert.clone().fingerprint();

        for keystore in [false, true].into_iter() {
            let revocation = sq.scratch_file(Some(&format!(
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
            )[..]));

            if keystore {
                // When using the keystore, we need to import the key.

                sq.cert_import(&cert_path);
                sq.key_import(&thirdparty_path);
            }

            let revocation_cert = sq.key_revoke(
                if keystore {
                    FileOrKeyHandle::from(cert.key_handle())
                } else {
                    FileOrKeyHandle::from(&cert_path)
                },
                if keystore {
                    FileOrKeyHandle::from(thirdparty_cert.key_handle())
                } else {
                    FileOrKeyHandle::from(&thirdparty_path)
                },
                reason_str,
                message,
                None,
                notations,
                Some(revocation.as_path()));

            assert!(! revocation_cert.is_tsk());

            // evaluate revocation status
            let status = revocation_cert.revocation_status(
                STANDARD_POLICY, revocation_time.map(Into::into));
            if let RevocationStatus::CouldBe(sigs) = status {
                // there is only one signature packet
                assert_eq!(sigs.len(), 1);
                let sig = sigs.into_iter().next().unwrap();

                // it is a key revocation
                assert_eq!(sig.typ(), SignatureType::KeyRevocation);

                // the issuer is a thirdparty revoker
                assert_eq!(
                    sig.get_issuers().into_iter().next().as_ref(),
                    Some(&thirdparty_fingerprint.clone().into())
                );

                // the revocation can be verified
                if sig
                    .clone()
                    .verify_primary_key_revocation(
                        thirdparty_cert.primary_key().key(),
                        cert.primary_key().key(),
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
                compare_notations(sig, notations)?;
            } else {
                panic!("there are no signatures in {:?}", status);
            }
        }
    }

    Ok(())
}
