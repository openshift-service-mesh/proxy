use std::fs::File;

use sequoia_openpgp as openpgp;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;

use super::common::Sq;
use super::common::STANDARD_POLICY;

#[test]
fn keyring_merge_revocation() -> Result<()> {
    let sq = Sq::new();

    // Generate a key.  (We don't use sq on purpose: we want to make
    // sure we have a bare revocation certificate.)
    let (alice_cert, alice_rev) = CertBuilder::general_purpose(
        Some("alice@example.org"))
        .set_creation_time(sq.now())
        .generate()?;

    // Write out the certificate.
    let alice_cert_file = sq.scratch_file("alice_cert");
    alice_cert.as_tsk().serialize(&mut File::create(&alice_cert_file)?)?;

    // Write out the revocation certificate.
    let alice_rev_file = sq.scratch_file("alice_rev");
    Packet::from(alice_rev).serialize(&mut File::create(&alice_rev_file)?)?;

    let (_bob, bob_cert_file, _bob_rev_file)
        = sq.key_generate(&[], &["bob"]);

    // "Merge" a single cert.
    let certs = sq.keyring_merge(
        &[ &alice_cert_file ][..],
        None, None);
    assert_eq!(certs.len(), 1);
    assert!(! matches!(
        certs[0].revocation_status(STANDARD_POLICY, sq.now()),
        RevocationStatus::Revoked(_)));

    // "Merge" two certs.
    let certs = sq.keyring_merge(
        &[ &alice_cert_file, &bob_cert_file ][..],
        None, None);
    assert_eq!(certs.len(), 2);
    assert!(! matches!(
        certs[0].revocation_status(STANDARD_POLICY, sq.now()),
        RevocationStatus::Revoked(_)));

    // "Merge" a single cert and its revocation certificate.
    let certs = sq.keyring_merge(
        &[ &alice_rev_file, &alice_cert_file ][..],
        None, None);
    assert_eq!(certs.len(), 1);
    assert!(matches!(
        certs[0].revocation_status(STANDARD_POLICY, sq.now()),
        RevocationStatus::Revoked(_)));

    // Merging a revocation certificate without the certificate should
    // result in an error.
    assert!(sq.keyring_merge_maybe(
        &[ &alice_rev_file ][..],
        None, None).is_err());

    // Merging a revocation certificate without the certificate should
    // result in an error.
    assert!(sq.keyring_merge_maybe(
        &[ &alice_rev_file, &bob_cert_file ][..],
        None, None).is_err());

    Ok(())
}
