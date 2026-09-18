use crate::integration::common::CertArg;
use crate::integration::common::Sq;
use crate::integration::common::check_fingerprints;

#[test]
fn list() {
    let mut sq = Sq::new();

    let alice_email = "alice@example.org";
    let alice_userid = &format!("Alice <{}>", alice_email);
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ alice_userid ]);
    sq.key_import(&alice_pgp);

    let bob_email = "bob@example.org";
    let bob_userid = &format!("Bob <{}>", bob_email);
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[ bob_userid ]);
    sq.key_import(&bob_pgp);

    let carol_email = "carol@example.org";
    let carol_userid = &format!("Carol <{}>", carol_email);
    let (carol, carol_pgp, _carol_rev)
        = sq.key_generate(&[], &[ carol_userid ]);
    sq.key_import(&carol_pgp);

    // Alice hasn't certified anything.  `sq pki vouch list` with no
    // filter should show nothing, but still return success.
    let output = sq.pki_vouch_list(&[], CertArg::from(&alice), None);
    check_fingerprints(&output, []);

    // Alice hasn't certified Bob, so this should return nothing.
    let output = sq.pki_vouch_list(
        &[],
        CertArg::from(&alice),
        CertArg::from(&bob));
    check_fingerprints(&output, []);

    // No one has certified Bob, so this should return nothing.
    let output = sq.pki_vouch_list(
        &[],
        None,
        CertArg::from(&bob));
    check_fingerprints(&output, []);

    sq.tick(10);

    // Alice certifies Bob (the certification expires in a day).

    sq.pki_vouch_add(
        &["--expiration", "1d"],
        &alice.key_handle(), &bob.key_handle(), &[bob_userid],
        None);

    // Now listing the certifications for Bob's certificate should
    // work.
    let output = sq.pki_vouch_list(
        &[], CertArg::from(&alice),
        CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 1),
        ]);

    let output = sq.pki_vouch_list(
        &[], None,
        CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 1),
        ]);

    // But not when we specify Carol.
    let output = sq.pki_vouch_list(
        &[], CertArg::from(&alice),
        CertArg::from(&carol));
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(
        &[], None,
        CertArg::from(&carol));
    check_fingerprints(&output, []);

    // It will still list the certification after it has expired.
    let output = sq.pki_vouch_list(
        &["--time", "+2d"],
        CertArg::from(&alice),
        CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 1),
        ]);

    // And it will list the certification even if the certification
    // was made in the future.
    sq.pki_vouch_list(
        &["--time", "-5s"],
        CertArg::from(&alice),
        CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 1),
        ]);
}

#[test]
fn list_multiple_certifications() {
    // Check that all certifications are shown.

    let mut sq = Sq::new();

    let alice_email = "alice@example.org";
    let alice_userid = &format!("Alice <{}>", alice_email);
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ alice_userid ]);
    sq.key_import(&alice_pgp);

    let bob_email = "bob@example.org";
    let bob_userid = &format!("Bob <{}>", bob_email);
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[ bob_userid ]);
    sq.key_import(&bob_pgp);

    let carol_email = "carol@example.org";
    let carol_userid = &format!("Carol <{}>", carol_email);
    let (carol, carol_pgp, _carol_rev)
        = sq.key_generate(&[], &[ carol_userid ]);
    sq.key_import(&carol_pgp);

    // No one has certified anything.  `sq pki vouch list` should show
    // nothing, but still return success.
    let output = sq.pki_vouch_list(&[], CertArg::from(&alice), None);
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(&[], CertArg::from(&bob), None);
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(&[], CertArg::from(&carol), None);
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(&[], None, CertArg::from(&alice));
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(&[], None, CertArg::from(&bob));
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(&[], None, CertArg::from(&carol));
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(
        &[], CertArg::from(&bob), CertArg::from(&alice));
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(
        &[], CertArg::from(&alice), CertArg::from(&bob));
    check_fingerprints(&output, []);

    let output = sq.pki_vouch_list(
        &[], CertArg::from(&alice), CertArg::from(&carol));
    check_fingerprints(&output, []);


    // Alice certifies Carol once.
    sq.tick(10);
    sq.pki_vouch_add(
        &[],
        &alice.key_handle(), &carol.key_handle(), &[carol_userid],
        None);

    // Bob certifies Carol twice.
    for _ in 0..2 {
        sq.tick(10);
        sq.pki_vouch_add(
            &[],
            &bob.key_handle(), &carol.key_handle(), &[carol_userid],
            None);
    }

    // Carol certifies Bob three times.
    for _ in 0..3 {
        sq.tick(10);
        sq.pki_vouch_add(
            &[],
            &carol.key_handle(), &bob.key_handle(), &[bob_userid],
            None);
    }

    // Now list the certifications.

    let output = sq.pki_vouch_list(&[], CertArg::from(&alice), None);
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 0),
            (carol.fingerprint(), 1),
        ]);

    let output = sq.pki_vouch_list(&[], CertArg::from(&bob), None);
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 1),
            (carol.fingerprint(), 2),
        ]);

    let output = sq.pki_vouch_list(&[], CertArg::from(&carol), None);
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 3),
            (carol.fingerprint(), 1),
        ]);


    let output = sq.pki_vouch_list(&[], None, CertArg::from(&alice));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 0),
            (carol.fingerprint(), 0),
        ]);


    let output = sq.pki_vouch_list(&[], None, CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 3),
            (carol.fingerprint(), 1),
        ]);


    let output = sq.pki_vouch_list(&[], None, CertArg::from(&carol));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 1),
            (carol.fingerprint(), 3),
        ]);


    let output = sq.pki_vouch_list(
        &[], CertArg::from(&bob), CertArg::from(&alice));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 0),
            (carol.fingerprint(), 0),
        ]);


    let output = sq.pki_vouch_list(
        &[], CertArg::from(&alice), CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 0),
            (carol.fingerprint(), 0),
        ]);


    let output = sq.pki_vouch_list(
        &[], CertArg::from(&alice), CertArg::from(&carol));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 0),
            (carol.fingerprint(), 1),
        ]);


    let output = sq.pki_vouch_list(
        &[], CertArg::from(&bob), CertArg::from(&carol));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 1),
            (carol.fingerprint(), 2),
        ]);


    let output = sq.pki_vouch_list(
        &[], CertArg::from(&carol), CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 0),
            (bob.fingerprint(), 3),
            (carol.fingerprint(), 1),
        ]);
}

#[test]
fn list_with_unauthenticated_handle() {
    // Make sure it isn't possible to use --cert-email, etc. with an
    // unauthenticated handle.
    let sq = Sq::new();

    let alice_name = "Alice Lovelace";
    let alice_domain = "example.org";
    let alice_email = &format!("alice@{}", alice_domain);
    let alice_userid = &format!("{} <{}>", alice_name, alice_email);

    let (alice_cert, alice_cert_path, _rev_path)
        = sq.key_generate(&[], &[ alice_userid, ]);

    sq.key_import(&alice_cert_path);

    let bob_name = "Bob Lovelace";
    let bob_domain = "example.org";
    let bob_email = &format!("bob@{}", bob_domain);
    let bob_userid = &format!("{} <{}>", bob_name, bob_email);

    let (bob_cert, bob_cert_path, _rev_path)
        = sq.key_generate(&[], &[ bob_userid, ]);

    sq.key_import(&bob_cert_path);

    sq.pki_vouch_add(
        &["--expiration", "1d"],
        &alice_cert.key_handle(), bob_cert.key_handle(), &[bob_userid],
        None);

    // We need to link a user ID otherwise sq pki vouch list will
    // refuse to list the certificate.
    sq.pki_link_add(
        &["--amount", "40"], alice_cert.key_handle(), &[ alice_userid ]);

    for linked in [false, true] {
        if linked {
            // The second time through we link the certificates and
            // make sure the certificate designator actually work.
            sq.pki_link_add(
                &[], alice_cert.key_handle(), &[ alice_userid ]);
            sq.pki_link_add(
                &[], bob_cert.key_handle(), &[ bob_userid ]);
        }


        sq.pki_vouch_list(&[], CertArg::from(&alice_cert), None);
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::UserID(alice_userid),
                                         None).is_ok(),
                   linked);
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::Email(alice_email),
                                         None).is_ok(),
                   linked);

        sq.pki_vouch_list(&[],
                          CertArg::from(&alice_cert),
                          CertArg::from(&bob_cert));
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::from(&alice_cert),
                                         CertArg::UserID(bob_userid)).is_ok(),
                   linked);
        assert_eq!(sq.try_pki_vouch_list(&[],
                                         CertArg::from(&alice_cert),
                                         CertArg::Email(bob_email)).is_ok(),
                   linked);
    }
}

#[test]
fn list_missing_certifier() {
    // Alice certifies Bob's certificate.  The certificate store only
    // contains Bob's certificate.  We should still list Alice's
    // certification, even though we can't verify it.

    let sq = Sq::new();

    let alice_email = "alice@example.org";
    let alice_userid = &format!("Alice <{}>", alice_email);
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ alice_userid ]);
    // We explicitly DO not import Alice's certificate.
    // sq.key_import(&alice_pgp);

    let bob_email = "bob@example.org";
    let bob_userid = &format!("Bob <{}>", bob_email);
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[ bob_userid ]);
    sq.key_import(&bob_pgp);

    sq.pki_vouch_add(
        &[],
        &alice_pgp, &bob.key_handle(), &[bob_userid],
        None);

    let output = sq.pki_vouch_list(
        &[], None,
        CertArg::from(&bob));
    check_fingerprints(
        &output,
        [
            (alice.fingerprint(), 1),
            (bob.fingerprint(), 1),
        ]);
    assert!(output.contains("unknown: missing certificate"));
}
