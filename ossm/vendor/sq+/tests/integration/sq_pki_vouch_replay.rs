use crate::integration::common::CertArg;
use crate::integration::common::Sq;
use crate::integration::common::check_certifications;

#[test]
fn replay() {
    let mut sq = Sq::new();

    // The old certificate.
    let alice_email = "alice@example.org";
    let alice_userid = &format!("Alice <{}>", alice_email);
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ alice_userid ]);
    sq.key_import(&alice_pgp);

    // The new certificate.
    let alice_email = "alice@example.org";
    let alice_userid = &format!("Alice <{}>", alice_email)[..];
    let (alice2, alice2_pgp, _alice2_rev)
        = sq.key_generate(&[], &[ alice_userid ]);
    sq.key_import(&alice2_pgp);

    let bob_email = "bob@example.org";
    let bob_userid = &format!("Bob <{}>", bob_email)[..];
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[ bob_userid ]);
    sq.key_import(&bob_pgp);

    let carol_email = "carol@example.org";
    let carol_userid = &format!("Carol <{}>", carol_email)[..];
    let (carol, carol_pgp, _carol_rev)
        = sq.key_generate(&[], &[ carol_userid ]);
    sq.key_import(&carol_pgp);

    let dave_email = "dave@example.org";
    let dave_userid = &format!("Dave <{}>", dave_email)[..];
    let (dave, dave_pgp, _dave_rev)
        = sq.key_generate(&[], &[ dave_userid ]);
    sq.key_import(&dave_pgp);

    // We should have no certifications... yet.
    let certs = sq.cert_export_all();
    check_certifications(&certs, &[][..]);

    // Alice hasn't certified anything.  `sq pki vouch replay` with no
    // filter should not fail.
    sq.pki_vouch_replay(
        &[], CertArg::from(&alice), CertArg::from(&alice2), None);

    // Replaying to a certificate with no common self-signed user IDs
    // should fail.
    assert!(sq.try_pki_vouch_replay(
        &[], CertArg::from(&alice), CertArg::from(&bob), None).is_err());

    // Unless we force it.
    sq.pki_vouch_replay(
        &["--allow-dissimilar-userids"],
        CertArg::from(&alice), CertArg::from(&bob), None);

    // Create some certifications.
    for i in 1..=2 {
        sq.tick(10);

        // Alice certifies Bob.
        sq.pki_vouch_add(
            &["--amount", &i.to_string()],
            &alice.key_handle(), &bob.key_handle(), &[bob_userid],
            None);

        sq.pki_vouch_add(
            &["--amount", &i.to_string()],
            &alice.key_handle(), &carol.key_handle(), &[carol_userid],
            None);

        sq.pki_vouch_add(
            &["--amount", &i.to_string()],
            &alice.key_handle(), &dave.key_handle(), &[dave_userid],
            None);
    }

    let certs = sq.cert_export_all();
    check_certifications(
        &certs,
        &[
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 1, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 1, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 1, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),
        ][..]);

    // Now replay them.  Subsequent copies should be no-ops.
    for _ in 0..3 {
        sq.tick(1);

        sq.pki_vouch_replay(
            &[], CertArg::from(&alice), CertArg::from(&alice2), None);
        let certs = sq.cert_export_all();
        check_certifications(
            &certs,
            &[
                (alice.fingerprint(), bob.fingerprint(), bob_userid, 1, 1),
                (alice.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
                (alice.fingerprint(), carol.fingerprint(), carol_userid, 1, 1),
                (alice.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
                (alice.fingerprint(), dave.fingerprint(), dave_userid, 1, 1),
                (alice.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

                // New.
                (alice2.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
                // New.
                (alice2.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
                // New.
                (alice2.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),
            ][..]);
    }

    // Alice certifies Bob.
    sq.tick(10);
    sq.pki_vouch_add(
        &["--amount", "3" ],
        &alice.key_handle(), &bob.key_handle(), &[bob_userid],
        None);
    // Bob certifies Alice.
    sq.pki_vouch_add(
        &["--amount", "3" ],
        &bob.key_handle(), &alice.key_handle(), &[alice_userid],
        None);
    sq.pki_vouch_replay(
        &[], CertArg::from(&alice), CertArg::from(&alice2), None);
    let certs = sq.cert_export_all();
    check_certifications(
        &certs,
        &[
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 1, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 1, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 1, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            // New.
            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice2.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice2.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (bob.fingerprint(), alice.fingerprint(), alice_userid, 3, 1),
        ][..]);


    // Alice certifies Bob, and it expires in 100 seconds.
    sq.tick(10);
    sq.pki_vouch_add(
        &["--amount", "4", "--expiration", "100s", ],
        &alice.key_handle(), &bob.key_handle(), &[bob_userid],
        None);
    // Go back a second and replay the certifications.  This should be a
    // no-op as certification #4 is not yet live.
    sq.rewind(1);
    sq.pki_vouch_replay(
        &[], CertArg::from(&alice), CertArg::from(&alice2), None);
    let certs = sq.cert_export_all();
    check_certifications(
        &certs,
        &[
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 1, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 4, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 1, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 1, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice2.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice2.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (bob.fingerprint(), alice.fingerprint(), alice_userid, 3, 1),
        ][..]);
    // Undo.
    sq.tick(1);

    // Go forward and replay the certifications.  This should be a no-op
    // as certification #4 is expired.
    sq.tick(200);
    sq.pki_vouch_replay(
        &[], CertArg::from(&alice), CertArg::from(&alice2), None);
    let certs = sq.cert_export_all();
    check_certifications(
        &certs,
        &[
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 1, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 4, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 1, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 1, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice2.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice2.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (bob.fingerprint(), alice.fingerprint(), alice_userid, 3, 1),
        ][..]);
    // Undo.
    sq.rewind(200);

    // 10 seconds pass since the creation of the #4 certification.
    // Replay it.
    sq.tick(10);
    sq.pki_vouch_replay(
        &[], CertArg::from(&alice), CertArg::from(&alice2), None);
    let certs = sq.cert_export_all();
    check_certifications(
        &certs,
        &[
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 1, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 4, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 1, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 1, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            // New.
            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 4, 1),
            (alice2.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice2.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (bob.fingerprint(), alice.fingerprint(), alice_userid, 3, 1),
        ][..]);

    // Another 91 seconds pass.  The alice -> bob #4 certification
    // will have expired, but the alice2 -> bob #4 certification won't
    // have.  So this will replay the #3 certification (again).
    sq.tick(91);
    sq.pki_vouch_replay(
        &[], CertArg::from(&alice), CertArg::from(&alice2), None);
    let certs = sq.cert_export_all();
    check_certifications(
        &certs,
        &[
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 1, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 3, 1),
            (alice.fingerprint(), bob.fingerprint(), bob_userid, 4, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 1, 1),
            (alice.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 1, 1),
            (alice.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 2, 1),
            // New (a second copy).
            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 3, 2),
            (alice2.fingerprint(), bob.fingerprint(), bob_userid, 4, 1),
            (alice2.fingerprint(), carol.fingerprint(), carol_userid, 2, 1),
            (alice2.fingerprint(), dave.fingerprint(), dave_userid, 2, 1),

            (bob.fingerprint(), alice.fingerprint(), alice_userid, 3, 1),
        ][..]);
}
