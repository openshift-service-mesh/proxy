use crate::integration::common::Sq;
use crate::integration::common::UserIDArg;

#[test]
fn list_empty() {
    let sq = Sq::new();

    // Listing an empty key store should not be an error.
    sq.pki_link_list(&[]);

    // Listing an empty key store with a pattern (that doesn't
    // match anything) should be.
    assert!(sq.try_pki_link_list(&["not found"]).is_err());

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ "alice" ]);
    sq.key_import(cert_path);

    // Not linked => error.
    assert!(sq.try_pki_link_list(&["alice"]).is_err());

    // Not found => error.
    assert!(sq.try_pki_link_list(&["not found"]).is_err());

    // Linked and found => ok.
    sq.pki_link_add(&[], cert.key_handle(), &["alice"]);
    sq.pki_link_list(&["alice"]);
}

#[test]
fn list_uncertified_cert_designator() {
    // Consider a certificate with the following user IDs:
    //
    // - alice@one.org
    // - alice@two.org
    //
    // The user authorizes alice@one.org as a trusted introducer.
    // This means that alice@two.org can be authenticated (trust root
    // -> alice@one.org -> alice@two.org) and can be used as a
    // certificate designator.  Consequently, `sq pki link list
    // --cert-email alice@two.org` should work, and the whole command
    // should succeed because *some* user ID has been linked.

    let mut sq = Sq::new();

    let alice_one_email = "alice@one.org";
    let alice_one_userid = &format!("Alice <{}>", alice_one_email);

    let alice_two_email = "alice@two.org";
    let alice_two_userid = &format!("Alice <{}>", alice_two_email);

    let (alice, alice_pgp, _) = sq.key_generate(
        &[], &[ alice_one_userid, alice_two_userid ]);

    let alice_kh = &alice.key_handle().to_string();

    sq.key_import(&alice_pgp);

    // alice@one.org is not authenticated, and can't be used as a
    // certificate designator.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_one_email)).is_err());
    assert!(sq.try_pki_link_list(&["--cert-email", alice_one_email]).is_err());

    // alice@two.org is not authenticated, and can't be used as a
    // certificate designator.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_two_email)).is_err());
    assert!(sq.try_pki_link_list(&["--cert-email", alice_two_email]).is_err());

    sq.tick(1);

    sq.pki_link_authorize(
        &["--unconstrained"], alice.key_handle(), &[ alice_one_userid ]);

    // alice@one.org is authenticated, so we should be able to use it
    // to designate the certificate.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_one_email)).is_ok());
    sq.pki_link_list(&["--cert-email", alice_one_email]);

    // alice@two.org is authenticated, so we should be able to use it
    // to designate the certificate even though it was not linked.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_two_email)).is_ok());
    sq.pki_link_list(&["--cert-email", alice_two_email]);
}

#[test]
fn list_partially_trusted() {
    // If a certificate is partially trusted, then we should be able
    // to list it by fingerprint.

    let mut sq = Sq::new();

    let alice_example_email = "alice@example.org";
    let alice_example_userid = &format!("Alice <{}>", alice_example_email);

    let (alice, alice_pgp, _) = sq.key_generate(
        &[], &[ alice_example_userid ]);

    let alice_kh = &alice.key_handle().to_string();

    sq.key_import(&alice_pgp);

    // alice@example.org is not authenticated, and can't be used as a
    // certificate designator.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::Email(alice_example_email)).is_err());
    assert!(sq.try_pki_link_list(&["--cert-email", alice_example_email]).is_err());

    sq.tick(1);

    sq.pki_link_add(
        &["--amount", "40"], alice.key_handle(), &[ alice_example_userid ]);

    // alice@example.org is NOT authenticated, so we should NOT be
    // able to use it to designate the certificate.
    assert!(sq.pki_authenticate(
        &[], alice_kh, UserIDArg::UserID(alice_example_userid)).is_err());
    assert!(sq.try_pki_link_list(&["--cert-userid", alice_example_userid]).is_err());

    // But, as always, using the fingerprint should be okay.
    sq.pki_link_list(&["--cert", alice_kh]);
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

    // We need to link a user ID otherwise sq pki link list will
    // refuse to list the certificate.
    sq.pki_link_add(
        &["--amount", "40"], alice_cert.key_handle(), &[ alice_userid ]);

    let list = |args: &[&str], success: bool| {
        assert_eq!(sq.try_pki_link_list(args).is_ok(), success);
    };

    list(&["--cert", &alice_cert.fingerprint().to_string()], true);
    list(&["--cert-userid", alice_userid], false);
    list(&["--cert-email", alice_email], false);
    list(&["--cert-domain", alice_domain], false);
    list(&["--cert-grep", &alice_name[1..]], false);
}

