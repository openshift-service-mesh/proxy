use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;

use super::common::artifact;
use super::common::Sq;
use super::common::STANDARD_POLICY;
use super::common::UserIDArg;

#[test]
fn list() {
    let sq = Sq::new();

    let alice_name = "Alice Lovelace";

    // Self-signed and linked.
    let alice_authenticated_domain = "example.org";
    let alice_authenticated_email
        = &format!("alice@{}", alice_authenticated_domain);
    let alice_authenticated_userid
        = &format!("{} <{}>", alice_name, alice_authenticated_email);
    let alice_name = "Alice Lovelace";

    // Self-signed, but not linked.
    let alice_unauthenticated_domain = "some.org";
    let alice_unauthenticated_email
        = &format!("alice@{}", alice_unauthenticated_domain);
    let alice_unauthenticated_userid
        = &format!("{} <{}>", alice_name, alice_unauthenticated_email);

    // Self-signed, and partially (but insufficiently) authenticated.
    let alice_insufficient_domain = "insufficient.org";
    let alice_insufficient_email
        = &format!("alice@{}", alice_insufficient_domain);
    let alice_insufficient_userid
        = &format!("{} <{}>", alice_name, alice_insufficient_email);

    let (alice_cert, alice_cert_path, _rev_path)
        = sq.key_generate(
            &[],
            &[
                alice_authenticated_userid,
                alice_unauthenticated_userid,
                alice_insufficient_userid,
            ]);

    sq.key_import(&alice_cert_path);
    sq.pki_link_add(&[], alice_cert.key_handle(), &[ alice_authenticated_userid ]);
    sq.pki_link_add(&["--amount=1"], alice_cert.key_handle(),
                    &[ alice_insufficient_userid ]);

    // Not self-signed, but linked.
    let alice_petname_domain = "other.org";
    let alice_petname_email
        = &format!("alice@{}", alice_petname_domain);
    let alice_petname_userid
        = &format!("{} <{}>", alice_name, alice_petname_email);

    sq.pki_link_add(&[], alice_cert.key_handle(),
                    &[ UserIDArg::AddUserID(alice_petname_userid) ]);

    let unknown_domain = "unknown.org";
    let unknown_email = &format!("alice@{}", unknown_domain);
    let unknown_userid = &format!("{} <{}>", alice_name, unknown_email);

    let list = |args: &[&str], success: bool, gossip_success: bool| {
        assert_eq!(sq.cert_list_maybe(args).is_ok(), success);

        let mut gossip_args: Vec<&str> = args.to_vec();
        gossip_args.push("--gossip");
        assert_eq!(sq.cert_list_maybe(&gossip_args[..]).is_ok(), gossip_success);
    };

    // By fingerprint.
    list(&[&alice_cert.fingerprint().to_string()], true, true);
    list(&["--cert", &alice_cert.fingerprint().to_string()], true, true);
    // By key ID.
    list(&[&alice_cert.keyid().to_string()], true, true);
    list(&["--cert", &alice_cert.keyid().to_string()], true, true);

    // By user ID.
    list(&[alice_authenticated_userid], true, true);
    list(&["--cert-userid", alice_authenticated_userid], true, true);

    list(&[alice_unauthenticated_userid], false, true);
    list(&["--cert-userid", alice_unauthenticated_userid], false, true);

    list(&[alice_insufficient_userid], false, true);
    list(&["--cert-userid", alice_insufficient_userid], false, true);

    list(&[alice_petname_userid], true, true);
    list(&["--cert-userid", alice_petname_userid], true, true);

    list(&[unknown_userid], false, false);
    list(&["--cert-userid", unknown_userid], false, false);

    // By email.
    list(&[alice_authenticated_email], true, true);
    list(&["--cert-email", alice_authenticated_email], true, true);

    list(&[alice_unauthenticated_email], false, true);
    list(&["--cert-email", alice_unauthenticated_email], false, true);

    list(&[alice_insufficient_email], false, true);
    list(&["--cert-email", alice_insufficient_email], false, true);

    list(&[alice_petname_email], true, true);
    list(&["--cert-email", alice_petname_email], true, true);

    list(&[unknown_email], false, false);
    list(&["--cert-email", unknown_email], false, false);

    // By domain.
    list(&[alice_authenticated_domain], true, true);
    list(&["--cert-domain", alice_authenticated_domain], true, true);

    list(&[alice_unauthenticated_domain], false, true);
    list(&["--cert-domain", alice_unauthenticated_domain], false, true);

    list(&[alice_insufficient_domain], false, true);
    list(&["--cert-domain", alice_insufficient_domain], false, true);

    list(&[alice_petname_domain], true, true);
    list(&["--cert-domain", alice_petname_domain], true, true);

    list(&[unknown_domain], false, false);
    list(&["--cert-domain", unknown_domain], false, false);

    // Grep.
    list(&[alice_name], true, true);
    list(&["--cert-grep", alice_name], true, true);

    list(&[&alice_authenticated_userid[1..]], true, true);
    list(&["--cert-grep", &alice_authenticated_userid[1..]], true, true);

    list(&[&alice_unauthenticated_userid[1..]], false, true);
    list(&["--cert-grep", &alice_unauthenticated_userid[1..]], false, true);

    list(&[&alice_insufficient_userid[1..]], false, true);
    list(&["--cert-grep", &alice_insufficient_userid[1..]], false, true);

    list(&[&alice_petname_userid[1..]], true, true);
    list(&["--cert-grep", &alice_petname_userid[1..]], true, true);

    list(&[&unknown_userid[1..]], false, false);
    list(&["--cert-grep", &unknown_userid[1..]], false, false);

    // By substring.
    list(&["lice"], true, true);
    list(&["LICE"], true, true);
    list(&["example.or"], true, true);
    list(&["ExAmPlE.Or"], true, true);

    // When we use --userid, then we don't do substring matching.
    list(&["--cert-userid", &alice_authenticated_userid[1..]], false, false);

    // When we use --email, then we don't do substring matching.
    list(&["--cert-email", &alice_authenticated_email[1..]], false, false);
}

#[test]
fn list_with_unauthenticated_handle() {
    // This is similar to the previous test, but uses a certificate
    // that only has unauthenticated user IDs.

    let sq = Sq::new();

    let alice_name = "Alice Lovelace";
    let alice_domain = "example.org";
    let alice_email = &format!("alice@{}", alice_domain);
    let alice_userid = &format!("{} <{}>", alice_name, alice_email);

    let (alice_cert, alice_cert_path, _rev_path)
        = sq.key_generate(&[], &[ alice_userid, ]);

    sq.key_import(&alice_cert_path);

    let list = |args: &[&str], success: bool, gossip_success: bool| {
        assert_eq!(sq.cert_list_maybe(args).is_ok(), success);

        let mut gossip_args: Vec<&str> = args.to_vec();
        gossip_args.push("--gossip");
        assert_eq!(sq.cert_list_maybe(&gossip_args[..]).is_ok(), gossip_success);
    };

    list(&["--cert", &alice_cert.fingerprint().to_string()], true, true);
    list(&["--cert-userid", alice_userid], false, true);
    list(&["--cert-email", alice_email], false, true);
    list(&["--cert-domain", alice_domain], false, true);
    list(&["--cert-grep", &alice_name[1..]], false, true);
}

/// Check that multiple simultaneous queries work.
#[test]
fn list_multiple_queries() {
    let sq = Sq::new();

    let alice_email = "alice@example.org";
    let alice_name = "Alice Lovelace";
    let alice_userid = &format!("{} <{}>", alice_name, alice_email);
    let (alice_cert, alice_cert_path, _rev_path)
        = sq.key_generate(&[], &[ alice_userid ]);

    sq.key_import(&alice_cert_path);

    let alice_petname_email = "alice@alice.org";
    let alice_petname_userid
        = &format!("{} <{}>", alice_name, alice_petname_email);

    let bob_email = "bob@example.org";
    let bob_name = "Bob";
    let bob_userid = &format!("{} <{}>", bob_name, bob_email);
    let (bob_cert, bob_cert_path, _rev_path)
        = sq.key_generate(&[], &[ bob_userid ]);

    sq.key_import(&bob_cert_path);

    let bob_petname_email = "bob@bob.org";
    let bob_petname_userid
        = &format!("{} <{}>", bob_name, bob_petname_email);

    let unknown_domain = "unknown.org";
    let unknown_email = "alice@unknown.org";
    //let unknown_userid = &format!("Unknown <{}>", unknown_email);

    // We don't link the self-signed user IDs, just the petnames.
    sq.pki_link_add(&[], alice_cert.key_handle(),
                    &[UserIDArg::AddUserID(alice_petname_userid)]);
    sq.pki_link_add(&[], bob_cert.key_handle(),
                    &[UserIDArg::AddUserID(bob_petname_userid)]);

    let list = |args: &[&str], success: bool, gossip_success: bool| {
        assert_eq!(sq.cert_list_maybe(args).is_ok(), success);

        let mut gossip_args: Vec<&str> = args.to_vec();
        gossip_args.push("--gossip");
        assert_eq!(sq.cert_list_maybe(&gossip_args[..]).is_ok(), gossip_success);
    };

    // Smoke test: make sure we the individual queries work.
    list(&[alice_email], false, true);
    list(&["--cert-email", alice_email], false, true);

    list(&[bob_email], false, true);
    list(&["--cert-email", bob_email], false, true);

    list(&[alice_petname_email], true, true);
    list(&["--cert-email", alice_petname_email], true, true);

    list(&[bob_petname_email], true, true);
    list(&["--cert-email", bob_petname_email], true, true);

    list(&[unknown_email], false, false);
    list(&["--cert-email", unknown_email], false, false);

    list(&["--cert-domain", "example.org"], false, true);
    list(&["--cert-domain", "alice.org"], true, true);
    list(&["--cert-domain", "bob.org"], true, true);
    list(&["--cert-domain", unknown_domain], false, false);

    // Multiple queries where all queries have an authenticated match.
    list(&["--cert-email", alice_petname_email,
           "--cert-email", bob_petname_email],
         true, true);
    list(&["--cert-domain", "alice.org",
           "--cert-domain", "bob.org"],
         true, true);
    list(&["--cert", &alice_cert.key_handle().to_string(),
           "--cert-domain", "bob.org"],
         true, true);
    list(&["--cert-domain", "alice.org",
           "--cert-domain", "bob.org",
           "--cert", &alice_cert.key_handle().to_string()],
         true, true);

    // Multiple queries where one query has a match, but that match
    // doesn't authenticate.
    list(&["--cert-email", alice_email,
           "--cert-email", bob_petname_email],
         false, true);
    list(&["--cert-email", alice_petname_email,
           "--cert-email", bob_email],
         false, true);
    list(&["--cert-email", alice_petname_email,
           "--cert-email", unknown_email],
         false, false);

    list(&["--cert-domain", "example.org",
           "--cert-domain", "bob.org"],
         false, true);
    list(&["--cert-domain", "example.org",
           "--cert-domain", unknown_domain],
         false, false);
}

#[test]
fn list_empty() {
    let sq = Sq::new();

    // Listing an empty certificate store should not be an error.
    sq.cert_list(&[]);

    // Listing an empty certificate store with a pattern (that doesn't
    // match anything) should be.
    assert!(sq.cert_list_maybe(&["not found"]).is_err());

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ "alice" ]);
    sq.key_import(cert_path);

    // Not linked => error.
    assert!(sq.cert_list_maybe(&["alice"]).is_err());
    // Not found => error.
    assert!(sq.cert_list_maybe(&["not found"]).is_err());

    // Linked and found => ok.
    sq.pki_link_add(&[], cert.key_handle(), &["alice"]);
    sq.cert_list(&["alice"]);
}

/// Tests that listing a cert without user IDs works.
#[test]
fn list_no_userids() {
    let sq = Sq::new();
    let (cert, cert_path, _rev_path)
        = sq.key_generate::<&str>(&[], &[]);
    sq.key_import(&cert_path);
    let fp = cert.fingerprint().to_string();

    // When listing by fingerprint, the certificate is considered
    // authenticated.
    let output = sq.cert_list(&[&fp]);
    assert!(std::str::from_utf8(&output).unwrap().contains(&fp));

    let output = sq.cert_list(&["--gossip", &fp]);
    assert!(std::str::from_utf8(&output).unwrap().contains(&fp));
}

#[test]
fn list_all_no_userids() {
    // Check that `sq cert list` does not show certificates without
    // user IDs, but `sq cert list --gossip` does.
    let sq = Sq::new();
    let (cert, cert_path, _rev_path)
        = sq.key_generate::<&str>(&[], &[]);
    sq.key_import(&cert_path);
    let fp = cert.fingerprint().to_string();

    let output = sq.cert_list(&[]);
    assert!(! std::str::from_utf8(&output).unwrap().contains(&fp));

    let output = sq.cert_list(&["--gossip"]);
    assert!(std::str::from_utf8(&output).unwrap().contains(&fp));
}

/// Check that --cert FPR shows certificates that are otherwise
/// unauthenticate.
#[test]
fn list_unauthenticated_cert() {
    let sq = Sq::new();

    let email = "alice@example.org";
    let name = "Alice Lovelace";
    let userid = &format!("{} <{}>", name, email);
    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ userid ]);

    sq.key_import(&cert_path);

    // The certificate is unauthenticated so the following won't work:
    assert!(sq.cert_list_maybe(&[email]).is_err());

    // If we use --cert FINGERPRINT or provide the fingerprint, it
    // will.
    sq.cert_list(&[&cert.fingerprint().to_string()]);
    sq.cert_list(&["--cert", &cert.fingerprint().to_string()]);

    // When we link it, the above will work.
    sq.pki_link_add(&[], cert.key_handle(), &[userid]);
    sq.cert_list(&[email]);
    sq.cert_list(&[&cert.fingerprint().to_string()]);
    sq.cert_list(&["--cert", &cert.fingerprint().to_string()]);
}

#[test]
fn list_invalid_certs() {
    // Check that we can't list invalid certificates.
    //
    // Check:
    //
    // - a certificate that only uses SHA-1
    // - a certificate that is revoked
    // - a certificate that is expired
    for path in [
        "keys/only-sha1-priv.pgp",
        "keys/soft-revoked-cert.pgp",
        "keys/expired-cert.pgp",
    ] {
        eprintln!("Checking {}", path);

        let sq = Sq::new();

        let cert_file = artifact(path);
        let cert = Cert::from_file(&cert_file).expect("valid cert");
        let fpr = &cert.fingerprint().to_string()[..];
        let userids = cert.userids()
            .map(|ua| String::from_utf8_lossy(ua.userid().value()))
            .collect::<Vec<_>>();

        sq.cert_import(&cert_file);

        assert!(sq.cert_list_maybe(&[fpr]).is_err());
        assert!(sq.cert_list_maybe(&["--gossip", fpr]).is_err());

        for userid in userids.iter() {
            assert!(sq.cert_list_maybe(&["--cert-userid", &userid[..]]).is_err());
            assert!(sq.cert_list_maybe(&["--gossip", "--cert-userid", &userid[..]])
                    .is_err());
            sq.cert_list(&["--gossip", "--unusable",
                           "--cert-userid", &userid[..]]);
        }
    }
}

#[test]
fn list_sha1_userid() {
    // Check that we can list a user ID with --gossip even if it is
    // only bound by a self-signature that relies on SHA-1.
    let sq = Sq::new();

    let cert_file = artifact("keys/sha1-userid-priv.pgp");
    let cert = Cert::from_file(&cert_file).expect("valid cert");
    let fpr = &cert.fingerprint().to_string()[..];

    sq.cert_import(&cert_file);

    // Listing the certificate is okay.
    sq.cert_list(&[fpr]);
    sq.cert_list(&["--gossip", fpr]);

    let mut saw_invalid = false;

    for ua in cert.userids() {
        let userid = String::from_utf8_lossy(ua.userid().value());

        if ua.with_policy(STANDARD_POLICY, None).is_err() {
            saw_invalid = true;
        }

        // Not linked, so should fail.
        assert!(
            sq.cert_list_maybe(&["--cert-userid", &userid[..]]).is_err());
        // Using --gossip should succeed.
        sq.cert_list(&["--gossip", "--cert-userid", &userid[..]]);
        sq.cert_list(&["--gossip", "--unusable", "--cert-userid", &userid[..]]);
    }

    assert!(saw_invalid);

    // We now link all of the user IDs.  Even though the
    // self-signature relies on SHA-1, the links don't so we'll be
    // able to authenticate the user IDs.
    for ua in cert.userids() {
        let userid = String::from_utf8_lossy(ua.userid().value()).to_string();
        sq.pki_link_add(&[], cert.key_handle(), &[UserIDArg::AddUserID(&userid)]);

        assert!(
            sq.cert_list_maybe(&["--cert-userid", &userid[..]]).is_ok());
        assert!(
            sq.cert_list_maybe(&["--gossip", "--cert-userid", &userid[..]]).is_ok());
        sq.cert_list(&["--gossip", "--unusable", "--cert-userid", &userid[..]]);
    }
}

#[test]
fn list_revoked_userid() {
    // Check that we can't list a user ID that is revoked.
    let sq = Sq::new();

    let cert_file = artifact("keys/retired-userid.pgp");
    let cert = Cert::from_file(&cert_file).expect("valid cert");
    let fpr = &cert.fingerprint().to_string()[..];

    sq.cert_import(&cert_file);

    // Listing the certificate is okay.
    sq.cert_list(&[fpr]);
    sq.cert_list(&["--gossip", fpr]);

    let mut saw_revoked = false;

    for ua in cert.userids() {
        let userid = String::from_utf8_lossy(ua.userid().value());

        let good = if let RevocationStatus::Revoked(_)
            = ua.revocation_status(STANDARD_POLICY, None)
        {
            saw_revoked = true;
            false
        } else {
            true
        };

        // Not linked, so should fail.
        assert!(
            sq.cert_list_maybe(&["--cert-userid", &userid[..]]).is_err());
        // Using --gossip, so should succeed if the user ID is valid.
        assert_eq!(
            sq.cert_list_maybe(&["--gossip", "--cert-userid", &userid[..]]).is_ok(),
            good);
        // Using --gossip --unusable, so should always succeed.
        sq.cert_list(&["--gossip", "--unusable", "--cert-userid", &userid[..]]);
    }

    assert!(saw_revoked);
}
