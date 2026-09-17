use super::common::NO_USERIDS;
use super::common::Sq;
use super::common::UserIDArg;

#[test]
fn sq_pki_link_authorize_then_authenticate() {
    let ca_example_org = "<ca@example.org>";

    for (all, userids) in &[
        (false, &[UserIDArg::UserID(ca_example_org)][..]),
        // Implicitly use all self-signed user IDs.
        (true, NO_USERIDS),
        // Use a non-self signed user ID.
        (false, &[UserIDArg::AddUserID("frank")]),
    ] {
        let mut sq = Sq::new();

        let (ca, ca_pgp, _ca_rev)
            = sq.key_generate(&[], &[ca_example_org]);
        sq.key_import(&ca_pgp);

        let alice_example_org = "<alice@example.org>";
        let (alice, alice_pgp, _alice_rev)
            = sq.key_generate(&[], &[alice_example_org]);
        sq.key_import(&alice_pgp);

        let bob_example_org = "<bob@example.org>";
        let bob_other_org = "<bob@other.org>";
        let (bob, bob_pgp, _bob_rev)
            = sq.key_generate(&[], &[bob_example_org, bob_other_org]);
        sq.key_import(&bob_pgp);

        sq.tick(1);

        // The ca certifies alice's and bob's certificates for each of
        // their user IDs.
        let certification = sq.scratch_file(None);
        sq.pki_vouch_add(
            &[],
            ca.key_handle(), alice.key_handle(),
            &[ alice_example_org ],
            certification.as_path());
        sq.cert_import(&certification);

        let certification = sq.scratch_file(None);
        sq.pki_vouch_add(
            &[],
            ca.key_handle(), bob.key_handle(),
            &[ bob_example_org, bob_other_org ],
            certification.as_path());
        sq.cert_import(certification);

        // Check whether we can authenticate alice's and bob's
        // certificates for their user ID.
        let check = |sq: &Sq,
                     can_authenticate_alice,
                     can_authenticate_bob1,
                     can_authenticate_bob2|
        {
            for (cert, userid, can_authenticate) in &[
                (&alice, alice_example_org, can_authenticate_alice),
                (&bob, bob_example_org, can_authenticate_bob1),
                (&bob, bob_other_org, can_authenticate_bob2),
            ]
            {
                let r = sq.pki_authenticate(
                    &[],
                    &cert.fingerprint().to_string(),
                    userid);

                match (can_authenticate, r.is_ok()) {
                    (true, false) => {
                        panic!("Expected to authenticated {}, but didn't.",
                               userid);
                    }
                    (false, true) => {
                        panic!("Expected to NOT authenticated {}, but did.",
                               userid);
                    }
                    _ => (),
                }
            }
        };

        let maybe_all = |args: &[&'static str]| {
            let mut args = args.to_vec();
            if *all {
                args.push("--all");
            }
            args
        };

        // No delegation yet.
        println!("CA: not authorized");
        check(
            &sq,
            false, // Alice.
            false, // bob@example.org
            false);// bob@other.org

        // The user completely authorizes the CA.
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--unconstrained"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized, and unconstrained");
        check(
            &sq,
            true, // alice@example.org
            true, // bob@example.org
            true);// bob@other.org

        // The user authorizes the CA with the regex contraint "example".
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--regex", "example"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for \"example\"");
        check(
            &sq,
            true,  // alice@example.org
            true,  // bob@example.org
            false);// bob@other.org

        // The user authorizes the CA with the domain contraint
        // "example.org".
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--domain", "example.org"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for \"example.org\"");
        check(
            &sq,
            true,  // alice@example.org
            true,  // bob@example.org
            false);// bob@other.org

        // The user authorizes the CA with the regex contraint "other".
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--regex", "other"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for \"other\"");
        check(
            &sq,
            false, // alice@example.org
            false, // bob@example.org
            true); // bob@other.org

        // The user authorizes the CA with the regex contraint "bob".
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--regex", "bob"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for \"bob\"");
        check(
            &sq,
            false, // alice@example.org
            true,  // bob@example.org
            true); // bob@other.org

        // The user authorizes the CA with the regex contraint "bob" or
        // "alice".
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--regex", "bob",
                                          "--regex", "alice"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for \"bob\" or \"alice\"");
        check(
            &sq,
            true, // alice@example.org
            true, // bob@example.org
            true);// bob@other.org


        // The user authorizes the CA for the domains example.org and
        // other.org.
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--domain", "example.org",
                                          "--domain", "other.org"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for the domains example.org and other.org");
        check(
            &sq,
            true, // alice@example.org
            true, // bob@example.org
            true);// bob@other.org


        // The user authorizes the CA for the domain example.com and the
        // regex alice.
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--domain", "other.org",
                                          "--regex", "alice"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for the domains example.org and other.org");
        check(
            &sq,
            true,  // alice@example.org
            false, // bob@example.org
            true); // bob@other.org


        // The user authorizes the CA with the regex contraint "zoo".
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--regex", "zoo"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for \"zoo\"");
        check(
            &sq,
            false, // alice@example.org
            false, // bob@example.org
            false);// bob@other.org

        // The user authorizes the CA with the domain contraint "example".
        sq.tick(1);
        sq.pki_link_authorize(&maybe_all(&["--domain", "example"]),
                              ca.key_handle(),
                              userids);

        println!("CA: authorized for \"zoo\"");
        check(
            &sq,
            false, // alice@example.org
            false, // bob@example.org
            false);// bob@other.org
    }
}

#[test]
fn retract_explicit() {
    // Authorize a CA via multiple user IDs.  Retract one
    // authorization at a time.  Make sure the CA remains a trusted
    // introducer until all authorizations are retracted.

    let ca_example_org = "<ca@example.org>";
    let ca_example_com = "<ca@example.com>";
    let self_signed_userids = &[ca_example_org, ca_example_com][..];

    // When authorizing the CA we can either authorize implicitly
    // (i.e., all self-signed user IDs) or explicitly.  Try both.
    for explicit_all in [true, false] {
        eprintln!("explicit all = {}", explicit_all);

        let mut sq = Sq::new();
        let (ca, ca_pgp, _ca_rev)
            = sq.key_generate(&[], self_signed_userids);
        sq.key_import(&ca_pgp);

        let alice_example_org = "<alice@example.org>";
        let (alice, alice_pgp, _alice_rev)
            = sq.key_generate(&[], &[alice_example_org]);
        sq.key_import(&alice_pgp);

        sq.tick(1);

        // The ca certifies alice's certificate
        let certification = sq.scratch_file(None);
        sq.pki_vouch_add(&[],
                             ca.key_handle(), alice.key_handle(),
                             &[ alice_example_org ],
                             certification.as_path());
        sq.cert_import(&certification);

        let check = |sq: &Sq, can_authenticate: bool| {
            let r = sq.pki_authenticate(
                &[],
                &alice.fingerprint().to_string(),
                alice_example_org);

            match (can_authenticate, r.is_ok()) {
                (true, false) => {
                    panic!("Expected to authenticated {}, but didn't.",
                           alice_example_org);
                }
                (false, true) => {
                    panic!("Expected to NOT authenticated {}, but did.",
                           alice_example_org);
                }
                _ => (),
            }
        };

        // The ca is not yet authorized so we shouldn't be able to
        // authenticate alice.
        check(&sq, false);

        // Authorize via all user IDs.
        sq.tick(1);
        let userids = self_signed_userids;
        sq.pki_link_authorize(if explicit_all {
                                  &["--unconstrained", "--all"]
                              } else {
                                  &["--unconstrained"]
                              },
                              ca.key_handle(),
                              if explicit_all {
                                  &[]
                              } else {
                                  userids
                              });
        check(&sq, true);

        for (i, userid) in userids.iter().enumerate() {
            // Retract the authorization of one user ID.  It should
            // still be a trusted introducer.
            sq.tick(1);
            sq.pki_link_retract(&[], ca.key_handle(), &[userid]);

            if i == userids.len() - 1 {
                // We've retracted all authorizations.  This should
                // now fail.
                check(&sq, false);
            } else {
                check(&sq, true);
            }
        }
    }
}

#[test]
fn retract_non_self_signed() {
    // Make sure we can retract non-self-signed user IDs.

    let self_signed = "<ca@example.org>";
    let non_self_signed = "<ca@example.com>";

    let mut sq = Sq::new();
    let (ca, ca_pgp, _ca_rev)
        = sq.key_generate(&[], &[self_signed]);
    sq.key_import(&ca_pgp);

    let alice_example_org = "<alice@example.org>";
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[alice_example_org]);
    sq.key_import(&alice_pgp);

    sq.tick(1);

    // The ca certifies alice's certificate
    let certification = sq.scratch_file(None);
    sq.pki_vouch_add(&[],
                         ca.key_handle(), alice.key_handle(),
                         &[ alice_example_org ],
                         certification.as_path());
    sq.cert_import(&certification);

    let check = |sq: &Sq, can_authenticate: bool| {
        let r = sq.pki_authenticate(
            &[],
            &alice.fingerprint().to_string(),
            alice_example_org);

        match (can_authenticate, r.is_ok()) {
            (true, false) => {
                panic!("Expected to authenticated {}, but didn't.",
                       alice_example_org);
            }
            (false, true) => {
                panic!("Expected to NOT authenticated {}, but did.",
                       alice_example_org);
            }
            _ => (),
        }
    };

    // The ca is not yet authorized so we shouldn't be able to
    // authenticate alice.
    check(&sq, false);

    // Authorize the CA via a non-self-signed user ID.  Now we can
    // authenticate alice.
    sq.tick(1);
    sq.pki_link_authorize(&["--unconstrained"],
                          ca.key_handle(),
                          &[UserIDArg::AddUserID(non_self_signed)]);
    check(&sq, true);

    // Retract the authorization.  It should no longer be considered a
    // trusted introducer.
    sq.tick(1);
    sq.pki_link_retract(&[], ca.key_handle(), &[non_self_signed]);
    check(&sq, false);
}

#[test]
fn retract_all() {
    // Link all self-signed user IDs and a non-self-signed user ID.
    // When we retract all, make sure they are all retracted.

    let self_signed = "<ca@example.org>";
    let non_self_signed = "<ca@example.com>";

    let mut sq = Sq::new();
    let (ca, ca_pgp, _ca_rev)
        = sq.key_generate(&[], &[self_signed]);
    sq.key_import(&ca_pgp);

    let alice_example_org = "<alice@example.org>";
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[alice_example_org]);
    sq.key_import(&alice_pgp);

    sq.tick(1);

    // The ca certifies alice's certificate
    let certification = sq.scratch_file(None);
    sq.pki_vouch_add(&[],
                         ca.key_handle(), alice.key_handle(),
                         &[ alice_example_org ],
                         certification.as_path());
    sq.cert_import(&certification);

    let check = |sq: &Sq, can_authenticate: bool| {
        let r = sq.pki_authenticate(
            &[],
            &alice.fingerprint().to_string(),
            alice_example_org);

        match (can_authenticate, r.is_ok()) {
            (true, false) => {
                panic!("Expected to authenticated {}, but didn't.",
                       alice_example_org);
            }
            (false, true) => {
                panic!("Expected to NOT authenticated {}, but did.",
                       alice_example_org);
            }
            _ => (),
        }
    };

    // The ca is not yet authorized so we shouldn't be able to
    // authenticate alice.
    check(&sq, false);

    // Authorize the CA via a non-self-signed user ID.  Now we can
    // authenticate alice.
    sq.tick(1);
    sq.pki_link_authorize(&["--unconstrained"],
                          ca.key_handle(),
                          &[UserIDArg::UserID(self_signed),
                            UserIDArg::AddUserID(non_self_signed)]);
    check(&sq, true);

    // Retract all authorizations.  It should no longer be considered
    // a trusted introducer.
    sq.tick(1);
    sq.pki_link_retract(&["--all"], ca.key_handle(), NO_USERIDS);
    check(&sq, false);
}

#[test]
fn sq_pki_link_all_revoked() {
    // When we don't provide any user IDs, `sq pki link authorize`
    // certifies all of the self signed user IDs.  Make sure this
    // works in the presence of a revoked user ID, which should be
    // ignored.

    let mut sq = Sq::new();

    let ca_example_org = "<ca@example.org>";
    let ca_example_com = "<ca@example.com>";
    let (ca, ca_pgp, _ca_rev)
        = sq.key_generate(&[], &[ca_example_org, ca_example_com]);
    sq.key_import(&ca_pgp);

    // Revoke ca@example.com.
    sq.tick(1);
    let revocation = sq.scratch_file("revocation");
    sq.key_userid_revoke(&[], ca.fingerprint(), ca_example_com,
                         "retired", "bye", Some(revocation.as_path()));
    sq.cert_import(&revocation);

    let alice_example_org = "<alice@example.org>";
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[alice_example_org]);
    sq.key_import(&alice_pgp);

    sq.tick(1);

    // The ca certifies alice's certificate.
    let certification = sq.scratch_file(None);
    sq.pki_vouch_add(
        &[],
        ca.key_handle(), alice.key_handle(),
        &[ alice_example_org ],
        certification.as_path());
    sq.cert_import(&certification);

    // Check whether we can authenticate alice's and bob's
    // certificates for their user ID using otto as the trust root.
    let check = |sq: &Sq, can_authenticate|
    {
        let r = sq.pki_authenticate(
            &[],
            &alice.fingerprint().to_string(),
            alice_example_org);

        match (can_authenticate, r.is_ok()) {
            (true, false) => {
                panic!("Expected to authenticated {}, but didn't.",
                       alice_example_org);
            }
            (false, true) => {
                panic!("Expected to NOT authenticated {}, but did.",
                       alice_example_org);
            }
            _ => (),
        }
    };

    // No delegation yet.
    println!("CA: not authorized");
    check(&sq, false);

    // The user completely authorizes the CA.  Note: we don't specify
    // any user IDs so only valid self-signed user IDs should be used.
    // That means the revoked user ID should be skipped.
    sq.tick(1);
    sq.pki_link_authorize(&["--unconstrained", "--all"],
                          ca.key_handle(), NO_USERIDS);

    println!("CA: authorized, and unconstrained");
    check(&sq, true);
}
