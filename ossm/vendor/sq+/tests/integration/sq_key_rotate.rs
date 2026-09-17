use sequoia_openpgp as openpgp;
use openpgp::types::ReasonForRevocation;
use openpgp::types::KeyFlags;

use crate::integration::common::STANDARD_POLICY;
use crate::integration::common::Sq;
use crate::integration::common::check_certifications;

#[test]
fn rotate() {
    let s = &KeyFlags::signing();
    let a = &KeyFlags::authentication();
    let es = &KeyFlags::storage_encryption();
    let ec = &KeyFlags::transport_encryption();

    for kf in [
        &(&(s | a) | &(es | ec)),
        s,
        &(s | es),
        &(s | ec),
        a
    ] {
        let mut sq = Sq::new();

        let mut args = Vec::new();
        if kf.for_signing() {
            args.push("--can-sign");
        } else {
            args.push("--cannot-sign");
        }
        if kf.for_authentication() {
            args.push("--can-authenticate");
        } else {
            args.push("--cannot-authenticate");
        }
        match (kf.for_storage_encryption(), kf.for_transport_encryption()) {
            (true, true) => args.push("--can-encrypt=universal"),
            (true, false) => args.push("--can-encrypt=storage"),
            (false, true) => args.push("--can-encrypt=transport"),
            (false, false) => args.push("--cannot-encrypt"),
        }

        // The original certificate.
        let alice_email = "alice@example.org";
        let alice_userid = &format!("Alice <{}>", alice_email);
        let alice_email2 = "alice@other.org";
        let alice_userid2 = &format!("Alice <{}>", alice_email2);
        let (alice, alice_pgp, _alice_rev)
            = sq.key_generate(&args, &[ alice_userid, alice_userid2 ]);
        sq.key_import(&alice_pgp);

        // Link a user ID.
        sq.pki_link_add(&[], alice.key_handle(), &[ alice_userid ]);
        assert!(sq.pki_authenticate(
            &[], &alice.key_handle().to_string(), alice_userid).is_ok());
        assert!(sq.pki_authenticate(
            &[], &alice.key_handle().to_string(), alice_userid2).is_err());

        let bob_email = "bob@example.org";
        let bob_userid = &format!("Bob <{}>", bob_email)[..];
        let bob_email2 = "bob@other.org";
        let bob_userid2 = &format!("Bob <{}>", bob_email2)[..];
        let (bob, bob_pgp, _bob_rev)
            = sq.key_generate(&[], &[ bob_userid, bob_userid2 ]);
        sq.key_import(&bob_pgp);

        // Alice certifies Bob.
        sq.tick(1);
        sq.pki_vouch_add(
            &["--amount", "1"],
            &alice.key_handle(), &bob.key_handle(), &[bob_userid],
            None);

        // And do the rotation...
        sq.tick(1);
        sq.key_rotate(&[], alice.key_handle().into(), None);

        // Extract the updated certificates.
        let certs = sq.cert_export_all();
        assert_eq!(certs.len(), 3);
        let mut alice2 = None;
        let mut bob2 = None;
        let mut alice_new = None;
        for cert in certs.iter() {
            if cert.fingerprint() == alice.fingerprint() {
                alice2 = Some(cert);
            } else if cert.fingerprint() == bob.fingerprint() {
                bob2 = Some(cert);
            } else {
                alice_new = Some(cert);
            }
        }

        drop(alice);
        drop(bob);

        let alice2 = alice2.unwrap();
        let alice2_vc = alice2.with_policy(STANDARD_POLICY, sq.now()).unwrap();
        let bob2 = bob2.unwrap();
        let alice_new = alice_new.unwrap();
        let alice_new_vc = alice_new.with_policy(STANDARD_POLICY, sq.now()).unwrap();

        // Check the key structure.
        let alice2_kf = alice2_vc.keys().fold(KeyFlags::empty(), |kf, ka| {
            if let Some(subkeys_kf) = ka.key_flags() {
                &kf | &subkeys_kf
            } else {
                kf
            }
        });
        assert!(alice2_kf != KeyFlags::empty());
        let alice_new_kf = alice_new_vc.keys().fold(KeyFlags::empty(), |kf, ka| {
            if let Some(subkeys_kf) = ka.key_flags() {
                &kf | &subkeys_kf
            } else {
                kf
            }
        });
        assert_eq!(alice2_kf, alice_new_kf);

        // Check the user IDs.
        let mut alice2_userids
            = alice2_vc.userids().map(|ua| ua.userid()).collect::<Vec<_>>();
        assert!(alice2_userids.len() > 0);
        alice2_userids.sort();

        let mut alice_new_userids
            = alice_new_vc.userids().map(|ua| ua.userid()).collect::<Vec<_>>();
        alice_new_userids.sort();

        assert_eq!(alice2_userids, alice_new_userids);

        // Check the certifications.
        check_certifications(
            &certs,
            &[
                (alice2.fingerprint(), bob2.fingerprint(), bob_userid, 1, 1),

                // Cross sigs.
                (alice2.fingerprint(), alice_new.fingerprint(), alice_userid, 120, 1),
                (alice2.fingerprint(), alice_new.fingerprint(), alice_userid2, 120, 1),
                (alice_new.fingerprint(), alice2.fingerprint(), alice_userid, 120, 1),
                (alice_new.fingerprint(), alice2.fingerprint(), alice_userid2, 120, 1),

                // The replayed signature.
                (alice_new.fingerprint(), bob2.fingerprint(), bob_userid, 1, 1),
            ][..]);

        // Make sure the links were copied.
        assert!(sq.pki_authenticate(
            &[], &alice2.key_handle().to_string(), alice_userid).is_ok());
        assert!(sq.pki_authenticate(
            &[], &alice2.key_handle().to_string(), alice_userid2).is_err());

        assert!(sq.pki_authenticate(
            &[], &alice_new.key_handle().to_string(), alice_userid).is_ok());
        assert!(sq.pki_authenticate(
            &[], &alice_new.key_handle().to_string(), alice_userid2).is_err());

        // Alice should have exactly one revocation certificate.  It
        // should say the certificate is retired, and it should contain
        // the fingerprint of the new certificate.
        let revs = alice2_vc.primary_key().self_revocations().collect::<Vec<_>>();
        assert_eq!(revs.len(), 1);
        let rev = revs.into_iter().next().unwrap();
        let (reason, message)
            = rev.reason_for_revocation().expect("have revocation reason");
        assert_eq!(reason, ReasonForRevocation::KeyRetired);
        assert!(String::from_utf8_lossy(message)
                .contains(&alice_new.fingerprint().to_string()));
    }
}
