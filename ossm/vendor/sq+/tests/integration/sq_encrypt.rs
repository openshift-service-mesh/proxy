use std::collections::HashSet;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::KeyID;
use openpgp::Fingerprint;
use openpgp::Packet;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::Result;

use crate::integration::common::power_set;
use crate::integration::common::Sq;
use crate::integration::common::STANDARD_POLICY;

// Encrypts a message to the specified recipients.  If
// `decryption_keys` is empty, asserts that encrypt failed.  If
// `decryption_keys` is not empty, asserts that the recipients of the
// PKESKs match `decryption_keys`.
fn try_encrypt(sq: &Sq, extra_args: &[&str],
               decryption_keys: &[&Fingerprint],
               recipient_certs: &[&Fingerprint],
               recipient_userids: &[&str],
               recipient_emails: &[&str])
{
    let mut args: Vec<&str> = extra_args.to_vec();

    let recipient_certs_ = recipient_certs
        .iter()
        .map(|fpr| fpr.to_string())
        .collect::<Vec<_>>();
    for recipient_cert in recipient_certs_.iter() {
        args.push("--for");
        args.push(&recipient_cert);
    }

    for recipient_userid in recipient_userids.iter() {
        args.push("--for-userid");
        args.push(&recipient_userid);
    }

    for recipient_email in recipient_emails.iter() {
        args.push("--for-email");
        args.push(&recipient_email);
    }

    eprintln!("sq encrypt {:?}", args);

    let message = format!("{:?}", args);

    let result = sq.encrypt_maybe(&args, message.as_bytes());

    match result {
        Err(err) => {
            assert!(decryption_keys.is_empty(),
                    "Error encrypting message: {}", err);
        }
        Ok(ciphertext) => {
            // Make sure we can decrypt the message using the keys
            // on the key store.
            let plaintext = sq.decrypt(&[], &ciphertext);
            assert_eq!(message.as_bytes(), plaintext);

            let mut die = false;

            let mut actual_recipients = Vec::new();
            let mut ppr = PacketParser::from_bytes(&ciphertext)
                .expect("valid ciphertet");
            while let PacketParserResult::Some(pp) = ppr {
                let (packet, next_ppr) = pp.next().expect("valid message");
                ppr = next_ppr;

                // Process the packet.
                if let Packet::PKESK(pkesk) = packet {
                    eprintln!("  PKESK for {:?}", pkesk.recipient());
                    actual_recipients.push(pkesk.recipient().map(KeyID::from));
                }
            }
            actual_recipients.sort();

            // Make sure the recipients are deduped.
            for rs in actual_recipients.windows(2) {
                let r1 = &rs[0];
                let r2 = &rs[1];

                if r1 == r2 {
                    eprintln!("Multiple PKESKs for the same recipient ({:?}).",
                              r1);
                    die = true;
                }
            }

            let actual_recipients: HashSet<KeyID>
                = actual_recipients.into_iter().filter_map(|x| x).collect();

            let mut decryption_keyids = decryption_keys
                .iter()
                .map(|fpr| KeyID::from(*fpr))
                .collect::<Vec<KeyID>>();
            decryption_keyids.sort();
            let decryption_keyids
                = HashSet::from_iter(decryption_keyids.into_iter());

            for missing in decryption_keyids.difference(&actual_recipients) {
                eprintln!("Message should have been encrypted to {}, \
                           but wasn't",
                          missing);
                die = true;
            }

            for extra in actual_recipients.difference(&decryption_keyids) {
                eprintln!("Message was encrypted to {}, \
                           but shouldn't have been",
                          extra);
                die = true;
            }

            if die {
                eprintln!("Actual recipients: {:?}", actual_recipients);
                eprintln!("Expected: {:?}", decryption_keyids);
                panic!("Something went wrong");
            }
        }
    }
}

#[test]
fn sq_encrypt_using_cert_store() -> Result<()>
{
    let sq = Sq::new();

    // Generate a key.
    let (cert, key_pgp, _key_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<alice@example.org>"]);
    let key_pgp = key_pgp.to_str().expect("valid UTF-8");

    // Try to encrypt a message.  This should fail, because we
    // haven't imported the key.
    for kh in [KeyHandle::from(cert.fingerprint()),
               KeyHandle::from(cert.keyid())]
    {
        assert!(
            sq.encrypt_maybe(&["--for", &kh.to_string()], &b""[..])
                .is_err());
    }

    // Import the certificate.
    sq.cert_import(key_pgp);

    const MESSAGE: &[u8] = b"\na secret message\n\nor two\n";

    // Now we should be able to encrypt a message to it, and
    // decrypt it.
    for kh in [KeyHandle::from(cert.fingerprint()),
               KeyHandle::from(cert.keyid())]
    {
        let ciphertext = sq.encrypt(
            &["--for", &kh.to_string()], MESSAGE);

        let plaintext = sq.decrypt(
            &["--recipient-file", &key_pgp], ciphertext);

        assert_eq!(MESSAGE, plaintext);
    }

    Ok(())
}

#[test]
fn sq_encrypt_recipient_userid() -> Result<()>
{
    let sq = Sq::new();

    // Generate the keys.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<alice@example.org>"]);
    let alice_pgp = alice_pgp.to_str().expect("valid UTF-8");

    let bob_userids = &[
        "<bob@some.org>",
        "Bob <bob@other.org>",
        "<bob@other.org>",
    ];
    let bob_emails = &[
        "bob@some.org",
        "bob@other.org",
    ];

    let bob_certified_userids = &[
        "Bob <bob@other.org>",
    ];
    let bob_certified_emails = &[
        "bob@other.org",
    ];

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &["--expiration", "never"],
        bob_userids);
    let bob_pgp = bob_pgp.to_str().expect("valid UTF-8");

    // Import the certificates.
    sq.cert_import(alice_pgp);
    sq.cert_import(bob_pgp);

    const MESSAGE: &[u8] = &[0x42; 24 * 1024 + 23];
    let encrypt = |trust_roots: &[&str],
                   recipients: &[(&str, &str)],
                   decryption_keys: &[&str]|
    {
        let mut args = Vec::new();

        for trust_root in trust_roots {
            args.push("--trust-root");
            args.push(trust_root);
        }

        for (option, recipient) in recipients.iter() {
            args.push(option);
            args.push(recipient);
        }

        let result = sq.encrypt_maybe(&args, MESSAGE);

        if decryption_keys.is_empty() {
            assert!(result.is_err(), "should have failed");
        } else {
            let ciphertext = result.expect("should have succeeded");

            let args = decryption_keys.iter()
                .flat_map(|k| vec![ "--recipient-file", k ])
                .collect::<Vec<&str>>();
            let plaintext = sq.decrypt(&args, ciphertext);

            assert_eq!(MESSAGE, plaintext);
        }
    };

    // Encryption by fingerprint should work.
    encrypt(&[],
            &[("--for", &bob.fingerprint().to_string())],
            &[&bob_pgp]);

    // Encryption by email address and user id should fail if the
    // binding can't be authenticated.
    for email in bob_emails.iter() {
        encrypt(&[],
                &[("--for-email", email)],
                &[]);
    }
    for userid in bob_userids.iter() {
        encrypt(&[],
                &[("--for-userid", userid)],
                &[]);
    }

    // Alice certifies Bob's certificate.
    for userid in bob_certified_userids {
        let certification
            = sq.scratch_file(Some(&format!("alice-certifies-{}", userid)[..]));
        sq.pki_vouch_add(&[], alice_pgp, bob_pgp, &[userid],
                             Some(certification.as_path()));
        sq.cert_import(certification);
    }

    // Still don't use a trust root.  This should still fail.
    for email in bob_emails.iter() {
        encrypt(&[],
                &[("--for-email", email)],
                &[]);
    }
    for userid in bob_userids.iter() {
        encrypt(&[],
                &[("--for-userid", userid)],
                &[]);
    }

    // Make Alice the trust root.  This should succeed.
    for email in bob_emails.iter() {
        if bob_certified_emails.contains(email) {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--for-email", email)],
                    &[ &bob_pgp ]);
        } else {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--for-email", email)],
                    &[]);
        }
    }
    for userid in bob_userids.iter() {
        if bob_certified_userids.contains(userid) {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--for-userid", userid)],
                    &[ &bob_pgp ]);
        } else {
            encrypt(&[&alice.fingerprint().to_string()],
                    &[("--for-userid", userid)],
                    &[]);
        }
    }

    // Make Bob a trust root.  This should succeed for all
    // self-signed user ids.
    for email in bob_emails.iter() {
        encrypt(&[&bob.fingerprint().to_string()],
                &[("--for-email", email)],
                &[&bob_pgp]);
    }
    for userid in bob_userids.iter() {
        encrypt(&[&bob.fingerprint().to_string()],
                &[("--for-userid", userid)],
                &[&bob_pgp]);
    }

    Ok(())
}

// Encrypt a message to two recipients: one whose certificate is
// in the certificate store, and one whose certificated is in a
// keyring.
#[test]
fn sq_encrypt_keyring() -> Result<()>
{
    let sq = Sq::new();

    // Generate the keys.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<alice@example.org>"]);
    let alice_pgp = alice_pgp.to_str().expect("valid UTF-8");
    let alice_fpr = alice.fingerprint().to_string();

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &["--expiration", "never"],
        &["<bob@example.org>"]);
    let bob_pgp = bob_pgp.to_str().expect("valid UTF-8");
    let bob_fpr = bob.fingerprint().to_string();

    const MESSAGE: &[u8] = &[0x42; 24 * 1024 + 23];
    let encrypt = |keyrings: &[&str],
                   recipients: &[&str],
                   decryption_keys: &[&str]|
    {
        let mut args = Vec::new();

        for keyring in keyrings.iter() {
            args.push("--keyring");
            args.push(keyring);
        }

        for recipient in recipients.iter() {
            args.push("--for");
            args.push(recipient);
        }

        let result = sq.encrypt_maybe(&args, MESSAGE);

        match result {
            Err(err) => {
                assert!(decryption_keys.is_empty(),
                        "Error encrypting message: {}", err);
            }
            Ok(ciphertext) => {
                for key in decryption_keys.iter() {
                    let plaintext
                        = sq.decrypt(&["--recipient-file", &key], &ciphertext);
                    assert_eq!(MESSAGE, plaintext);
                }
            }
        }
    };

    encrypt(&[&alice_pgp, &bob_pgp],
            &[&alice_fpr, &bob_fpr],
            &[&alice_pgp, &bob_pgp]);

    // Import Alice's certificate.
    sq.cert_import(&alice_pgp);

    encrypt(&[&alice_pgp, &bob_pgp],
            &[&alice_fpr, &bob_fpr],
            &[&alice_pgp, &bob_pgp]);

    encrypt(&[&bob_pgp],
            &[&alice_fpr, &bob_fpr],
            &[&alice_pgp, &bob_pgp]);


    Ok(())
}

#[test]
fn sq_encrypt_with_password() -> Result<()>
{
    let sq = Sq::new();

    let password = "hunter2";
    let password_file = sq.base().join("password");
    std::fs::write(&password_file, password)?;

    const MESSAGE: &str = "\na secret message\n\nor two\n";

    let plain_file = sq.base().join("plaintext");
    std::fs::write(&plain_file, MESSAGE)?;

    let cipher_file = sq.base().join("ciphertext");
    let mut cmd = sq.command();
    cmd.args(["encrypt",
              "--with-password-file", &password_file.display().to_string(),
              "--without-signature",
              "--output", &cipher_file.display().to_string(),
              &plain_file.display().to_string()]);
    sq.run(cmd, Some(true));

    let mut cmd = sq.command();
    cmd.args(["decrypt",
              "--password-file", &password_file.display().to_string(),
              &cipher_file.display().to_string()]);
    let output = sq.run(cmd, Some(true));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout, MESSAGE);

    Ok(())
}

// Exercise various ways to encrypt a message to a recipient
// (--for, --for-userid, and --for-email).
// When designating a certificate by name, make sure only
// authenticated certificates are used.
#[test]
fn sq_encrypt_cert_designators() -> Result<()>
{
    let sq = Sq::new();

    // Generate and import the keys.
    let gen_key = |userids: &[&str]| {
        let (cert, cert_pgp, _cert_rev)
            = sq.key_generate(&[], userids);
        let cert_vc = cert.with_policy(STANDARD_POLICY, None).expect("valid cert");
        let cert_enc = cert_vc.keys().for_transport_encryption()
            .map(|ka| ka.key().fingerprint())
            .collect::<Vec<_>>();
        assert_eq!(cert_enc.len(), 1);
        let cert_enc = cert_enc.into_iter().next().unwrap();

        eprintln!("{} {:?} => {}",
                  cert.fingerprint(), userids, cert_enc);

        sq.key_import(&cert_pgp);

        (cert, cert_enc)
    };

    let alice_email = "alice@example.org";
    let alice_userid = format!("Alice <{}>", alice_email);
    let (alice, alice_enc) = gen_key(&[&alice_userid]);
    let alice_fpr = alice.fingerprint();

    sq.pki_link_add(&[], alice.key_handle(), &[&alice_userid]);

    let bob_email1 = "bob@example.org";
    let bob_userid1 = format!("Bob <{}>", bob_email1);
    let bob_email2 = "bob@other.org";
    let bob_userid2 = format!("Bob <{}>", bob_email2);
    let (bob, bob_enc) = gen_key(&[&bob_userid1, &bob_userid2]);
    let bob_fpr = bob.fingerprint();

    sq.pki_link_add(&[], bob.key_handle(), &[&bob_userid1]);
    sq.pki_link_add(&[], bob.key_handle(), &[&bob_userid2]);

    // Mallory's certificate includes Alice's and Bob's user IDs.
    // Since Mallory's certificate is not authenticated, it shouldn't
    // be used when addressing certificates by user ID or email
    // address.
    let mallory_email = "mallory@example.org";
    let mallory_userid = format!("Mallory <{}>", mallory_email);
    let (mallory, mallory_enc)
        = gen_key(&[&mallory_userid, &alice_userid, &bob_userid1, &bob_userid2]);
    let mallory_fpr = mallory.fingerprint();

    // Check that different subsets of fingerprints, user ids, and
    // email addresses can be used to select recipients.  Check that
    // we encrypt to the relevant certificates, and only the relevant
    // certificates.  This checks that we only consider authenticated
    // user IDs: mallory's certificate is completely unauthenticated,
    // but contains Alice's and Bob's user IDs.
    let power_set_of = |recipients: &[(&Fingerprint, // Recipient
                                       Option<&Fingerprint>, // Fingerprint
                                       Option<&str>, // User ID
                                       Option<&str>)]| // Email
    {
        for recipients in power_set(recipients) {
            let intended_recipients = recipients.iter()
                .map(|(fpr, _, _, _)| *fpr)
                .collect::<Vec<_>>();

            let recipient_fprs = recipients.iter()
                .filter_map(|(_, fpr, _, _)| fpr.as_ref())
                .map(|fpr| *fpr)
                .collect::<Vec<&Fingerprint>>();
            let recipient_userids = recipients.iter()
                .filter_map(|(_, _, userid, _)| userid.as_ref())
                .map(|userid| &userid[..])
                .collect::<Vec<&str>>();
            let recipient_emails = recipients.iter()
                .filter_map(|(_, _, _, email)| email.as_ref())
                .map(|email| &email[..])
                .collect::<Vec<&str>>();

            try_encrypt(&sq, &[],
                        &intended_recipients,
                        &recipient_fprs[..],
                        &recipient_userids,
                        &recipient_emails);
        }
    };

    // Because a power set results in a combinatorial explosion, we
    // check the power set of a couple of different smaller sets
    // instead of one large set.

    let all = &[
        // Primary fingerprint.
        (&[-1, 0, 2][..], (&alice_enc, Some(&alice_fpr), None, None)),
        (&[-1, 2], (&bob_enc, Some(&bob_fpr), None, None)),
        (&[-1, 0, 1, 4], (&mallory_enc, Some(&mallory_fpr), None, None)),
        // User ID.
        (&[-3, 0, 3], (&alice_enc, None, Some(&alice_userid[..]), None)),
        (&[-3, 2, 3], (&bob_enc, None, Some(&bob_userid1[..]), None)),
        (&[-3, 1, 3], (&bob_enc, None, Some(&bob_userid2[..]), None)),
        // Email
        (&[-4, 1, 4], (&alice_enc, None, None, Some(alice_email))),
        (&[-4, 0, 4], (&bob_enc, None, None, Some(bob_email1))),
        (&[-4, 2, 4], (&bob_enc, None, None, Some(bob_email2))),
    ];

    let mut runs: Vec<isize> = all.iter()
        .flat_map(|(runs, _)| runs.iter().cloned())
        .collect();
    runs.sort();
    runs.dedup();

    for run in runs.into_iter() {
        let recipients = all
            .iter()
            .filter_map(|(runs, recipient)| {
                if runs.contains(&run) {
                    Some(recipient.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        power_set_of(&recipients[..]);
    }


    // Make sure we can't encrypt to mallory's certificate using his
    // primary user ID (it's not authenticated).
    try_encrypt(&sq, &[], &[], &[], &[], &[&mallory_email]);
    try_encrypt(&sq, &[], &[], &[], &[&mallory_userid], &[]);

    // Make sure we don't encrypt succeed even if we have a valid designator.
    try_encrypt(&sq, &[], &[], &[&alice_fpr], &[], &[&mallory_email]);
    try_encrypt(&sq, &[], &[], &[&alice_fpr], &[&mallory_userid], &[]);
    try_encrypt(&sq, &[], &[], &[&mallory_fpr], &[&mallory_userid], &[]);

    Ok(())
}

// Try encrypting to a certificate that does not have an encryption
// capable subkey.  Make sure it fails.
#[test]
fn sq_encrypt_not_encryption_capable() -> Result<()>
{
    let sq = Sq::new();

    // Generate the keys.  Alice has an encryption capable subkey, but
    // Bob doesn't.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &[],
        &["<alice@example.org>"]);
    sq.key_import(alice_pgp);

    let alice_enc = alice.keys().with_policy(STANDARD_POLICY, sq.now())
        .for_storage_encryption()
        .next()
        .expect("have a storage encryption-capable subkey")
        .key()
        .fingerprint();

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &["--cannot-encrypt"],
        &["<bob@example.org>"]);
    sq.key_import(bob_pgp);

    for (i, (recipients, result)) in [
        (&[ &alice ][..], &[ &alice_enc ][..]),
        (&[ &bob ], &[]),
        (&[ &alice, &bob ], &[]),
    ].into_iter().enumerate() {
        eprintln!("Test #{}", i + 1);

        let recipients = recipients.iter().map(|r| r.fingerprint())
            .collect::<Vec<Fingerprint>>();
        let recipients = recipients.iter()
            .collect::<Vec<&Fingerprint>>();

        try_encrypt(&sq, &[], result, &recipients, &[], &[]);
    }

    Ok(())
}

// Try encrypting to a certificate with an expired subkey.  Make sure
// it fails, unless '--use-expired-subkey' is provided.
#[test]
fn sq_encrypt_expired() -> Result<()>
{
    let mut sq = Sq::new();

    // Generate the keys.  Alice has an encryption capable subkey, but
    // Bob doesn't.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &[],
        &["<alice@example.org>"]);
    sq.key_import(alice_pgp);

    let alice_enc = alice.keys().with_policy(STANDARD_POLICY, sq.now())
        .for_storage_encryption()
        .next()
        .expect("have a storage encryption-capable subkey")
        .key()
        .fingerprint();

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &[],
        &["<bob@example.org>"]);
    sq.key_import(&bob_pgp);

    let bob_enc = bob.keys().with_policy(STANDARD_POLICY, sq.now())
        .for_storage_encryption()
        .next()
        .expect("have a storage encryption-capable subkey")
        .key();

    sq.tick(1);

    // Expire in a day.
    let bob = sq.key_subkey_expire(
        bob.key_handle(), &[bob_enc.key_handle()], "1d",
        None, None, true)
        .expect("can set expiration");
    sq.cert_import(&bob_pgp);

    let bob_enc = bob_enc.fingerprint();

    // Two days pass...
    sq.tick(2 * 24 * 60 * 60);

    for (i, (args, recipients, result)) in [
        (&[][..], &[ &alice ][..], &[ &alice_enc ][..]),
        (&[], &[ &bob ], &[]),
        (&[], &[ &alice, &bob ], &[]),
        (&["--use-expired-subkey"], &[ &alice ], &[ &alice_enc ]),
        (&["--use-expired-subkey"], &[ &bob ], &[ &bob_enc ]),
        (&["--use-expired-subkey"], &[ &alice, &bob ], &[ &alice_enc, &bob_enc ]),
    ].into_iter().enumerate() {
        eprintln!("Test #{}", i + 1);

        let recipients = recipients.iter().map(|r| r.fingerprint())
            .collect::<Vec<Fingerprint>>();
        let recipients = recipients.iter()
            .collect::<Vec<&Fingerprint>>();

        try_encrypt(&sq, args, result, &recipients, &[], &[]);
    }

    Ok(())
}

// Try encrypting to a certificate with a revoked subkey.  Make sure
// it fails.
#[test]
fn sq_encrypt_revoked_subkey() -> Result<()>
{
    let mut sq = Sq::new();

    // Generate the keys.  Alice has an encryption capable subkey, but
    // Bob doesn't.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &[],
        &["<alice@example.org>"]);
    sq.key_import(alice_pgp);

    let alice_enc = alice.keys().with_policy(STANDARD_POLICY, sq.now())
        .for_storage_encryption()
        .next()
        .expect("have a storage encryption-capable subkey")
        .key()
        .fingerprint();

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &[],
        &["<bob@example.org>"]);
    sq.key_import(&bob_pgp);

    let bob_enc = bob.keys().with_policy(STANDARD_POLICY, sq.now())
        .for_storage_encryption()
        .next()
        .expect("have a storage encryption-capable subkey")
        .key();

    sq.tick(1);

    // Revoke.
    let bob = sq.key_subkey_revoke(
        bob.key_handle(), &[bob_enc.key_handle()], None,
        "retired", "retired this key", None, &[], None);

    // Two days pass...
    sq.tick(2 * 24 * 60 * 60);

    for (i, (recipients, result)) in [
        (&[ &alice ][..], &[ &alice_enc ][..]),
        (&[ &bob ], &[]),
        (&[ &alice, &bob ], &[]),
    ].into_iter().enumerate() {
        eprintln!("Test #{}", i + 1);

        let recipients = recipients.iter().map(|r| r.fingerprint())
            .collect::<Vec<Fingerprint>>();
        let recipients = recipients.iter()
            .collect::<Vec<&Fingerprint>>();

        try_encrypt(&sq, &[], result, &recipients, &[], &[]);
    }

    Ok(())
}

// Try encrypting to a revoked certificate.  Make sure it fails.
#[test]
fn sq_encrypt_revoked() -> Result<()>
{
    let mut sq = Sq::new();

    // Generate the keys.  Alice has an encryption capable subkey, but
    // Bob doesn't.
    let (alice, alice_pgp, _alice_rev) = sq.key_generate(
        &[],
        &["<alice@example.org>"]);
    sq.key_import(alice_pgp);

    let alice_enc = alice.keys().with_policy(STANDARD_POLICY, sq.now())
        .for_storage_encryption()
        .next()
        .expect("have a storage encryption-capable subkey")
        .key()
        .fingerprint();

    let (bob, bob_pgp, _bob_rev) = sq.key_generate(
        &[],
        &["<bob@example.org>"]);
    sq.key_import(&bob_pgp);

    sq.tick(1);

    // Revoke.
    let bob = sq.key_revoke(
        bob.key_handle(), None,
        "retired", "retired this key", None, &[], None);

    // Two days pass...
    sq.tick(2 * 24 * 60 * 60);

    for (i, (recipients, result)) in [
        (&[ &alice ][..], &[ &alice_enc ][..]),
        (&[ &bob ], &[]),
        (&[ &alice, &bob ], &[]),
    ].into_iter().enumerate() {
        eprintln!("Test #{}", i + 1);

        let recipients = recipients.iter().map(|r| r.fingerprint())
            .collect::<Vec<Fingerprint>>();
        let recipients = recipients.iter()
            .collect::<Vec<&Fingerprint>>();

        try_encrypt(&sq, &[], result, &recipients, &[], &[]);
    }

    Ok(())
}

// Try encrypting to a certificate with a weakly bound key.  Make sure
// it fails.
#[test]
fn sq_encrypt_weak() -> Result<()>
{
    let mut sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("sha1-subkey-priv.pgp");
    sq.key_import(&cert_path);

    let cert = Cert::from_file(&cert_path).expect("can read");

    sq.tick(1);

    // Two days pass...
    sq.tick(2 * 24 * 60 * 60);

    try_encrypt(&sq, &[], &[], &[ &cert.fingerprint() ], &[], &[]);

    Ok(())
}
