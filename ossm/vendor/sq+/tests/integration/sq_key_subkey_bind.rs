use super::common::FileOrKeyHandle;
use super::common::{Sq, artifact};

use std::path;

use sequoia_openpgp as openpgp;

use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::KeyFlags;

fn alice() -> path::PathBuf {
    //     Fingerprint: 5CCB BA06 74EA 5162 615E  36E9 80E5 ADE9 43CA 0DC3
    // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
    // Public-key size: 256 bits
    //      Secret key: Unencrypted
    //   Creation time: 2020-12-21 23:00:49 UTC
    //       Key flags: certification
    //
    //          Subkey: 6A3B 1EC7 6233 62BC 066E  75AB DC42 7976 95D6 24E5
    // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
    // Public-key size: 256 bits
    //      Secret key: Unencrypted
    //   Creation time: 2020-12-21 23:00:49 UTC
    //       Key flags: signing
    //
    //          Subkey: 827E 4397 F330 7EDA 6ABD  2A6E AD9C 461D 6D2F 0982
    // Public-key algo: ECDH public key algorithm
    // Public-key size: 256 bits
    //      Secret key: Unencrypted
    //   Creation time: 2020-12-21 23:00:49 UTC
    //       Key flags: transport encryption, data-at-rest encryption
    //
    //          UserID: Alice Lovelace <alice@example.org>
    artifact("keys").join("alice-lovelace-encryption-subkey-signing-subkey-priv.pgp")
}
fn alice_primary() -> (Fingerprint, KeyFlags) {
    ("5CCB BA06 74EA 5162 615E  36E9 80E5 ADE9 43CA 0DC3".parse().unwrap(),
     KeyFlags::empty().set_certification())
}
fn alice_signing() -> (Fingerprint, KeyFlags) {
    ("6A3B 1EC7 6233 62BC 066E  75AB DC42 7976 95D6 24E5".parse().unwrap(),
     KeyFlags::empty().set_signing())
}
fn alice_encryption() -> (Fingerprint, KeyFlags) {
    ("827E 4397 F330 7EDA 6ABD  2A6E AD9C 461D 6D2F 0982".parse().unwrap(),
     KeyFlags::empty().set_transport_encryption().set_storage_encryption())
}
fn bob() -> path::PathBuf {
    //     Fingerprint: C1CF 22F6 C838 07CE 3901  6CDE 8463 B196 87EE 13BB
    // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
    // Public-key size: 256 bits
    //      Secret key: Unencrypted
    //   Creation time: 2020-12-21 23:02:23 UTC
    //       Key flags: certification
    //
    //          UserID: Bob Babbage <bob@example.org>
    artifact("keys").join("bob-babbage-cert-only-priv.pgp")
}
fn bob_primary() -> (Fingerprint, KeyFlags) {
    ("C1CF 22F6 C838 07CE 3901  6CDE 8463 B196 87EE 13BB".parse().unwrap(),
     KeyFlags::empty().set_certification())
}

fn carol() -> path::PathBuf {
    //     Fingerprint: 0B17 34A8 2726 A5D1 D5AC  1568 1EC1 4781 FD88 09B4
    // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
    // Public-key size: 256 bits
    //      Secret key: Unencrypted
    //   Creation time: 2020-12-22 00:02:24 UTC
    //       Key flags: certification
    //
    //          Subkey: 3D56 A424 3D5C C345 638D  FB19 05D8 B9EA DB92 A8C1
    // Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
    // Public-key size: 256 bits
    //      Secret key: Unencrypted
    //   Creation time: 2020-12-22 00:02:24 UTC
    //       Key flags: signing
    //
    //          Subkey: 1F47 6866 1260 CFFA D3DE  B630 5652 476A 8B74 5CE5
    // Public-key algo: ECDH public key algorithm
    // Public-key size: 256 bits
    //      Secret key: Unencrypted
    //   Creation time: 2020-12-22 00:02:24 UTC
    //       Key flags: transport encryption, data-at-rest encryption
    //
    //          UserID: Carol <carol@example.org>
    artifact("keys").join("carol-encryption-subkey-signing-subkey-priv.pgp")
}
fn carol_primary() -> (Fingerprint, KeyFlags) {
    ("0B17 34A8 2726 A5D1 D5AC  1568 1EC1 4781 FD88 09B4".parse().unwrap(),
     KeyFlags::empty().set_certification())
}
fn carol_signing() -> (Fingerprint, KeyFlags) {
    ("3D56 A424 3D5C C345 638D  FB19 05D8 B9EA DB92 A8C1".parse().unwrap(),
     KeyFlags::empty().set_signing())
}
fn carol_encryption() -> (Fingerprint, KeyFlags) {
    ("1F47 6866 1260 CFFA D3DE  B630 5652 476A 8B74 5CE5".parse().unwrap(),
     KeyFlags::empty().set_transport_encryption().set_storage_encryption())
}

fn bare() -> path::PathBuf {
    // $ sq inspect bare.pgp
    // bare.pgp: Revocation Certificate.
    //
    //     Fingerprint: B321BA8F650CB16443E06826DBFA98A78CF6562F
    //                  Invalid: No binding signature at time 2024-09-26T08:21:08Z
    // Public-key algo: RSA
    // Public-key size: 2048 bits
    //   Creation time: 1970-01-01 00:00:00 UTC
    artifact("keys").join("bare.pgp")
}
fn bare_signing() -> (Fingerprint, KeyFlags) {
    ("B321BA8F650CB16443E06826DBFA98A78CF6562F".parse().unwrap(),
     KeyFlags::empty().set_signing())
}

fn check(cert: &Cert,
         key_count: usize,
         keys: ((Fingerprint, KeyFlags), &[(Fingerprint, KeyFlags)]))
         -> Result<()>
{
    let p = &StandardPolicy::new();

    let vc = cert.with_policy(p, None).unwrap();

    assert_eq!(key_count, vc.keys().count());

    assert_eq!(vc.primary_key().key().fingerprint(), keys.0.0);
    assert_eq!(vc.primary_key().key_flags(), Some(keys.0.1));

    for (subkey, keyflags) in keys.1 {
        let mut found = false;
        for k in vc.keys().subkeys() {
            if k.key().fingerprint() == *subkey {
                assert_eq!(k.key_flags().as_ref(), Some(keyflags));
                found = true;
                break;
            }
        }
        assert!(found);
    }

    Ok(())
}

#[test]
fn bind_encryption() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice() ],
            // Handle
            bob().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), bob() ],
            // Handle
            bob_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Have Bob bind alice's encryption subkey.
        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [ alice_encryption().0.clone() ].to_vec(),
            "-");

        assert!(
            check(&cert, 2, (bob_primary(), &[alice_encryption()])).is_ok());
    }

    Ok(())
}

#[test]
fn bind_signing() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice() ],
            // Handle
            bob().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), bob() ],
            // Handle
            bob_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Bind a signing subkey (subkey has secret key material).
        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [ alice_signing().0.clone() ].to_vec(),
            "-");

        assert!(
            check(&cert, 2, (bob_primary(), &[alice_signing()])).is_ok());
    }

    Ok(())
}

#[test]
fn bind_certification() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(carol()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice() ],
            // Handle
            carol().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), carol() ],
            // Handle
            carol_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Bind a certification subkey (subkey has secret key
        // material).
        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [ alice_primary().0.clone() ].to_vec(),
            "-");

        assert!(check(&cert, 4, (carol_primary(), &[alice_primary()])).is_ok());
    }

    Ok(())
}

#[test]
fn bind_encryption_and_signing() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice() ],
            // Handle
            bob().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), bob() ],
            // Handle
            bob_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [
                alice_signing().0.clone(),
                alice_encryption().0.clone(),
            ].to_vec(),
            "-");

        assert!(
            check(&cert, 3,
                  (bob_primary(),
                   &[alice_signing(), alice_encryption()]))
                .is_ok());
    }

    Ok(())
}

#[test]
fn bind_twice() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice() ],
            // Handle
            bob().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), bob() ],
            // Handle
            bob_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Bind the same an encryption subkey twice.
        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [
                alice_encryption().0.clone(),
                alice_encryption().0.clone(),
            ].to_vec(),
            "-");

        assert!(
            check(&cert, 2, (bob_primary(), &[alice_encryption()])).is_ok());
    }

    Ok(())
}

#[test]
fn bind_key_appears_twice() -> Result<()> {
    let sq = Sq::new();

    // Bind an encryption subkey that appears twice.
    let cert = sq.key_subkey_bind(
        &[],
        [ alice(), alice(), ].to_vec(),
        bob(),
        [
            alice_encryption().0.clone(),
        ].to_vec(),
        "-");

    assert!(
        check(&cert, 2, (bob_primary(), &[alice_encryption()])).is_ok());

    Ok(())
}

#[test]
fn bind_own_encryption() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(alice()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice() ],
            // Handle
            alice().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), bob() ],
            // Handle
            alice_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Bind its own encryption subkey.  This should be a noop.
        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [
                alice_encryption().0.clone(),
            ].to_vec(),
            "-");

        assert!(
            check(&cert, 3, (alice_primary(), &[alice_encryption()])).is_ok());
    }

    Ok(())
}

#[test]
fn bind_own_primary() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ bob() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ bob() ],
            // Handle
            bob().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ bob() ],
            // Handle
            bob_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Bind own primary key.
        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [
                bob_primary().0.clone(),
            ].to_vec(),
            "-");

        assert!(
            check(&cert, 2, (bob_primary(), &[bob_primary()])).is_ok());
    }

    Ok(())
}

#[test]
fn bind_missing() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice(), bob() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ bob() ],
            // Handle
            bob().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ bob() ],
            // Handle
            bob_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Bind a key that is not present.
        let r = sq.key_subkey_bind_maybe(
            &[],
            keyrings.to_vec(),
            handle,
            [
                "1234 5678 90AB CDEF  1234 5678 90AB CDEF"
                    .parse::<KeyHandle>()
                    .expect("valid fingerprint")
            ].to_vec(),
            "-");

        assert!(r.is_err());
    }

    Ok(())
}

#[test]
fn bind_from_multiple() -> Result<()> {
    for (keyrings, key_imports, handle) in [
        (
            // Keyrings
            &[ alice(), carol() ][..],
            // Key store imports.
            &[][..],
            // Handle
            FileOrKeyHandle::from(bob()),
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), carol() ],
            // Handle
            bob().into()
        ),
        (
            // Keyrings
            &[][..],
            // Key store imports.
            &[ alice(), bob(), carol(), ],
            // Handle
            bob_primary().0.into()
        ),
    ] {
        let sq = Sq::new();

        for file in key_imports {
            sq.key_import(file);
        }

        // Bind own primary key.
        let cert = sq.key_subkey_bind(
            &[],
            keyrings.to_vec(),
            handle,
            [
                alice_signing().0.clone(),
                alice_encryption().0.clone(),
                carol_signing().0.clone(),
                carol_encryption().0.clone(),
            ].to_vec(),
            "-");

        assert!(
            check(&cert, 5,
                  (bob_primary(),
                   &[
                       alice_signing(), alice_encryption(),
                       carol_signing(), carol_encryption()
                   ]))
                .is_ok());
    }

    Ok(())
}

// A bare certificate is a certificate that consists of just a primary
// key (no subkeys, no user IDs, and no signatures).  Make sure we are
// able to bind one.
#[test]
fn bind_bare() -> Result<()> {
    let sq = Sq::new();

    sq.key_import(alice());

    let alice2_pgp = sq.scratch_file("alice2.pgp");

    let to_bind = bare_signing().0;

    let bare_file = bare();
    let bare = Cert::from_file(&bare_file).expect("can read file");

    // First, a bare certificate doesn't have any key flags set.  Make
    // sure `sq key bind` complains, if we don't specify any (e.g.,
    // `--can-encrypt`).
    let r = sq.key_subkey_bind_maybe(
        &[],
        vec![ bare_file.clone() ],
        alice_primary().0,
        vec![ to_bind.clone() ],
        &alice2_pgp);
    if r.is_ok() {
        panic!("sq key bind succeeded, but should have complained about \
                missing key flags");
    }

    let cert = sq.key_subkey_bind(
        &["--can-encrypt", "universal"],
        vec![ bare_file.clone() ],
        alice_primary().0,
        vec![ to_bind.clone() ],
        &alice2_pgp);

    let mut found = false;
    for k in cert.keys() {
        let was_bound = k.key().mpis() == bare.primary_key().key().mpis();

        eprintln!("{}{}", k.key().fingerprint(),
                  if was_bound {
                      " (bound)"
                  } else {
                      ""
                  });
        if was_bound {
            found = true;
        }
    }
    if ! found {
        panic!("{} was not bound", to_bind);
    }

    Ok(())
}

// Check that we can set the key creation time.
#[test]
fn key_creation_time() -> Result<()> {
    let sq = Sq::new();

    sq.key_import(alice());

    let alice2_pgp = sq.scratch_file("alice2.pgp");

    let to_bind = bare_signing().0;

    // $ date --iso-8601=seconds --utc --date='@1577483647'
    // 2019-12-27T21:54:07+00:00
    let time = 1577483647;
    let time = std::time::UNIX_EPOCH + std::time::Duration::new(time, 0);
    let time_str = "2019-12-27T21:54:07+00:00";

    let bare_file = bare();
    let bare = Cert::from_file(&bare_file).expect("can read file");

    let cert = sq.key_subkey_bind(
        &["--can-encrypt", "universal", "--creation-time", time_str ],
        vec![ bare_file ],
        alice_primary().0,
        vec![ to_bind.clone() ],
        &alice2_pgp);

    let mut found = false;
    for k in cert.keys() {
        let was_bound = k.key().mpis() == bare.primary_key().key().mpis();

        eprintln!("{}: {:?}{}",
                  k.key().fingerprint(),
                  k.key().creation_time(),
                  if was_bound {
                      " (bound)"
                  } else {
                      ""
                  });
        if was_bound {
            assert_eq!(k.key().creation_time(), time);
            found = true;
        }
    }
    if ! found {
        panic!("{} was not bound", to_bind);
    }

    Ok(())
}
