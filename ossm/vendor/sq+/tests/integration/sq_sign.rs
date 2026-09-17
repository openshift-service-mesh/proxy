use std::fs::{self, File};
use std::io;

use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::{Packet, PacketPile, Cert};
use openpgp::cert::CertBuilder;
use openpgp::crypto::KeyPair;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::types::{CompressionAlgorithm, SignatureType};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Message, Signer, Compressor, LiteralWriter};
use openpgp::serialize::Serialize;

use super::common::*;

const P: &StandardPolicy = &StandardPolicy::new();

#[test]
fn sq_sign() -> Result<()> {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign message.
    sq.sign(artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"), None,
            &artifact("messages/a-cypherpunks-manifesto.txt"), sig.as_path());

    #[cfg(unix)]
    {
        // Check permissions of the generated file.

        use std::os::unix::fs::PermissionsExt;

        // The permissions should not differ from the dummy file's
        // permissions as no secrets got exported.
        let dummy_file_path = sq.scratch_file("dummy.txt");
        let _dummy_file = std::fs::File::create(&dummy_file_path)?;
        let dummy_mode = std::fs::metadata(&dummy_file_path)?
            .permissions()
            .mode();

        let mode = std::fs::metadata(&sig)?.permissions().mode();
        assert_eq!(mode, dummy_mode,
                   "Got: {:o}, expected: {:o}", mode, dummy_mode);
    }

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::Message, &sig, None);

    Ok(())
}

#[test]
fn sq_sign_with_notations() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign message.
    sq.sign_args(&["--signature-notation", "foo", "bar",
                   "--signature-notation", "!foo", "xyzzy",
                   "--signature-notation", "hello@example.org", "1234567890"],
                 artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"), None,
                 &artifact("messages/a-cypherpunks-manifesto.txt"), sig.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);

        eprintln!("{:?}", sig);

        let hr = NotationDataFlags::empty().set_human_readable();
        let notations = &mut [
            (NotationData::new("foo", "bar", hr.clone()), false),
            (NotationData::new("foo", "xyzzy", hr.clone()), false),
            (NotationData::new("hello@example.org", "1234567890", hr), false)
        ];

        for n in sig.notation_data() {
            if n.name() == "salt@notations.sequoia-pgp.org" {
                continue;
            }

            for (m, found) in notations.iter_mut() {
                if n == m {
                    assert!(!*found);
                    *found = true;
                }
            }
        }
        for (n, found) in notations.iter() {
            assert!(found, "Missing: {:?}", n);
        }
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
                "--known-notation", "foo"],
              Verify::Message, &sig, None);
}

#[test]
fn sq_sign_append() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Sign message.
    sq.sign(artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"), None,
            &artifact("messages/a-cypherpunks-manifesto.txt"), sig0.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::Message, &sig0, None);

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    sq.sign_args(
        &["--append"],
        artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
        None, sig0.as_path(), sig1.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::Message, &sig1, None);
    sq.verify(&["--signer-file", &artifact_s("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")],
              Verify::Message, &sig1, None);
}

#[test]
#[allow(unreachable_code)]
fn sq_sign_append_on_compress_then_sign() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // This is quite an odd scheme, so we need to create such a
    // message by foot.
    let tsk = Cert::from_file(&artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"))
        .unwrap();
    let key = tsk.keys().with_policy(P, None).for_signing().next().unwrap().key();
    let sec = match key.optional_secret() {
        Some(SecretKeyMaterial::Unencrypted(ref u)) => u.clone(),
        _ => unreachable!(),
    };
    let keypair = KeyPair::new(key.clone(), sec).unwrap();
    let message = Message::new(File::create(&sig0).unwrap());
    let signer = Signer::new(message, keypair).unwrap()
        .creation_time(sq.now())
        .build().unwrap();
    let compressor = Compressor::new(signer)
        .algo(CompressionAlgorithm::Uncompressed)
        .build().unwrap();
    let mut literal = LiteralWriter::new(compressor).build()
        .unwrap();
    io::copy(
        &mut File::open(&artifact("messages/a-cypherpunks-manifesto.txt")).unwrap(),
        &mut literal)
        .unwrap();
    literal.finalize()
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    // Verify signed message.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::Message, &sig0, None);

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    sq.command()
        .arg("sign")
        .arg("--message")
        .arg("--append")
        .arg("--signer-file").arg(artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"))
        .arg("--output")
        .arg(&*sig1.to_string_lossy())
        .arg(&*sig0.to_string_lossy())
        .assert()
        .failure(); // XXX: Currently, this is not implemented.

    // XXX: Currently, this is not implemented in sq.
    return;

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::Message, &sig0, None);
    sq.verify(&["--signer-file", &artifact_s("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")],
              Verify::Message, &sig0, None);
}

#[test]
fn sq_sign_detached() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    sq.sign_detached(&[],
                     artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"),
                     &artifact("messages/a-cypherpunks-manifesto.txt"),
                     sig.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::SignatureFile(sig),
              &artifact("messages/a-cypherpunks-manifesto.txt"), None);
}

#[test]
fn sq_sign_detached_append() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    sq.sign_detached(&[],
                     artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"),
                     &artifact("messages/a-cypherpunks-manifesto.txt"),
                     sig.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::SignatureFile(sig.clone()),
              &artifact("messages/a-cypherpunks-manifesto.txt"), None);

    // Check that we don't blindly overwrite signatures.
    sq.try_sign_detached(&[],
                         artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
                         &artifact("messages/a-cypherpunks-manifesto.txt"),
                         sig.as_path())
        .unwrap_err();

    // Now add a second signature with --append.
    eprintln!("now");
    sq.sign_detached(&["--append"],
                     artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
                     &artifact("messages/a-cypherpunks-manifesto.txt"),
                     sig.as_path());
    eprintln!("done");

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify both detached signatures.
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::SignatureFile(sig.clone()),
              &artifact("messages/a-cypherpunks-manifesto.txt"), None);
    sq.verify(&["--signer-file", &artifact_s("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")],
              Verify::SignatureFile(sig.clone()),
              &artifact("messages/a-cypherpunks-manifesto.txt"), None);

    // Finally, check that we don't truncate the file if something
    // goes wrong.
    sq.command()
        .arg("sign")
        .arg("--signature-file")
        .arg("--append")
        .arg("--signer-file") // Not a private key => signing will fail.
        .arg(&artifact("keys/erika-corinna-daniela-simone-antonia-nistp521.pgp"))
        .args(["--output", &sig.to_string_lossy()])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .failure();

    // Check that the content is still sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
}

// Notarizations ahead.

#[ignore]
#[test]
fn sq_sign_append_a_notarization() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    sq.sign_detached(
        &["--append"],
        artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
        &artifact("messages/signed-1-notarized-by-ed25519.pgp"),
        sig0.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    sq.verify(&["--signer-file", &artifact_s("keys/neal.pgp")],
              Verify::Message, &sig0, None);
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::Message, &sig0, None);
    sq.verify(&["--signer-file", &artifact_s("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")],
              Verify::Message, &sig0, None);
}

#[ignore]
#[test]
fn sq_sign_notarize() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    sq.sign_args(
        &["--notarize"],
        artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
        None,
        &artifact("messages/signed-1.gpg"),
        sig0.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    sq.verify(&["--signer-file", &artifact_s("keys/neal.pgp")],
              Verify::Message, &sig0, None);
    sq.verify(&["--signer-file", &artifact_s("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")],
              Verify::Message, &sig0, None);
}

#[ignore]
#[test]
fn sq_sign_notarize_a_notarization() {
    let sq = Sq::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    sq.sign_args(
        &["--notarize"],
        artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
        None,
        &artifact("messages/signed-1-notarized-by-ed25519.pgp"),
        sig0.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 2);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    sq.verify(&["--signer-file", &artifact_s("keys/neal.pgp")],
              Verify::Message, &sig0, None);
    sq.verify(&["--signer-file", &artifact_s("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")],
              Verify::Message, &sig0, None);
    sq.verify(&["--signer-file", &artifact_s("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp")],
              Verify::Message, &sig0, None);
}

#[test]
fn sq_multiple_signers() -> Result<()> {
    let sq = Sq::new();
    let tmp = TempDir::new()?;

    let gen = |userid: &str| {
        CertBuilder::new()
            .add_signing_subkey()
            .add_userid(userid)
            .generate().map(|(key, _rev)| key)
    };

    let alice = gen("<alice@some.org>")?;
    let alice_pgp = tmp.path().join("alice.pgp");
    let mut file = File::create(&alice_pgp)?;
    alice.as_tsk().serialize(&mut file)?;

    let bob = gen("<bob@some.org>")?;
    let bob_pgp = tmp.path().join("bob.pgp");
    let mut file = File::create(&bob_pgp)?;
    bob.as_tsk().serialize(&mut file)?;

    // Sign message.
    let assertion = sq.command()
        .args([
            "sign",
            "--signer-file", alice_pgp.to_str().unwrap(),
            "--signer-file", &bob_pgp.to_str().unwrap(),
            "--signature-file=-",
        ])
        .write_stdin(&b"foo"[..])
        .assert().try_success()?;

    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);

    let pp = PacketPile::from_bytes(&*stdout)?;

    assert_eq!(pp.children().count(), 2,
               "expected two packets");

    let mut sigs: Vec<Fingerprint> = pp.children().map(|p| {
        if let &Packet::Signature(ref sig) = p {
            if let Some(KeyHandle::Fingerprint(fpr))
                = sig.get_issuers().into_iter().next()
            {
                fpr
            } else {
                panic!("No issuer fingerprint subpacket!");
            }
        } else {
            panic!("Expected a signature, got: {:?}", pp);
        }
    }).collect();
    sigs.sort();

    let alice_sig_fpr = alice.with_policy(P, None)?
        .keys().for_signing().next().unwrap().key().fingerprint();
    let bob_sig_fpr = bob.with_policy(P, None)?
        .keys().for_signing().next().unwrap().key().fingerprint();

    let mut expected = vec![
        alice_sig_fpr,
        bob_sig_fpr,
    ];
    expected.sort();

    assert_eq!(sigs, expected);

    Ok(())
}

#[test]
fn sq_sign_using_cert_store() -> Result<()> {
    let sq = Sq::new();
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let msg_pgp = dir.path().join("msg.pgp");

    // Generate a key.
    let (alice, alice_pgp, _rev) =
        sq.key_generate(&["--expiration", "never"], &["<alice@example.org>"]);

    // Import it.
    let mut cmd = sq.command();
    cmd.args(["--cert-store", &certd,
              "cert", "import"]);
    cmd.arg(&alice_pgp);
    sq.run(cmd, true);

    // Sign a message.
    sq.sign(&alice_pgp, None,
            &artifact("messages/a-cypherpunks-manifesto.txt"),
            msg_pgp.as_path());

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&msg_pgp).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);

        let alice_signer = alice.with_policy(P, None)?
            .keys().for_signing().next().expect("have one");
        assert_eq!(sig.get_issuers().into_iter().next(),
                   Some(KeyHandle::from(alice_signer.key().fingerprint())));
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&msg_pgp).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify the signed message.  First, we specify the certificate
    // explicitly.
    sq.verify(&["--signer-file", &alice_pgp.display().to_string()],
              Verify::Message, &msg_pgp, None);

    // Verify the signed message.  Now, we don't specify the
    // certificate or use a certificate store.
    let result = sq.verify_maybe(&[], Verify::Message, &msg_pgp, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("missing certificate."), "{}", err);
    assert!(err.contains("Error: Verification failed") , "{}", err);

    // Now we use the certificate store.
    let result = sq.verify_maybe(
        &["--cert-store", &certd], Verify::Message, &msg_pgp, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();

    // The default trust model says that certificates from the
    // certificate store are not authenticated.
    assert!(err.contains("the certificate can't be authenticated."),
            "{}", err);
    assert!(err.contains("Error: Verification failed"),
            "{}", err);

    // Now we use the certificate store *and* specify the certificate.
    let mut cmd = sq.command();
    cmd.arg("--cert-store").arg(&certd)
        .arg("verify").arg("--message")
        .arg("--signer").arg(&alice.fingerprint().to_string())
        .arg(&msg_pgp);
    let output = cmd.output().expect("success");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    // The default trust model says that certificates from the
    // certificate store are not authenticated.
    assert!(stderr.contains("Authenticated signature made by "),
            "stdout:\n{}\nstderr: {}", stdout, stderr);
    assert!(stderr.contains("1 authenticated signature."),
            "stdout:\n{}\nstderr: {}", stdout, stderr);

    Ok(())
}

// Verify signatures using the web of trust to authenticate the
// signers.
#[test]
fn sq_verify_wot() -> Result<()> {
    let sq = Sq::new();
    let dir = TempDir::new()?;

    let certd = dir.path().join("cert.d").display().to_string();
    std::fs::create_dir(&certd).expect("mkdir works");

    let alice_pgp = dir.path().join("alice.pgp").display().to_string();
    let bob_pgp = dir.path().join("bob.pgp").display().to_string();
    let carol_pgp = dir.path().join("carol.pgp").display().to_string();
    let dave_pgp = dir.path().join("dave.pgp").display().to_string();
    let msg_pgp = dir.path().join("msg.pgp").display().to_string();

    // Generates a key.
    //
    // If cert_store is not `None`, then the resulting certificate is also
    // imported.
    let sq_gen_key = |sq: &Sq, userids: &[&str], file_out: &str|
        -> Cert
    {
        let (cert, file, _) = sq.key_generate(&[], userids);
        sq.cert_import(&file);
        fs::rename(file, file_out).unwrap();
        cert
    };

    // Verifies a signed message.
    let sq_verify = |sq: &Sq,
                     trust_roots: &[&str],
                     signer_files: &[&str],
                     msg_pgp: &str|
    {
        let mut cmd = sq.command();
        for trust_root in trust_roots {
            cmd.args(&["--trust-root", trust_root]);
        }
        cmd.arg("verify").arg("--message");
        for signer_file in signer_files {
            cmd.args(&["--signer-file", signer_file]);
        }
        cmd.arg(msg_pgp);
        let output = sq.run(cmd, None);

        (output.status.clone(),
         String::from_utf8_lossy(&output.stdout).to_string(),
         String::from_utf8_lossy(&output.stderr).to_string())
    };

    // Certifies a binding.
    //
    // The certification is imported into the cert store.
    let sq_certify = |sq: &Sq,
                      certifier: &str, cert: &str, userid: &str,
                      trust_amount: Option<usize>|
    {
        let mut extra_args = Vec::new();
        let trust_amount_;
        if let Some(trust_amount) = trust_amount {
            extra_args.push("--amount");
            trust_amount_ = format!("{}", trust_amount);
            extra_args.push(&trust_amount_);
        }

        let certification = sq.scratch_file(Some(&format!(
            "certification {} {} by {}", cert, userid, certifier)[..]));

        let cert = if let Ok(kh) = cert.parse::<KeyHandle>() {
            kh.into()
        } else {
            FileOrKeyHandle::FileOrStdin(cert.into())
        };

        sq.pki_vouch_add(&extra_args, certifier, cert, &[userid],
                             Some(certification.as_path()));
        sq.cert_import(&certification);
    };

    let alice = sq_gen_key(&sq, &[ "<alice@example.org>" ], &alice_pgp);
    let bob = sq_gen_key(&sq, &[ "<bob@example.org>" ], &bob_pgp);
    let carol = sq_gen_key(&sq, &[ "<carol@example.org>" ], &carol_pgp);
    let dave = sq_gen_key(&sq, &[ "<dave@example.org>" ], &dave_pgp);

    let alice_fpr = alice.fingerprint().to_string();
    let bob_fpr = bob.fingerprint().to_string();
    let carol_fpr = carol.fingerprint().to_string();
    let dave_fpr = dave.fingerprint().to_string();

    // Sign a message.
    sq.command()
        .arg("sign")
        .arg("--message")
        .args(["--signer-file", &bob_pgp])
        .args(["--signer-file", &carol_pgp])
        .args(["--signer-file", &dave_pgp])
        .args(["--output", &msg_pgp])
        .arg(&artifact("messages/a-cypherpunks-manifesto.txt"))
        .assert()
        .success();

    // When designating the signers using a file, the signers are
    // fully trusted.
    {
        let output = sq_verify(&sq, &[], &[&bob_pgp], &msg_pgp);
        assert!(output.0.success());
        let output = sq_verify(&sq, &[], &[&carol_pgp], &msg_pgp);
        assert!(output.0.success());
        let output = sq_verify(&sq, &[], &[&dave_pgp], &msg_pgp);
        assert!(output.0.success());

        // Alice did not sign it so this should fail.
        let output = sq_verify(&sq, &[], &[&alice_pgp], &msg_pgp);
        assert!(! output.0.success());

        // But, one authenticated signature is enough.
        let output = sq_verify(&sq, &[], &[&alice_pgp, &bob_pgp], &msg_pgp);
        assert!(output.0.success());
    }

    // When the signers' certificates are found in the cert store, and
    // they can't be authenticated with the web of trust, the
    // verification will fail.
    {
        let output = sq_verify(&sq, &[], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("the certificate can't be authenticated."),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);

        // Specifying a trust root won't help if there is no path to a
        // signer.
        let output = sq_verify(&sq, &[&alice_fpr], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("the certificate can't be authenticated."),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // A trust root can certify itself
    {
        let output = sq_verify(&sq, &[&bob_fpr], &[], &msg_pgp);
        assert!(output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Authenticated signature made by "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);

        let output = sq_verify(
            &sq, &[&alice_fpr, &bob_fpr], &[], &msg_pgp);
        assert!(output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Authenticated signature made by "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // Have Alice partially certify Bob, and make Alice the trust
    // root.  The signature should still be bad.
    {
        sq_certify(&sq, &alice_pgp,
                   &bob.fingerprint().to_string(), "<bob@example.org>",
                   Some(90));
        let output = sq_verify(&sq, &[&alice_fpr], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("the certificate can't be authenticated."),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // Have Alice also partially certify Carol, and make Alice the
    // trust root.  Bob and Carol combined don't (currently) make the
    // signature good.
    {
        sq_certify(&sq, &alice_pgp,
                   &carol_fpr, "<carol@example.org>",
                   Some(60));
        let output = sq_verify(&sq, &[&alice_fpr], &[], &msg_pgp);
        assert!(! output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("the certificate can't be authenticated."),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
        assert!(output.2.contains("3 unauthenticated signatures"),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    // Have Alice fully certify Dave, and make Alice the trust root.
    // Now the signature will be considered verified.
    {
        sq_certify(&sq, &alice_pgp,
                   &dave_fpr, "<dave@example.org>",
                   None);
        let output = sq_verify(&sq, &[&alice_fpr], &[], &msg_pgp);
        assert!(output.0.success(),
                "stdout:\n{}\nstderr:\n{}", output.1, output.2);
        assert!(output.2.contains("Authenticated signature made by "),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
        assert!(output.2.contains("1 authenticated signature, 2 unauthenticated signatures"),
                "stdout:\n{}\nstderr:\n{}",
                output.1, output.2);
    }

    Ok(())
}

#[test]
fn sq_sign_keyring() {
    // Check that we can provide the secret key material via
    // --keyring.

    let sq = Sq::new();

    let (_alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["alice"]);

    let mut alice_pub = alice_pgp.clone();
    alice_pub.set_extension("pub");

    sq.key_delete(&alice_pgp, Some(&*alice_pub));

    // We pass the secret key material via --keyring.  This should
    // work.
    let mut cmd = sq.command();
    cmd.arg("--keyring").arg(&alice_pgp)
        .arg("sign")
        .arg("--message")
        .arg("--signer-file").arg(&alice_pub);

    sq.run(cmd, Some(true));

    // If we don't pass the secret key material, this should fail.
    let mut cmd = sq.command();
    cmd.arg("sign")
        .arg("--message")
        .arg("--signer-file").arg(&alice_pub);

    sq.run(cmd, Some(false));
}

/// Creates a text signature.
#[test]
fn sq_sign_mode_text() -> Result<()> {
    let sq = Sq::new();

    let (_alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["alice"]);

    let data_n = sq.scratch_dir().join("data_n");
    std::fs::write(&data_n, "Hello\n")?;

    let sig = sq.scratch_dir().join("sig");
    sq.sign_detached(&["--mode=text"], alice_pgp.as_path(),
                     data_n.as_path(), sig.as_path());

    let verify_args = ["--signer-file", &alice_pgp.display().to_string()];
    sq.verify(&verify_args, Verify::SignatureFile(sig.clone()), &data_n, None);

    let data_rn = sq.scratch_dir().join("data_rn");
    std::fs::write(&data_rn, "Hello\r\n")?;
    sq.verify(&verify_args, Verify::SignatureFile(sig.clone()), &data_rn, None);

    Ok(())
}
