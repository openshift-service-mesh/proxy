use std::time;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::Result;
use openpgp::crypto::mpi::PublicKey;
use openpgp::types::Curve;
use openpgp::types::KeyFlags;
use openpgp::types::PublicKeyAlgorithm;

use super::common;
use super::common::UserIDArg;
use super::common::NO_USERIDS;
use super::common::NULL_POLICY;

#[test]
fn sq_key_generate_no_userid() -> Result<()> {
    let sq = common::Sq::new();

    // Stateless key generation.
    let (cert, _, _) = sq.key_generate::<&str>(&[], &[]);
    assert_eq!(cert.userids().count(), 0);

    // Stateful key generation.
    let mut cmd = sq.command();
    cmd.args(["key", "generate", "--own-key", "--no-userids",
              "--without-password"]);
    sq.run(cmd, true);

    Ok(())
}

#[test]
fn sq_key_generate_creation_time() -> Result<()>
{
    let sq = common::Sq::new();

    // $ date +'%Y%m%dT%H%M%S%z'; date +'%s'
    let iso8601 = "20220120T163236+0100";
    let t = 1642692756;

    let (result, _, _) = sq.key_generate(&[
        "--time", iso8601,
        "--expiration", "never",
    ], NO_USERIDS);
    let vc = result.with_policy(common::STANDARD_POLICY, None)?;

    assert_eq!(vc.primary_key().key().creation_time(),
               time::UNIX_EPOCH + time::Duration::new(t, 0));
    assert!(vc.primary_key().key_expiration_time().is_none());

    Ok(())
}

#[test]
fn sq_key_generate_name_email() -> Result<()> {
    let sq = common::Sq::new();
    let (cert, _, _) = sq.key_generate(
        &[],
        &[
            UserIDArg::Name("Joan Clarke"),
            UserIDArg::Name("Joan Clarke Murray"),
            UserIDArg::Email("joan@hut8.bletchley.park"),
        ]);

    assert_eq!(cert.userids().count(), 3);
    assert!(cert.userids().any(|u| u.userid().value() == b"Joan Clarke"));
    assert!(cert.userids().any(|u| u.userid().value() == b"Joan Clarke Murray"));
    assert!(
        cert.userids().any(|u| u.userid().value() == b"<joan@hut8.bletchley.park>"));

    Ok(())
}

#[test]
fn sq_key_generate_with_password() -> Result<()> {
    let sq = common::Sq::new();

    let password = "hunter2";
    let path = sq.base().join("password");
    std::fs::write(&path, password)?;

    let (cert, _, _) = sq.key_generate(&[
        "--new-password-file", &path.display().to_string(),
    ], NO_USERIDS);

    assert!(cert.is_tsk());

    let password = password.into();
    for key in cert.keys() {
        let secret = key.key().optional_secret().unwrap();
        assert!(secret.is_encrypted());
        assert!(secret.clone().decrypt(key.key(), &password).is_ok());
    }

    Ok(())
}

// Make sure we can write to /dev/null.
#[cfg(unix)]
#[test]
fn sq_key_generate_dev_null() -> Result<()> {
    let sq = common::Sq::new();

    let cert_file = sq.scratch_file("cert");

    let mut cmd = sq.command();
    cmd.args([
        "key", "generate", "--own-key", "--no-userids",
        "--without-password",
        "--output", &cert_file.display().to_string(),
        "--rev-cert", "/dev/null",
    ]);
    sq.run(cmd, true);

    let _cert = Cert::from_file(cert_file).expect("Have a cert");

    Ok(())
}

// Make sure we can overwrite a file in a directory that is not
// writable.
#[cfg(unix)]
#[test]
fn sq_key_generate_overwrite() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let sq = common::Sq::new();

    let dir = sq.scratch_dir();
    let cert_file = dir.join("cert.pgp");
    std::fs::write(&cert_file, "foo").expect("can write");
    let rev_file = dir.join("cert.rev");
    std::fs::write(&rev_file, "foo").expect("can write");

    // Remove the write bit.
    let metadata = std::fs::metadata(&dir).expect("can stat");
    let mut permissions = metadata.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&dir, permissions)
        .expect("can chmod");

    // Make sure we can still write to the existing file, but we can't
    // create new files.
    std::fs::write(&cert_file, "foo").expect("can write");
    std::fs::write(dir.join("other"), "foo").expect_err("can't create");

    // Now overwrite cert.pgp.
    let mut cmd = sq.command();
    cmd.args([
        "key", "generate",
        "--overwrite",
        "--own-key", "--no-userids",
        "--without-password",
        "--output", &cert_file.display().to_string(),
        "--rev-cert", &rev_file.display().to_string(),
    ]);
    sq.run(cmd, true);

    let _cert = Cert::from_file(&cert_file).expect("Have a cert");

    // Check the permissions of the output file. Access (read/write) by
    // group and other should not be allowed.
    let permissions = std::fs::metadata(&cert_file)?.permissions();
    assert_eq!(permissions.mode() & 0o077, 0);

    // Check that the certificate was not appended to the existing
    // data.
    let content = std::fs::read(&cert_file).expect("Can read file");
    assert!(content.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"),
            "Expected an ASCII-armored key, but got: {:?}",
            String::from_utf8_lossy(&content));

    let _rev = Cert::from_file(&rev_file).expect("Have a cert");

    // Check that the certificate was not appended to the existing
    // data.
    let content = std::fs::read(&rev_file).expect("Can read file");
    assert!(content.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
            "Expected an ASCII-armored certificate, but got: {:?}",
            String::from_utf8_lossy(&content));

    Ok(())
}

#[test]
fn sq_key_generate_encryption_algorithm() -> Result<()> {
    let sq = common::Sq::new();

    #[allow(deprecated)]
    for (arg, profile, algo, curve) in
        [
            ("rsa2k", "rfc4880", PublicKeyAlgorithm::RSAEncryptSign, None),
            ("rsa3k", "rfc4880", PublicKeyAlgorithm::RSAEncryptSign, None),
            ("rsa4k", "rfc4880", PublicKeyAlgorithm::RSAEncryptSign, None),
            ("elgamal2k", "rfc4880", PublicKeyAlgorithm::ElGamalEncrypt, None),
            // >7 seconds on a fast machine, skip.
            //("elgamal3k", "rfc4880", PublicKeyAlgorithm::ElGamalEncrypt, None),
            ("cv25519", "rfc4880", PublicKeyAlgorithm::ECDH, Some(Curve::Cv25519)),
            ("x25519", "rfc4880", PublicKeyAlgorithm::X25519, None),
            ("x448", "rfc4880", PublicKeyAlgorithm::X448, None),
            ("nistp256", "rfc4880", PublicKeyAlgorithm::ECDH, Some(Curve::NistP256)),
            ("nistp384", "rfc4880", PublicKeyAlgorithm::ECDH, Some(Curve::NistP384)),
            ("nistp521", "rfc4880", PublicKeyAlgorithm::ECDH, Some(Curve::NistP521)),
            ("brainpoolp256", "rfc4880", PublicKeyAlgorithm::ECDH, Some(Curve::BrainpoolP256)),
            ("brainpoolp384", "rfc4880", PublicKeyAlgorithm::ECDH, Some(Curve::BrainpoolP384)),
            ("brainpoolp512", "rfc4880", PublicKeyAlgorithm::ECDH, Some(Curve::BrainpoolP512)),
            ("mlkem768-x25519", "rfc4880", PublicKeyAlgorithm::MLKEM768_X25519, None),
            ("mlkem1024-x448", "rfc9580", PublicKeyAlgorithm::MLKEM1024_X448, None),
        ]
    {
        eprintln!("Checking {}/{}: {}, {:?}", arg, profile, algo, curve);

        if ! algo.is_supported() {
            eprintln!("Skipping {}/{}: {} not supported by crypto backend",
                      arg, profile, algo);
            continue;
        }
        if let Some(curve) = curve.as_ref() {
            if ! curve.is_supported() {
                eprintln!("Skipping {}/{}: {} not supported by crypto backend",
                          arg, profile, curve);
                continue;
            }
        }

        let (cert, _, _) = sq.key_generate(
            &[
                "--encryption-algorithm", arg,
                "--profile", profile,
            ],
            NO_USERIDS);

        assert!(cert.is_tsk());

        let mut have_one = false;
        let vc = cert.with_policy(NULL_POLICY, None).expect("valid cert");
        for k in vc.keys() {
            let kf = k.key_flags().unwrap_or(KeyFlags::empty());
            if kf.for_transport_encryption()
                || kf.for_storage_encryption()
            {
                have_one = true;
                assert_eq!(k.key().pk_algo(), algo);

                let got_curve = match k.key().mpis() {
                    PublicKey::EdDSA { curve, .. }
                    | PublicKey::ECDSA { curve, .. }
                    | PublicKey::ECDH { curve, .. } => {
                        Some(curve)
                    }
                    _ => None,
                };
                assert_eq!(got_curve, curve.as_ref());
            }
        }
        assert!(have_one);
    }

    Ok(())
}

#[test]
fn sq_key_generate_signing_algorithm() -> Result<()> {
    let sq = common::Sq::new();

    #[allow(deprecated)]
    for (arg, profile, algo, curve) in
        [
            ("rsa2k", "rfc4880", PublicKeyAlgorithm::RSAEncryptSign, None),
            ("rsa3k", "rfc4880", PublicKeyAlgorithm::RSAEncryptSign, None),
            ("rsa4k", "rfc4880", PublicKeyAlgorithm::RSAEncryptSign, None),
            // >4 seconds on a fast machine, skip.
            //("dsa2k", "rfc4880", PublicKeyAlgorithm::DSA, None),
            // >10 seconds on a fast machine, skip.
            //("dsa3k", "rfc4880", PublicKeyAlgorithm::DSA, None),
            ("cv25519", "rfc4880", PublicKeyAlgorithm::EdDSA, Some(Curve::Ed25519)),
            ("ed25519", "rfc4880", PublicKeyAlgorithm::Ed25519, None),
            ("ed448", "rfc4880", PublicKeyAlgorithm::Ed448, None),
            ("nistp256", "rfc4880", PublicKeyAlgorithm::ECDSA, Some(Curve::NistP256)),
            ("nistp384", "rfc4880", PublicKeyAlgorithm::ECDSA, Some(Curve::NistP384)),
            ("nistp521", "rfc4880", PublicKeyAlgorithm::ECDSA, Some(Curve::NistP521)),
            ("brainpoolp256", "rfc4880", PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP256)),
            ("brainpoolp384", "rfc4880", PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP384)),
            ("brainpoolp512", "rfc4880", PublicKeyAlgorithm::ECDSA, Some(Curve::BrainpoolP512)),
            ("mldsa65-ed25519", "rfc9580", PublicKeyAlgorithm::MLDSA65_Ed25519, None),
            ("mldsa87-ed448", "rfc9580", PublicKeyAlgorithm::MLDSA87_Ed448, None),
            ("slhdsa128f", "rfc9580", PublicKeyAlgorithm::SLHDSA128f, None),
            ("slhdsa128s", "rfc9580", PublicKeyAlgorithm::SLHDSA128s, None),
            ("slhdsa256s", "rfc9580", PublicKeyAlgorithm::SLHDSA256s, None),
        ]
    {
        eprintln!("Checking {}/{}: {}, {:?}", arg, profile, algo, curve);

        if ! algo.is_supported() {
            eprintln!("Skipping {}/{}: {} not supported by crypto backend",
                      arg, profile, algo);
            continue;
        }
        if algo == PublicKeyAlgorithm::DSA && cfg!(feature = "crypto-cng") {
            // PublicKey::DSA::is_supported returns true with Windows
            // CND, but Windows CNG only supports
            eprintln!("Skipping {}/{}: {} not supported by crypto backend",
                      arg, profile, algo);
            continue;
        }

        if let Some(curve) = curve.as_ref() {
            if ! curve.is_supported() {
                eprintln!("Skipping {}/{}: {} not supported by crypto backend",
                          arg, profile, curve);
                continue;
            }
        }

        let (cert, _, _) = sq.key_generate(
            &[
                "--signing-algorithm", arg,
                "--profile", profile,
            ],
            NO_USERIDS);

        assert!(cert.is_tsk());

        let mut have = 0;
        let vc = cert.with_policy(NULL_POLICY, None).expect("valid cert");
        for k in vc.keys() {
            let kf = k.key_flags().unwrap_or(KeyFlags::empty());
            if kf.for_signing()
                || kf.for_certification()
                || kf.for_authentication()
            {
                have += 1;
                assert_eq!(k.key().pk_algo(), algo);

                let got_curve = match k.key().mpis() {
                    PublicKey::EdDSA { curve, .. }
                    | PublicKey::ECDSA { curve, .. }
                    | PublicKey::ECDH { curve, .. } => {
                        Some(curve)
                    }
                    _ => None,
                };
                assert_eq!(got_curve, curve.as_ref());
            }
        }
        assert_eq!(have, 3);
    }

    Ok(())
}

// For newly generated output files containing sensitive data, check if
// the permissions of the new files forbid access to group and other.
//
// Warning: A umask setting of 0o077 renders this test ineffective.
#[cfg(unix)]
#[test]
fn sq_key_generate_check_permissions() -> Result<()> {
    // This test is already limited to Unix.
    use std::os::unix::fs::PermissionsExt;

    let sq = common::Sq::new();

    let dir = sq.scratch_dir();
    let cert_file = dir.join("cert.pgp");
    let rev_file = dir.join("cert.rev");

    // run the command, create the output files
    let mut cmd = sq.command();
    cmd.args([
        "key", "generate",
        "--own-key", "--no-userids",
        "--without-password",
        "--output", &cert_file.display().to_string(),
        "--rev-cert", &rev_file.display().to_string(),
    ]);
    sq.run(cmd, true);

    let _cert = Cert::from_file(&cert_file).expect("Have a cert");

    // Check permissions of the generated files. As they contain a key
    // and a revocation certificate, they should not be accessible to
    // group or other.
    let permissions = std::fs::metadata(&cert_file)?.permissions();
    assert_eq!(permissions.mode() & 0o077, 0);
    let permissions = std::fs::metadata(&rev_file)?.permissions();
    assert_eq!(permissions.mode() & 0o077, 0);

   Ok(())
}
