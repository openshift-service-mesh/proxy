use std::fs::File;
use std::io::Seek;
use std::io::Write;
use std::io;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use super::common::*;

// Make sure verifying bad data fails, and removes the intermediate
// file.
#[test]
fn sq_verify_bad() -> Result<()> {
    let sq = Sq::new();

    // The signer.
    let (_cert, cert_file, _rev_file) = sq.key_generate(&[], &["alice"]);

    // Create a big file.  When verifying, we buffer the first ~25 MB
    // of verified data so that we can at least withhold some data if
    // we can't verify the message.
    let data_file = sq.scratch_file("data");
    let size = {
        let mut file = File::create(&data_file)?;
        let data = vec![42; 1024 * 1024];
        let mut size = 0;
        for _ in 0..30 {
            file.write_all(&data).expect("can write");
            size += data.len();
        }

        size as u64
    };
    assert_eq!(std::fs::metadata(&data_file).expect("can stat").len(),
               size);

    // Sign the message.
    let sig_file = sq.scratch_file("sig");
    sq.sign(&cert_file, None, &data_file, sig_file.as_path());

    // Verify the signed message.
    let output = sq.scratch_file("output");
    std::fs::write(&output, "xxx").expect("can write to scratch file");
    sq.verify(
        &["--overwrite",
          "--signer-file", &cert_file.display().to_string()],
        Verify::Message,
        &sig_file,
        output.as_path());
    assert!(output.exists());
    assert_eq!(std::fs::metadata(&output).expect("can stat").len(),
               size);

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

        let mode = std::fs::metadata(&output)?.permissions().mode();
        assert_eq!(mode, dummy_mode,
                   "Got: {:o}, expected: {:o}", mode, dummy_mode);
    }

    // Modify the data, and make sure verification now fails.
    let mut f = File::options().write(true).open(&sig_file)?;
    f.seek(io::SeekFrom::Start(size / 2)).expect("can seek");
    f.write_all(b"xxx").expect("can write");
    drop(f);

    let output2 = sq.scratch_file("output2");
    std::fs::write(&output2, "xxx").expect("can write to scratch file");
    assert!(
        sq.verify_maybe(
            &["--overwrite",
              "--signer-file", &cert_file.display().to_string()],
            Verify::Message,
            &sig_file,
            output2.as_path())
            .is_err());
    // Since we failed to verify the message, we should have deleted
    // the output file.
    assert!(! output2.exists());

    Ok(())
}

// Ensure bad/missing keyring produce errors
#[test]
fn sq_verify_bad_keyring() -> Result<()> {
    let sq = Sq::new();
    let msg = artifact("examples/document.pgp");

    let error_doesnotexist = sq.verify_maybe(
        &["--keyring", "doesnotexist"],
        Verify::Message,
        &msg,
        None
    );

    assert!(format!("{error_doesnotexist:?}").contains("Open"));
    assert!(format!("{error_doesnotexist:?}").contains("doesnotexist"));

    // Just use the readme as an invalid keyring
    let error_invalid = sq.verify_maybe(
        &[
            "--keyring",
            &artifact("examples/README.md").display().to_string(),
        ],
        Verify::Message,
        &msg,
        None,
    );

    assert!(format!("{error_invalid:?}").contains("Parsing"));
    assert!(format!("{error_invalid:?}").contains("examples/README.md"));

    Ok(())
}

// Make sure --policy-as-of works
#[test]
fn sq_verify_policy_as_of() -> Result<()> {
    let sq = Sq::at_str("2024-11-01");

    let cert = artifact("keys/only-sha1-pub.pgp");
    let msg = artifact("messages/signed-by-only-sha1.pgp");

    assert!(
        sq.verify_maybe(
            &[
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_err());

    // Setting the reference time is not enough, because the message's
    // creation time would be in the future.
    assert!(
        sq.verify_maybe(
            &[
                "--time", "2022-01-01",
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_err());

    // But setting the policy time is.
    assert!(
        sq.verify_maybe(
            &[
                "--policy-as-of", "2022-01-01",
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_ok());

    // Make sure we can set both the reference time and the policy
    // time.
    assert!(
        sq.verify_maybe(
            &[
                "--time", "2025-01-01",
                "--policy-as-of", "2022-01-01",
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_ok());

    Ok(())
}

// Make sure --policy-as-of works with relative time.
#[test]
fn sq_verify_policy_as_of_relative_time() -> Result<()> {
    let sq = Sq::at_str("2024-11-01");

    // Creation time: 2020-11-04 18:36:04 UTC
    let cert = artifact("keys/only-sha1-pub.pgp");
    let msg = artifact("messages/signed-by-only-sha1.pgp");

    // Signature creation time: 2024-10-31 13:40:28 UTC
    assert!(
        sq.verify_maybe(
            &[
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_err());

    // Setting the reference time is not enough, because the message's
    // creation time would be in the future.
    assert!(
        sq.verify_maybe(
            &[
                // => 2021-11-01
                "--time", "-3y",
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_err());

    // But setting the policy time is.
    assert!(
        sq.verify_maybe(
            &[
                // => 2021-11-01
                "--policy-as-of", "-3y",
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_ok());

    // Make sure we can set both the reference time and the policy
    // time.
    assert!(
        sq.verify_maybe(
            &[
                "--time", "2025-11-01",
                // => 2021-11-01
                "--policy-as-of", "-4y",
                "--signer-file", &cert.display().to_string(),
            ],
            Verify::Message,
            &msg,
            None)
            .is_ok());

    Ok(())
}

/// Make sure designated signers are respected.
#[test]
fn sq_verify_designated_signers() -> Result<()> {
    let sq = Sq::new();

    // First, import Neal's cert and make sure the message verifies
    // ok.
    sq.cert_import(artifact("examples/juliet.pgp"));
    sq.pki_link_add(&["--all"],
                    "7A58B15E3B9459483D9FFA8D40E299AC5F2B0872".parse()?,
                    NO_USERIDS);
    assert!(sq.verify_maybe(
        &[],
        Verify::Message,
        artifact("examples/document.pgp"), None).is_ok());

    // Now repeat, but require a signature from Bob, which doesn't
    // exist.
    assert!(sq.verify_maybe(
        &[&format!("--signer-file={}", artifact("examples/bob.pgp").display())],
        Verify::Message,
        artifact("examples/document.pgp"), None).is_err());

    Ok(())
}
