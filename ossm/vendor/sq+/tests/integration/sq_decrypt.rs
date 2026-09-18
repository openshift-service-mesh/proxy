use std::fs::File;
use std::io::Write;

use predicates::prelude::*;

use sequoia_openpgp as openpgp;
use openpgp::Result;

use super::common::{Sq, artifact};

// Integration tests should be done with subplot.
// However, at this time, subplot does not support static binary files in tests.
// Generating the test files would mean encrypting some static text symmetrically
// and then extracting the session key, which means parsing of human readabe cli output.
// So, for now, the tests go here.
#[test]
fn session_key() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("decrypt")
        .args(["--session-key", "1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Decryption failed").not());
    Ok(())
}

#[test]
fn session_key_with_prefix() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("decrypt")
        .args(["--session-key", "9:1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Decryption failed").not());
    Ok(())
}

#[test]
fn session_key_multiple() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("decrypt")
        .args(["--session-key", "2FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .args(["--session-key", "9:1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .args(["--session-key", "3FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Decryption failed").not());
    Ok(())
}

#[test]
fn session_key_wrong_key() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("decrypt")
        .args(["--session-key", "BB9CCB8EDE22DC222C83BD1C63AEB97335DDC7B696DB171BD16EAA5784CC0478"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("Decryption failed"));
    Ok(())
}

// Make sure verifying bad data fails, and removes the intermediate
// file.
//
// Warning: A umask setting of 0o077 renders the permission check in
// this test ineffective.
#[test]
fn sq_decrypt_bad() -> Result<()> {
    let sq = Sq::new();

    // The signer.
    let (_cert, signer_file, _rev_file) = sq.key_generate(&[], &["alice"]);
    let (_cert, recip_file, _rev_file) = sq.key_generate(&[], &["bob"]);

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

    // Sign and encrypt the message.
    let file = sq.scratch_file("file");
    sq.encrypt(
        &[
            "--for-file", &recip_file.display().to_string(),
            "--signer-file", &signer_file.display().to_string(),
            "--output", &file.display().to_string(),
        ],
        &data_file);

    // Verify the signed message.
    let output = sq.scratch_file("output");
    std::fs::write(&output, "xxx").expect("can write to scratch file");
    sq.decrypt(
        &["--overwrite",
          "--recipient-file", &recip_file.display().to_string(),
          "--signer-file", &signer_file.display().to_string(),
          "--output", &output.display().to_string(),
        ],
        &file);
    assert!(output.exists());
    assert_eq!(std::fs::metadata(&output).expect("can stat").len(),
               size);
    // Check permissions of scratch file, they should not contain permissions
    // for group and other (unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::metadata(&output)?.permissions();
        assert_eq!(permissions.mode() & 0o077, 0);
    }

    // Making signing fail and ensure the output is deleted.
    let output2 = sq.scratch_file("output2");
    std::fs::write(&output2, "xxx").expect("can write to scratch file");
    assert!(
        sq.decrypt_maybe(
            &["--overwrite",
              "--recipient-file", &recip_file.display().to_string(),
              "--signer-file", &recip_file.display().to_string(),
              "--output", &output2.display().to_string(),
            ],
            &file)
            .is_err());
    // Since we failed to verify the message, we should have deleted
    // the output file.
    assert!(! output2.exists());

    Ok(())
}
