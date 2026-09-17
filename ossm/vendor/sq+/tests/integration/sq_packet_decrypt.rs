use predicates::prelude::*;

use openpgp::Result;
use sequoia_openpgp as openpgp;

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
        .arg("packet")
        .arg("decrypt")
        .args(["--session-key", "1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stderr(predicate::str::contains("Encrypted with Session Key"));
    Ok(())
}

#[test]
fn session_key_with_prefix() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("packet")
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
        .arg("packet")
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
        .arg("packet")
        .arg("decrypt")
        .args(["--session-key", "BB9CCB8EDE22DC222C83BD1C63AEB97335DDC7B696DB171BD16EAA5784CC0478"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("No key to decrypt message"));
    Ok(())
}
