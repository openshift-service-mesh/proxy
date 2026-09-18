use predicates::prelude::*;

use openpgp::Result;
use sequoia_openpgp as openpgp;

use super::common::{Sq, artifact};

#[test]
fn session_key_without_prefix() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Decryption failed").not());
    Ok(())
}

#[test]
fn session_key_with_prefix() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "9:1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Decryption failed").not());
    Ok(())
}

#[test]
fn session_key_with_bad_prefix() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "1:1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Indicated Symmetric algo: IDEA"))
        .stdout(predicate::str::contains("Decryption failed"));
    Ok(())
}

#[test]
fn session_key_wrong_length_without_prefix() -> Result<()> {
    // too short
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Decryption failed"));

    // too long
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4AB"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Decryption failed"));
    Ok(())
}

#[test]
fn session_key_wrong_length_with_prefix() -> Result<()> {
    // too short
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "1:1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Decryption failed"));

    // too long
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "1:1FE820EC21FB5D7E33D83367106D1D3747DCD48E6320C1AEC57EE7D18FC437D4AB"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Decryption failed"));
    Ok(())
}

#[test]
fn session_key_wrong_key_with_prefix() -> Result<()> {
    let sq = Sq::new();
    sq.command()
        .arg("packet")
        .arg("dump")
        .args(["--session-key", "9:BB9CCB8EDE22DC222C83BD1C63AEB97335DDC7B696DB171BD16EAA5784CC0478"])
        .arg(artifact("messages/rsa.msg.pgp"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Decryption failed"));
    Ok(())
}
