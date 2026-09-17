use std::path::PathBuf;

use sequoia_openpgp as openpgp;
use openpgp::{
    KeyHandle,
    Result,
};

use chrono::Utc;
use chrono::DateTime;

use super::common::{Sq, artifact};

/// Returns the time formatted as an ISO 8106 string.
pub fn time_as_string(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[test]
fn sq_autocrypt_import() -> Result<()>
{
    let t = chrono::DateTime::parse_from_str("20240304T0100z", "%Y%m%dT%H%M%#z")
        .expect("valid date");
    let sq = Sq::at(t.into());

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let eml = manifest_dir.join("tests").join("data").join("autocrypt")
        .join("E43FF9D5-ABE5-42D4-852F-4692FB643B10@probier.email.eml");

    // Import the message, first without being able to decrypt it.
    let mut cmd = sq.command();
    cmd.arg("cert").arg("import")
        .arg(&eml);
    sq.run(cmd, true);

    // Check that the cert is imported.
    sq.cert_export("A614C91D0392D83EE6B1C4A4DD4147FEF78AD630".parse::<KeyHandle>()?);

    // We can now partially authenticate the sender.
    let mut cmd = sq.command();
    cmd.arg("pki").arg("authenticate")
        .arg("--amount=40")
        .arg("--cert").arg("A614C91D0392D83EE6B1C4A4DD4147FEF78AD630")
        .arg("--email").arg("pink@probier.email");
    eprintln!("Running: {:?}", cmd);
    eprintln!("pre: {}", time_as_string(std::time::SystemTime::now().into()));
    sq.run(cmd, true);
    eprintln!("post: {}", time_as_string(std::time::SystemTime::now().into()));

    // Import the message again, now with one of the recipient keys.
    sq.key_import(artifact("examples/alice-secret.pgp"));
    let mut cmd = sq.command();
    cmd.arg("cert").arg("import")
        .arg(&eml);
    sq.run(cmd, true);

    // We can now weakly authenticate the peers.
    let mut cmd = sq.command();
    cmd.arg("pki").arg("authenticate")
        .arg("--gossip")
        .arg("--cert").arg("CBCD8F030588653EEDD7E2659B7DD433F254904A")
        .arg("--email").arg("justus@sequoia-pgp.org");
    sq.run(cmd, true);

    let mut cmd = sq.command();
    cmd.arg("pki").arg("authenticate")
        .arg("--gossip")
        .arg("--cert").arg("BB6B7E5F8343B2BE990EB7A7F3AF066F267892C1")
        .arg("--email").arg("hilal-maria@probier.email");
    sq.run(cmd, true);

    Ok(())
}

#[test]
fn sq_autocrypt_import_signed() -> Result<()>
{
    let t = chrono::DateTime::parse_from_str("20241214T0100z", "%Y%m%dT%H%M%#z")
        .expect("valid date");
    let sq = Sq::at(t.into());

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let eml = manifest_dir.join("tests").join("data").join("autocrypt")
        .join("signed.eml");

    // Import the message.
    let mut cmd = sq.command();
    cmd.arg("cert").arg("import").arg(&eml);
    sq.run(cmd, true);

    // Check that the cert is imported.
    sq.cert_export("64F4DD76866EA6896E4A869BA0FCAE2B43465576".parse::<KeyHandle>()?);

    // We can now partially authenticate the sender.
    let mut cmd = sq.command();
    cmd.arg("pki").arg("authenticate")
        .arg("--amount=40")
        .arg("--cert").arg("64F4DD76866EA6896E4A869BA0FCAE2B43465576")
        .arg("--email").arg("patrick@enigmail.net");
    eprintln!("Running: {:?}", cmd);
    sq.run(cmd, true);

    Ok(())
}
