use std::{
    fs::File,
    io::{Cursor, Read},
    sync::OnceLock,
};

use sequoia_openpgp::{
    Packet,
    Result,
    cert::{Cert, CertParser},
    packet::signature::SignatureBuilder,
    parse::Parse,
    serialize::Serialize,
    types::SignatureType,
};

use super::common::{Sq, artifact};

/// Creates a keyring.
fn build_keyring(sq: &Sq) {
    let bob = sq.scratch_dir().join("bob.pgp");
    bob_with_alices_primary()
        .serialize(&mut File::create(&bob).unwrap()).unwrap();

    let mut cmd = sq.command();
    cmd.arg("keyring")
        .arg("merge")
        .arg("--output=keys.pgp")
        .arg(artifact("examples").join("alice-secret.pgp"))
        .arg(bob)
        .arg(artifact("keys").join("neal.pgp"));
    sq.run(cmd, true);
}

/// Bind Alice's primary key to Bob's certificate.
fn bob_with_alices_primary() -> &'static Cert {
    static ONCE: OnceLock<Cert> = OnceLock::new();
    ONCE.get_or_init(|| {
        let alice = Cert::from_file(
            artifact("examples").join("alice-secret.pgp")).unwrap();
        let bob = Cert::from_file(
            artifact("examples").join("bob-secret.pgp")).unwrap();

        let mut bobs_signer = bob.primary_key().key().clone()
            .parts_into_secret().unwrap().into_keypair().unwrap();
        let k = alice.primary_key().key().clone().role_into_subordinate();
        let sig = k.bind(&mut bobs_signer,
                         &bob,
                         SignatureBuilder::new(SignatureType::SubkeyBinding))
            .unwrap();

        let bob = bob.strip_secret_key_material().insert_packets(vec![
            Packet::from(k),
            sig.into(),
        ]).unwrap().0;

        bob
    })
}

/// Reads all certs in.
fn read_certs(source: &mut (dyn Read + Sync + Send)) -> Vec<Cert> {
    CertParser::from_reader(source).unwrap()
        .collect::<Result<Vec<_>>>().unwrap()
}

/// Filters the keyring, then reads all certs in.
fn filter(sq: &Sq, args: &[&str]) -> Vec<Cert> {
    let mut cmd = sq.command();
    cmd.arg("keyring")
        .arg("filter")
        .arg("--experimental")
        .arg("--output=-")
        .args(args)
        .arg("keys.pgp");
    let output = sq.run(cmd, true);

    read_certs(&mut Cursor::new(output.stdout))
}

#[test]
fn to_cert() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let keys = read_certs(&mut File::open(sq.working_dir().join("keys.pgp"))?);
    assert!(keys.iter().any(|cert| cert.is_tsk()));

    let certs = filter(&sq, &["--to-cert"]);
    assert!(! certs.iter().any(|cert| cert.is_tsk()));

    Ok(())
}

#[test]
fn userid() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &["--userid", "Alice <alice@example.org>"]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?);

    Ok(())
}

#[test]
fn userid_prune() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let neals_uid = "Neal H. Walfield <neal@sequoia-pgp.org>";
    let certs = filter(&sq, &["--prune-certs", "--userid", neals_uid]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?);
    assert_eq!(certs[0].userids().count(), 1);
    assert_eq!(certs[0].userids().next().unwrap().userid().value(),
               neals_uid.as_bytes());

    Ok(())
}

#[test]
fn domain() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &["--domain", "example.org"]);
    assert_eq!(certs.len(), 2);
    let mut fiprs = certs.iter().map(Cert::fingerprint).collect::<Vec<_>>();
    fiprs.sort();
    assert_eq!(&fiprs[..],
               &[
                   "511257EBBF077B7AEDAE5D093F68CB84CE537C9A".parse()?,
                   "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?,
               ]);

    Ok(())
}

#[test]
fn domain_prune() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &["--prune-certs", "--domain", "sequoia-pgp.org"]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "8F17777118A33DDA9BA48E62AACB3243630052D9".parse()?);
    assert_eq!(certs[0].userids().count(), 1);
    assert_eq!(certs[0].userids().next().unwrap().userid().value(),
               b"Neal H. Walfield <neal@sequoia-pgp.org>");

    Ok(())
}

#[test]
fn cert() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &[
        "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
    ]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?);
    assert_eq!(certs[0].keys().count(), 4);

    Ok(())
}

#[test]
fn cert_prune() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let certs = filter(&sq, &[
        "--prune-certs",
        "--cert", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
    ]);
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].fingerprint(),
               "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?);
    assert_eq!(certs[0].keys().count(), 4);

    Ok(())
}

#[test]
fn key() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let mut certs = filter(&sq, &[
        "--key", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
    ]);

    // Bob stole Alice's primary key.
    assert_eq!(certs.len(), 2);
    certs.sort_by_key(|c| c.fingerprint());
    let fiprs = certs.iter().map(Cert::fingerprint).collect::<Vec<_>>();
    assert_eq!(&fiprs[..],
               &[
                   "511257EBBF077B7AEDAE5D093F68CB84CE537C9A".parse()?,
                   "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?,
               ]);

    Ok(())
}

#[test]
fn key_prune() -> Result<()> {
    let sq = Sq::new();
    build_keyring(&sq);

    let mut certs = filter(&sq, &[
        "--prune-certs",
        "--key", "EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
    ]);

    // Bob stole Alice's primary key.
    assert_eq!(certs.len(), 2);
    certs.sort_by_key(|c| c.fingerprint());
    assert_eq!(certs[0].fingerprint(),
               "511257EBBF077B7AEDAE5D093F68CB84CE537C9A".parse()?);
    assert_eq!(certs[0].keys().count(), 2);
    assert_eq!(certs[1].fingerprint(),
               "EB28F26E2739A4870ECC47726F0073F60FD0CBF0".parse()?);
    assert_eq!(certs[1].keys().count(), 1);

    Ok(())
}
