use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::packet::Key;
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;

use super::common::power_set;
use super::common::Sq;

#[test]
fn sq_key_import_export() -> Result<()>
{
    let sq = Sq::new();

    // Generate a few keys as red herrings.
    for i in 0..10 {
        let (_, key_pgp, _) = sq.key_generate(&[], &[&format!("Key {}", i)]);
        sq.key_import(key_pgp);
    }

    // Generate and import a key.
    let (cert, key_pgp, _) = sq.key_generate(&[], &["Alice"]);
    sq.key_import(key_pgp);

    // Export the whole certificate.
    for by_fpr in [true, false] {
        let kh: KeyHandle = if by_fpr {
            cert.fingerprint().into()
        } else {
            cert.keyid().into()
        };

        let got = sq.key_export(kh);
        assert_eq!(cert, got);
    }

    // Export each non-empty subset of keys.

    eprintln!("Certificate:");
    for k in cert.keys() {
        eprintln!("  {}", k.key().fingerprint());
    }

    let keys: Vec<Key<_, _>> = cert.keys()
        .map(|k| {
            k.key().clone()
        })
        .collect();

    let key_ids = keys.iter().map(|k| k.fingerprint()).collect::<Vec<_>>();

    for (i, selection) in power_set(&key_ids).into_iter().enumerate() {
        for by_fpr in [true, false] {
            eprintln!("Test #{}, by {}:",
                      i + 1,
                      if by_fpr { "fingerprint" } else { "key ID" });
            eprintln!("  Exporting:");
            for k in selection.iter() {
                eprintln!("    {}", k);
            }

            // Export the selection.
            let got = sq.key_subkey_export(
                cert.key_handle(), selection.clone());

            // Make sure we got exactly what we asked for; no
            // more, no less.
            eprintln!("  Got:");

            let mut secrets = 0;
            for got in got.keys() {
                let expected = keys.iter()
                    .find(|k| k.fingerprint() == got.key().fingerprint())
                    .expect("have key");

                eprintln!("    {} {} secret key material",
                          got.key().fingerprint(),
                          if got.key().has_secret() {
                              "has"
                          } else {
                              "doesn't have"
                          });

                if let Ok(got) = got.key().parts_as_secret() {
                    assert!(
                        selection.contains(&got.fingerprint()),
                        "got secret key material \
                         for a key we didn't ask for ({})",
                        got.fingerprint());

                    assert_eq!(expected.parts_as_secret().expect("have secrets"),
                               got);

                    secrets += 1;
                } else {
                    assert!(
                        ! selection.contains(&got.key().fingerprint()),
                        "didn't get secret key material \
                         for a key we asked for ({})",
                        got.key().fingerprint());

                    assert_eq!(expected, got.key());
                }
            }
            assert_eq!(secrets, selection.len());
        }
    }

    Ok(())
}

#[cfg(unix)]
#[test]
// For newly generated output files containing sensitive data, check if
// the permissions of the new files forbid access to group and other.
//
// Warning: A umask setting of 0o077 renders this test ineffective.
fn sq_key_export_check_permissions() -> Result<()> {
    // This test is already limited to Unix.
    use std::os::unix::fs::PermissionsExt;

    let sq = Sq::new();

    let dir = sq.scratch_dir();
    let cert_file = dir.join("cert.pgp");

    // Generate and import a key.
    let (cert, key_pgp, _) = sq.key_generate(&[], &["Alice"]);
    sq.key_import(key_pgp);

    // Run the command, create the output files.
    let mut cmd = sq.command();
    cmd.args([
        "key", "export",
        "--cert", cert.fingerprint().to_hex().as_str(),
        "--overwrite",
        "--output", &cert_file.display().to_string(),
    ]);
    sq.run(cmd, true);

    let _cert = Cert::from_file(&cert_file).expect("Have a cert");

    // Check the permissions of the generated file.  As it contains a
    // key it should not be accessible to group or other.
    let permissions = std::fs::metadata(&cert_file)?.permissions();
    eprintln!("permissions: {:?}", permissions);
    assert_eq!(permissions.mode() & 0o077, 0);

    Ok(())
}
