use std::borrow::Cow;
use std::ops::Deref;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;

use super::common::Sq;

#[test]
fn sq_cert_export() -> Result<()>
{
    let sq = Sq::new();

    struct Data {
        userids: &'static [&'static str],
        cert: Option<Cert>,
    }

    impl Data {
        fn cert(&self) -> &Cert {
            self.cert.as_ref().expect("have the cert")
        }
    }

    let data: &mut [Data] = &mut [
        Data {
            userids: &[ "<alice@example.org>" ][..],
            cert: None,
        },
        Data {
            userids: &[ "<bob@example.org>" ][..],
            cert: None,
        },
        Data {
            userids: &[
                "<carol@sub.example.org>",
                "<carol@other.org>",
            ][..],
            cert: None,
        },
    ][..];

    // Generate and import the keys.
    for data in data.iter_mut() {
        eprintln!("Generating key for {}",
                  data.userids.join(", "));
        let (cert, key_file, _rev) =
            sq.key_generate(&["--expiration", "never"], &data.userids);

        eprintln!("Importing {}", cert.fingerprint());
        for ka in cert.keys().subkeys() {
            eprintln!("  - {}", ka.key().fingerprint());
        }

        data.cert = Some(cert);

        sq.cert_import(key_file);
    }

    assert_eq!(data.len(), 3);
    let alice = &data[0];
    let bob = &data[1];
    let carol = &data[2];

    // Checks that the data contains exactly the listed
    // certificates.
    let check = |data: &[&Data], stdout: Cow<str>, stderr: Cow<str>| {
        let parser = CertParser::from_bytes(stdout.as_bytes())
            .expect("valid");
        let found = parser.collect::<Result<Vec<Cert>>>()
            .expect("valid");

        assert_eq!(found.len(), data.len(),
                   "found: {}\nexpected: {}\n\
                    stdout:\n{}\nstderr:\n{}",
                   found.iter().map(|c| c.fingerprint().to_string())
                   .collect::<Vec<_>>()
                   .join(", "),
                   data.iter().map(|d| d.cert().fingerprint().to_string())
                   .collect::<Vec<_>>()
                   .join(", "),
                   stdout, stderr);
        for cert in found.iter() {
            let fpr = cert.fingerprint();
            if let Some(_data) = data.iter().find(|data| {
                data.cert().fingerprint() == fpr
            }) {
                ()
            } else {
                panic!("Didn't find {} (have: {})\n\
                        stdout:\n{}\nstderr:\n{}",
                       fpr,
                       data.iter()
                       .map(|d| d.cert().fingerprint().to_string())
                       .collect::<Vec<String>>()
                       .join(", "),
                       stdout, stderr);
            };
        }
    };

    // args: --cert|--userid|... pattern
    let call = |args: &[&str], success: bool, data: &[&Data]| {
        let mut cmd = sq.command();
        cmd.args(["cert", "export"]);
        cmd.args(args);

        let args = args.iter()
            .map(|s| format!("{:?}", s))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("sq cert export {}...", args);

        let output = cmd.output().expect("success");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if success {
            assert!(output.status.success(),
                    "sq cert export {} should succeed\n\
                     stdout:\n{}\nstderr:\n{}",
                    args, stdout, stderr);
            check(data, stdout, stderr);
        } else {
            assert!(! output.status.success(),
                    "sq cert export {} should fail\n\
                     stdout:\n{}\nstderr:\n{}",
                    args, stdout, stderr);
            check(&[], stdout, stderr);
        }
    };

    for data in data.iter() {
        let cert = data.cert.as_ref().unwrap();

        // Export them by the cert's fingerprint and keyid.
        for kh in [KeyHandle::from(cert.fingerprint()),
                   KeyHandle::from(cert.keyid())]
        {
            call(&["--cert", &kh.to_string()], true, &[data]);
        }

        for ua in cert.userids() {
            // Only certs selected by authenticated user ID bindings
            // are exported.
            for authenticated in [false, true] {
                if authenticated {
                    sq.pki_link_add(
                        &[], cert.key_handle(),
                        &[std::str::from_utf8(ua.userid().value()).unwrap()]);
                }

                // Export by user id.
                let userid = String::from_utf8_lossy(
                    ua.userid().value()).into_owned();
                let email = ua.userid().email().unwrap().unwrap();

                call(&["--cert-userid", &userid], true && authenticated, &[data]);
                call(&["--cert-userid", &email], false, &[]);
                // Should be case sensitive.
                call(&["--cert-userid", &userid.deref().to_uppercase()], false, &[]);
                // Substring should fail.
                call(&["--cert-userid", &userid[1..]], false, &[]);

                call(&["--cert-email", &userid], false, &[]);
                call(&["--cert-email", &email], true && authenticated, &[data]);
                // Email is case insensitive.
                call(&["--cert-email", &email.to_uppercase()], true && authenticated,
                     &[data]);
                // Substring should fail.
                call(&["--cert-email", &email[1..]], false, &[]);

                call(&["--cert-grep", &userid], true && authenticated, &[data]);
                call(&["--cert-grep", &email], true && authenticated, &[data]);
                // Should be case insensitive.
                call(&["--cert-grep", &userid.deref().to_uppercase()],
                     true && authenticated, &[data]);
                // Substring should succeed.
                call(&["--cert-grep", &userid[1..]], true && authenticated, &[data]);
            }
        }
    }

    // By domain.
    call(&["--cert-domain", "example.org"], true, &[alice, bob]);
    call(&["--cert-domain", "EXAMPLE.ORG"], true, &[alice, bob]);
    call(&["--cert-domain", "sub.example.org"], true, &[carol]);
    call(&["--cert-domain", "SUB.EXAMPLE.ORG"], true, &[carol]);
    call(&["--cert-domain", "other.org"], true, &[carol]);

    call(&["--cert-domain", "hello.com"], false, &[]);
    call(&["--cert-domain", "me@hello.com"], false, &[]);
    call(&["--cert-domain", "alice@example.org"], false, &[]);
    call(&["--cert-domain", "xample.org"], false, &[]);
    call(&["--cert-domain", "example.or"], false, &[]);
    call(&["--cert-domain", "@example.org"], false, &[]);

    // Match a cert in many ways.  It should only be exported
    // once.
    call(&["--cert", &carol.cert().fingerprint().to_string(),
           "--cert-userid", carol.userids[0],
           "--cert-email", "carol@sub.example.org",
           "--cert-domain", "other.org"
    ], true, &[carol]);

    // Match multiple certs in different ways.
    call(&["--cert", &alice.cert().fingerprint().to_string(),
           "--cert", &bob.cert().fingerprint().to_string(),
           "--cert-email", "carol@sub.example.org",
    ], true, &[alice, bob, carol]);

    Ok(())
}

#[cfg(unix)]
#[test]
fn sq_cert_export_check_permissions() -> Result<()> {
    let sq = Sq::new();

    // Generate and import a key.
    let (cert, key_pgp, _) = sq.key_generate(&[], &["Alice"]);
    sq.key_import(key_pgp);

    let cert_file = sq.scratch_file("cert.pgp");

    // Run the command, create the output files.
    let mut cmd = sq.command();
    cmd.args([
        "cert", "export",
        "--cert", cert.fingerprint().to_hex().as_str(),
        "--output", &cert_file.display().to_string(),
    ]);
    sq.run(cmd, true);

    let _cert = Cert::from_file(&cert_file).expect("Have a cert");

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

        let mode = std::fs::metadata(&cert_file)?.permissions().mode();
        assert_eq!(mode, dummy_mode,
                   "Got: {:o}, expected: {:o}", mode, dummy_mode);
    }

    Ok(())
}
