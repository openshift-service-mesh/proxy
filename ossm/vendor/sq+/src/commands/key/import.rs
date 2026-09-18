use std::path::PathBuf;

use sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;

use crate::output::import::ImportStats;

use crate::cli;
use crate::cli::types::FileOrStdin;
use crate::Sq;
use crate::Result;

pub fn import(sq: Sq, command: cli::key::import::Command)
    -> Result<()>
{
    let o = &mut std::io::stdout();
    let mut stats = Default::default();
    let r = import_internal(o, &sq, command, &mut stats);
    stats.print_summary(o, &sq)?;
    r
}

fn import_internal(o: &mut dyn std::io::Write,
                   sq: &Sq, command: cli::key::import::Command,
                   stats: &mut ImportStats)
                   -> Result<()>
{
    let inputs = if command.input.is_empty() {
        vec![ PathBuf::from("-") ]
    } else {
        command.input
    };

    // Return the first error.
    let mut ret = Ok(());

    for file in inputs {
        let input = FileOrStdin::from(file.clone());
        let input_reader = input.open("OpenPGP keys")?;

        for r in CertParser::from_buffered_reader(input_reader)? {
            let cert = match r {
                Ok(cert) => cert,
                Err(err) => {
                    wwriteln!(o, "Error reading {}: {}", file.display(), err);
                    if ret.is_ok() {
                        ret = Err(err);
                    }
                    continue;
                }
            };

            let fp = cert.fingerprint();
            let id = format!("{} {}",
                             cert.fingerprint(),
                             sq.best_userid(&cert, true).display());

            let cert_is_tsk = cert.is_tsk();
            match sq.import_key(cert, stats) {
                Ok((key, cert)) => {
                    wwriteln!(o, "Imported {} from {}: {}",
                              id, file.display(),
                              if key == cert {
                                  key.to_string()
                              } else {
                                  format!("key {}, cert {}", key, cert)
                              });

                    sq.hint(format_args!("If this is your key, you should  \
                                          mark it as a fully trusted \
                                          introducer:"))
                        .sq().arg("pki").arg("link").arg("authorize")
                        .arg("--unconstrained")
                        .arg_value("--cert", &fp)
                        .arg("--all")
                        .done();

                    sq.hint(format_args!("Otherwise, consider marking it as \
                                          authenticated:"))
                        .sq().arg("pki").arg("link").arg("add")
                        .arg_value("--cert", &fp)
                        .arg("--all")
                        .done();
                }

                Err(err) => {
                    wwriteln!(o, "Error importing {} from {}: {}",
                              id, file.display(), err);

                    if ! cert_is_tsk {
                        sq.hint(format_args!(
                            "To import certificates, do:"))
                            .sq().arg("cert").arg("import")
                            .arg(file.display())
                            .done();
                    }

                    if ret.is_ok() {
                        ret = Err(err);
                    }
                }
            }
        }
    }

    ret
}
