use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    Result,
    serialize::Serialize,
};

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::{
    Sq,
    print_error_chain,
    utils::cert_exportable,
};

use crate::cli::cert::export;
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, cmd: export::Command) -> Result<()> {
    let cert_store = sq.cert_store_or_else()?;

    if cmd.certs.is_empty() && ! cmd.all {
        sq.hint(format_args!(
            "Use --all to export all certs, or give a query."));
        return Err(anyhow::anyhow!("no query given"));
    }

    let mut sink = cmd.output.create_pgp_safe(
        &sq,
        false,
        armor::Kind::PublicKey,
    )?;

    let mut exported_something = false;

    if cmd.all {
        // Export everything.
        for cert in cert_store.certs()
            .filter(|c| cmd.local
                    || c.to_cert().map(cert_exportable).unwrap_or(false))
        {
            // Turn parse errors into warnings: we want users to be
            // able to recover as much of their data as possible.
            let result = cert.to_cert()
                .with_context(|| {
                    format!("Parsing {} from certificate directory",
                            cert.fingerprint())
                });
            match result {
                Ok(cert) => if cmd.local {
                    cert.serialize(&mut sink)?;
                } else {
                    cert.export(&mut sink)?;
                },
                Err(err) => {
                    print_error_chain(&err);
                    continue;
                }
            }
        }

        // When specifying `--all`, if we have nothing and we export
        // nothing, that is fine.
        exported_something = true;
    } else {
        let (certs, errors)
            = sq.resolve_certs(&cmd.certs, TrustThreshold::Full)?;
        for error in errors.iter() {
            print_error_chain(error);
        }
        if ! errors.is_empty() {
            return Err(anyhow::anyhow!("Failed to resolve certificates"));
        }

        for cert in certs.into_iter() {
            if cmd.local {
                cert.serialize(&mut sink)?;
            } else {
                cert.export(&mut sink)?;
            }
            exported_something = true;
        }
    }

    sink.finalize().context("Failed to export certificates")?;

    if exported_something {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Search terms did not match any certificates"))
    }
}
