//! Deletes all of a certificate's secret key material.

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::cert::amalgamation::ValidateAmalgamation;
use openpgp::cert::amalgamation::key::PrimaryKey;

use crate::Result;
use crate::Sq;
use crate::cli;
use crate::common::NULL_POLICY;
use crate::common::key::delete;
use crate::common::key::get_keys;
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, command: cli::key::delete::Command)
                -> Result<()>
{
    let (cert, cert_source)
        = sq.resolve_cert(&command.cert, TrustThreshold::Full)?;

    // Fail if the certificate is not valid under the current policy.
    Cert::with_policy(&cert, sq.policy, sq.time)
        .with_context(|| {
            sq.hint(format_args!(
                "The certificate {} is not valid under the \
                 current policy.  You can still delete individual \
                 keys using `sq key subkey delete`.",
                cert.fingerprint()));

            format!("The certificate {} is not valid under the \
                     current policy.",
                    cert.fingerprint())
        })?;

    // We want to delete all secret key material associated with the
    // certificate, but we don't want to delete secret key material
    // that we are not confident belongs to the certificate.
    //
    // Imagine Alice creates a new certificate.  Mallory see this, and
    // anticipates that she is going to delete the old certificate.
    // He attaches her new encryption-capable subkey to the old
    // certificate using some weak cryptography, publishes it, and
    // then Alice gets the update to her old certificate via
    // parcimonie.  When she deletes the secret key material
    // associated with the old certificate, she would also delete her
    // new secret key material.  Ouch!  Admittedly, this attack is a
    // bit contrived.
    //
    // Alternatively, we could skip subkeys whose bindings rely on
    // weak cryptography.  This behavior would probably surprise most
    // users.  It could have serious consequences as well, since the
    // user thought they deleted the secret key material, but didn't.
    //
    // Instead, we are conservative: if a subkey's binding signature
    // relies on weak cryptography AND we have secret key material for
    // it, we abort, and suggest using `sq key subkey delete` instead.

    // Get all keys valid under the NULL policy.
    let nc = Cert::with_policy(&cert, NULL_POLICY, sq.time)
        .with_context(|| {
            format!("The certificate {} is not valid under the \
                     null policy.",
                    cert.fingerprint())
        })?;

    let kas = nc.keys().collect::<Vec<_>>();
    let kas = kas.iter().collect::<Vec<_>>();
    let to_delete = get_keys(&sq, &cert_source, &kas, true)?;

    // Go through the keys with secret key material, and make sure
    // their binding is valid under the current policy.
    let mut bad = Vec::new();
    for (ka, _remote) in to_delete.iter() {
        if ka.primary() {
            // We check that the primary key is valid above.
            continue;
        }
        if let Err(err) = ka.with_policy(sq.policy, sq.time) {
            bad.push((ka.key().fingerprint(), err));
        }
    }
    if ! bad.is_empty() {
        weprintln!("Some keys are not valid according \
                    to the current policy:");
        for (fpr, err) in bad.into_iter() {
            weprintln!("  - {}: {}",
                       fpr,
                       crate::one_line_error_chain(err));
        }
        weprintln!("Cowardly refusing to delete all of the secret key \
                    material to avoid accidentally losing data.  Use \
                    `sq key subkey delete` to delete the keys individually.");

        return Err(anyhow::anyhow!(
            "The authenticity of some subkeys is uncertain."));
    }

    if to_delete.is_empty() {
        return Err(anyhow::anyhow!(
            "{} does not contain any secret key material.",
            cert.fingerprint()));
    }

    if cert_source.is_key_handle() {
        let mut die = false;

        // Make sure this is not ambiguous.
        for (ka, _remote) in to_delete.iter() {
            if let Ok(certs) = sq.lookup_with_policy(
                std::iter::once(ka.key().key_handle()),
                None,
                true,
                true,
                NULL_POLICY,
                sq.time)
            {
                if certs.len() > 1 {
                    die = true;
                    weprintln!("{} is associated with multiple certificates:",
                               ka.key().fingerprint());
                    for cert in certs.iter() {
                        weprintln!(" - {}", cert.fingerprint());
                    }
                }
            }
        }

        if die {
            weprintln!("Cowardly refusing to delete secret key material to \
                        avoid accidentally losing data.  Use \
                        `sq key subkey delete` to delete the keys \
                        individually.");

            return Err(anyhow::anyhow!(
                "Some keys are associated with multiple certificates."));
        }
    }

    delete::delete(sq, &cert, cert_source, to_delete,
                   command.output, false)
}
