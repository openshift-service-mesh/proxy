use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::serialize::Serialize;

use crate::Result;
use crate::Sq;
use crate::cli;
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, command: cli::key::export::Command)
                -> Result<()>
{
    let ks = sq.key_store_or_else()?;
    let mut ks = ks.lock().unwrap();

    let certs = sq.resolve_certs_or_fail(
        &command.certs, TrustThreshold::Full)?;

    // Note: Sq::resolve_certs already deduped the certificates.
    let mut results = Vec::new();

    for cert in certs.into_iter() {
        let vc = Cert::with_policy(&cert, sq.policy, sq.time)
            .with_context(|| {
                format!("The certificate {} is not valid under the \
                         current policy.  Use sq key subkey export --key \
                         to export specific keys.",
                        cert.fingerprint())
            })?;

        let mut secret_keys: Vec<Packet> = Vec::new();
        let mut errs = Vec::new();

        for ka in vc.keys().into_iter().collect::<Vec<_>>() {
            if ka.key().has_secret() {
                // We already have the secret key material.
                continue;
            }

            let key_handle = ka.key().key_handle();

            for mut remote in ks.find_key(key_handle)? {
                match remote.export() {
                    Ok(secret_key) => {
                        if ka.primary() {
                            secret_keys.push(
                                secret_key.role_into_primary().into());
                        } else {
                            secret_keys.push(
                                secret_key.role_into_subordinate().into());
                        }
                        break;
                    }
                    Err(err) => {
                        errs.push((ka.key().fingerprint(), err));
                    }
                }
            }
        }

        if secret_keys.is_empty() {
            for (fpr, err) in errs.into_iter() {
                weprintln!("Exporting {}: {}", fpr, err);
            }
            return Err(anyhow::anyhow!(
                "Failed to export {}: no secret key material is available",
                cert.fingerprint()));
        }

        let cert = cert.insert_packets(secret_keys)?.0;
        results.push(cert);
    }

    let mut output = command.output.for_secrets().create_safe(&sq)?;

    if false {
        for cert in results.into_iter() {
            cert.as_tsk().export(&mut output)
                .with_context(|| {
                    format!("Serializing {}", cert.fingerprint())
                })?;
        }
    } else {
        let mut output = openpgp::armor::Writer::new(
            output,
            openpgp::armor::Kind::SecretKey)?;

        for cert in results.into_iter() {
            cert.as_tsk().export(&mut output)
                .with_context(|| {
                    format!("Serializing {}", cert.fingerprint())
                })?;
        }

        output.finalize()?;
    }

    Ok(())
}
