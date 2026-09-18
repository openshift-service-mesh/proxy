use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::cert::Cert;
use openpgp::packet::Packet;
use openpgp::serialize::Serialize;

use anyhow::Context;

use crate::Result;
use crate::Sq;
use crate::sq::NULL_POLICY;
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::export::Command)
    -> Result<()>
{
    let ks = sq.key_store_or_else()?;
    let mut ks = ks.lock().unwrap();

    assert_eq!(command.cert.len(), 1);
    assert!(command.keys.len() > 0);

    let (mut cert, cert_source)
        = sq.resolve_cert(&command.cert, TrustThreshold::Full)?;

    // Yes, we unconditionally use the NULL policy.  This is safe as
    // the user explicitly named both the certificate, and keys to
    // export.
    let vc = Cert::with_policy(&cert, &NULL_POLICY, sq.time)
        .with_context(|| {
            format!("The certificate {} is not valid under the \
                     null policy.",
                    cert.fingerprint())
        })?;

    let kas = sq.resolve_keys(&vc, &cert_source, &command.keys, true)?;

    let mut secret_keys: Vec<Packet> = Vec::new();
    let mut errs = Vec::new();

    for ka in kas {
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

    cert = cert.insert_packets(secret_keys)?.0;

    let mut output = command.output.for_secrets().create_safe(&sq)?;

    if false {
        cert.as_tsk().export(&mut output)
            .with_context(|| {
                format!("Serializing {}", cert.fingerprint())
            })?;
    } else {
        let mut output = openpgp::armor::Writer::new(
            output,
            openpgp::armor::Kind::SecretKey)?;

        cert.as_tsk().export(&mut output)
            .with_context(|| {
                format!("Serializing {}", cert.fingerprint())
            })?;

        output.finalize()?;
    }

    Ok(())
}

