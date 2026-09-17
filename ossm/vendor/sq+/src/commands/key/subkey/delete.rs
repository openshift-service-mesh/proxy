//! Deletes one or more key's secret key material.

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;

use crate::Result;
use crate::Sq;
use crate::common::key::delete;
use crate::common::NULL_POLICY;
use crate::common::key::get_keys;
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::delete::Command)
    -> Result<()>
{
    assert!(! command.keys.is_empty());

    let (cert, cert_source)
        = sq.resolve_cert(&command.cert, TrustThreshold::Full)?;

    let vc = Cert::with_policy(&cert, NULL_POLICY, sq.time)
        .with_context(|| {
            format!("The certificate {} is not valid under the \
                     null policy.",
                    cert.fingerprint())
        })?;

    let kas = sq.resolve_keys(&vc, &cert_source, &command.keys, true)?;
    let kas = kas.iter().collect::<Vec<_>>();

    let to_delete = get_keys(&sq, &cert_source, &kas, false)?;

    delete::delete(sq, &cert, cert_source, to_delete,
                   command.output, false)
}
