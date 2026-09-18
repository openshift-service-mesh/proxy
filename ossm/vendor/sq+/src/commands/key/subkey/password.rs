//! Changes the password protecting one or more keys.

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;

use crate::Result;
use crate::Sq;
use crate::common::NULL_POLICY;
use crate::common::key::get_keys;
use crate::common::key::password;
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::password::Command)
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

    let to_change = get_keys(&sq, &cert_source, &kas, false)?;

    password(sq, &cert, cert_source, to_change,
             command.clear_password, command.new_password_file.as_deref(),
             command.output, false)
}

