use std::collections::BTreeSet;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::cert::SubkeyRevocationBuilder;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::{Key, Signature, key};
use openpgp::types::ReasonForRevocation;

use crate::Result;
use crate::Sq;
use crate::common::NULL_POLICY;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::sq::TrustThreshold;

/// Handle the revocation of a subkey
struct SubkeyRevocation {
    cert: Cert,
    revoker: Cert,
    revocations: Vec<(Key<key::PublicParts, key::SubordinateRole>, Signature)>,
}

impl SubkeyRevocation {
    /// Create a new SubkeyRevocation
    pub fn new(
        sq: &Sq,
        kas: &[ValidErasedKeyAmalgamation<key::PublicParts>],
        cert: &Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (revoker, mut signer)
            = get_secret_signer(sq, &cert, revoker.as_ref())?;

        let mut revocations = Vec::new();
        let mut revoked = BTreeSet::new();
        for ka in kas {
            // Did we already revoke it?
            if revoked.contains(&ka.key().fingerprint()) {
                continue;
            }
            revoked.insert(ka.key().fingerprint());

            let mut rev = SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(reason, message.as_bytes())?;
            rev = rev.set_signature_creation_time(sq.time)?;
            for (critical, notation) in notations {
                rev = rev.add_notation(
                    notation.name(),
                    notation.value(),
                    Some(notation.flags().clone()),
                    *critical,
                )?;
            }
            let key = ka.key().clone().role_into_subordinate();
            let rev = rev.build(&mut signer, &cert, &key, None)?;
            revocations.push((key, rev));
        }

        Ok(SubkeyRevocation {
            cert: cert.clone(),
            revoker,
            revocations,
        })
    }
}

impl RevocationOutput for SubkeyRevocation {
    fn cert(&self) -> Result<Cert> {
         Cert::from_packets(
            std::iter::once(
                Packet::from(self.cert.primary_key().key().clone()))
                .chain(self.revocations.iter().flat_map(
                    |(k, s)| [k.clone().into(), s.clone().into()].into_iter()))
        )
    }

    fn comment(&self) -> String {
        if self.revocations.len() == 1 {
            format!("This is a revocation certificate for \
                     the subkey {} of cert {}.",
                    self.revocations[0].0.fingerprint(),
                    self.cert.fingerprint())
        } else {
            let fingerprints: Vec<_> = self.revocations.iter()
                .map(|k| k.0.fingerprint().to_string()).collect();
            format!("This is a revocation certificate for \
                     the subkeys {} of cert {}.",
                    fingerprints.join(", "),
                    self.cert.fingerprint())
        }
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

/// Revoke a Subkey of an existing primary key
///
/// ## Errors
///
/// Returns an error if parsing of the [`KeyHandle`] fails, if reading of the
/// [`Cert`] fails, if retrieval of [`NotationData`] fails or if the eventual
/// revocation fails.
pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::revoke::Command)
    -> Result<()>
{
    let (cert, cert_source) =
        sq.resolve_cert(&command.cert, TrustThreshold::Full)?;

    let vc = Cert::with_policy(&cert, NULL_POLICY, sq.time)
        .with_context(|| {
            format!("The certificate {} is not valid under the \
                     null policy.",
                    cert.fingerprint())
        })?;

    let keys = sq.resolve_keys(&vc, &cert_source, &command.keys, true)?;

    let revoker = if command.revoker.is_empty() {
        None
    } else {
        Some(sq.resolve_cert(&command.revoker, TrustThreshold::Full)?.0)
    };

    let notations = command.signature_notations.parse()?;

    let revocation = SubkeyRevocation::new(
        &sq,
        &keys[..],
        &cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(&sq, command.output, false)?;

    Ok(())
}
