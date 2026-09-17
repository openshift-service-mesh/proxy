use sequoia_openpgp as openpgp;
use openpgp::cert::CertRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::types::ReasonForRevocation;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use crate::Sq;
use crate::cli::key::revoke::Command;
use crate::common::get_secret_signer;
use crate::common::RevocationOutput;
use crate::sq::TrustThreshold;

/// Handle the revocation of a certificate
struct CertificateRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
}

impl CertificateRevocation {
    /// Create a new CertificateRevocation
    pub fn new(
        sq: &Sq,
        cert: Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (revoker, mut signer) = get_secret_signer(
            sq,
            &cert,
            revoker.as_ref(),
        )?;

        let revocation_packet = {
            // Create a revocation for the certificate.
            let mut rev = CertRevocationBuilder::new()
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
            let rev = rev.build(&mut signer, &cert, None)?;
            Packet::Signature(rev)
        };

        Ok(CertificateRevocation {
            cert,
            revoker,
            revocation_packet,
        })
    }
}

impl RevocationOutput for CertificateRevocation
{
    fn cert(&self) -> Result<Cert> {
        let cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        Ok(cert)
    }

    fn comment(&self) -> String {
        format!("This is a revocation certificate for the cert {}.",
                self.cert.fingerprint())
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

/// Revoke a certificate
pub fn certificate_revoke(
    sq: Sq,
    command: Command,
) -> Result<()> {
    let cert =
        sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

    let revoker = if command.revoker.is_empty() {
        None
    } else {
        Some(sq.resolve_cert(&command.revoker, TrustThreshold::Full)?.0)
    };

    let notations = command.signature_notations.parse()?;

    let revocation = CertificateRevocation::new(
        &sq,
        cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
    )?;
    revocation.write(&sq, command.output, false)?;

    Ok(())
}
