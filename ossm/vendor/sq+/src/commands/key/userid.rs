use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::cert::UserIDRevocationBuilder;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::UserID;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::ReasonForRevocation;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::cli::key::userid::RevokeCommand;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::cli;
use crate::common::RevocationOutput;
use crate::common::get_secret_signer;
use crate::common::ui;
use crate::common::userid::{
    lint_emails,
    lint_names,
    lint_userids,
};
use crate::sq::TrustThreshold;

/// Handle the revocation of a User ID
struct UserIDRevocation {
    cert: Cert,
    revoker: Cert,
    revocation_packet: Packet,
    uid: UserID,
}

impl UserIDRevocation {
    /// Create a new UserIDRevocation
    pub fn new(
        sq: &Sq,
        uid: ResolvedUserID,
        cert: Cert,
        revoker: Option<Cert>,
        reason: ReasonForRevocation,
        message: &str,
        notations: &[(bool, NotationData)],
    ) -> Result<Self> {
        let (revoker, mut signer)
            = get_secret_signer(sq, &cert, revoker.as_ref())?;

        let revocation_packet = {
            // Create a revocation for a User ID.
            let mut rev = UserIDRevocationBuilder::new()
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
            let rev = rev.build(
                &mut signer,
                &cert,
                uid.userid(),
                None,
            )?;
            Packet::Signature(rev)
        };

        Ok(UserIDRevocation {
            cert,
            revoker,
            revocation_packet,
            uid: uid.userid().clone(),
        })
    }
}

impl RevocationOutput for UserIDRevocation
{
    fn cert(&self) -> Result<Cert> {
        let cert = Cert::from_packets(vec![
            self.cert.primary_key().key().clone().into(),
            self.uid.clone().into(),
            self.revocation_packet.clone(),
        ].into_iter())?;

        Ok(cert)
    }

    fn comment(&self) -> String {
        format!("This is a revocation certificate for \
                 the User ID {} of cert {}.",
                ui::Safe(&self.uid),
                self.cert.fingerprint())
    }

    fn revoker(&self) -> &Cert {
        &self.revoker
    }
}

pub fn dispatch(
    sq: Sq,
    command: cli::key::userid::Command,
) -> Result<()> {
    match command {
        cli::key::userid::Command::Add(c) => userid_add(sq, c)?,
        cli::key::userid::Command::Revoke(c) => userid_revoke(sq, c)?,
    }

    Ok(())
}

fn userid_add(
    sq: Sq,
    mut command: cli::key::userid::AddCommand,
) -> Result<()> {
    let cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

    let mut signer = sq.get_primary_key(&cert, None)?;

    // Names, email addresses, and user IDs.
    lint_names(&command.names)?;
    for n in &command.names {
        command.userid.push(UserID::from(n.as_str()));
    }

    lint_emails(&command.emails)?;
    for n in &command.emails {
        command.userid.push(UserID::from_address(None, None, n)?);
    }

    // Make sure the user IDs are in canonical form.  If not, and
    // `--allow-non-canonical-userids` is not set, error out.
    if ! command.allow_non_canonical_userids {
        lint_userids(&command.userid)?;
    }

    // Fail if any of the User IDs to add already exist in the ValidCert
    let cert_userids: Vec<_> =
        cert.userids().map(|u| u.userid().value()).collect();
    let exists: Vec<_> = command
        .userid
        .iter()
        .filter(|s| cert_userids.contains(&s.value()))
        .collect();
    if !exists.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate already contains the User ID(s) {}.",
            exists.iter().map(|s| ui::Safe(*s).to_string())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }

    let vcert = cert
        .with_policy(sq.policy, sq.time)
        .with_context(|| {
            format!("Certificate {} is not valid", cert.fingerprint())
        })?;

    // Use the primary User ID or direct key signature as template for the
    // SignatureBuilder.
    //
    // XXX: Long term, this functionality belongs next to
    // openpgp/src/cert/builder/key.rs.
    let mut sb = if let Ok(primary_user_id) = vcert.primary_userid() {
        SignatureBuilder::from(primary_user_id.binding_signature().clone())
    } else if let Ok(direct_key_sig) = vcert.direct_key_signature() {
        SignatureBuilder::from(direct_key_sig.clone())
            .set_type(SignatureType::PositiveCertification)
    } else {
        // If there is neither a valid uid binding signature, nor a
        // valid direct key signature, we shouldn't have gotten a
        // ValidCert above.
        unreachable!("ValidCert has to have one of the above.")
    };

    // Remove bad algorithms from preferred algorithm subpackets,
    // and make sure preference lists contain at least one good algorithm.

    // - symmetric_algorithms
    let mut symmetric_algorithms: Vec<_> =
        sb.preferred_symmetric_algorithms().unwrap_or(&[]).to_vec();
    symmetric_algorithms
        .retain(|algo| sq.policy.symmetric_algorithm(*algo).is_ok());
    if symmetric_algorithms.is_empty() {
        symmetric_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_symmetric_algorithms(symmetric_algorithms)?;

    // - hash_algorithms
    let mut hash_algorithms: Vec<_> =
        sb.preferred_hash_algorithms().unwrap_or(&[]).to_vec();
    hash_algorithms.retain(|algo| {
        sq
            .policy
            .hash_cutoff(*algo, HashAlgoSecurity::CollisionResistance)
            .map(|cutoff| cutoff.lt(&SystemTime::now()))
            .unwrap_or(true)
    });
    if hash_algorithms.is_empty() {
        hash_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_hash_algorithms(hash_algorithms)?;

    // Remove the following types of SubPacket, if they exist
    #[allow(deprecated)]
    const REMOVE_SUBPACKETS: &[SubpacketTag] = &[
        // The Signature should be exportable.
        // https://openpgp-wg.gitlab.io/rfc4880bis/#name-exportable-certification
        // "If this packet is not present, the certification is exportable;
        // it is equivalent to a flag containing a 1."
        SubpacketTag::ExportableCertification,
        // PreferredAEADAlgorithms has been removed by WG.
        // It was replaced by `39  Preferred AEAD Ciphersuites`,
        //  see https://openpgp-wg.gitlab.io/rfc4880bis/#section-5.2.3.5-7)
        SubpacketTag::PreferredAEADAlgorithms,
        // Strip the primary userid SubPacket
        // (don't implicitly make a User ID primary)
        SubpacketTag::PrimaryUserID,
        // Other SubPacket types that shouldn't be in use in this context
        SubpacketTag::TrustSignature,
        SubpacketTag::RegularExpression,
        SubpacketTag::SignersUserID,
        SubpacketTag::ReasonForRevocation,
        SubpacketTag::SignatureTarget,
        SubpacketTag::EmbeddedSignature,
        SubpacketTag::ApprovedCertifications,
    ];

    sb = sb.modify_hashed_area(|mut subpacket_area| {
        REMOVE_SUBPACKETS
            .iter()
            .for_each(|sp| subpacket_area.remove_all(*sp));

        Ok(subpacket_area)
    })?;

    // New User ID should only be made primary if explicitly specified by user.
    // xxx: add a parameter to set a new user id as primary?

    // Collect packets to add to the key (new User IDs and binding signatures)
    let mut add: Vec<Packet> = vec![];

    // Make new User IDs and binding signatures
    for uid in command.userid {
        let uid: UserID = uid.into();
        add.push(uid.clone().into());

        // Creation time.
        sb = sb.set_signature_creation_time(sq.time)?;

        let binding = uid.bind(&mut signer, &cert, sb.clone())?;
        add.push(binding.into());
    }

    // Merge the new User IDs into cert.
    let cert = cert.insert_packets(add)?.0;

    if let Some(output) = command.output {
        let mut sink = output.for_secrets().create_safe(&sq)?;
        if false {
            cert.as_tsk().serialize(&mut sink)?;
        } else {
            cert.as_tsk().armored().serialize(&mut sink)?;
        }
    } else {
        let cert_store = sq.cert_store_or_else()?;
        cert_store.update(Arc::new(cert.into()))?;
    }

    Ok(())
}

/// Revoke a UserID of an existing primary key
///
/// ## Errors
///
/// Returns an error if reading of the [`Cert`] fails, if retrieval of
/// [`NotationData`] fails or if the eventual revocation fails.
pub fn userid_revoke(
    sq: Sq,
    command: RevokeCommand,
) -> Result<()> {
    let cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;
    // To revoke a user ID, we require the certificate be valid under
    // the current policy.  Users can still revoke user IDs whose
    // binding signature relies on weak cryptography using
    // `--add-user`.
    let vcert = cert.with_policy(sq.policy, sq.time)
        .with_context(|| {
            format!("The certificate is not valid under the current \
                     policy.  Consider revoking the whole certificate \
                     using `sq key revoke`, or fixing it using \
                     `sq cert lint` after verifying the certificate's \
                     integrity.")
        })?;
    let userids = command.userids.resolve(&vcert)?;
    assert_eq!(userids.len(), 1, "exactly one user ID enforced by clap");
    let userid = userids.into_iter().next().unwrap();

    let revoker = if command.revoker.is_empty() {
        None
    } else {
        Some(sq.resolve_cert(&command.revoker, TrustThreshold::Full)?.0)
    };

    let notations = command.signature_notations.parse()?;

    let revocation = UserIDRevocation::new(
        &sq,
        userid,
        cert,
        revoker,
        command.reason.into(),
        &command.message,
        &notations,
    )?;

    revocation.write(&sq, command.output, false)?;

    Ok(())
}
