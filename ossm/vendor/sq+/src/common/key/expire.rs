//! Changes key expiration.

use std::sync::Arc;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store::StoreUpdate;

use crate::Sq;
use crate::cli::types::CertDesignators;
use crate::cli::types::Expiration;
use crate::cli::types::FileOrStdout;
use crate::cli::types::KeyDesignators;
use crate::cli::types::cert_designator;
use crate::sq::GetKeysOptions;
use crate::sq::TrustThreshold;

/// cert must resolve to a single certificate.
///
/// If `keys` is `None`, the primary key's expiration is changed.
/// Otherwise the expiration of each of the specified keys is
/// extended.
pub fn expire<A, P, O, D>(sq: Sq,
                          cert: CertDesignators<A, P, O, D>,
                          keys: Option<KeyDesignators>,
                          expiration: Expiration,
                          mut output: Option<FileOrStdout>,
                          binary: bool)
    -> Result<()>
where P: cert_designator::ArgumentPrefix,
      O: typenum::Unsigned,
{
    let options = O::to_usize();
    let one_value
        = (options & cert_designator::OneValue::to_usize()) > 0;
    assert!(one_value);
    let optional_value
        = (options & cert_designator::OptionalValue::to_usize()) > 0;
    assert!(! optional_value);

    let (cert, cert_handle)
        = sq.resolve_cert(&cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(sq.policy, sq.time)?;

    let keys = if let Some(keys) = keys {
        sq.resolve_keys(&vc, &cert_handle, &keys, false)?
    } else {
        // The primary key.
        vec![ vc.keys().next().expect("have a primary key") ]
    };

    if cert_handle.is_file() {
        if output.is_none() {
            // None means to write to the cert store.  When reading
            // from a file, we want to write to stdout by default.
            output = Some(FileOrStdout::new(None));
        }
    }

    let mut primary_signer
        = sq.get_primary_key(&cert, Some(&[GetKeysOptions::AllowNotAlive]))?;

    // Fix the new expiration time.
    let expiration_time = expiration.to_system_time(sq.time)?;

    let (primary, subkeys): (Vec<_>, Vec<_>)
        = keys.into_iter().partition(|ka| ka.primary());
    assert!(primary.len() <= 1);

    // Collect new signatures here, then canonicalize once.
    let mut acc = Vec::<Packet>::new();

    // To update subkey expiration times, create new binding
    // signatures.
    for ka in subkeys {
        // Use the binding signature under our policy as the template.
        let template = ka.binding_signature();

        // Push a copy of the key to make reordering easier.
        acc.push(Packet::from(ka.key().clone().role_into_subordinate()));
        acc.push(ka.key().role_as_subordinate().bind(
            &mut primary_signer,
            &cert,
            SignatureBuilder::from(template.clone())
                .set_signature_creation_time(sq.time)?
                .set_key_expiration_time(ka.key(), expiration_time)?)?
                 .into());
    }

    // To change the cert's expiration time, create a new direct key
    // signature and new binding signatures for the user IDs.
    if let Some(ka) = primary.get(0) {
        let template = ka.binding_signature().clone();

        // Clean the template.
        let template = SignatureBuilder::from(template)
            .modify_unhashed_area(|mut a| {
                a.clear();
                Ok(a)
            })?
            .modify_hashed_area(|mut a| {
                // XXX: Rework once
                // https://gitlab.com/sequoia-pgp/sequoia/-/issues/1127
                // is available.
                let mut strip_tags: std::collections::BTreeSet<_> =
                    a.iter().map(|s| s.tag()).collect();

                // Symbolic names for the policy below.
                let strip = true;
                let keep = false;

                use openpgp::packet::signature::subpacket::SubpacketTag::*;
                #[allow(deprecated)]
                strip_tags.retain(|t| match t {
                    // These we keep.
                    PreferredSymmetricAlgorithms => keep,
                    RevocationKey => keep,
                    NotationData => keep,
                    PreferredHashAlgorithms => keep,
                    PreferredCompressionAlgorithms => keep,
                    KeyServerPreferences => keep,
                    PreferredKeyServer => keep,
                    PolicyURI => keep,
                    KeyFlags => keep,
                    Features => keep,
                    // XXXv6: PreferredAEADCiphersuites => keep,

                    // Oddballs, keep them.
                    Reserved(_) => keep,
                    Private(_) => keep,
                    Unknown(_) => keep,

                    // These we want to strip.
                    SignatureCreationTime => strip,
                    SignatureExpirationTime => strip,
                    ExportableCertification => strip,
                    TrustSignature => strip,
                    RegularExpression => strip,
                    Revocable => strip,
                    KeyExpirationTime => strip,
                    PlaceholderForBackwardCompatibility => strip,
                    Issuer => strip,
                    PrimaryUserID => strip,
                    SignersUserID => strip,
                    ReasonForRevocation => strip,
                    SignatureTarget => strip,
                    EmbeddedSignature => strip,
                    IssuerFingerprint => strip,
                    PreferredAEADAlgorithms => strip, // Note, "v5".
                    IntendedRecipient => strip,
                    ApprovedCertifications => strip,

                    // Enum is non-exhaustive, conservative choice is
                    // to keep unknown subpackets.
                    _ => keep,
                });

                for t in strip_tags {
                    a.remove_all(t);
                }

                Ok(a)
            })?;

        // We can't add a copy of the primary key, as that's not
        // allowed by `Cert::insert_packets`.  But it's easy to
        // reorder direct key signatures as there is only a single
        // possible component, the primary key.
        acc.push(template
                 .set_type(SignatureType::DirectKey)
                 .set_signature_creation_time(sq.time)?
                 .set_key_expiration_time(cert.primary_key().key(),
                                          expiration_time)?
                 .sign_direct_key(&mut primary_signer, None)?
                 .into());

        for uidb in vc.userids() {
            if let RevocationStatus::Revoked(_) = uidb.revocation_status() {
                // The user ID is revoked.  Skip it.  (Adding a new
                // self signature would actually "unrevoke it"!)
                continue;
            }

            // Use the binding signature that is valid under our
            // policy as of the reference time.
            let template = uidb.binding_signature().clone();

            // Push a copy of the user ID to make reordering easier.
            acc.push(Packet::from(uidb.userid().clone()));
            acc.push(uidb.userid().bind(
                &mut primary_signer,
                &cert,
                SignatureBuilder::from(template)
                    .set_signature_creation_time(sq.time)?
                    .set_key_expiration_time(cert.primary_key().key(),
                                             expiration_time)?)?
                     .into());
        }
    }

    // Merge and canonicalize.
    let cert = cert.insert_packets(acc)?.0;

    if let Some(sink) = output {
        let path = sink.path().map(Clone::clone);
        let mut output = sink.for_secrets().create_safe(&sq)?;
        if binary {
            cert.as_tsk().serialize(&mut output)?;
        } else {
            cert.as_tsk().armored().serialize(&mut output)?;
        }

        if let Some(path) = path {
            sq.hint(format_args!(
                "Updated certificate written to {}.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:",
                path.display()))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert-file", path.display())
                .done();
        } else {
            sq.hint(format_args!(
                "To make the update effective, it has to be published \
                 so that others can find it."));
        }
    } else {
        let cert_store = sq.cert_store_or_else()?;

        let fipr = cert.fingerprint();
        if let Err(err) = cert_store.update(Arc::new(cert.into())) {
            weprintln!("Error importing updated cert: {}", err);
            return Err(err);
        } else {
            sq.hint(format_args!(
                "Imported updated cert into the cert store.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:"))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert", fipr)
                .done();
        }
    }

    Ok(())
}
