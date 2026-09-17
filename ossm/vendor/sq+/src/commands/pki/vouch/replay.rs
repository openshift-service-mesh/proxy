use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::packet::UserID;
use openpgp::serialize::Serialize;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::cli::pki::vouch::replay;
use crate::output::sanitize::Safe;
use crate::sq::TrustThreshold;

const TRACE: bool = false;

pub fn replay(sq: Sq, c: replay::Command)
    -> Result<()>
{
    tracer!(TRACE, "sq::pki::vouch::replay");

    let source =
        sq.resolve_cert(&c.source, TrustThreshold::Full)?.0;

    let target =
        sq.resolve_cert(&c.target, TrustThreshold::Full)?.0;

    t!("Replaying certifications made by {} with {}",
       source.fingerprint(), target.fingerprint());

    if ! c.allow_dissimilar_userids {
        // Check that the certificates have a self-signed user ID in
        // common.
        let source_vc = source.with_policy(sq.policy, sq.time)?;
        let target_vc = target.with_policy(sq.policy, sq.time)?;
        let source_userids: BTreeSet<&UserID>
            = source_vc.userids().map(|ua| ua.userid()).collect();
        let target_userids: BTreeSet<&UserID>
            = target_vc.userids().map(|ua| ua.userid()).collect();

        if source_userids.intersection(&target_userids).next().is_none() {
            weprintln!("The source and target certificates don't share a \
                        self-signed user ID.  Normally you don't want to \
                        replay certifications made by someone else.  If you \
                        are sure, pass --allow-dissimilar-userids to \
                        disable this check.");
            weprintln!("Source certificate's self-signed user IDs:");
            for userid in source_userids {
                weprintln!(initial_indent = " - ", "{}", Safe(userid));
            }
            weprintln!("Target certificate's self-signed user IDs:");
            for userid in target_userids {
                weprintln!(initial_indent = " - ", "{}", Safe(userid));
            }

            return Err(anyhow::anyhow!(
                "Cowardly refusing to replay the certifications.  The source \
                 and target certificates appear to be for different entities."));
        }
    }

    let o = &mut std::io::stderr();

    let source = RefCell::new(source);
    let results = crate::common::pki::replay::replay(
        &sq, o, "", RefCell::clone(&source), &target, None, None)?;

    if results.is_empty() {
        return Ok(());
    }

    if let Some(output) = c.output {
        // And export it.
        let path = output.path().map(Clone::clone);
        let mut message = output.create_pgp_safe(
            &sq,
            false, // binary
            sequoia_openpgp::armor::Kind::PublicKey)?;
        for cert in results.into_iter() {
            cert.serialize(&mut message)?;
        }
        message.finalize()?;

        if let Some(path) = path {
            sq.hint(format_args!(
                "Updated certificates written to {}.  \
                 To make the updates effective, they have to be published \
                 so that others can find them, for example using:",
                path.display()))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert-file", path.display())
                .done();
        } else {
            sq.hint(format_args!(
                "To make the updates effective, they have to be published \
                 so that others can find them."));
        }
    } else {
        // Import it.
        let cert_store = sq.cert_store_or_else()?;

        let mut hint = sq.hint(format_args!(
            "Imported updated certificates into the cert store.  \
             To make the updates effective, they have to be published \
             so that others can find them, for example using:"))
                .sq().arg("network").arg("keyserver").arg("publish");

        for cert in results.into_iter() {
            let fpr = cert.fingerprint();

            if let Err(err) = cert_store.update(Arc::new(cert.into())) {
                weprintln!("Error importing updated certificate: {}", err);
                return Err(err);
            }
            hint = hint.arg_value("--cert", fpr)
        }

        hint.done();
    }

    Ok(())
}
