use std::{
    collections::BTreeSet,
};

use sequoia_openpgp::{
    Result,
    serialize::Serialize,
};

use sequoia_cert_store::Store;
use sequoia_wot as wot;

use crate::Sq;
use crate::cli::key::approvals;
use crate::cli;
use crate::common::{ca_creation_time, ui};
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, command: approvals::Command)
                -> Result<()>
{
    match command {
        approvals::Command::List(c) => list(sq, c),
        approvals::Command::Update(c) => update(sq, c),
    }
}

fn list(sq: Sq, cmd: approvals::ListCommand) -> Result<()> {
    let o = &mut std::io::stdout();

    let store = sq.cert_store_or_else()?;

    let cert =
        sq.resolve_cert(&cmd.cert, TrustThreshold::Full)?.0;
    let vcert = cert.with_policy(sq.policy, sq.time)?;
    let userids = cmd.userids.resolve(&vcert)?;

    // resolve returns ResolvedUserIDs, which contain UserIDs, but we
    // need ValidUserIDAmalgamations.
    let all = userids.is_empty();
    let mut designated_userids = BTreeSet::from_iter(
        userids.into_iter().map(|u| u.userid().clone()));
    let mut pending = 0;
    for uid in vcert.userids() {
        if ! all && ! designated_userids.remove(uid.userid()) {
            continue;
        }

        wwriteln!(stream=o,
                  initial_indent = " - ", "{}",
                  ui::Safe(uid.userid()));

        let approved =
            uid.approved_certifications().collect::<BTreeSet<_>>();

        let mut any = false;
        for c in uid.certifications() {
            // Ignore non-exportable certifications.
            if c.exportable().is_err() {
                sq.info(format_args!(
                    "Ignoring non-exportable certification from {} on {}.",
                    c.get_issuers()
                        .into_iter()
                        .next()
                        .map(|kh| kh.to_string())
                        .unwrap_or_else(|| "unknown certificate".to_string()),
                    ui::Safe(uid.userid())));
                continue;
            }

            let approved = approved.contains(c);
            if ! approved {
                pending += 1;
            }

            if approved == cmd.pending {
                // It's approved and we want pending, or it's pending
                // and we want approved.
                continue;
            }

            // Verify certifications by looking up the issuing cert.
            let mut issuer = None;
            let mut err = None;
            for i in c.get_issuers().into_iter()
                .filter_map(|i| store.lookup_by_cert(&i).ok()
                            .map(IntoIterator::into_iter))
                .flatten()
            {
                match c.verify_signature(&i.primary_key()) {
                    Ok(_) => issuer = Some(i),
                    Err(e) => err = Some(e),
                }
            }

            // If the certificate should not be exported, we don't
            // approve the certification.
            if let Some(Ok(i)) = issuer.as_ref().map(|i| i.to_cert()) {
                if ! i.exportable() {
                    sq.info(format_args!(
                        "Ignoring certification from non-exportable \
                         certificate {} on {}.",
                        i.fingerprint(), ui::Safe(uid.userid())));
                    continue;
                }
                if i.primary_key().key().creation_time() == ca_creation_time() {
                    sq.info(format_args!(
                        "Ignoring certification from local shadow CA \
                         {} on {}.",
                        i.fingerprint(), ui::Safe(uid.userid())));
                    continue;
                }
            }

            wwriteln!(stream=o,
                      initial_indent = "   - ", "{}{}: {}",
                      issuer.as_ref()
                      .map(|c| format!("{} ", c.fingerprint()))
                      .unwrap_or_else(|| "".into()),
                      issuer.as_ref()
                      .and_then(|i| Some(sq.best_userid(i.to_cert().ok()?, true)
                                         .display().to_string()))
                      .or(c.get_issuers().into_iter().next()
                          .map(|h| h.to_string()))
                      .unwrap_or_else(|| "no issuer information".into()),
                      if issuer.is_none() {
                          if let Some(e) = err {
                              e.to_string()
                          } else {
                              "issuer cert not found".into()
                          }
                      } else if approved {
                          "approved".into()
                      } else {
                          "unapproved".into()
                      });
            any = true;
        }

        if ! any {
            wwriteln!(stream=o,
                      initial_indent = "   - ", "no {} certifications",
                      if cmd.pending {
                          "unapproved"
                      } else {
                          "approved"
                      });
        }
    }
    assert!(designated_userids.is_empty());

    if ! cmd.pending && pending > 0 {
        wwriteln!(stream=o,
                  "{} certifications are pending approval.  Using `--pending` \
                   to see them.",
                  pending);
    }

    Ok(())
}

fn update(
    sq: Sq,
    command: cli::key::approvals::UpdateCommand,
) -> Result<()> {
    let store = sq.cert_store_or_else()?;

    let key = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;
    let vcert = key.with_policy(sq.policy, sq.time)?;
    let userids = command.userids.resolve(&vcert)?;

    // Lookup any explicitly goodlisted certifiers.  We need these to
    // verify the certifications.
    let mut add_by = Vec::new();
    for i in &command.add_by {
        add_by.append(&mut store.lookup_by_cert(i)?);
    }

    // If we want to authenticate, prepare the authentication network.
    let network_threshold = command.add_authenticated.then_some(
        (wot::NetworkBuilder::rooted(store, &*sq.trust_roots()).build(),
         sequoia_wot::FULLY_TRUSTED));

    // Get a signer.
    let mut pk_signer = sq.get_primary_key(&key, None)?;

    // Now, create new approval signatures.
    let mut approval_signatures = Vec::new();

    // resolve returns ResolvedUserIDs, which contain UserIDs, but we
    // need ValidUserIDAmalgamations.
    let all = userids.is_empty();
    let mut designated_userids = BTreeSet::from_iter(
        userids.into_iter().map(|u| u.userid().clone()));
    let mut removed = 0;
    let mut added = 0;
    for uid in vcert.userids() {
        if ! all && ! designated_userids.remove(uid.userid()) {
            continue;
        }

        weprintln!(initial_indent = " - ", "{}",
                   ui::Safe(uid.userid()));

        let previously_approved =
            uid.approved_certifications().collect::<BTreeSet<_>>();

        // Start from scratch or from the current set?
        let mut next_approved = if command.remove_all {
            Default::default()
        } else {
            previously_approved.clone()
        };

        // Selectively remove approvals.
        next_approved.retain(|s| ! s.get_issuers().iter().any(
            // Quadratic, but how bad can it be...?
            |i| command.remove_by.iter().any(|j| i.aliases(j))));

        // Selectively add approvals.
        let next_approved_cloned = next_approved.clone();
        for sig in uid.certifications()
            // Don't consider those that we already approved.
            .filter(|s| ! next_approved_cloned.contains(s))
        {
            // Ignore non-exportable certifications.
            if sig.exportable().is_err() {
                sq.info(format_args!(
                    "Ignoring non-exportable certification from {} on {}.",
                    sig.get_issuers()
                        .into_iter()
                        .next()
                        .map(|kh| kh.to_string())
                        .unwrap_or_else(|| "unknown certificate".to_string()),
                    ui::Safe(uid.userid())));
                continue;
            }

            // Try and get the issuer's certificate.
            let mut issuer = None;
            let mut err = None;
            for i in sig.get_issuers().into_iter()
                .filter_map(|i| store.lookup_by_cert(&i).ok()
                            .map(IntoIterator::into_iter))
                .flatten()
            {
                match sig.verify_signature(&i.primary_key()) {
                    Ok(_) => {
                        issuer = Some(i)
                    }
                    Err(e) => err = Some((i.fingerprint(), e)),
                }
            }

            if issuer.is_none() {
                if let Some((fpr, err)) = err {
                    // We have the alleged signer, but we couldn't
                    // verify the certification.  It's bad; silently
                    // ignore it.
                    sq.info(format_args!(
                        "Ignoring invalid certification from {}: {}",
                        fpr, err));
                    continue;
                }
            }

            // Convert it from a lazy cert to a cert.
            let issuer = if let Some(Ok(i))
                = issuer.as_ref().map(|i| i.to_cert())
            {
                Some(i)
            } else {
                None
            };

            // If the certificate should not be exported, we don't
            // approve the certification.
            if let Some(i) = issuer.as_ref() {
                if ! i.exportable() {
                    sq.info(format_args!(
                        "Ignoring certification from non-exportable \
                         certificate {} on {}.",
                        i.fingerprint(), ui::Safe(uid.userid())));
                    continue;
                }
                if i.primary_key().key().creation_time() == ca_creation_time() {
                    sq.info(format_args!(
                        "Ignoring certification from local shadow CA \
                         {} on {}.",
                        i.fingerprint(), ui::Safe(uid.userid())));
                    continue;
                }
            }

            // Skip if the issuer is in --remove-by.
            if let Some(issuer) = issuer.as_ref() {
                if command.remove_by.iter().any(|j| issuer.key_handle().aliases(j)) {
                    continue;
                }
            } else if ! sig.get_issuers().iter().any(
                // Quadratic, but how bad can it be...?
                |i| command.remove_by.iter().any(|j| i.aliases(j)))
            {
                continue;
            }

            // Add if --add-all is passed.
            if command.add_all {
                next_approved.insert(sig);
                continue;
            }

            // Add if the issuer is in --add-by.
            if let Some(issuer) = issuer.as_ref() {
                if command.add_by.iter().any(|j| issuer.key_handle().aliases(j)) {
                    next_approved.insert(sig);
                    continue;
                }
            } else if let Some(cert) = sig.get_issuers().iter().find_map(
                // Quadratic, but how bad can it be...?
                |i| add_by.iter().find_map(
                    |cert| i.aliases(cert.key_handle()).then_some(cert)))
            {
                if sig.verify_signature(&cert.primary_key()).is_ok() {
                    next_approved.insert(sig);
                }
                continue;
            }

            // Add authenticated certifiers.
            if let Some(issuer) = issuer.as_ref() {
                if let Some((ref network, threshold)) = network_threshold {
                    if issuer.userids().any(
                        |u| network.authenticate(u.userid(),
                                                 issuer.fingerprint(),
                                                 threshold)
                            .amount() >= threshold)
                    {
                        next_approved.insert(sig);
                        continue;
                    }
                }
            }
        }

        let mut any = false;
        for (prev, next, c) in uid.certifications()
            .map(|c| (previously_approved.contains(c),
                      next_approved.contains(c), c))
        {
            // Verify certifications by looking up the issuing cert.
            let mut issuer = None;
            let mut err = None;
            for i in c.get_issuers().into_iter()
                .filter_map(|i| store.lookup_by_cert(&i).ok()
                            .map(IntoIterator::into_iter))
                .flatten()
            {
                match c.verify_signature(&i.primary_key()) {
                    Ok(_) => issuer = Some(i),
                    Err(e) => err = Some(e),
                }
            }

            if ! prev && next {
                added += 1;
            }
            if prev && ! next {
                removed += 1;
            }

            weprintln!(initial_indent = "  ", "{} {}{}: {}",
                       match (prev, next) {
                           (false, false) => '.',
                           (true, false) => '-',
                           (false, true) => '+',
                           (true, true) => '=',
                       },
                       issuer.as_ref()
                       .map(|c| format!("{} ", c.fingerprint()))
                       .unwrap_or_else(|| "".into()),
                       issuer.as_ref()
                       .and_then(|i| Some(sq.best_userid(i.to_cert().ok()?, true)
                                          .display().to_string()))
                       .or(c.get_issuers().into_iter().next()
                           .map(|h| h.to_string()))
                       .unwrap_or_else(|| "no issuer information".into()),
                       if issuer.is_none() {
                           if let Some(e) = err {
                               e.to_string()
                           } else {
                               "issuer cert not found".into()
                           }
                       } else if next {
                           "approved".into()
                       } else if prev {
                           "previously approved".into()
                       } else {
                           "unapproved".into()
                       });
            any = true;
        }

        if ! any {
            weprintln!("    no certifications");
        }

        approval_signatures.append(&mut uid.approve_of_certifications(
            &mut pk_signer,
            next_approved.into_iter(),
        )?);
    }
    assert!(designated_userids.is_empty());

    match (added, removed) {
        (1, 1) => {
            weprintln!("1 new approval, 1 approval retracted");
        }
        (added, 1) => {
            weprintln!("{} new approvals, 1 approval retracted",
                       added);
        }
        (1, removed) => {
            weprintln!("1 new approval, {} approvals retracted",
                       removed);
        }
        (added, removed) => {
            weprintln!("{} new approvals, {} approvals retracted",
                       added, removed);
        }
    }

    // Finally, add the new signatures.
    let key = key.insert_packets(approval_signatures)?.0;

    if let Some(sink) = command.output {
        let path = sink.path().map(Clone::clone);
        let mut output = sink.for_secrets().create_safe(&sq)?;
        if false {
            key.as_tsk().serialize(&mut output)?;
        } else {
            key.as_tsk().armored().serialize(&mut output)?;
        }

        if let Some(path) = path {
            sq.hint(format_args!(
                "Updated key written to {}.  \
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
        let fipr = key.fingerprint();
        if let Err(err) = sq.import_cert(key) {
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
