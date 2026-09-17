use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Packet;
use openpgp::Result;
use openpgp::crypto;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;
use openpgp::types::RevocationStatus;

use crate::Sq;
use crate::common::pki::certify::diff_certification;
use crate::common::pki::list::summarize_certification;
use crate::common::ui::emit_cert_userid_indent;
use crate::common::ui;

const TRACE: bool = false;

// Concatenate two strings.
fn strcat<'a>(a: &'a str, b: &'a str) -> Cow<'a, str> {
    if a.is_empty() {
        Cow::Borrowed(b)
    } else if b.is_empty() {
        Cow::Borrowed(a)
    } else {
        Cow::Owned(format!("{}{}", a, b))
    }
}

/// Replays the active certifications made by source using target.
///
/// If target already certified a binding, and the active
/// certification has the same parameters as the certification being
/// replayed, no new certification is created.
///
/// Certifications are also not replayed if a binding is invalid (the
/// certificate is not valid according to the policy, is revoked, or
/// not live, or the user ID is revoked).
///
/// If `certs` is provided, only certifications of the specified
/// certificates are replyed.  Otherwise, all certificates are
/// considered.
pub fn replay(sq: &Sq, o: &mut dyn std::io::Write, indent: &str,
              source: RefCell<Cert>,
              target: &Cert,
              target_signer: Option<&mut Box<dyn crypto::Signer + Send + Sync>>,
              certs: Option<&[RefCell<Cert>]>)
    -> Result<Vec<Cert>>
{
    tracer!(TRACE, "pki::replay");

    let source_kh = source.borrow().key_handle();
    let source_pk = source.borrow().primary_key().key().clone();

    let target_pk = target.primary_key().key().clone();

    // Get the signer to certify with (and fail early if its not
    // available).
    let mut signer_;
    let signer = if let Some(signer) = target_signer {
        signer
    } else {
        signer_ = sq.get_certification_key(target, None)?;
        &mut signer_
    };

    // Get all of the certifications that the source made.
    let certifications = if let Some(certs) = certs {
        let mut results = Vec::new();
        for cert in certs {
            results.append(
                &mut crate::common::pki::list::list_certifications(
                    &sq, Some(RefCell::clone(&source)),
                    Some(RefCell::clone(cert)))?);
        }
        results
    } else {
        crate::common::pki::list::list_certifications(
            &sq, Some(RefCell::clone(&source)), None)?
    };

    // Drop the certifier (its always source) and convert the
    // certifications to a vector so that we can merge them.
    let mut certifications = certifications
        .into_iter()
        .map(|(certifier, cert, userid, certification)| {
            assert_eq!(certifier.key_handle(), source_kh);

            (cert, userid, vec![ certification ])
        })
        .collect::<Vec<_>>();

    // Sort by certificate and user ID, then merge.
    certifications.sort_by(
        |(a_cert, a_userid, _a_certifications),
         (b_cert, b_userid, _b_certifications)|
        {
            a_cert.borrow().fingerprint()
                .cmp(&b_cert.borrow().fingerprint())
                .then_with(|| {
                    a_userid.cmp(&b_userid)
                })
        });
    certifications.dedup_by(
        |(a_cert, a_userid, a_certifications),
         (b_cert, b_userid, b_certifications)| {
             if a_cert.borrow().fingerprint() == b_cert.borrow().fingerprint()
                 && a_userid == b_userid
             {
                 b_certifications.append(a_certifications);
                 true
             } else {
                 false
             }
        });

    // The signed certificates.
    let mut results: BTreeMap<Fingerprint, Cert> = BTreeMap::new();

    'next_binding: for (cert, userid, mut certifications)
        in certifications.into_iter()
    {
        let cert = cert.borrow();

        if cert.fingerprint() == target.fingerprint() {
            // `source` certified `target`.  `target` does not need to
            // certify itself.
            continue;
        }

        t!("{}: {}, {} certifications",
           cert.fingerprint(),
           String::from_utf8_lossy(userid.value()),
           certifications.len());

        wwriteln!(stream = o, indent = indent,
                  "Considering the source certificate's certification \
                   of the binding:");
        emit_cert_userid_indent(o, indent, &cert, &userid)?;

        // Skip if cert is invalid, expired, or revoked, or
        // user ID is revoked.
        let vc = match cert.with_policy(sq.policy, sq.time) {
            Ok(vc) => vc,
            Err(err) => {
                wwriteln!(stream = o,
                          indent = strcat(indent, "  "),
                          "Certificate is not valid according to the \
                           policy: {}",
                          crate::one_line_error_chain(err));
                continue;
            }
        };

        if let RevocationStatus::Revoked(sigs) = vc.revocation_status() {
            let sig = sigs.into_iter().next().expect("have one");
            if let Some((reason, message)) = sig.reason_for_revocation()
            {
                wwriteln!(stream = o,
                          initial_indent = strcat(indent, "  "),
                          "Certificate was revoked: {}, {}",
                          reason, ui::Safe(message));
            } else {
                wwriteln!(stream = o,
                          initial_indent = strcat(indent, "  - "),
                          "Certificate was revoked");
            }

            continue;
        }

        if let Err(err) = vc.alive() {
            wwriteln!(stream = o,
                      initial_indent = strcat(indent, "  "),
                      "Certificate is not live: {}", err);
            continue;
        }

        let ua = cert.userids().find(|u| u.userid() == &userid);
        if let Some(ua) = ua.as_ref() {
            if let RevocationStatus::Revoked(sigs)
                = ua.revocation_status(sq.policy, sq.time)
            {
                let sig = sigs.into_iter().next().expect("have one");
                if let Some((reason, message)) = sig.reason_for_revocation()
                {
                    wwriteln!(stream = o,
                              initial_indent = strcat(indent, "  "),
                              "User ID was revoked: {}, {}",
                              reason, ui::Safe(message));
                } else {
                    wwriteln!(stream = o,
                              initial_indent = strcat(indent, "  - "),
                              "User ID was revoked");
                }

                continue;
            }
        }

        certifications.sort_by(|a, b| {
            a.signature_creation_time().cmp(&b.signature_creation_time())
                // Newest first.
                .reverse()
                .then_with(|| {
                    // Break ties deterministically using the MPIs.
                    a.mpis().cmp(&b.mpis())
                })
        });

        let mut reasons = Vec::new();
        let mut good = false;

        // Iterate over the certifications created by the source.
        for certification in certifications.into_iter() {
            let ct = if let Some(ct) = certification.signature_creation_time() {
                ct
            } else {
                // No creation time => invalid signature.
                t!("Ignoring invalid certification: \
                    no signature creation time.");
                continue;
            };
            let ct_str = chrono::DateTime::<chrono::Utc>::from(ct)
                .format("%Y‑%m‑%d %H:%M:%S")
                .to_string();

            if let Err(err) = certification.signature_alive(sq.time, None) {
                t!("Not considering certification made at {}: {}",
                   ct_str,
                   err);
                reasons.push((ct_str, err));
            } else if let Err(err) = sq.policy.signature(
                &certification,
                HashAlgoSecurity::CollisionResistance)
            {
                // Policy violation.
                t!("Certification made at {} by {} on {}, {} is invalid: {}",
                   ct_str,
                   source_kh,
                   cert.fingerprint(),
                   String::from_utf8_lossy(userid.value()),
                   err);

                reasons.push((ct_str, err));
            } else if let Err(err) = certification.verify_userid_binding(
                &source_pk, cert.primary_key().key(), &userid)
            {
                // Invalid signature.
                t!("Certification made at {} by {} on {}, {} is invalid: {}",
                   ct_str,
                   source_pk,
                   cert.fingerprint(),
                   String::from_utf8_lossy(userid.value()),
                   err);

                reasons.push((ct_str, err));
            } else {
                wwriteln!(stream=o,
                          indent=strcat(indent, "  "),
                          "Source certificate's active certification:");
                summarize_certification(o, &strcat(indent, "  "),
                                        &certification, false)?;

                // Check that the target hasn't already certified the
                // target with the same parameters.
                let builder: SignatureBuilder = certification.into();

                if let Some(ua) = ua.as_ref() {
                    for preexisting in ua.active_certifications_by_key(
                        sq.policy, sq.time, &target_pk)
                    {
                        let preexisting_ct = if let Some(ct)
                            = preexisting.signature_creation_time()
                        {
                            ct
                        } else {
                            // No signature creation time: invalid.
                            continue;
                        };

                        // When checking for differences, use the
                        // preexisting creation time and not `sq.time`
                        // as we don't want the creation time or the
                        // expiration time to flag a difference.
                        let mut trace: Vec<u8> = Vec::new();
                        let mut sink = std::io::sink();
                        if ! diff_certification(
                            if TRACE { &mut trace } else { &mut sink },
                            preexisting, &builder, preexisting_ct)
                        {
                            let p_ct = preexisting.signature_creation_time()
                                .expect("valid signature");
                            let p_ct_str = chrono::DateTime::<chrono::Utc>::from(p_ct)
                                .format("%Y‑%m‑%d %H:%M:%S")
                                .to_string();
                            wwriteln!(stream = o,
                                      initial_indent = strcat(indent, "  "),
                                      "Skipping: the target already \
                                       certified the binding with the same \
                                       parameters at {}.",
                                      p_ct_str);
                            t!("Differences: {}",
                               String::from_utf8_lossy(&trace));
                            continue 'next_binding;
                        }
                        t!("Differences: {}",
                           String::from_utf8_lossy(&trace));
                    }
                }

                // The expiration is not an absolute time, but a
                // period that is relative to the creation time.  This
                // means that if the new certification's creation time
                // is a year later, and we leave the expiration period
                // as is, the new certification will expire a year
                // later.
                //
                // Should we adjust the expiration period?  By using
                // this command, the user is explicitly opting in to
                // refreshing the certification.  So, we leave it as
                // is.

                let builder = builder.set_signature_creation_time(sq.time)?;

                let sig = builder.sign_userid_binding(
                    signer,
                    cert.primary_key().key(),
                    &userid)
                    .with_context(|| {
                        format!("Creating certification for {}, {}",
                                cert.fingerprint(),
                                ui::Safe(String::from_utf8_lossy(userid.value())))
                    })?;

                let packets = [
                    Packet::from(userid.clone()),
                    sig.into(),
                ];

                match results.entry(cert.fingerprint()) {
                    Entry::Occupied(oe) => {
                        let c = oe.into_mut();
                        *c = c.clone().insert_packets(packets.into_iter())?.0;
                    }
                    Entry::Vacant(vc) => {
                        vc.insert(cert.clone()
                                  .insert_packets(packets.into_iter())?.0);
                    }
                }

                wwriteln!(stream = o, indent = strcat(indent, "  "),
                          "Replayed certification.");

                good = true;
                break;
            }
        }

        if ! good {
            wwriteln!(stream = o, indent = strcat(indent, "  "),
                      "Warning: {} certified {}, {} but none of the \
                       certifications are usable:",
                      source_kh,
                      cert.fingerprint(),
                      String::from_utf8_lossy(userid.value()));
            for (ct, err) in reasons.into_iter() {
                wwriteln!(stream = o, indent = strcat(indent, "  "),
                          "Certification made at {} is invalid: {}",
                          ct, crate::one_line_error_chain(err));
            }
        }
    }

    if results.is_empty() {
        wwriteln!(stream=o, indent = indent, "Nothing to replay");
    }

    return Ok(results.into_values().collect());
}
