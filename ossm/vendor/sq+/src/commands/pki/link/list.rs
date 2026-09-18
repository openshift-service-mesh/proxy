use std::collections::BTreeMap;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::KeyHandle;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;

use crate::Result;
use crate::Sq;
use crate::cli::pki::link;
use crate::cli::types::cert_designator;
use crate::commands::active_certification;
use crate::common::pki::list::summarize_certification;
use crate::common::ui;
use crate::sq::TrustThreshold;

pub fn list(sq: Sq, c: link::ListCommand)
    -> Result<()>
{
    tracer!(TRACE, "sq::pki::link::list");

    let cert_store = sq.cert_store_or_else()?;
    cert_store.prefetch_all();

    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let mut certs = c.certs;

    if let Some(pattern) = c.pattern {
        let mut d = None;
        if let Ok(kh) = pattern.parse::<KeyHandle>() {
            if matches!(kh, KeyHandle::Fingerprint(Fingerprint::Unknown { .. })) {
                let hex = pattern.chars()
                    .map(|c| {
                        if c == ' ' { 0 } else { 1 }
                    })
                    .sum::<usize>();

                if hex >= 16 {
                    weprintln!("Warning: {} looks like a fingerprint or key ID, \
                                but its invalid.  Treating it as a text pattern.",
                               pattern);
                }
            } else {
                d = Some(cert_designator::CertDesignator::Cert(kh));
            }
        };

        certs.push(d.unwrap_or_else(|| {
            cert_designator::CertDesignator::Grep(pattern)
        }));
    }

    let mut active_certifications_cache: BTreeMap<Fingerprint, _>
        = BTreeMap::new();

    let (certs, errors) = if certs.is_empty() {
        (cert_store.certs(), Vec::new())
    } else {
        let (c, e) = sq.resolve_certs_filter(
            &certs, TrustThreshold::Full, &mut |_designator, cert| {
                let userids = cert.userids();
                let cert = cert.to_cert()?;

                let active_certifications = active_certification(
                    &sq, cert, userids,
                    trust_root.primary_key().key().role_as_unspecified());

                if active_certifications.iter().any(|(_userid, certifications)| {
                    certifications.is_some()
                })
                {
                    active_certifications_cache.insert(
                        cert.fingerprint(),
                        active_certifications);
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("{} {} was never linked",
                                        cert.fingerprint(),
                                        sq.best_userid(cert, true).display()))
                }
            })?;
        (Box::new(c.into_iter().map(|c| Arc::new(LazyCert::from(c))))
         as Box<dyn Iterator<Item=Arc<LazyCert<'_>>>>,
         e)
    };

    for error in errors.iter() {
        crate::print_error_chain(error);
    }
    if ! errors.is_empty() {
        return Err(anyhow::anyhow!("Failed to resolve certificates"));
    }

    let o = &mut std::io::stdout();
    let mut dirty = false;

    for cert in certs {
        let cert = if let Ok(cert) = cert.to_cert() {
            cert
        } else {
            // Invalid cert.  Skip it.
            continue;
        };

        let active_certifications = if let Some(ac)
            = active_certifications_cache.remove(&cert.fingerprint())
        {
            ac
        } else {
            let userids = cert.userids().map(|ua| ua.userid().clone());

            active_certification(
                &sq, &cert, userids,
                trust_root.primary_key().key().role_as_unspecified())
        };

        for (userid, certification) in active_certifications
            .into_iter()
            .filter_map(|(user, certification)| {
                if let Some(certification) = certification {
                    Some((user, certification))
                } else {
                    None
                }
            })
        {
            let (depth, _amount) = certification.trust_signature()
                .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

            if c.ca && depth == 0 {
                // Only show CAs.
                continue;
            }

            if dirty {
                wwriteln!(stream=o);
            }
            dirty = true;

            ui::emit_cert_userid(o, &cert, &userid)?;
            let indent = "    ";
            summarize_certification(o, indent, &certification, true)?;
        }
    }

    Ok(())
}
