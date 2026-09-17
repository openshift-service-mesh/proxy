use std::cell::RefCell;
use std::cmp::Ordering;

use sequoia_openpgp as openpgp;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::policy::HashAlgoSecurity;
use openpgp::policy::Policy;

use crate::Sq;
use crate::cli::pki::vouch::list;
use crate::common::ui;
use crate::sq::TrustThreshold;

const TRACE: bool = false;

pub fn list(sq: Sq, c: list::Command)
    -> Result<()>
{
    tracer!(TRACE, "pki::vouch::list");

    // Optional certifier.
    let (certifier, error) =
        sq.resolve_certs(&c.certifier, TrustThreshold::Full)?;
    assert!(certifier.len() <= 1);
    assert!(error.len() <= 1);
    let certifier = certifier.into_iter().next().map(RefCell::new);

    if let Some(error) = error.into_iter().next() {
        return Err(error);
    }

    // Optional target cert.
    let (target_cert, error) = sq.resolve_certs(&c.cert, TrustThreshold::Full)?;
    assert!(target_cert.len() <= 1);
    assert!(error.len() <= 1);
    if let Some(error) = error.into_iter().next() {
        return Err(error);
    }
    let target_cert = target_cert.into_iter().next().map(RefCell::new);

    let mut candidates = crate::common::pki::list::list_certifications(
        &sq, certifier, target_cert)?;

    let o = &mut std::io::stdout();

    t!("Have {} possible certifications", candidates.len());
    candidates.sort_by(
        |(a_certifier, a_cert, a_userid, a_certification),
         (b_certifier, b_cert, b_userid, b_certification)|
        {
            match (a_certifier.key_handle(), b_certifier.key_handle()) {
                (KeyHandle::Fingerprint(a), KeyHandle::Fingerprint(b)) => {
                    a.cmp(&b)
                }
                (KeyHandle::Fingerprint(_), KeyHandle::KeyID(_)) => {
                    Ordering::Greater
                }
                (KeyHandle::KeyID(_), KeyHandle::Fingerprint(_)) => {
                    Ordering::Less
                }
                (KeyHandle::KeyID(a), KeyHandle::KeyID(b)) => {
                    a.cmp(&b)
                }
            }
                .then_with(|| {
                    a_cert.borrow().fingerprint()
                        .cmp(&b_cert.borrow().fingerprint())
                })
                .then_with(|| {
                    a_userid.cmp(&b_userid)
                })
                .then_with(|| {
                    a_certification.signature_creation_time().cmp(
                        &b_certification.signature_creation_time())
                        // Newest first.
                        .reverse()
                })
                .then_with(|| {
                    // Break ties deterministically using the MPIs.
                    a_certification.mpis().cmp(
                        &b_certification.mpis())
                })
        });

    let mut first = true;
    let mut current_certifier = None;
    for (certifier, cert, userid, certification) in candidates.into_iter() {
        let cert = cert.borrow();

        let invalid = if let Some(certifier) = certifier.cert() {
            if let Err(err) = certification.verify_userid_binding(
                certifier.primary_key().key(),
                cert.primary_key().key(),
                &userid)
            {
                // Invalid signature.
                t!("Certification by {} on {}, {} is invalid: {}",
                   certifier.key_handle(),
                   cert.fingerprint(),
                   String::from_utf8_lossy(userid.value()),
                   err);

                Some(err)
            } else {
                // Check the policy.
                if let Err(err) = sq.policy.signature(
                    &certification,
                    HashAlgoSecurity::CollisionResistance)
                {
                    Some(err)
                } else {
                    None
                }
            }
        } else {
            Some(anyhow::anyhow!("Cannot check signature: missing certificate"))
        };

        if first {
            first = false;
        } else {
            wwriteln!(o, "");
        }

        if current_certifier != Some(certifier.key_handle()) {
            current_certifier = Some(certifier.key_handle());

            wwriteln!(o, " - Certifier:");
            if let Some(certifier) = certifier.cert() {
                ui::emit_cert_indent(o, "  ", &sq, &certifier)?;
            } else {
                ui::emit_cert_key_handle_userid_str_indent(
                    o, "  ",
                    &certifier.key_handle(), "<unknown: missing certificate>")?;
            }
            wwriteln!(o, "");
        }

        if certifier.cert().is_some() {
            if let Some(ref err) = invalid {
                wwriteln!(o, "   - Invalid certification: {}",
                          crate::one_line_error_chain(err));
            } else {
                wwriteln!(o, "   - Certified the binding:");
            }
        } else {
            wwriteln!(o, "   - Unchecked and possible invalid certification \
                          of the binding:");
        }
        ui::emit_cert_userid_indent(o, "    ", &cert, &userid)?;

        wwriteln!(o, "");
        let indent = "      ";
        crate::common::pki::list::summarize_certification(
            o, indent, &certification, false)?;
    }

    Ok(())
}
