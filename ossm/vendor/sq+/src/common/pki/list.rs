use std::cell::Ref;
use std::cell::RefCell;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::packet::Signature;
use openpgp::packet::Tag;
use openpgp::packet::UserID;
use openpgp::types::KeyFlags;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::Result;
use crate::Sq;
use crate::common::key_handle_dealias;
use crate::common::ui;

const TRACE: bool = false;

pub enum CertOrKeyHandle {
    Cert(RefCell<Cert>),
    KeyHandle(KeyHandle),
}

impl CertOrKeyHandle {
    pub fn key_handle(&self) -> KeyHandle {
        match self {
            CertOrKeyHandle::Cert(cert) => cert.borrow().key_handle(),
            CertOrKeyHandle::KeyHandle(kh) => kh.clone(),
        }
    }

    pub fn cert(&self) -> Option<Ref<Cert>> {
        match self {
            CertOrKeyHandle::Cert(cert) => Some(cert.borrow()),
            CertOrKeyHandle::KeyHandle(_) => None,
        }
    }
}

impl From<RefCell<Cert>> for CertOrKeyHandle {
    fn from(cert: RefCell<Cert>) -> CertOrKeyHandle {
        CertOrKeyHandle::Cert(cert)
    }
}

impl From<&KeyHandle> for CertOrKeyHandle {
    fn from(kh: &KeyHandle) -> CertOrKeyHandle {
        CertOrKeyHandle::KeyHandle(kh.clone())
    }
}

impl From<KeyHandle> for CertOrKeyHandle {
    fn from(kh: KeyHandle) -> CertOrKeyHandle {
        CertOrKeyHandle::KeyHandle(kh)
    }
}

/// Returns the certifications made by `certifier` if not `None` and
/// the certifications of `target_cert`, if not `None`.
///
/// If both `certifier` and `target_cert` are provided, returns the
/// intersection.
///
/// At least one of `certifier` and `target_cert` must be provided.
///
/// This returns all possible certificates.  It does not check their
/// legitimacy.
pub fn list_certifications(sq: &Sq,
                           certifier: Option<RefCell<Cert>>,
                           target_cert: Option<RefCell<Cert>>)
    -> Result<Vec<(CertOrKeyHandle, RefCell<Cert>, UserID, Signature)>>
{
    tracer!(TRACE, "list_certifications");

    let cert_store = sq.cert_store_or_else()?;

    // Certifier, target cert, target user ID, certification.
    let mut candidates: Vec<(CertOrKeyHandle, RefCell<Cert>, UserID, Signature)>
        = Vec::new();

    if let Some(target_cert) = target_cert {
        // The user wants to know who certified a particular certificate.

        let target_cert_fpr = target_cert.borrow().fingerprint();

        // Get all of the certifications made on the target cert.
        for ua in target_cert.borrow().userids() {
            for certification in ua.certifications() {
                let issuers = certification.get_issuers();

                if let Some(ref certifier) = certifier {
                    // The user wants to know about a specific certifier.

                    let certifier_kh = certifier.borrow().key_handle();

                    if issuers.into_iter().any(|kh| kh.aliases(&certifier_kh)) {
                        candidates.push(
                            (RefCell::clone(certifier).into(),
                             RefCell::clone(&target_cert).into(),
                             ua.userid().clone(),
                             certification.clone()));
                    }
                } else {
                    // The user wants to know about any certifier.

                    for kh in key_handle_dealias(&issuers) {
                        if let Ok(certifiers)
                            = sq.lookup(std::iter::once(&kh),
                                        Some(KeyFlags::certification()),
                                        false, true)
                        {
                            for certifier in certifiers.into_iter() {
                                t!("  Possible certification of {}, {:?} by {}, {}",
                                   target_cert_fpr,
                                   String::from_utf8_lossy(ua.userid().value()),
                                   certifier.fingerprint(),
                                   sq.best_userid(&certifier, true).display());
                                candidates.push(
                                    (RefCell::new(certifier).into(),
                                     RefCell::clone(&target_cert),
                                     ua.userid().clone(),
                                     certification.clone()));
                            }
                        } else {
                            t!("  Possible certification by {}, but we can't \
                                check it as we don't have the certificate",
                               kh);
                            candidates.push(
                                (kh.into(),
                                 RefCell::clone(&target_cert),
                                 ua.userid().clone(),
                                 certification.clone()));
                        }
                    }
                }
            }
        }
    } else if let Some(certifier) = certifier {
        let certifier_fpr = certifier.borrow().fingerprint();
        let certifier_kh = KeyHandle::from(&certifier_fpr);

        // The user wants to know what certificates `certifier`
        // certified.  Since certifications are stored alongside the
        // certified certificate, we have to iterate over all of the
        // certificates in the store.
        //
        // To avoid fully parsing certificates, which is expensive, we
        // first do a lightweight check with the `RawCert`: if the
        // `RawCert` doesn't contain a signature packet with
        // `certifier` as the issuer, then we can skip it.

        // XXX: We're iterating over all certificates in the
        // certificate store.  Consider parallelizing this.
        for cert in cert_store.certs() {
            t!("Considering {}, {}",
               cert.fingerprint(),
               cert.userids().next()
                   .map(|userid| {
                       String::from_utf8_lossy(userid.value()).to_string()
                   })
                   .unwrap_or_else(|| "<no userids>".to_string()));
            if cert.userids().next().is_none() {
                // The certificate has no user IDs.  Thus, it can't
                // have been certified.
                t!("  Skipping: no user IDs.");
                continue;
            }
            if cert.fingerprint() == certifier_fpr {
                // We can't make a third-party certification on
                // ourself; that's a first-party certification!
                t!("  Skipping: is certifier.");
                continue;
            }

            if let Some(cert) = cert.raw_cert() {
                let mut possible_certification = false;
                for raw_packet in cert.packets() {
                    let sig = if raw_packet.tag() == Tag::Signature {
                        match Packet::try_from(raw_packet) {
                            Ok(packet) => {
                                if let Packet::Signature(sig) = packet {
                                    sig
                                } else {
                                    unreachable!();
                                }
                            }
                            Err(err) => {
                                // Invalid packet.
                                t!("  Invalid signature: {}.", err);
                                continue;
                            }
                        }
                    } else {
                        // Not a signature packet.
                        continue;
                    };

                    if ! matches!(
                        sig.typ(),
                        SignatureType::GenericCertification
                            | SignatureType::PersonaCertification
                            | SignatureType::CasualCertification
                            | SignatureType::PositiveCertification)
                    {
                        // Not a certification.
                        continue;
                    }

                    // Check that an issuer packet names the
                    // certifier.
                    let issuers = sig.get_issuers();
                    if issuers.into_iter().any(|issuer| {
                        issuer.aliases(
                            KeyHandle::from(cert.fingerprint()))
                    })
                    {
                        t!("  Have a possible certification");
                        possible_certification = true;
                        break;
                    }
                }

                if ! possible_certification {
                    t!("  Skipping: No certifications found.");
                    continue;
                }
            }

            // Add any certifications to the candidates list.
            match cert.to_cert() {
                Ok(cert) => {
                    let cert_cell: RefCell<Cert> = RefCell::new(cert.clone());
                    let cert = cert_cell.borrow();
                    for ua in cert.userids() {
                        for certification in ua.certifications() {
                            let issuers = certification.get_issuers();
                            if issuers.into_iter().any(|issuer| {
                                issuer.aliases(&certifier_kh)
                            })
                            {
                                t!("  Possible certification of {}, {:?}",
                                   cert.fingerprint(),
                                   String::from_utf8_lossy(ua.userid().value()));
                                candidates.push(
                                    (RefCell::clone(&certifier).into(),
                                     RefCell::clone(&cert_cell).into(),
                                     ua.userid().clone(),
                                     certification.clone()));
                            }
                        }
                    }
                }
                Err(err) => {
                    // Silently ignore the parse error.
                    t!("Error parsing {}: {}", cert.fingerprint(), err);
                    continue;
                }
            }
        }
    } else {
        // The user must supply either --certifier or --cert (or
        // both).
        return Err(clap::Error::raw(
            clap::error::ErrorKind::MissingRequiredArgument,
            "Either a certifier (using, e.g., --certifier) \
             or a target certificate (using, e.g., --cert) \
             must be supplied").into());
    }

    Ok(candidates)
}

/// `link` is whether "link" should be used to talk about the
/// certification or "certification".
pub fn summarize_certification(o: &mut dyn std::io::Write,
                               indent: &str,
                               certification: &Signature,
                               link: bool)
    -> Result<()>
{
    let (link, linked) = if link {
        ("link", "linked")
    } else {
        ("certification", "certified")
    };

    let indent = &format!("{} - ", indent)[..];

    if let Some(t) = certification.signature_creation_time() {
        wwriteln!(stream=o, initial_indent=indent,
                  "created at {}",
                  chrono::DateTime::<chrono::Utc>::from(t)
                  .format("%Y‑%m‑%d %H:%M:%S"));
    } else {
        wwriteln!(stream=o, initial_indent=indent,
                  "creation time missing");
    }

    let (depth, amount) = certification.trust_signature()
        .unwrap_or((0, sequoia_wot::FULLY_TRUSTED as u8));

    if amount == 0 {
        wwriteln!(stream=o, initial_indent=indent,
                  "{} was retracted", link);
    } else {
        let mut regex: Vec<_> = certification.regular_expressions()
            .map(|re| ui::Safe(re).to_string())
            .collect();
        regex.sort();
        regex.dedup();

        if depth > 0 {
            if amount == sequoia_wot::FULLY_TRUSTED as u8
                && regex.is_empty()
            {
                wwriteln!(stream=o, initial_indent=indent,
                          "{} as a fully trusted CA", linked);
            } else {
                wwriteln!(stream=o, initial_indent=indent,
                          "{} as a partially trusted CA", linked);
            }
        }

        if let Some(e) = certification.signature_expiration_time() {
            wwriteln!(stream=o, initial_indent=indent,
                      "expiration: {}",
                      chrono::DateTime::<chrono::Utc>::from(e)
                      .format("%Y‑%m‑%d"));
        }

        if depth != 0 && depth != 255 {
            wwriteln!(stream=o, initial_indent=indent,
                      "trust depth: {}", depth);
        }

        if amount != sequoia_wot::FULLY_TRUSTED as u8 {
            wwriteln!(stream=o, initial_indent=indent,
                      "trust amount: {}", amount);
        }

        if ! regex.is_empty() {
            wwriteln!(stream=o, initial_indent=indent,
                      "regular expressions: {}", regex.join("; "));
        }
    }

    Ok(())
}
