use std::cmp::Ordering;
use std::io::IsTerminal;
use std::io:: Write;
use std::time::SystemTime;
use std::sync::Arc;

use termcolor::{WriteColor, StandardStream, ColorChoice, ColorSpec, Color};

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::crypto::Signer;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::HashAlgorithm;
use openpgp::types::KeyFlags;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;
use openpgp::types::SymmetricAlgorithm;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::StoreUpdate;

use crate::{
    Sq,
    cli::cert::lint::Command,
    cli::types::cert_designator::CertDesignator,
    commands::FileOrStdout,
    common::ui,
    sq::TrustThreshold,
};

fn update_cert_revocation(sq: &Sq,
                          cert: &Cert, rev: &Signature,
                          reference_time: &SystemTime)
    -> Result<Signature>
{
    assert_eq!(rev.typ(), SignatureType::KeyRevocation);

    let ka = cert.primary_key();
    let pk = ka.key();

    // Derive a signer.
    let mut signer = sq.get_signer(&ka)?;

    let sig = SignatureBuilder::from(rev.clone())
        .set_signature_creation_time(reference_time.clone())?
        .set_hash_algo(HashAlgorithm::SHA256)
        .preserve_signature_creation_time()?
        .sign_direct_key(&mut signer, pk)?;

    Ok(sig)
}

const GOOD_HASHES: &[ HashAlgorithm ] = &[
    HashAlgorithm::SHA256,
    HashAlgorithm::SHA512,
];

// Update the binding signature for ua.
//
// ua is using a weak policy.
fn update_user_id_binding(sq: &Sq,
                          ua: &ValidUserIDAmalgamation,
                          reference_time: &SystemTime)
    -> Result<Signature>
{
    let ka = ua.cert().primary_key();
    let pk = ka.key();

    // Derive a signer.
    let mut signer = sq.get_signer(&ka)?;

    let sym = &[
        SymmetricAlgorithm::AES128,
        SymmetricAlgorithm::AES192,
        SymmetricAlgorithm::AES256,
        SymmetricAlgorithm::Twofish,
        SymmetricAlgorithm::Camellia128,
        SymmetricAlgorithm::Camellia192,
        SymmetricAlgorithm::Camellia256,
    ];

    // Update the signature.
    let sig = ua.binding_signature();
    let sig = SignatureBuilder::from(sig.clone())
        .set_signature_creation_time(reference_time.clone())?
        .set_hash_algo(GOOD_HASHES[0])
        .set_preferred_hash_algorithms(
            sig.preferred_hash_algorithms()
                .unwrap_or(&[ HashAlgorithm::SHA512, HashAlgorithm::SHA256 ])
                .iter()
                .map(|h| h.clone())
                .filter(|a| GOOD_HASHES.contains(&a))
                .collect())?
        .set_preferred_symmetric_algorithms(
            sig.preferred_symmetric_algorithms()
                .unwrap_or(&[
                    SymmetricAlgorithm::AES128,
                    SymmetricAlgorithm::AES256,
                ])
                .iter()
                .map(|h| h.clone())
                .filter(|a| sym.contains(&a))
                .collect())?
        .sign_userid_binding(&mut signer, pk, ua.userid())?;

    // Verify it.
    assert!(sig.verify_userid_binding(signer.public(), pk, ua.userid())
            .is_ok());

    // Make sure the signature is integrated.
    assert!(ua.cert().clone()
        .insert_packets(Packet::from(sig.clone())).unwrap().0
        .into_packets()
        .any(|p| {
            if let Packet::Signature(s) = p {
                s == sig
            } else {
                false
            }
        }));

    Ok(sig)
}

// Update the subkey binding signature for ka.
//
// ka is using a weak policy.
fn update_subkey_binding<P>(sq: &Sq,
                            ka: &ValidSubordinateKeyAmalgamation<P>,
                            reference_time: &SystemTime)
    -> Result<Signature>
    where P: key::KeyParts + Clone
{
    let primary = ka.cert().primary_key();
    let pk = primary.key();

    // Derive a signer.
    let mut signer = sq.get_signer(&primary)?;

    // Update the signature.
    let sig = ka.binding_signature();
    let mut builder = SignatureBuilder::from(sig.clone())
        .set_signature_creation_time(reference_time.clone())?
        .set_hash_algo(HashAlgorithm::SHA256);

    // If there is a valid backsig, recreate it.
    if let Some(backsig) = sig.embedded_signatures()
        .filter(|backsig| {
            (*backsig).clone().verify_primary_key_binding(
                pk,
                ka.key()).is_ok()
        })
        .nth(0)
    {
        // Derive a signer.
        let mut subkey_signer = sq.get_signer(ka.amalgamation())?;

        let backsig = SignatureBuilder::from(backsig.clone())
            .set_signature_creation_time(reference_time.clone())?
            .set_hash_algo(HashAlgorithm::SHA256)
            .sign_primary_key_binding(&mut subkey_signer, pk, ka.key())?;
        builder = builder.set_embedded_signature(backsig)?;
    }

    let sig = builder.sign_subkey_binding(&mut signer, pk, ka.key())?;

    // Verify it.
    assert!(sig.verify_subkey_binding(signer.public(), pk, ka.key())
            .is_ok());

    // Make sure the signature is integrated.
    assert!(ka.cert().clone()
        .insert_packets(Packet::from(sig.clone())).unwrap().0
        .into_packets()
        .any(|p| {
            if let Packet::Signature(s) = p {
                s == sig
            } else {
                false
            }
        }));

    Ok(sig)
}

pub fn lint(sq: Sq, mut args: Command) -> Result<()> {
    // Number of certs that have issues.
    let mut certs_with_issues = 0;
    // Whether we were unable to fix at least one issue.
    let mut unfixed_issue = 0;

    // Standard policy that unconditionally rejects SHA-1: this is
    // where we want to be.
    let mut sp = StandardPolicy::at(sq.policy_as_of);
    sp.reject_hash(HashAlgorithm::SHA1);
    let sp = &sp;

    // A standard policy that also accepts SHA-1.
    let mut sp_sha1 = StandardPolicy::at(sq.policy_as_of);
    sp_sha1.accept_hash(HashAlgorithm::SHA1);
    let sp_sha1 = &sp_sha1;

    // The number of valid and invalid certificates (according to
    // SP+SHA-1).
    let mut certs_valid = 0;
    let mut certs_invalid = 0;

    // Certificates that are revoked.
    let mut certs_revoked = 0;
    let mut certs_with_inadequota_revocations = 0;
    let mut certs_expired = 0;

    // Certificates that are valid and have a valid User ID.
    let mut certs_sp_sha1_userids = 0;
    let mut certs_with_a_sha1_protected_userid = 0;
    let mut certs_with_only_sha1_protected_userids = 0;

    // Subkeys.
    let mut certs_with_subkeys = 0;
    let mut certs_with_a_sha1_protected_binding_sig = 0;
    let mut certs_with_signing_subkeys = 0;
    let mut certs_with_sha1_protected_backsig = 0;

    let reference_time = sq.time;

    // If no inputs are given, read from stdin.
    if args.certs.is_empty() {
        args.certs.designators.push(CertDesignator::Stdin);
    }

    let certs = sq.resolve_certs_or_fail(
        &args.certs, TrustThreshold::Full)?;

    let contains_secrets = certs.iter().any(|c: &Cert| c.is_tsk());

    let mut out = if args.output.is_some()
        || args.certs.iter().any(|d| d.from_file() || d.from_stdin())
    {
        let output = if let Some(output) = args.output {
            if contains_secrets {
                output.for_secrets()
            } else {
                output
            }
        } else {
            FileOrStdout::new(None)
        };

        Some(output.create_pgp_safe(
            &sq, false,
            if contains_secrets {
                armor::Kind::SecretKey
            } else {
                armor::Kind::PublicKey
            })?)
    } else {
        None
    };

    {
        'next_cert: for cert in certs {
            // Whether we found at least one issue.
            let mut found_issue = false;

            macro_rules! diag {
                ($($arg:tt)*) => {{
                    // found_issue may appear to be unused if
                    // diag is immediately followed by a
                    // continue or break.
                    #[allow(unused_assignments)]
                    {
                        if ! found_issue {
                            certs_with_issues += 1;
                            found_issue = true;
                        }
                        if ! sq.quiet() {
                            weprintln!($($arg)*);
                        }
                    }
                }};
            }

            let mut updates: Vec<Signature> = Vec::new();

            macro_rules! next_cert {
                () => {{
                    if updates.len() > 0 {
                        let cert = cert.insert_packets(updates)?.0;
                        if let Some(mut out) = out.as_mut() {
                            cert.as_tsk().serialize(&mut out)?;
                        } else {
                            let fpr = cert.fingerprint();
                            let cert_store = sq.cert_store_or_else()?;
                            cert_store.update(Arc::new(LazyCert::from(cert)))
                                .with_context(|| {
                                    format!("Error importing the {} into cert store",
                                            fpr)
                                })?;
                        }
                    }
                    continue 'next_cert;
                }}
            }

            let sp_vc = cert.with_policy(sp, reference_time);

            let sp_sha1_vc = cert.with_policy(sp_sha1, reference_time);
            if let Err(ref err) = sp_sha1_vc {
                diag!("Certificate {} is not valid under \
                       the standard policy + SHA-1: {}",
                      cert.keyid().to_hex(), err);
                certs_invalid += 1;
                unfixed_issue += 1;
                continue;
            }
            let sp_sha1_vc = sp_sha1_vc.unwrap();

            certs_valid += 1;

            // Check if the certificate is revoked.
            //
            // There are four cases to consider:
            //
            //   1. SHA1 certificate,   SHA1 revocation certificate
            //   2. SHA1 certificate,   SHA256 revocation certificate
            //   3. SHA256 certificate, SHA1 revocation certificate
            //   4. SHA256 certificate, SHA256 revocation certificate
            //
            // When the revocation certificate uses SHA256,
            // there is nothing to do even if something else
            // relies on SHA1: the certificate should be
            // ignore, because it is revoked!
            //
            // In the case that we have a SHA1 certificate and
            // a SHA1 revocation certificate, we also don't
            // have to do anything: either the whole
            // certificate will be considered invalid or
            // implementation accepts SHA1 and it will be
            // considered revoked.
            //
            // So, the only case that we have to fix is when
            // the certificate uses SHA256, but the revocation
            // certificate uses SHA1.  In this case, we need
            // to upgrade the revocation certificate.
            if let RevocationStatus::Revoked(mut revs)
                = sp_sha1_vc.revocation_status()
            {
                certs_revoked += 1;

                if sp_vc.is_err() {
                    // Cases #1 and #2.  Nothing to do.
                    next_cert!();
                }

                // Dedup based on creation time and the reason
                // for revocation.  Prefer revocations that do
                // not use SHA-1.
                let cmp = |a: &&Signature, b: &&Signature| -> Ordering
                {
                    a.signature_creation_time()
                        .cmp(&b.signature_creation_time())
                        .then(a.reason_for_revocation()
                              .cmp(&b.reason_for_revocation()))
                };

                revs.sort_by(cmp);
                revs.dedup_by(
                    |a: &mut &Signature, b: &mut &Signature| -> bool
                    {
                        let x = cmp(a, b);
                        if x != Ordering::Equal {
                            return false;
                        }

                        // Prefer the non-SHA-1 variant.
                        // Recall: if the elements are
                        // considered equal, a is removed and
                        // b is kept.
                        if GOOD_HASHES.contains(&a.hash_algo())
                            && b.hash_algo() == HashAlgorithm::SHA1
                        {
                            *b = *a;
                        }
                        true
                    });

                // See what revocation certificates need to be
                // fixed.
                let mut inadequate_revocation = false;
                for rev in revs {
                    if rev.hash_algo() == HashAlgorithm::SHA1 {
                        if ! inadequate_revocation {
                            inadequate_revocation = true;
                            certs_with_inadequota_revocations += 1;
                        }

                        diag!("Certificate {}: Revocation certificate \
                               {:02X}{:02X} uses SHA-1.",
                              cert.keyid().to_hex(),
                              rev.digest_prefix()[0],
                              rev.digest_prefix()[1]);
                        if args.fix {
                            match update_cert_revocation(
                                &sq, &cert, rev, &reference_time)
                            {
                                Ok(sig) => {
                                    updates.push(sig);
                                }
                                Err(err) => {
                                    unfixed_issue += 1;
                                    weprintln!("Certificate {}: \
                                                Failed to update \
                                                revocation certificate \
                                                {:02X}{:02X}: {}",
                                               cert.keyid().to_hex(),
                                               rev.digest_prefix()[0],
                                               rev.digest_prefix()[1],
                                               err);
                                }
                            }
                        }
                    }

                    continue;
                }

                next_cert!();
            }


            // Check if the certificate is alive.
            match (sp_sha1_vc.alive(),
                   sp_vc.as_ref().map(|vc| vc.alive()))
            {
                (Err(_), Err(_)) => {
                    // SP+SHA1: Not alive, SP: Invalid
                    //
                    // It only uses SHA1, and under SP+SHA1,
                    // it is expired.  Invalid or expired, we
                    // don't need to fix it.
                    certs_expired += 1;
                    next_cert!();
                }
                (Err(_), Ok(Err(_))) => {
                    // SP+SHA1: Not alive, SP: Not alive.
                    //
                    // However you look at it, it's expired.
                    certs_expired += 1;
                    next_cert!();
                }
                (Err(_), Ok(Ok(_))) => {
                    // SP+SHA1: Not alive, SP: Alive
                    //
                    // Impossible.
                    panic!();
                }
                (Ok(_), Err(_)) => {
                    // SP+SHA1: Alive, SP: Invalid.
                    //
                    // The certificate only uses SHA-1.  Lint
                    // it as usual.
                    ()
                }
                (Ok(_), Ok(Err(_))) => {
                    // SP+SHA1: Alive, SP: Not alive.
                    //
                    // We have a binding signature using SHA1
                    // that says the certificate does not
                    // expire, and a newer binding signature
                    // using SHA2+ that is expired.
                    //
                    // Linting should(tm) fix this.
                    diag!("Certificate {} is live under SP+SHA1, \
                           but expire under SP.",
                          cert.keyid().to_hex());
                }
                (Ok(_), Ok(Ok(_))) => {
                    // SP+SHA1: Alive, SP: Alive.  Lint it as
                    // usual.
                    ()
                }
            }


            if let Err(ref err) = sp_vc {
                diag!("Certificate {} is not valid under \
                       the standard policy: {}",
                      cert.keyid().to_hex(), err);
            }


            // User IDs that are not revoked, and valid under
            // the standard policy + SHA-1.
            let mut a_userid = false;
            let mut sha1_protected_userid = false;
            let mut not_sha1_protected_userid = false;

            let not_revoked = |ua: &ValidUserIDAmalgamation| -> bool {
                if let RevocationStatus::Revoked(_)
                    = ua.revocation_status()
                {
                    false
                } else {
                    true
                }
            };

            for ua in sp_sha1_vc.userids().filter(not_revoked) {
                if ! a_userid {
                    a_userid = true;
                    certs_sp_sha1_userids += 1;
                }

                let sig = ua.binding_signature();
                if sig.hash_algo() == HashAlgorithm::SHA1 {
                    diag!("Certificate {} contains a \
                           User ID ({}) protected by SHA-1",
                          cert.keyid().to_hex(),
                          ui::Safe(ua.userid()));

                    if !sha1_protected_userid {
                        sha1_protected_userid = true;
                        certs_with_a_sha1_protected_userid += 1;
                    }
                    if args.fix {
                        match update_user_id_binding(
                            &sq, &ua, &reference_time)
                        {
                            Ok(sig) => {
                                updates.push(sig);
                            }
                            Err(err) => {
                                unfixed_issue += 1;
                                weprintln!("Certificate {}: User ID {}: \
                                            Failed to update \
                                            binding signature: {}",
                                           cert.keyid().to_hex(),
                                           ui::Safe(ua.userid()),
                                           err);
                            }
                        }
                    }
                } else {
                    if !not_sha1_protected_userid {
                        not_sha1_protected_userid = true;
                    }
                }
            }

            if sha1_protected_userid && ! not_sha1_protected_userid {
                certs_with_only_sha1_protected_userids += 1;
            }

            let sha1_subkeys: Vec<_> = sp_sha1_vc
                .keys().subkeys()
                .revoked(false).alive()
                .collect();
            if sha1_subkeys.len() > 0 {
                certs_with_subkeys += 1;

                // Does this certificate have any subkeys whose
                // binding signatures use SHA-1?
                let mut uses_sha1_protected_binding_sig = false;
                let mut uses_certs_with_signing_subkeys = false;
                let mut uses_sha1_protected_backsig = false;
                for ka in sha1_subkeys.into_iter() {
                    let sig = ka.binding_signature();
                    if sig.hash_algo() == HashAlgorithm::SHA1 {
                        diag!("Certificate {}, key {} uses a \
                               SHA-1-protected binding signature.",
                              cert.keyid().to_hex(),
                              ka.key().keyid().to_hex());
                        if ! uses_sha1_protected_binding_sig {
                            uses_sha1_protected_binding_sig = true;
                            certs_with_a_sha1_protected_binding_sig += 1;
                        }
                        if args.fix {
                            match update_subkey_binding(
                                &sq, &ka, &reference_time)
                            {
                                Ok(sig) => updates.push(sig),
                                Err(err) => {
                                    unfixed_issue += 1;
                                    weprintln!("Certificate {}, key {}: \
                                                Failed to update \
                                                binding signature: {}",
                                               cert.keyid().to_hex(),
                                               ka.key().keyid().to_hex(),
                                               err);
                                }
                            }
                        }

                        continue;
                    }

                    // Check if the backsig uses SHA-1.

                    if ! ka.has_any_key_flag(
                        KeyFlags::empty()
                            .set_signing()
                            .set_certification())
                    {
                        // No backsig required.
                        continue;
                    }

                    if ! uses_certs_with_signing_subkeys {
                        uses_certs_with_signing_subkeys = true;
                        certs_with_signing_subkeys += 1;
                    }

                    // Get the cryptographically valid backsigs.
                    let mut backsigs: Vec<_> = sig.embedded_signatures()
                        .filter(|backsig| {
                            (*backsig).clone().verify_primary_key_binding(
                                cert.primary_key().key(),
                                ka.key()).is_ok()
                        })
                        .collect();
                    if backsigs.len() == 0 {
                        // We can't get here.  If the key is
                        // valid under sp+SHA-1, and requires
                        // a backsig, then it must have a
                        // valid backsig.
                        panic!("Valid signing-capable subkey without \
                                a valid backsig?");
                    }
                    backsigs.sort();
                    backsigs.dedup();

                    if backsigs.len() > 1 {
                        weprintln!("Warning: multiple cryptographically \
                                    valid backsigs.");
                    }

                    if backsigs
                        .iter()
                        .any(|s| {
                            sp.signature(s, ka.key().hash_algo_security())
                                .is_ok()
                        })
                    {
                        // It's valid under the standard
                        // policy.  We're fine.
                    } else if backsigs
                        .iter()
                        .any(|s| {
                            sp_sha1.signature(s, ka.key().hash_algo_security())
                                .is_ok()
                        })
                    {
                        // It's valid under SP+SHA-1 policy.
                        // Update it.
                        diag!("Certificate {}, key {} uses a \
                               {}-protected binding signature, \
                               but a SHA-1-protected backsig",
                              cert.keyid().to_hex(),
                              ka.key().keyid().to_hex(),
                              sig.hash_algo());
                        if ! uses_sha1_protected_backsig {
                            uses_sha1_protected_backsig = true;
                            certs_with_sha1_protected_backsig += 1;
                        }
                        if args.fix {
                            match update_subkey_binding(
                                &sq, &ka, &reference_time)
                            {
                                Ok(sig) => updates.push(sig),
                                Err(err) => {
                                    unfixed_issue += 1;
                                    weprintln!("Certificate {}, key: {}: \
                                                Failed to update \
                                                binding signature: {}",
                                               cert.keyid().to_hex(),
                                               ka.key().keyid().to_hex(),
                                               err);
                                }
                            }
                        }
                    } else {
                        let sig = backsigs[0];
                        let err = sp_sha1.signature(sig, ka.key().hash_algo_security()).unwrap_err();
                        diag!("Cert {}: backsig {:02X}{:02X} for \
                               {} is not valid under SP+SHA-1: {}.  \
                               Ignoring.",
                              cert.keyid().to_hex(),
                              sig.digest_prefix()[0],
                              sig.digest_prefix()[1],
                              ka.key().keyid().to_hex(),
                              err);
                        unfixed_issue += 1;
                    }
                }
            }

            if !found_issue {
                if let Err(err) = sp_vc {
                    diag!("Certificate {} is not valid under \
                           the standard policy: {}",
                          cert.keyid().to_hex(), err);
                }
            }

            next_cert!();
        }
    }

    if let Some(out) = out {
        out.finalize()?;
    }

    let pl = |n, singular, plural| { if n == 1 { singular } else { plural } };
    macro_rules! err {
        ($n:expr, $($arg:tt)*) => {{
            eprint!($($arg)*);
            eprint!(" (");
            if $n > 0 {
                if std::io::stderr().is_terminal() {
                    let mut stderr = StandardStream::stderr(ColorChoice::Auto);
                    stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
                    write!(&mut stderr, "BAD")?;
                    stderr.reset()?;
                } else {
                    eprint!("BAD");
                }
            } else {
                if std::io::stderr().is_terminal() {
                    let mut stderr = StandardStream::stderr(ColorChoice::Auto);
                    stderr.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
                    write!(&mut stderr, "GOOD")?;
                    stderr.reset()?;
                } else {
                    eprint!("GOOD");
                }
            }
            weprintln!(")");
        }};
    }

    if ! sq.quiet() {
        weprintln!("Examined {} {}.",
                   certs_valid + certs_invalid,
                   pl(certs_valid + certs_invalid,
                      "certificate", "certificates"));

        err!(certs_invalid,
             "  {} {} invalid and {} not linted.",
             certs_invalid,
             pl(certs_invalid, "certificate is", "certificates are"),
             pl(certs_invalid, "was", "were"));
        if certs_valid > 0 {
            weprintln!("  {} {} linted.",
                       certs_valid,
                       pl(certs_valid,
                          "certificate was", "certificates were"));
            err!(certs_with_issues,
                 "  {} of the {} certificates ({}%) \
                  {} at least one issue.",
                 certs_with_issues,
                 certs_valid + certs_invalid,
                 certs_with_issues * 100 / (certs_valid + certs_invalid),
                 pl(certs_with_issues, "has", "have"));
            weprintln!("{} of the linted certificates {} revoked.",
                       certs_revoked,
                       pl(certs_revoked, "was", "were"));
            err!(certs_with_inadequota_revocations,
                 "  {} of the {} certificates has revocation certificates \
                  that are weaker than the certificate and should be \
                  recreated.",
                 certs_with_inadequota_revocations,
                 certs_revoked);
            weprintln!("{} of the linted certificates {} expired.",
                       certs_expired,
                       pl(certs_expired, "was", "were"));
            weprintln!("{} of the non-revoked linted {} at least one non-revoked User ID:",
                       certs_sp_sha1_userids,
                       pl(certs_sp_sha1_userids,
                          "certificate has", "certificates have"));
            err!(certs_with_a_sha1_protected_userid,
                 "  {} {} at least one User ID protected by SHA-1.",
                 certs_with_a_sha1_protected_userid,
                 pl(certs_with_a_sha1_protected_userid, "has", "have"));
            err!(certs_with_only_sha1_protected_userids,
                 "  {} {} all User IDs protected by SHA-1.",
                 certs_with_only_sha1_protected_userids,
                 pl(certs_with_only_sha1_protected_userids,
                    "has", "have"));
            weprintln!("{} of the non-revoked linted certificates {} at least one \
                        non-revoked, live subkey:",
                       certs_with_subkeys,
                       pl(certs_with_subkeys,
                          "has", "have"));
            err!(certs_with_a_sha1_protected_binding_sig,
                 "  {} {} at least one non-revoked, live subkey with \
                  a binding signature that uses SHA-1.",
                 certs_with_a_sha1_protected_binding_sig,
                 pl(certs_with_a_sha1_protected_binding_sig,
                    "has", "have"));
            weprintln!("{} of the non-revoked linted certificates {} at least one non-revoked, live, \
                        signing-capable subkey:",
                       certs_with_signing_subkeys,
                       pl(certs_with_signing_subkeys,
                          "has", "have"));
            err!(certs_with_sha1_protected_backsig,
                 "  {} {} at least one non-revoked, live, signing-capable subkey \
                  with a strong binding signature, but a backsig \
                  that uses SHA-1.",
                 certs_with_sha1_protected_backsig,
                 pl(certs_with_sha1_protected_backsig,
                    "certificate has", "certificates have"));
        }
    }

    if args.fix {
        if unfixed_issue > 0 {
            if ! sq.quiet() {
                err!(unfixed_issue,
                     "Failed to fix {} {}.",
                     unfixed_issue,
                     pl(unfixed_issue, "issue", "issues"));
            }
            return Err(anyhow::anyhow!(
                "Failed to fix {} {}",
                unfixed_issue,
                pl(unfixed_issue, "issue", "issues")));
        }
    } else if certs_with_issues > 0 {
        return Err(anyhow::anyhow!("{} {} have at least one issue",
                                   certs_with_issues,
                                   pl(certs_with_issues,
                                      "certificate", "certificates")));
    }

    Ok(())
}
