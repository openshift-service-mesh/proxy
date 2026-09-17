use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use chrono::DateTime;
use chrono::Utc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::Packet;
use openpgp::Result;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::CertBuilder;
use openpgp::cert::CertRevocationBuilder;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::crypto::Password;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;
use openpgp::types::SignatureType;

use sequoia_cert_store as cert_store;
use cert_store::StoreUpdate;

use crate::Sq;
use crate::cli::types::Expiration;
use crate::cli::types::FileOrStdout;
use crate::cli::types::TrustAmount;
use crate::cli;
use crate::commands::inspect::inspect;
use crate::common::key::certify_generated;
use crate::common::password;
use crate::common::pki::list::summarize_certification;
use crate::common::pki::replay::replay;
use crate::common::ui;
use crate::output::import::ImportStatus;
use crate::sq::TrustThreshold;

pub fn dispatch(
    mut sq: Sq,
    command: cli::key::rotate::Command,
) -> Result<()> {
    let o = &mut std::io::stderr();

    if command.output.as_ref().map(|s| s.is_stdout()).unwrap_or(false)
        && command.rev_cert.as_ref().map(|s| s.is_stdout()).unwrap_or(false)
    {
        return Err(anyhow::anyhow!(
            "--output and --rev-cert must not both be stdout"));
    }

    if command.output.is_none() {
        // We're going to save the output to the certificate store and
        // the key store.  Make sure they are enabled.
        sq.cert_store_or_else()?;
        sq.key_store_or_else()?;
    }

    let mut old_cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;
    let old_vc = old_cert.with_policy(sq.policy, sq.time)?;

    // Common key flags.  If this is a shared key, mark it as such.
    assert!(! (command.own_key && command.shared_key));
    let key_flags_template = if command.own_key {
        KeyFlags::empty()
    } else if command.shared_key {
        KeyFlags::empty().set_group_key()
    } else {
        if old_vc.keys().any(|ka| {
            ka.key_flags().map(|kf| kf.is_group_key()).unwrap_or(false)
        }) {
            KeyFlags::empty().set_group_key()
        } else {
            KeyFlags::empty()
        }
    };

    let mut builder = CertBuilder::new();

    let userids = old_vc.userids()
        .filter_map(|ua| {
            if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                // Skip revoked user IDs.
                None
            } else {
                Some(ua.userid().clone())
            }
        })
        .collect::<Vec<_>>();

    if userids.is_empty() {
        wwriteln!(stream = o,
                  "{} has no non-revoked self-signed user IDs, \
                   using direct key signature",
                  old_vc.fingerprint());
    } else {
        for userid in &userids {
            builder = builder.add_userid(userid.clone());
        }
    }

    // Creation time.
    builder = builder.set_creation_time(sq.time);

    // Expiration.
    builder = builder.set_validity_period(
        command
        .expiration
        .as_duration(DateTime::<Utc>::from(sq.time))?
    );

    // Cipher Suite
    builder = builder.set_cipher_suite(
        sq.config.cipher_suite(&command.cipher_suite,
                               command.cipher_suite_source));

    // Profile.  XXX: Currently, this is not actionable.
    let _profile = sq.config.key_generate_profile(
        &command.profile, command.profile_source);

    // Primary key capabilities.
    builder = builder.set_primary_key_flags(
        key_flags_template.clone().set_certification());

    // Get everything the old certificate could do.
    let mut old_cert_key_flags = KeyFlags::certification();
    for ka in old_vc.keys() {
        // We consider the key flags even if the subkey is revoked or
        // expired.
        if let Some(kf) = ka.key_flags() {
            old_cert_key_flags = &old_cert_key_flags | &kf
        }
    }

    // Signing Capability
    match (command.can_sign, command.cannot_sign) {
        (true, false) => {
            builder = builder.add_subkey(
                key_flags_template.clone().set_signing(),
                None, None);
        }
        (false, true) => { /* no signing subkey */ }
        (true, true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-sign and --cannot-sign"
            ));
        }
        (false, false) => {
            if old_cert_key_flags.for_signing() {
                builder = builder.add_subkey(
                    key_flags_template.clone().set_signing(),
                    None, None);
            } else {
                // No signing subkey.
            }
        }
    }

    // Authentication Capability
    match (command.can_authenticate, command.cannot_authenticate) {
        (true, false) => {
            builder = builder.add_subkey(
                key_flags_template.clone().set_authentication(),
                None, None);
        }
        (false, true) => { /* no authentication subkey */ }
        (true, true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-authenticate and \
                 --cannot-authenticate"
            ));
        }
        (false, false) => {
            if old_cert_key_flags.for_authentication() {
                builder = builder.add_subkey(
                    key_flags_template.clone().set_authentication(),
                    None, None);
            } else {
                // No authentication subkey.
            }
        }
    }

    // Encryption Capability
    use cli::types::EncryptPurpose::*;
    match (command.can_encrypt, command.cannot_encrypt) {
        (Some(Universal), false) => {
            builder = builder.add_subkey(
                key_flags_template.clone()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None, None);
        }
        (Some(Storage), false) => {
            builder = builder.add_subkey(
                key_flags_template.clone().set_storage_encryption(),
                None, None);
        }
        (Some(Transport), false) => {
            builder = builder.add_subkey(
                key_flags_template.clone().set_transport_encryption(),
                None, None);
        }
        (None, true) => { /* no encryption subkey */ }
        (Some(_), true) => {
            return Err(anyhow::anyhow!(
                "Conflicting arguments --can-encrypt and \
                             --cannot-encrypt"
            ));
        }
        (None, false) => {
            let mut enc = KeyFlags::empty();
            if old_cert_key_flags.for_storage_encryption() {
                enc = enc.set_storage_encryption()
            }
            if old_cert_key_flags.for_transport_encryption() {
                enc = enc.set_transport_encryption()
            }
            if enc != KeyFlags::empty() {
                builder = builder.add_subkey(
                    &key_flags_template | &enc,
                    None, None);
            } else {
                // No encryption subkey.
            }
        }
    }

    if let Some(password_file) = command.new_password_file {
        let password: Password = std::fs::read(&password_file)
            .with_context(|| {
                format!("Reading {}", password_file.display())
            })?.into();
        sq.cache_password(password.clone());
        builder = builder.set_password(Some(password));
    } else if ! command.without_password {
        let password
            = password::prompt_for_new_or_none(&sq, "the new key")?;
        if let Some(password) = password.as_ref() {
            sq.cache_password(password.clone());
        }
        builder = builder.set_password(password);
    }

    let on_keystore = command.output.is_none();

    // Generate the key
    let gen = || {
        builder.generate()
    };

    let (mut cert, rev);

    let rev_path = if let Some(rev_cert) = command.rev_cert {
        (cert, rev) = gen()?;

        rev_cert
    } else if on_keystore {
        if let Some(home) = &sq.home {
            let dir = home.data_dir(sequoia_directories::Component::Other(
                "revocation-certificates".into()));
            std::fs::create_dir_all(&dir)
                .with_context(|| {
                    format!("While creating {}", dir.display())
                })?;

            (cert, rev) = gen()?;
            FileOrStdout::new(
                Some(dir.join(format!("{}-revocation.pgp",
                                      cert.fingerprint()))))
        } else {
            return Err(anyhow::anyhow!(
                "Missing arguments: --rev-cert is mandatory if --home=none is \
                 given."
            ));
        }
    } else {
        return Err(anyhow::anyhow!(
            "Missing arguments: --rev-cert is mandatory if --output is \
             given."
        ));
    };

    // Certificates that need to be updated.
    let mut updates: BTreeMap<Fingerprint, Cert> = BTreeMap::new();
    let mut update = |cert: Cert| -> Result<()> {
        match updates.entry(cert.fingerprint()) {
            Entry::Occupied(oe) => {
                let c = oe.into_mut();
                *c = c.clone().merge_public(cert)?;
            }
            Entry::Vacant(vc) => {
                vc.insert(cert);
            }
        }

        Ok(())
    };


    // Cross sign.
    wwriteln!(stream = o);
    wwriteln!(stream = o,
              "Cross signing the old and new certificates.");

    let mut old_cert_signer = sq.get_certification_key(&old_cert, None)?;
    let mut cert_signer = sq.get_certification_key(&cert, None)?;

    let mut builder
        = SignatureBuilder::new(SignatureType::GenericCertification)
        .set_signature_creation_time(sq.time)?;
    builder = builder.set_trust_signature(255, 120)?;

    let mut old_cert_updates = Vec::new();
    let mut new_cert_updates = Vec::new();

    for userid in userids.iter() {
        // Old authorizes new.
        let sig = builder.clone().sign_userid_binding(
            &mut old_cert_signer,
            cert.primary_key().key(),
            &userid)
            .with_context(|| {
                format!("Creating certification for {}, {}",
                        cert.fingerprint(),
                        ui::Safe(String::from_utf8_lossy(userid.value())))
            })?;

        new_cert_updates.extend([
            Packet::from(userid.clone()),
            sig.into(),
        ]);

        // New authorizes old.
        let sig = builder.clone().sign_userid_binding(
            &mut cert_signer,
            old_cert.primary_key().key(),
            &userid)
            .with_context(|| {
                format!("Creating certification for {}, {}",
                        old_cert.fingerprint(),
                        ui::Safe(String::from_utf8_lossy(userid.value())))
            })?;

        old_cert_updates.extend([
            Packet::from(userid.clone()),
            sig.into(),
        ]);
    }

    if ! old_cert_updates.is_empty() {
        old_cert = old_cert.insert_packets(old_cert_updates)?.0;
        update(old_cert.clone())?;

        cert = cert.insert_packets(new_cert_updates)?.0;
        update(cert.clone())?;
    }

    // Replay the trust root -> cert onto the new certificate.
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;
    let mut trust_root_signer = sq.get_certification_key(trust_root, None)?;

    if ! command.own_key && ! command.shared_key {
        wwriteln!(stream = o);
        wwriteln!(stream = o,
                  "Replaying the old certificate's links:");

        let mut packets = Vec::new();

        for ua in old_cert.userids() {
            for sig in ua.active_certifications_by_key(
                sq.policy,
                sq.time,
                trust_root.primary_key().key())
            {
                wwriteln!(stream = o, indent="  ",
                           "Copying link for {}:",
                           ui::Safe(String::from_utf8_lossy(
                               ua.userid().value())));
                summarize_certification(o, "  ", &sig, true)?;

                let builder: SignatureBuilder = sig.clone().into();
                let builder = builder.set_signature_creation_time(sq.time)?;

                let sig = builder.sign_userid_binding(
                    &mut trust_root_signer,
                    cert.primary_key().key(),
                    &ua.userid())
                    .with_context(|| {
                        format!("Creating link for {}, {}",
                                cert.fingerprint(),
                                ui::Safe(String::from_utf8_lossy(
                                    ua.userid().value())))
                    })?;

                packets.extend([
                    Packet::from(ua.userid().clone()),
                    sig.into(),
                ]);
            }
        }

        if packets.is_empty() {
            wwriteln!(stream = o, indent = "  ",
                      "The certificate was never linked.");
        } else {
            cert = cert.insert_packets(packets)?.0;
            update(cert.clone())?;
        }
    }

    // Replay the certifications that old cert made.
    wwriteln!(stream = o);
    wwriteln!(stream = o,
              "Replaying certifications made by the old certificate:");
    for cert in replay(&sq, o, "  ",
                       RefCell::new(old_cert.clone()),
                       &cert, Some(&mut cert_signer), None)?
        .into_iter()
    {
        update(cert)?;
    }


    if let Expiration::Timestamp(retire_at) = command.retire_in.value() {
        // Retire the old certificate.
        wwriteln!(stream = o);

        let retire_at = retire_at.to_system_time(sq.time)?;
        let retire_at_str = chrono::DateTime::<chrono::Utc>::from(retire_at)
            .format("%Y‑%m‑%d %H:%M:%S")
            .to_string();

        wwriteln!(stream = o,
                  "Retiring the old certificate as of {}.",
                  retire_at_str);

        let mut rev = CertRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::KeyRetired,
                format!("This certificate has been retired, and is \
                         replaced by {}.",
                        cert.fingerprint())
                    .as_bytes())?;
        rev = rev.set_signature_creation_time(retire_at)?;
        let rev = rev.build(&mut old_cert_signer, &old_cert, None)?;
        update(old_cert.insert_packets(rev)?.0)?;
    }

    let headers = cert.armor_headers();

    // write out rev cert
    {
        let mut headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();
        headers.insert(0, ("Comment", "Revocation certificate for"));

        let w = rev_path.for_secrets().create_safe(&sq)?;
        let mut w = Writer::with_headers(w, Kind::PublicKey, headers)?;
        Packet::from(cert.primary_key().key().clone()).serialize(&mut w)?;
        Packet::Signature(rev).serialize(&mut w)?;
        w.finalize()?;
    }

    // write out key and the updates.
    {
        let headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();

        match command.output {
            Some(ref output_file) => {
                // Write the key to a file or to stdout.
                let w = output_file.clone().for_secrets()
                    .create_safe(&sq)?;
                let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
                cert.as_tsk().serialize(&mut w)?;
                for (_fpr, cert) in updates.iter() {
                    cert.serialize(&mut w)?;
                }
                w.finalize()?;
            }
            None => {
                // write the key to the key store

                // Certify the key with a per-host shadow CA if there
                // are any user IDs to certify.
                let have_userids = cert.userids().next().is_some();
                if have_userids {
                    cert = certify_generated(&mut sq, &cert)?;
                }

                match sq.import_key(cert.clone(), &mut Default::default())
                    .map(|(key_status, _cert_status)| key_status)
                {
                    Ok(ImportStatus::New) => { /* success */ }
                    Ok(ImportStatus::Unchanged) => {
                        panic!(
                            "The new key is identical to an existing one; this \
                             should never happen");
                    }
                    Ok(ImportStatus::Updated) => {
                        panic!(
                            "The new key collides with an existing one; this \
                             should never happen")
                    }
                    Err(err) => {
                        return Err(anyhow::anyhow!(
                            "Failed saving to the store: {}", err))
                    }
                }

                // If the user provided `--own-key` or `--shared-key`,
                // certify the user IDs using the local trust root.
                // (If they didn't then already replayed the local
                // trust root's certifications of the certificate.)
                if command.own_key && have_userids {
                    // Mark all user IDs as authenticated, and mark
                    // the key as a trusted introducer.
                    crate::common::pki::certify::certify(
                        o,
                        &sq,
                        false, // Recreate.
                        &trust_root,
                        &cert,
                        &userids.into_iter().map(Into::into)
                            .collect::<Vec<_>>(),
                        true, // User-supplied user IDs.
                        &[(TrustAmount::Full, Expiration::Never)],
                        // Make it an unconstrained trusted introducer.
                        u8::MAX, // Trust depth.
                        &[][..], // Domain.
                        &[][..], // Regex.
                        true, // Local.
                        false, // Non-revocable.
                        &[][..], // Notations.
                        None, // Output.
                        false, // Binary.
                    )?;
                } else if command.shared_key && have_userids {
                    // Mark all user IDs as authenticated.
                    crate::common::pki::certify::certify(
                        o,
                        &sq,
                        false, // Recreate.
                        &trust_root,
                        &cert,
                        &userids.into_iter().map(Into::into)
                            .collect::<Vec<_>>(),
                        true, // User-supplied user IDs.
                        &[(TrustAmount::Full, Expiration::Never)],
                        // No trusted introducer.
                        0, // Trust depth.
                        &[][..], // Domain.
                        &[][..], // Regex.
                        true, // Local.
                        false, // Non-revocable.
                        &[][..], // Notations.
                        None, // Output.
                        false, // Binary.
                    )?;
                }

                // And save any updates.
                let cert_store = sq.cert_store_or_else()?;

                for cert in updates.values() {
                    if let Err(err) = cert_store.update(
                        Arc::new(cert.clone().into()))
                    {
                        wwriteln!(stream = o,
                                  "Error importing updated certificate: {}",
                                  err);
                        return Err(err);
                    }
                }
            }
        }
    }

    // Display the new certificate.
    {
        let mut bytes = Vec::new();
        cert.as_tsk().serialize(&mut bytes)
            .expect("serializing to a vector is infallible");

        wwriteln!(stream = o);
        if let Err(err) = inspect(
            &mut sq,
            buffered_reader::Memory::with_cookie(&bytes, Default::default()),
            command.output
                .as_ref()
                .and_then(|output| {
                    output.path().map(|p| p.display().to_string())
                })
                .as_deref(),
            &mut (Box::new(std::io::stderr()) as Box<dyn std::io::Write + Send + Sync>),
            true, false)
        {
            wwriteln!(stream = o, "Failed to display key: {}", err);
            wwriteln!(stream = o,
                      "This is probably a bug in sq, please report it to \
                       https://gitlab.com/sequoia-pgp/sequoia-sq/-/issues/new .");
        }
    }

    // If we are writing to key store, provide some guidance.
    if on_keystore && command.own_key {
        sq.hint(format_args!("Because you supplied the `--own-key` flag, \
                              the user IDs on this key have been marked as \
                              authenticated, and this key has been marked \
                              as a fully trusted introducer.  \
                              If that was a mistake, you can undo that \
                              with:"))
            .sq().arg("pki").arg("link").arg("retract")
            .arg_value("--cert", cert.fingerprint())
            .arg("--all")
            .done();
    }

    if on_keystore && command.shared_key {
        sq.hint(format_args!("The user IDs on the key have been marked as \
                              authenticated.  \
                              If that was a mistake, you can undo that \
                              with:"))
            .sq().arg("pki").arg("link").arg("retract")
            .arg_value("--cert", cert.fingerprint())
            .arg("--all")
            .done();
    }

    if on_keystore {
        sq.hint(format_args!("You can export your certificate as follows:"))
            .sq().arg("cert").arg("export")
            .arg_value("--cert", cert.fingerprint())
            .done();

        sq.hint(format_args!("Once you are happy you can upload it to public \
                              directories using:"))
            .sq().arg("network").arg("keyserver").arg("publish")
            .arg_value("--cert", cert.fingerprint())
            .done();

        if ! updates.is_empty() {
            let mut hint = sq.hint(format_args!(
                "To make updates to other certificates effective, \
                 they also have to be published, for example using:"))
                .sq().arg("network").arg("keyserver").arg("publish");

            for cert in updates.values() {
                hint = hint.arg_value("--cert", cert.fingerprint())
            }

            hint.done();
        }
    } else {
        let mut shown = false;
        if let Some(ref output) = command.output {
            if let Some(output_path) = output.path() {
                sq.hint(format_args!("You can extract the certificate from the \
                                      generated key by running:"))
                    .sq().arg_value("--keyring", output_path.display())
                    .arg("cert").arg("export")
                    .arg_value("--cert", &cert.fingerprint().to_string())
                    .arg_value("--output", output_path.with_extension("cert").display())
                    .done();
                shown = true;
            }
        }

        if ! shown {
            sq.hint(format_args!("You can extract the certificate from the \
                                  generated key using:"))
                .sq().arg("key").arg("delete").done();
        }
    }

    Ok(())
}
