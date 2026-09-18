use chrono::DateTime;
use chrono::Utc;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::armor::Kind;
use openpgp::armor::Writer;
use openpgp::cert::CertBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::Packet;
use openpgp::packet::UserID;
use openpgp::Result;

use crate::common::password;
use crate::common::userid::{lint_userids, lint_names, lint_emails};
use crate::Sq;
use crate::cli::{
    self,
    types::{
        Expiration,
        FileOrStdout,
        TrustAmount,
    },
};
use crate::commands::inspect::inspect;
use crate::common::key::certify_generated;
use crate::output::import::ImportStatus;

pub fn generate(
    mut sq: Sq,
    mut command: cli::key::generate::Command,
) -> Result<()> {
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

    // Common key flags.  If this is a shared key, mark it as such.
    assert!(command.own_key ^ command.shared_key);
    let key_flags_template = if command.own_key {
        KeyFlags::empty()
    } else {
        KeyFlags::empty().set_group_key()
    };

    let mut builder = CertBuilder::new()
        .set_profile(command.profile.into())?;

    // Names, email addresses, and user IDs.
    lint_names(&command.names)?;
    for n in &command.names {
        command.userid.push(UserID::from(n.as_str()));
    }

    lint_emails(&command.emails)?;
    for n in &command.emails {
        command.userid.push(UserID::from_address(None, None, n)?);
    }

    if command.userid.is_empty() {
        weprintln!("No user ID given, using direct key signature");
    } else {
        // Make sure the user IDs are in canonical form.  If not, and
        // `--allow-non-canonical-userids` is not set, error out.
        if ! command.allow_non_canonical_userids {
            lint_userids(&command.userid)?;
        }

        for uid in &command.userid {
            builder = builder.add_userid(uid.clone());
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

    if let Some(algo) = command.encryption_algorithm {
        builder = builder.set_encryption_algorithm(algo.into());
    }
    if let Some(algo) = command.signing_algorithm {
        builder = builder.set_signing_algorithm(algo.into());
    }

    // Profile.  XXX: Currently, this is not actionable.
    let _profile = sq.config.key_generate_profile(
        &command.profile, command.profile_source);

    // Primary key capabilities.
    builder = builder.set_primary_key_flags(
        key_flags_template.clone().set_certification());

    // Signing Capability
    match (command.can_sign, command.cannot_sign) {
        (false, false) | (true, false) => {
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
    }

    // Authentication Capability
    match (command.can_authenticate, command.cannot_authenticate) {
        (false, false) | (true, false) => {
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
    }

    // Encryption Capability
    use cli::types::EncryptPurpose::*;
    match (command.can_encrypt, command.cannot_encrypt) {
        (Some(Universal), false) | (None, false) => {
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
    }

    if let Some(password_file) = command.new_password_file {
        let password = std::fs::read(&password_file)
            .with_context(|| {
                format!("Reading {}", password_file.display())
            })?;
        builder = builder.set_password(Some(password.into()));
    } else if ! command.without_password {
        builder = builder.set_password(
            password::prompt_for_new_or_none(&sq, "key")?);
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

    let headers = cert.armor_headers();

    // write out rev cert
    {
        let mut headers: Vec<_> = headers
            .iter()
            .map(|value| ("Comment", value.as_str()))
            .collect();
        headers.insert(0, ("Comment", "Revocation certificate for"));

        let w = rev_path
            .for_secrets()
            .create_safe(&sq)?;
        let mut w = Writer::with_headers(w, Kind::PublicKey, headers)?;
        Packet::from(cert.primary_key().key().clone()).serialize(&mut w)?;
        Packet::Signature(rev).serialize(&mut w)?;
        w.finalize()?;
    }

    // write out key
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

                // Now certify the user IDs, and if this is our own
                // key, mark it as trusted introducer.
                let trust_root = sq.local_trust_root()?;
                let trust_root = trust_root.to_cert()?;

                if command.own_key && have_userids {
                    // Mark all user IDs as authenticated, and mark
                    // the key as a trusted introducer.
                    crate::common::pki::certify::certify(
                        &mut std::io::stderr(),
                        &sq,
                        false, // Recreate.
                        &trust_root,
                        &cert,
                        &command.userid.into_iter().map(Into::into)
                            .collect::<Vec<_>>(),
                        true, // User-supplied user IDs.
                        &[(TrustAmount::Full, Expiration::Never)],
                        // Make it a unconstrained trusted introducer.
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
                        &mut std::io::stderr(),
                        &sq,
                        false, // Recreate.
                        &trust_root,
                        &cert,
                        &command.userid.into_iter().map(Into::into)
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
            }
        }
    }

    {
        let mut bytes = Vec::new();
        cert.as_tsk().serialize(&mut bytes)
            .expect("serializing to a vector is infallible");

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
            false, false)
        {
            weprintln!("Failed to display key: {}", err);
            weprintln!("This is probably a bug in sq, please report it to \
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
    } else {
        let mut shown = false;
        if let Some(ref output) = command.output {
            if let Some(output_path) = output.path() {
                sq.hint(format_args!("You can extract the certificate from the \
                                      generated key by running:"))
                    .sq().arg("key").arg("delete")
                    .arg_value("--cert-file", output_path.display())
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
