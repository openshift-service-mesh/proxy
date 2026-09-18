use anyhow::Context;

use chrono::DateTime;
use chrono::Utc;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::KeyBuilder;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;

use crate::Sq;
use crate::cli::key::subkey::add::Command;
use crate::cli::types::EncryptPurpose;
use crate::common;
use crate::sq::TrustThreshold;

/// Add a new Subkey for an existing primary key
///
/// Creates a subkey with features (e.g. `KeyFlags`, `CipherSuite`) based on
/// user input (or application-wide defaults if not specified).
/// If no specific expiry is requested, the subkey never expires.
pub fn dispatch(sq: Sq, command: Command) -> Result<()>
{
    let cert =
        sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

    let valid_cert = cert.with_policy(sq.policy, sq.time)?;

    let validity = command
        .expiration
        .as_duration(DateTime::<Utc>::from(sq.time))?;

    let keyflags = KeyFlags::empty()
        .set_authentication_to(command.can_authenticate)
        .set_signing_to(command.can_sign)
        .set_storage_encryption_to(matches!(
            command.can_encrypt,
            Some(EncryptPurpose::Storage) | Some(EncryptPurpose::Universal)
        ))
        .set_transport_encryption_to(matches!(
            command.can_encrypt,
            Some(EncryptPurpose::Transport) | Some(EncryptPurpose::Universal)
        ));

    // If a password is needed to use the key, the user will be prompted.
    let (primary_key, password) =
        match sq.get_primary_key(&cert, None) {
            Ok(key) => {
                // Don't use a password, or prompt for one.
                if let Some(password_file) = command.new_password_file {
                    let password = std::fs::read(&password_file)
                        .with_context(|| {
                            format!("Reading {}", password_file.display())
                        })?;
                    (key, Some(password.into()))
                } else if command.without_password {
                    (key, None)
                } else {
                    (key, common::password::prompt_for_new_or_none(
                        &sq, "subkey")?)
                }
            }
            Err(error) => {
                return Err(error)
            }
        };

    let new_cert = KeyBuilder::new(keyflags)
        .set_creation_time(sq.time)
        .set_cipher_suite(
            sq.config.cipher_suite(&command.cipher_suite,
                                   command.cipher_suite_source))
        .set_password(password)
        .subkey(valid_cert)?
        .set_key_validity_period(validity)?
        .set_primary_key_signer(primary_key)
        .attach_cert()?;

    if let Some(output) = command.output {
        let mut sink = output.for_secrets().create_safe(&sq)?;
        if false {
            new_cert.as_tsk().serialize(&mut sink)?;
        } else {
            new_cert.as_tsk().armored().serialize(&mut sink)?;
        }
    } else {
        sq.import_key(new_cert, &mut Default::default())?;
    }

    Ok(())
}
