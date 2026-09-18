use std::path::Path;

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::crypto::Password;
use openpgp::packet::key::KeyParts;
use openpgp::serialize::Serialize;

use sequoia_keystore as keystore;
use keystore::Protection;

use crate::Convert;
use crate::Sq;
use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;
use crate::common::password;
use crate::common;

pub fn password<'a, P>(
    sq: Sq,
    cert: &Cert,
    cert_source: FileStdinOrKeyHandle,
    to_change: Vec<(
        &'a ValidErasedKeyAmalgamation<'a, P>,
        Option<Vec<keystore::Key>>
    )>,
    clear_password: bool,
    new_password_file: Option<&Path>,
    output: Option<FileOrStdout>,
    binary: bool)
    -> Result<()>
where
    P: 'a + KeyParts,
{
    make_qprintln!(sq.quiet());

    let mut new_password_ = None;
    // Some(password) => new password
    // None => clear password
    let mut get_new_password = || -> Result<Option<Password>> {
        if new_password_.is_none() {
            new_password_ = if clear_password {
                Some(None)
            } else if let Some(path) = new_password_file.as_ref() {
                Some(Some(std::fs::read(path)?.into()))
            } else {
                Some(common::password::prompt_for_new_or_none(&sq, "key")?)
            };
        }

        Ok(new_password_.clone().unwrap())
    };

    let uid = sq.best_userid(&cert, true);

    qprintln!("Changing password for {}, {}",
              cert.fingerprint(), uid.display());

    let ks = matches!(cert_source, FileStdinOrKeyHandle::KeyHandle(_));
    if ks {
        // Change the password of the secret key material on the key
        // store.
        for (key, remote_keys) in to_change.into_iter() {
            let remote_keys = remote_keys.expect("have remote keys");
            assert!(! remote_keys.is_empty());
            for mut remote_key in remote_keys.into_iter() {
                let provide_password
                    = if let Protection::Password(hint) = remote_key.locked()?
                {
                    let mut unlocked = false;
                    for p in sq.cached_passwords() {
                        if remote_key.unlock(p).is_ok() {
                            unlocked = true;
                            break;
                        }
                    }

                    if ! unlocked {
                        if let Some(hint) = hint {
                            weprintln!("{}", hint);
                        }

                        let time =
                            key.key().creation_time().convert().to_string();

                        let flags = if let Some(flags) = key.key_flags() {
                            let mut s = Vec::new();
                            if flags.for_certification() {
                                s.push("certifying");
                            }
                            if flags.for_signing() {
                                s.push("signing");
                            }
                            if flags.for_storage_encryption()
                                && flags.for_transport_encryption()
                            {
                                s.push("encryption");
                            } else if flags.for_storage_encryption() {
                                s.push("storage encryption");
                            } else if flags.for_transport_encryption() {
                                s.push("transport encryption");
                            }
                            if ! s.is_empty() {
                                format!(" for {}", s.join(", "))
                            } else {
                                "".into()
                            }
                        } else {
                            "".into()
                        };

                        loop {
                            let p = password::prompt_to_unlock(&sq, &format!(
                                "{}, created {}{}",
                                key.key().fingerprint(), time, flags))?;

                            match remote_key.unlock(p.clone()) {
                                Ok(()) => {
                                    sq.cache_password(p.clone());
                                    break;
                                }
                                Err(err) => {
                                    weprintln!("Failed to unlock key: {}", err);
                                }
                            }
                        }
                    }
                    true
                } else {
                    remote_key.password_source()?.is_inline()
                };

                let password = if provide_password {
                    if let Some(password) = get_new_password()? {
                        Some(password)
                    } else {
                        // change_password interprets None as prompt for
                        // password, and "" as clear password.
                        Some("".into())
                    }
                } else {
                    None
                };

                remote_key.change_password(password.as_ref())
                    .with_context(|| {
                        format!("Changing {}'s password", key.key().fingerprint())
                    })?;

                qprintln!("Changed password for {}", key.key().fingerprint());
            }
        }
    } else {
        // First, decrypt all secrets.
        let to_change = to_change.into_iter().map(|(ka, remote)| {
            let key = ka.key().clone().parts_into_secret()?;
            let key = sq.decrypt_key(
                Some(&cert),
                key,
                true, // May prompt.
                false, // Don't allow skipping.
            )?.parts_into_public();
            Ok((key, ka.primary(), remote))
        }).collect::<Result<Vec<_>>>()?;

        let mut packets: Vec<Packet> = Vec::new();
        if let Some(new) = get_new_password()? {
            for (key, primary, _remote_keys) in to_change.into_iter() {
                let key = key.parts_into_secret()
                    .expect("have secret key amterial")
                    .encrypt_secret(&new)?
                    .parts_into_public();

                if primary {
                    packets.push(
                        Packet::PublicKey(key.role_into_primary()));
                } else {
                    packets.push(
                        Packet::PublicSubkey(key.role_into_subordinate()));
                }
            }
        } else {
            for (key, primary, _remote_keys) in to_change.into_iter() {
                let key = key.parts_into_public();
                if primary {
                    packets.push(
                        Packet::PublicKey(key.role_into_primary()));
                } else {
                    packets.push(
                        Packet::PublicSubkey(key.role_into_subordinate()));
                }
            }
        }

        let cert = cert.clone().insert_packets(packets)?.0;

        let output = output.unwrap_or_else(|| FileOrStdout::new(None));
        let mut output = output.for_secrets().create_safe(&sq)?;
        if binary {
            cert.as_tsk().serialize(&mut output)?;
        } else {
            cert.as_tsk().armored().serialize(&mut output)?;
        }
    }

    Ok(())
}
