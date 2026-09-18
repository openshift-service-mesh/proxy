//! Deletes secret key material.
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Packet;
use openpgp::Result;
use openpgp::cert::amalgamation::key::PrimaryKey;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::packet::key::KeyParts;
use openpgp::serialize::Serialize;

use sequoia_keystore as keystore;

use crate::Sq;
use crate::cli::types::FileOrStdout;
use crate::cli::types::FileStdinOrKeyHandle;

pub fn delete<'a, P>(
    sq: Sq,
    cert: &Cert,
    cert_source: FileStdinOrKeyHandle,
    to_delete: Vec<(
        &'a ValidErasedKeyAmalgamation<'a, P>,
        Option<Vec<keystore::Key>>
    )>,
    output: Option<FileOrStdout>,
    binary: bool)
    -> Result<()>
where
    P: 'a + KeyParts,
{
    let ks = matches!(cert_source, FileStdinOrKeyHandle::KeyHandle(_));
    if ks {
        // Delete the secret key material from the key store.
        for (ka, remote_keys) in to_delete.into_iter() {
            let remote_keys = remote_keys.expect("have remote keys");
            assert!(! remote_keys.is_empty());
            for (i, mut kh) in remote_keys.into_iter().enumerate() {
                if let Err(err) = kh.delete_secret_key_material() {
                    if i > 0 {
                        // We failed to delete the key.  It could be
                        // that when we deleted another instance of
                        // the key, it deleted this instance.  (The
                        // softkey backend combines keys, and does
                        // this.)
                        if let Some(err)
                            = err.downcast_ref::<keystore::Error>()
                        {
                            if let keystore::Error::EOF = err {
                                continue;
                            }
                        }
                    }
                    Err(err).with_context(|| {
                        format!("Deleting {}", ka.key().fingerprint())
                    })?;
                }
            }
        }
    } else {
        // Strip the secret key material from the certificate.
        let mut stripped: Vec<Packet> = Vec::new();

        for (ka, _) in to_delete.into_iter() {
            let key = ka.key().clone().parts_into_secret().expect("have a secret");
            let pk = key.take_secret().0;
            if ka.primary() {
                stripped.push(
                    Packet::PublicKey(pk.role_into_primary()));
            } else {
                stripped.push(
                    Packet::PublicSubkey(pk.role_into_subordinate()));
            }
        }

        let cert = cert.clone().insert_packets(
            stripped.into_iter().map(|stripped| Packet::from(stripped)))?.0;

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
