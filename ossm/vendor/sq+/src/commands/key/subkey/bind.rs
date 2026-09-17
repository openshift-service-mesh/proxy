use anyhow::Context;

use openpgp::packet::key;
use openpgp::packet::signature::subpacket::SubpacketTag;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::Key;
use openpgp::packet::Signature;
use openpgp::policy::Policy;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::types::SignatureType;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::Sq;
use crate::cli;
use cli::types::EncryptPurpose;
use crate::common::password;
use crate::sq::TrustThreshold;

pub fn bind(sq: Sq, command: cli::key::subkey::bind::Command) -> Result<()>
{
    let cert = sq.resolve_cert(&command.cert, TrustThreshold::Full)?.0;

    let null_policy_;
    let adoptee_policy: &dyn Policy = if command.allow_broken_crypto {
        null_policy_ = unsafe { openpgp::policy::NullPolicy::new() };
        &null_policy_
    } else {
        sq.policy
    };

    // Find the corresponding keys.
    let wanted: Vec<(
        KeyHandle,
        Result<(
            Cert,
            Key<key::PublicParts, key::SubordinateRole>,
            SignatureBuilder,
        )>,
    )> = command.key
        .into_iter()
        .map(|kh| {
            let cert = match sq.lookup_with_policy(
                std::iter::once(kh.clone()), None, false, true,
                adoptee_policy, sq.time)
            {
                Ok(certs) => certs.into_iter().next().unwrap(),
                Err(err) => return (kh, Err(err)),
            };


            let key = cert.keys().key_handle(kh.clone())
                .next().expect("have key");

            use openpgp::cert::amalgamation::ValidateAmalgamation;
            let sig = key.with_policy(adoptee_policy, sq.time)
                .map(|k| k.binding_signature())
                .ok();
            let builder: SignatureBuilder = match sig {
                Some(sig) if sig.typ() == SignatureType::SubkeyBinding => {
                    sig.clone().into()
                }
                Some(sig) if sig.typ() == SignatureType::DirectKey
                    || sig.typ() == SignatureType::PositiveCertification
                    || sig.typ() == SignatureType::CasualCertification
                    || sig.typ() == SignatureType::PersonaCertification
                    || sig.typ() == SignatureType::GenericCertification =>
                {
                        // Convert to a binding signature.
                        let kf = match sig.key_flags().context(
                            "Missing required subpacket, KeyFlags")
                        {
                            Ok(kh) => kh,
                            Err(err) => return (kh, Err(err)),
                        };
                        match SignatureBuilder::new(SignatureType::SubkeyBinding)
                            .set_key_flags(kf)
                        {
                            Ok(b) => b,
                            Err(err) => return (kh, Err(err)),
                        }
                }
                None => {
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                }
                _ => panic!("Unsupported binding signature: {:?}", sig),
            };

            let builder = match builder.set_signature_creation_time(sq.time) {
                Ok(b) => b,
                Err(err) => return (kh, Err(err)),
            };

            let mut key_flags = builder.key_flags()
                .unwrap_or(KeyFlags::empty());
            if command.can_sign {
                key_flags = key_flags.set_signing();
            }
            if command.cannot_sign {
                key_flags = key_flags.clear_signing();
            }
            if command.can_authenticate {
                key_flags = key_flags.set_authentication();
            }
            if command.cannot_authenticate {
                key_flags = key_flags.clear_authentication();
            }
            if let Some(purpose) = command.can_encrypt.as_ref() {
                match purpose {
                    EncryptPurpose::Universal => {
                        key_flags = key_flags.set_storage_encryption()
                            .set_transport_encryption();
                    }
                    EncryptPurpose::Storage => {
                        key_flags = key_flags.set_storage_encryption();
                    }
                    EncryptPurpose::Transport => {
                        key_flags = key_flags.set_transport_encryption();
                    }
                }
            }
            if command.cannot_encrypt {
                key_flags = key_flags.clear_storage_encryption();
                key_flags = key_flags.clear_transport_encryption();
            }

            let builder = match builder.set_key_flags(key_flags) {
                Ok(b) => b,
                Err(err) => return (kh, Err(err)),
            };

            let mut key = key.key().clone().role_into_subordinate();

            if let Some(creation_time) = &command.creation_time {
                match creation_time.to_system_time(sq.time)
                    .and_then(|t| key.set_creation_time(t))
                {
                    Ok(_) => (),
                    Err(err) => return (kh, Err(err)),
                }
            } else if key.creation_time() == std::time::UNIX_EPOCH {
                // We have a bare key.  Set the creation time to now.
                match key.set_creation_time(sq.time) {
                    Ok(_) => (),
                    Err(err) => return (kh, Err(err)),
                }
            }

            (kh, Ok((cert, key, builder)))
        })
        .collect();

    // If we are missing any keys, stop now.
    let mut missing = false;
    let wanted = wanted.into_iter()
        .filter_map(|(id, keyo)| {
            match keyo {
                Ok((cert, key, builder)) => Some((cert, key, builder)),
                Err(err) => {
                    if ! missing {
                        weprintln!("Missing keys:");
                    }

                    weprintln!(initial_indent = "  - ", "{}: {}", id, err);

                    missing = true;
                    None
                }
            }
        })
        .collect::<Vec<_>>();
    if missing {
        return Err(anyhow::anyhow!("Missing some keys"));
    }

    // Get a signer.
    let pk = cert.primary_key().key();
    let mut pk_signer = sq.get_primary_key(&cert, None)
        .with_context(|| {
            format!("Getting signer for {}'s primary key",
                    cert.fingerprint())
        })?;

    // Add the keys and signatures to cert.
    let mut packets: Vec<Packet> = vec![];
    for (cert, mut key, mut builder) in wanted.into_iter() {
        // Set key expiration.
        if let Some(e) = command.expiration.value().to_system_time(sq.time)? {
            builder = builder.set_key_expiration_time(&key, e)?;
        }

        let key_flags = builder.key_flags().unwrap_or(KeyFlags::empty());
        if key_flags.is_empty() {
            return Err(anyhow::anyhow!(
                "{} has no key capabilities.  Pass at least one of \
                 --can-sign, --can-authenticate, and --can-encrypt to \
                 bind this key.",
                key.fingerprint()));
        };

        // If the key we got from the certificate does not contain a
        // secret (for example, because we got it from the cert
        // store), try to get it from the key store.  This will only
        // succeed for the softkeys backend.  But, for the softkeys
        // backend it is necessary to actually get the secret key
        // material, so that we have secret key material to import
        // back into the softkeys backend.
        //
        // Note that keys backed by the softkeys backend can also
        // bind keys with material backed by hardware keys.  In this
        // case, we'll import the public key and binding signature
        // into the cert store, and the change will not be reflected
        // in the key store.

        // If we have to prompt for a password in order to identify
        // the right key, at least store the keypair so that we don't
        // have to ask again.
        let mut keypair = None;

        if key.optional_secret().is_none() {
            let ks = sq.key_store_or_else()?;
            let mut ks = ks.lock().unwrap();

            // Try to get secrets from the store.
            let secrets = ks.find_key(key.key_handle())?.into_iter()
                .filter_map(|mut k| k.export().ok()).collect::<Vec<_>>();

            match secrets.len() {
                0 => (),
                1 => key = secrets.into_iter().next().unwrap().into(),
                _ => if secrets.iter().all(|k| ! k.secret().is_encrypted()) {
                    // There is more than one variant of the secret
                    // key, and all of them are unlocked.  Pick one.
                    let k = secrets.into_iter().next().unwrap();
                    keypair =
                        Some(k.clone().into_keypair()?);
                    key = k.into();
                } else {
                    // There is more than one variant of the secret
                    // key.  Prompt for a password to unlock one, so
                    // that we know which one the user wants.  This is
                    // a bit annoying, but on the plus side we don't
                    // need to ask the user again to create the
                    // primary key binding signature.
                    let uid = sq.best_userid(&cert, true);

                    'password_loop: loop {
                        let p = password::prompt_to_unlock(&sq, &format!(
                            "{}/{}, {}",
                            cert.keyid(), key.keyid(), uid.display()))?;

                        // Empty password given and a key without
                        // encryption?  Pick it.
                        if p.map(|p| p.is_empty()) {
                            if let Some(k) = secrets.iter()
                                .find(|k| ! k.secret().is_encrypted())
                            {
                                keypair =
                                    Some(k.clone().into_keypair()?);
                                key = k.clone().into();
                                break;
                            }
                        }

                        let mut err = None;
                        for k in &secrets {
                            match k.secret().clone().decrypt(&key, &p) {
                                Ok(decrypted) => {
                                    // Keep the decrypted keypair.
                                    keypair = Some({
                                        let k = key.add_secret(decrypted).0;
                                        k.clone().into_keypair()?
                                    });
                                    // Bind the encrypted key.
                                    key = k.clone().into();
                                    break 'password_loop;
                                },

                                Err(e) => err = Some(e),
                            }
                        }

                        if p == "".into() {
                            weprintln!("Giving up.");
                            return Err(anyhow::anyhow!(
                                "Failed to unlock key: {}",
                                err.expect("must be set when we came here")));
                        }
                    }
                },
            }
        }

        // If we need a valid backsig, create it.
        if key_flags.for_signing() || key_flags.for_certification() {
            // Derive a signer.
            let ka = cert.keys().key_handle(key.fingerprint())
                .next()
                .expect("have key");

            let mut subkey_signer = if let Some(k) = keypair {
                Box::new(k)
            } else {
                sq.get_signer(&ka)
                    .with_context(|| {
                        format!("Getting signer for {}", ka.key().fingerprint())
                    })?
            };

            let backsig = builder
                .embedded_signatures()
                .find(|backsig| {
                    (*backsig)
                        .clone()
                        .verify_primary_key_binding(cert.primary_key().key(), &key)
                        .is_ok()
                })
                .map(|sig| SignatureBuilder::from(sig.clone()))
                .unwrap_or_else(|| {
                    SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                })
                .set_signature_creation_time(sq.time)?
                .sign_primary_key_binding(&mut subkey_signer, pk, &key)?;

            builder = builder.set_embedded_signature(backsig)?;
        } else {
            builder = builder.modify_hashed_area(|mut a| {
                a.remove_all(SubpacketTag::EmbeddedSignature);
                Ok(a)
            })?;
        }

        let sig = builder.sign_subkey_binding(&mut pk_signer, pk, &key)?;

        // Verify it.
        assert!(sig
            .verify_subkey_binding(pk_signer.public(), pk, &key)
            .is_ok());

        packets.push(key.into());
        packets.push(sig.into());
    }

    let cert = cert.clone().insert_packets(packets.clone())?.0;

    let vc = cert.with_policy(sq.policy, None).expect("still valid");
    for pair in packets[..].chunks(2) {
        let newkey: &Key<key::PublicParts, key::UnspecifiedRole> = match pair[0]
        {
            Packet::PublicKey(ref k) => k.into(),
            Packet::PublicSubkey(ref k) => k.into(),
            Packet::SecretKey(ref k) => k.into(),
            Packet::SecretSubkey(ref k) => k.into(),
            ref p => panic!("Expected a key, got: {:?}", p),
        };
        let newsig: &Signature = match pair[1] {
            Packet::Signature(ref s) => s,
            ref p => panic!("Expected a sig, got: {:?}", p),
        };

        let mut found = false;
        for key in vc.keys() {
            if key.key().fingerprint() == newkey.fingerprint() {
                for sig in key.self_signatures() {
                    if sig == newsig {
                        found = true;
                        break;
                    }
                }
            }
        }
        assert!(found, "Subkey: {:?}\nSignature: {:?}", newkey, newsig);
    }

    if let Some(output) = command.output {
        let path = output.path().map(Clone::clone);
        let mut sink = output.for_secrets().create_safe(&sq)?;
        if false {
            cert.as_tsk().serialize(&mut sink)?;
        } else {
            cert.as_tsk().armored().serialize(&mut sink)?;
        }

        if let Some(path) = path {
            sq.hint(format_args!(
                "Updated key written to {}.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:",
                path.display()))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert-file", path.display())
                .done();
        } else {
            sq.hint(format_args!(
                "To make the update effective, it has to be published \
                 so that others can find it."));
        }
   } else {
        // Import it into the key store.
        let fipr = cert.fingerprint();
        let result = if cert.is_tsk() {
            sq.import_key(cert, &mut Default::default()).err()
        } else {
            sq.import_cert(cert).err()
        };
        if let Some(err) = result {
            weprintln!("Error importing updated cert: {}", err);
            return Err(err);
        } else {
            sq.hint(format_args!(
                "Imported updated cert into the cert store.  \
                 To make the update effective, it has to be published \
                 so that others can find it, for example using:"))
                .sq().arg("network").arg("keyserver").arg("publish")
                .arg_value("--cert", fipr)
                .done();
        }
    }

    Ok(())
}
