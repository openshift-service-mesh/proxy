use anyhow::Context as _;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use sequoia_openpgp as openpgp;
use openpgp::types::SymmetricAlgorithm;
use openpgp::fmt::hex;
use openpgp::KeyHandle;
use openpgp::crypto::{self, SessionKey, Decryptor};
use openpgp::{Fingerprint, Cert, KeyID, Result};
use openpgp::packet;
use openpgp::packet::prelude::*;
use openpgp::parse::{
    Parse,
    PacketParser,
    PacketParserResult,
};
use openpgp::parse::stream::{
    VerificationHelper, DecryptionHelper, DecryptorBuilder, MessageStructure,
};
use sequoia_openpgp::types::KeyFlags;

use sequoia_cert_store as cert_store;
use cert_store::store::StoreError;

use sequoia_keystore as keystore;

use crate::{
    cli,
    commands::{
        verify::VHelper,
    },
    common::password,
    common::ui,
    Sq,
    load_keys,
    sq::TrustThreshold,
};

pub fn dispatch(sq: Sq, command: cli::decrypt::Command) -> Result<()> {
    tracer!(TRACE, "decrypt::dispatch");

    let mut input = command.input.open("an encrypted message")?;
    let output_path = command.output.for_secrets();
    let mut output = output_path.create_safe(&sq)?;

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;

    // Fancy default for --signatures.  If you change this,
    // also change the description in the CLI definition.
    let signatures = command.signatures.unwrap_or_else(|| {
        if signers.is_empty() {
            // No certs are given for verification, use 0 as
            // threshold so we handle only-encrypted messages
            // gracefully.
            0
        } else {
            // At least one cert given, expect at least one
            // valid signature.
            1
        }
    });
    let secrets =
        load_keys(command.secret_key_file.iter())?;
    let session_keys = command.session_key;
    let result = decrypt(sq, &mut input, &mut output,
                         signatures, signers, secrets,
                         command.dump_session_key,
                         session_keys);
    if result.is_err() {
        if let Some(path) = output_path.path() {
            // Drop output here so that the file is persisted and
            // can be deleted.
            drop(output);

            if let Err(err) = std::fs::remove_file(path) {
                weprintln!("Decryption failed, failed to remove \
                            output saved to {}: {}",
                           path.display(), err);
            }
        }
    }

    result
}

pub struct Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    vhelper: VHelper<'c, 'store, 'rstore>,
    secret_keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>,
    key_identities: HashMap<KeyID, Arc<Cert>>,
    session_keys: Vec<cli::types::SessionKey>,
    dump_session_key: bool,

    /// The fingerprint of the public key that we used to the decrypt
    /// the message.  If None and decryption was success then we
    /// decrypted it in some other.
    decryptor: RefCell<Option<Fingerprint>>,
}

impl<'c, 'store, 'rstore> std::ops::Deref for Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    type Target = VHelper<'c, 'store, 'rstore>;

    fn deref(&self) -> &Self::Target {
        &self.vhelper
    }
}

impl<'c, 'store, 'rstore> std::ops::DerefMut for Helper<'c, 'store, 'rstore> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vhelper
    }
}

impl<'c, 'store, 'rstore> Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    pub fn new(sq: &'c Sq<'store, 'rstore>,
               signatures: usize, certs: Vec<Cert>, secrets: Vec<Cert>,
               session_keys: Vec<cli::types::SessionKey>,
               dump_session_key: bool)
               -> Self
    {
        let mut keys: HashMap<KeyID, (Cert, Key<key::SecretParts, key::UnspecifiedRole>)>
            = HashMap::new();
        let mut identities: HashMap<KeyID, Arc<Cert>> = HashMap::new();
        for tsk in secrets {
            let cert = Arc::new(tsk.clone().strip_secret_key_material());
            for ka in tsk.keys().secret()
                // XXX: Should use the message's creation time that we do not know.
                .with_policy(sq.policy, None)
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().fingerprint().into();
                let key = ka.key();
                keys.insert(id.clone(), (tsk.clone(), key.clone()));
                identities.insert(id.clone(), cert.clone());
            }
        }

        Helper {
            vhelper: VHelper::new(sq, signatures, certs),
            secret_keys: keys,
            key_identities: identities,
            session_keys,
            dump_session_key,
            decryptor: RefCell::new(None),
        }
    }

    /// Checks if a session key can decrypt the packet parser using
    /// `decrypt`.
    fn try_session_key(&self, fpr: &Fingerprint,
                       algo: Option<SymmetricAlgorithm>, sk: SessionKey,
                       decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
                       -> Option<Option<Cert>>
    {
        if decrypt(algo, &sk) {
            if self.dump_session_key {
                weprintln!("Session key: {}", hex::encode(&sk));
            }

            // XXX: make key identities map to certs, and failing that
            // look into the cert store.
            let cert = self.key_identities.get(&KeyID::from(fpr)).cloned();
            if let Some(cert) = &cert {
                // Prefer the reverse-mapped identity.
                self.decryptor.replace(Some(cert.fingerprint()));
            } else {
                // But fall back to the public key's fingerprint.
                self.decryptor.replace(Some(fpr.clone()));
            }
            Some(cert.map(|c| (*c).clone()))
        } else {
            None
        }
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    fn try_decrypt(&self, pkesk: &PKESK,
                   sym_algo: Option<SymmetricAlgorithm>,
                   mut keypair: Box<dyn crypto::Decryptor>,
                   decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
                   -> Option<Option<Cert>>
    {
        let fpr = keypair.public().fingerprint();
        let (sym_algo, sk) = pkesk.decrypt(&mut *keypair, sym_algo)?;
        self.try_session_key(&fpr, sym_algo, sk, decrypt)
    }

    /// Prints what certificate was used to decrypt the message.
    fn print_status(&self) {
        make_qprintln!(self.quiet);

        let decryptor = self.decryptor.borrow();
        if let Some(ref fpr) = *decryptor {
            let kh = KeyHandle::from(fpr);

            if let Ok(cert) = self.sq.lookup_one(kh, None, true) {
                qprintln!("Decrypted by {}, {}",
                          cert.fingerprint(),
                          self.sq.best_userid(&cert, true).display());
            } else {
                qprintln!("Decrypted by {}, unknown", fpr);
            }
        }
    }
}

impl<'c, 'store, 'rstore> VerificationHelper for Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.vhelper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.vhelper.check(structure)
    }
}

impl<'c, 'store, 'rstore> DecryptionHelper for Helper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    fn decrypt(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
               sym_algo: Option<SymmetricAlgorithm>,
               decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
               -> openpgp::Result<Option<Cert>>
    {
        make_qprintln!(self.quiet);

        // Before anything else, try the session keys
        for sk in &self.session_keys {
            let decrypted = if let Some(sa) = sk.symmetric_algo {
                decrypt(Some(sa), &sk.session_key)
            } else {
                // We don't know which algorithm to use,
                // try to find one that decrypts the message.
                (1u8..=19)
                    .map(SymmetricAlgorithm::from)
                    .any(|sa| decrypt(Some(sa), &sk.session_key))
            };
            if decrypted {
                qprintln!("Encrypted with Session Key {}",
                          sk.display_sensitive());
                return Ok(None);
            }
        }

        // Now, we try the secret keys that the user supplied on the
        // command line.

        let mut decrypt_key = |slf: &Self, pkesk, cert, key: &Key<_, _>, prompt: bool| {
            slf.vhelper.sq.decrypt_key(Some(cert), key.clone(), prompt, true)
                .ok()
                .and_then(|key| {
                    let keypair = Box::new(key.into_keypair()
                        .expect("decrypted secret key material"));

                    slf.try_decrypt(pkesk, sym_algo, keypair, decrypt)
                })
        };

        // First, we try those keys that we can use without prompting
        // for a password.
        for pkesk in pkesks {
            let keyid = pkesk.recipient().map(KeyID::from)
                .unwrap_or_else(KeyID::wildcard);
            if let Some((cert, key)) = self.secret_keys.get(&keyid) {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false) {
                    return Ok(fp);
                }
            }
        }

        // Second, we try those keys that are encrypted.
        for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient().map(KeyID::from);
            if let Some((cert, key)) = keyid.as_ref()
                .and_then(|k| self.secret_keys.get(k))
            {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true) {
                    return Ok(fp);
                }
            }
        }

        // Third, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, false) {
                    return Ok(fp);
                }
            }
        }

        // Fourth, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that are encrypted.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            for (cert, key) in self.secret_keys.values() {
                if let Some(fp) = decrypt_key(self, pkesk, cert, key, true) {
                    return Ok(fp);
                }
            }
        }

        // Try the key store.
        match self.vhelper.sq.key_store_or_else() {
            Ok(ks) => {
                let mut ks = ks.lock().unwrap();
                match ks.decrypt(&pkesks[..]) {
                    // Success!
                    Ok((_i, fpr, sym_algo, sk)) => {
                        if let Some(fp) =
                            self.try_session_key(
                                &fpr, sym_algo, sk, decrypt)
                        {
                            return Ok(fp);
                        }
                    }

                    Err(err) => {
                        match err.downcast() {
                            Ok(keystore::Error::InaccessibleDecryptionKey(keys)) => {
                                for key_status in keys.into_iter() {
                                    let pkesk = key_status.pkesk().clone();
                                    let mut key = key_status.into_key();
                                    let keyid = key.keyid();
                                    let (userid, _) = self.sq.best_userid_for(
                                        &KeyHandle::from(&keyid),
                                        KeyFlags::empty()
                                            .set_storage_encryption()
                                            .set_transport_encryption(),
                                        true);

                                    loop {
                                        if self.sq.batch {
                                            eprintln!(
                                                "{}, {} is locked, but not \
                                                 prompting for password, \
                                                 because you passed --batch.",
                                                keyid, userid.display());
                                            break;
                                        }

                                        match password::prompt_to_unlock_or_cancel(
                                            self.sq,
                                            &format!("{}, {}", keyid,
                                                     userid.display()))
                                        {
                                            Err(err) => {
                                                return Err(err).context(
                                                    "Prompting for password");
                                            }
                                            Ok(Some(password)) => {
                                                if let Err(_err) = key.unlock(password) {
                                                    weprintln!("Bad password.");
                                                    continue;
                                                }
                                            }
                                            Ok(None) => {
                                                // Cancelled.
                                                weprintln!("Skipping {}, {}",
                                                           keyid,
                                                           userid.display());
                                                break;
                                            }
                                        }

                                        let keypair = Box::new(key);
                                        if let Some(fp) = self.try_decrypt(
                                            &pkesk, sym_algo, keypair, decrypt)
                                        {
                                            return Ok(fp);
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                            // Failed to decrypt using the keystore.
                            Ok(_err) => (),
                            Err(_err) => (),
                        }
                    }
                }
            }
            Err(err) => {
                weprintln!("Warning: unable to connect to keystore: {}",
                           err);
            }
        }

        if skesks.is_empty() {
            weprintln!("No key to decrypt message.  The message appears \
                        to be encrypted to:");
            weprintln!();

            for recipient in pkesks.iter().map(|p| p.recipient()) {
                if let Some(r) = recipient {
                    let certs = self.sq.lookup(
                        std::iter::once(&r),
                        Some(KeyFlags::empty()
                             .set_storage_encryption()
                             .set_transport_encryption()),
                        false,
                        true);

                    match certs {
                        Ok(certs) => {
                            for cert in certs {
                                ui::emit_cert(&mut io::stderr(), self.sq, &cert)?;
                            }
                        }
                        Err(err) => {
                            if let Some(StoreError::NotFound(_))
                                = err.downcast_ref()
                            {
                                weprintln!(initial_indent = " - ",
                                           "{}, certificate not found", r);
                            } else {
                                weprintln!(initial_indent = " - ",
                                           "{}, error looking up certificate: {}",
                                           r, err);
                            }
                        }
                    }
                } else {
                    weprintln!(initial_indent = " - ",
                               "anonymous recipient, certificate not found");
                }
            }

            weprintln!();
            return Err(anyhow::anyhow!("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.  Before
        // prompting, try all passwords supplied on the cli.
        for password in self.sq.password_cache.lock().unwrap().iter() {
            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    if self.dump_session_key {
                        weprintln!("Session key: {}", hex::encode(&sk));
                    }
                    return Ok(None);
                }
            }
        }

        // Now prompt for passwords.
        let mut first = true;
        loop {
            let password = password::prompt_to_unlock(
                self.vhelper.sq, "the message")?;

            for skesk in skesks {
                if let Some(sk) = skesk.decrypt(&password).ok()
                    .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
                {
                    if self.dump_session_key {
                        weprintln!("Session key: {}", hex::encode(&sk));
                    }
                    return Ok(None);
                }
            }

            if password.map(|p| p.is_empty()) {
                break Err(anyhow::anyhow!("Decryption failed."));
            }

            if first {
                weprintln!("Incorrect password.  \
                            Hint: enter empty password to cancel.");
                first = false;
            } else {
                weprintln!("Incorrect password.");
            }
        }
    }
}

// Allow too many arguments now, should be reworked later
#[allow(clippy::too_many_arguments)]
pub fn decrypt(sq: Sq,
               input: &mut (dyn io::Read + Sync + Send),
               output: &mut dyn io::Write,
               signatures: usize, certs: Vec<Cert>, secrets: Vec<Cert>,
               dump_session_key: bool,
               sk: Vec<cli::types::SessionKey>)
               -> Result<()> {
    let helper = Helper::new(&sq, signatures, certs,
                             secrets, sk, dump_session_key);
    let mut decryptor = DecryptorBuilder::from_reader(input)?
        .with_policy(sq.policy, None, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output).context("Decryption failed")?;

    let helper = decryptor.into_helper();
    helper.print_status();
    helper.vhelper.print_status();
    Ok(())
}

pub fn decrypt_unwrap(sq: Sq,
                      input: &mut (dyn io::Read + Sync + Send),
                      output: &mut dyn io::Write,
                      secrets: Vec<Cert>,
                      session_keys: Vec<cli::types::SessionKey>,
                      dump_session_key: bool)
                      -> Result<()>
{
    let mut helper = Helper::new(&sq, 0, Vec::new(), secrets,
                                 session_keys,
                                 dump_session_key);

    let mut ppr = PacketParser::from_reader(input)?;

    let mut pkesks: Vec<packet::PKESK> = Vec::new();
    let mut skesks: Vec<packet::SKESK> = Vec::new();
    while let PacketParserResult::Some(mut pp) = ppr {
        let sym_algo_hint = match &pp.packet {
            Packet::SEIP(SEIP::V2(seip)) => Some(seip.symmetric_algo()),
            _ => None,
        };

        match pp.packet {
            Packet::SEIP(_) => {
                {
                    let mut decrypt = |algo, secret: &SessionKey| {
                        pp.decrypt(algo, secret).is_ok()
                    };
                    helper.decrypt(&pkesks[..], &skesks[..], sym_algo_hint,
                                   &mut decrypt)?;
                }
                if ! pp.processed() {
                    return Err(
                        openpgp::Error::MissingSessionKey(
                            "No session key".into()).into());
                }

                io::copy(&mut pp, output)?;
                return Ok(());
            },
            #[allow(deprecated)]
            Packet::MDC(ref mdc) => if ! mdc.valid() {
                return Err(openpgp::Error::ManipulatedMessage.into());
            },
            _ => (),
        }

        let (p, ppr_tmp) = pp.recurse()?;
        match p {
            Packet::PKESK(pkesk) => pkesks.push(pkesk),
            Packet::SKESK(skesk) => skesks.push(skesk),
            _ => (),
        }
        ppr = ppr_tmp;
    }

    Ok(())
}
