use std::{
    collections::btree_map::{BTreeMap, Entry},
    io,
    path::PathBuf,
};
use std::ops::Deref;
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    armor,
    cert::{
        Cert,
        CertParser,
    },
    Fingerprint,
    KeyHandle,
    KeyID,
    packet::{
        Packet,
        UserID,
        UserAttribute,
        Key,
        Signature,
        Tag,
        key,
    },
    parse::{
        PacketParser,
        PacketParserResult,
    },
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    Sq,
    Model,
    cli::types::FileOrStdout,
    common::file::PartFileWriter,
    output::KeyringListItem,
};

use crate::cli::keyring;
use crate::cli::types::StdinWarning;

pub fn dispatch(sq: Sq, c: keyring::Command) -> Result<()> {
    use keyring::Subcommands::*;
    match c.subcommand {
        Filter(command) => {
            let any_uid_predicates =
                ! command.userid.is_empty()
                || !command.name.is_empty()
                || !command.email.is_empty()
                || !command.domain.is_empty();
            let uid_predicate = |uid: &UserID| {
                let mut keep = false;

                for userid in &command.userid {
                    keep |= uid.value() == userid.as_bytes();
                }

                for name in &command.name {
                    keep |= uid
                        .name().unwrap_or(None)
                        .map(|n| n == name)
                        .unwrap_or(false);
                }

                for email in &command.email {
                    keep |= uid
                        .email().unwrap_or(None)
                        .map(|n| n == email)
                        .unwrap_or(false);
                }

                for domain in &command.domain {
                    keep |= uid
                        .email().unwrap_or(None)
                        .map(|n| n.ends_with(&format!("@{}", domain)))
                        .unwrap_or(false);
                }

                keep
            };

            let any_ua_predicates = false;
            let ua_predicate = |_ua: &UserAttribute| false;

            let any_cert_predicates = ! command.cert.is_empty();
            let cert_predicate = |key: &Key<_, key::PrimaryRole>| {
                let mut keep = false;

                for handle in &command.cert {
                    keep |= handle.aliases(key.key_handle());
                }

                keep
            };

            let any_key_predicates = ! command.key.is_empty();
            let key_predicate = |key: &Key<_, key::SubordinateRole>| {
                let mut keep = false;

                for handle in &command.key {
                    keep |= handle.aliases(key.key_handle());
                }

                keep
            };

            let filter_fn = |c: Cert| -> Option<Cert> {
                if ! (any_uid_predicates
                      || any_ua_predicates
                      || any_cert_predicates
                      || any_key_predicates) {
                    // If there are no filters, pass it through.
                    Some(c)
                } else if ! (c.userids().any(|c| uid_predicate(c.userid()))
                             || c.user_attributes().any(|c| ua_predicate(c.user_attribute()))
                             || cert_predicate(c.primary_key().key())
                             || key_predicate(c.primary_key().key().role_as_subordinate())
                             || c.keys().subkeys().any(|c| key_predicate(c.key()))) {
                    None
                } else if command.prune_certs {
                    let c = c
                        .retain_userids(|c| {
                            ! any_uid_predicates || uid_predicate(c.userid())
                        })
                        .retain_user_attributes(|c| {
                            ! any_ua_predicates || ua_predicate(c.user_attribute())
                        })
                        .retain_subkeys(|c| {
                            ! any_key_predicates || key_predicate(c.key())
                        });
                    if (c.userids().next().is_none()
                        && c.user_attributes().next().is_none()
                        && c.keys().subkeys().next().is_none())
                        || ((any_key_predicates
                             && c.keys().subkeys().next().is_none())
                            && (any_cert_predicates
                                && ! cert_predicate(c.primary_key().key())))
                    {
                        // We stripped all components, omit this cert.
                        None
                    } else {
                        Some(c)
                    }
                } else {
                    Some(c)
                }
            };

            filter(&sq, command.input, command.output, filter_fn,
                   false, command.to_certificate)
        },
        Merge(c) =>
            merge(&sq, c.input, c.output, false),
        List(c) => {
            let mut input = c.input.open("OpenPGP certificates")?;
            list(sq, &mut input, c.all_userids)
        },
        Split(c) => {
            let mut input = c.input.open("OpenPGP certificates")?;
            let prefix =
            // The prefix is either specified explicitly...
                c.prefix.unwrap_or(
                    // ... or we derive it from the input file...
                    c.input.and_then(|x| {
                        // (but only use the filename)
                        x.file_name().map(|f|
                            String::from(f.to_string_lossy())
                        )
                    })
                    // ... or we use a generic prefix...
                        .unwrap_or_else(|| String::from("output"))
                    // ... finally, add a hyphen to the derived prefix.
                        + "-");
            split(&mut input, &prefix, false)
        },
    }
}

/// Joins certificates and keyrings into a keyring, applying a filter.
fn filter<F>(sq: &Sq, inputs: Vec<PathBuf>, output: FileOrStdout,
             mut filter: F,
             binary: bool,
             to_certificate: bool)
             -> Result<()>
    where F: FnMut(Cert) -> Option<Cert>,
{
    let mut certs = Vec::new();

    if !inputs.is_empty() {
        for name in inputs {
            for cert in CertParser::from_file(name.deref())? {
                match cert {
                    Ok(c) => certs.push(c),
                    Err(e) =>
                        weprintln!("Malformed certificate in keyring {}: {}",
                                   name.display(), e),
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(StdinWarning::certs())? {
            match cert {
                Ok(c) => certs.push(c),
                Err(e) =>
                    weprintln!("Malformed certificate in keyring: {}", e),
            }
        }
    }

    let mut output = output.for_secrets().create_pgp_safe(
        &sq,
        binary,
        if ! to_certificate && certs.iter().any(|c| c.is_tsk()) {
            armor::Kind::SecretKey
        } else {
            armor::Kind::PublicKey
        },
    )?;

    for cert in certs {
        if let Some(cert) = filter(cert) {
            if to_certificate {
                cert.serialize(&mut output)?;
            } else {
                cert.as_tsk().serialize(&mut output)?;
            }
        }
    }
    output.finalize()?;

    Ok(())
}

/// Lists certs in a keyring.
fn list(sq: Sq,
        input: &mut (dyn io::Read + Sync + Send),
        list_all_uids: bool)
        -> Result<()>
{
    let mut certs = vec![];
    let iter = CertParser::from_reader(input)?
        .map(|item| KeyringListItem::from_cert_with_sq(item, &sq));
    for item in iter {
        certs.push(item);
    }
    let list = Model::keyring_list(certs, list_all_uids)?;
    list.write(&mut std::io::stdout())?;
    Ok(())
}

/// Splits a keyring into individual certs.
fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str, binary: bool)
         -> Result<()> {
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let (filename, cert, has_secrets) = match cert {
            Ok(cert) => {
                let filename = format!(
                    "{}{}-{:X}",
                    prefix,
                    i,
                    cert.fingerprint());
                let has_secrets = cert.is_tsk();
                (filename, Ok(cert), has_secrets)
            },
            Err(mut e) => if let Some(openpgp::Error::UnsupportedCert(m, p)) =
                e.downcast_mut::<openpgp::Error>()
            {
                // We didn't understand the cert.  But, we can still
                // write it out!
                let filename = format!(
                    "{}{}-{}",
                    prefix,
                    i,
                    to_filename_fragment(m).unwrap_or_else(|| "unknown".to_string()));
                let has_secrets = p.iter()
                    .any(|p|
                        p.tag() == Tag::SecretKey || p.tag() == Tag::SecretSubkey);
                (filename, Err(std::mem::take(p)), has_secrets)
            } else {
                return Err(e.context("Malformed certificate in keyring"));
            },
        };

        // Try to be more helpful by including the first userid in the
        // filename.
        let mut sink = if let Some(f) = cert.as_ref().ok()
            .and_then(|cert| cert.userids().next())
            .and_then(|uid| uid.userid().email().unwrap_or(None).map(|e| e.to_string()))
            .and_then(to_filename_fragment)
        {
            let filename_email = format!("{}-{}", filename, f);
            if let Ok(s) = PartFileWriter::create_with_restricted_permissions(
                filename_email, has_secrets) {
                s
            } else {
                // Degrade gracefully in case our sanitization
                // produced an invalid filename on this system.
                PartFileWriter::create_with_restricted_permissions(
                    &filename, has_secrets)
                    .context(format!("Writing cert to {:?} failed", filename))?
            }
        } else {
            PartFileWriter::create_with_restricted_permissions(
                &filename, has_secrets)
                .context(format!("Writing cert to {:?} failed", filename))?
        };

        if binary {
            match cert {
                Ok(cert) => cert.as_tsk().serialize(&mut sink)?,
                Err(packets) => for p in packets {
                    p.serialize(&mut sink)?;
                },
            }
        } else {
            use sequoia_openpgp::serialize::stream::{Message, Armorer};
            let message = Message::new(sink);
            let mut message = Armorer::new(message)
                .kind(if has_secrets {
                    armor::Kind::SecretKey
                } else {
                    armor::Kind::PublicKey
                })
                .build()?;
            match cert {
                Ok(cert) => cert.as_tsk().serialize(&mut message)?,
                Err(packets) => for p in packets {
                    p.serialize(&mut message)?;
                },
            }
            message.finalize()?;
        }
    }
    Ok(())
}

/// Merge multiple keyrings.
fn merge(sq: &Sq, inputs: Vec<PathBuf>, output: FileOrStdout,
         binary: bool)
         -> Result<()>
{
    let mut certs: BTreeMap<Fingerprint, Option<Cert>> = BTreeMap::new();
    let mut revocations: Vec<(Signature, String)> = Vec::new();

    let inputs: Box<dyn Iterator<Item = _>> = if inputs.is_empty() {
        Box::new(std::iter::once(
            ("stdin".to_string(),
             PacketParser::from_reader(StdinWarning::certs()))))
    } else {
        Box::new(
            inputs.into_iter()
                .map(|name| {
                    (name.display().to_string(),
                     PacketParser::from_file(&name))
                }))
    };

    for (name, result) in inputs {
        let parser = result.with_context(|| format!("Opening {}", name))?;

        // First see if we have a bare revocation certificate.
        let mut is_sig = false;
        if let PacketParserResult::Some(ref pp) = parser {
            if let Packet::Signature(_) = pp.packet {
                is_sig = true;
            }
        }
        if is_sig {
            // The first packet is a sig.  Make sure it is *only* a
            // sig.
            let sig = if let PacketParserResult::Some(pp) = parser {
                let (packet, next_ppr) = pp.next()?;

                let sig = if let Packet::Signature(sig) = packet {
                    sig
                } else {
                    return Err(anyhow::anyhow!(
                        "{}: Not a revocation certificate: got a {}.",
                        name, packet.tag()));
                };

                if let PacketParserResult::Some(_) = next_ppr {
                    return Err(anyhow::anyhow!(
                        "{}: Not a revocation certificate: \
                         got more than one packet.",
                        name));
                }

                sig
            } else {
                return Err(anyhow::anyhow!(
                    "{}: Not a bare revocation certificate.",
                    name));
            };

            revocations.push((sig.clone(), name));
            continue;
        }

        // Parse it like its a keyring.
        for cert in CertParser::from(parser) {
            let cert = cert.context(
                format!("Read a malformed certificate from {:?}", name))?;
            match certs.entry(cert.fingerprint()) {
                e @ Entry::Vacant(_) => {
                    e.or_insert(Some(cert));
                }
                Entry::Occupied(mut e) => {
                    let e = e.get_mut();
                    let curr = e.take().unwrap();
                    *e = Some(curr.merge_public_and_secret(cert)
                              .expect("Same certificate"));
                }
            }
        }
    }

    if ! revocations.is_empty() {
        // A map from key ID to fingerprint.
        //
        // This doesn't deal with colliding key IDs, but second
        // pre-images are not feasible, so this isn't a problem in
        // practice.
        let by_keyid: BTreeMap<KeyID, Fingerprint>
            = BTreeMap::from_iter(certs.values().filter_map(|cert| {
                cert.as_ref().map(|cert| {
                    (cert.keyid(), cert.fingerprint())
                })
            }));

        let mut die = false;
        let mut missing = Vec::new();

        'next_rev: for (sig, name) in revocations {
            let issuers = sig.get_issuers();

            let mut bad = None;

            for issuer in issuers.iter() {
                let cert = match issuer {
                    KeyHandle::Fingerprint(fpr) => {
                        certs.get_mut(fpr)
                    }
                    KeyHandle::KeyID(keyid) => {
                        by_keyid.get(keyid)
                            .and_then(|fpr| certs.get_mut(fpr))
                    }
                };

                let cert = if let Some(Some(cert)) = cert {
                    cert
                } else {
                    continue;
                };

                match sig.clone().verify_primary_key_revocation(
                    cert.primary_key().key(),
                    cert.primary_key().key())
                {
                    Ok(()) => {
                        *cert = cert.clone().insert_packets(sig.clone())?.0;
                        continue 'next_rev;
                    }
                    Err(err) => {
                        bad = Some((issuer, name.clone(), err));
                    }
                }
            }

            if let Some((_sig, name, err)) = bad {
                weprintln!("Could not add revocation certificate from {} \
                            to certificate: {}",
                           name, err);
                die = true;
            } else {
                missing.push((issuers[0].clone(), name.clone()));
                die = true;
            }
        }

        match missing.as_slice() {
            [] => (),
            [(issuer, name)] => {
                weprintln!("Couldn't merge revocation certificate \
                            from {}: missing {}.",
                           name, issuer);
            }
            _ => {
                weprintln!("Couldn't some merge revocation certificates:");
                for (issuer, name) in missing.into_iter() {
                    weprintln!("  - {}: missing {}",
                               name, issuer);
                }
            }
        }

        if die {
            return Err(anyhow::anyhow!(
                "Failed to merge some revocation certificates"));
        }
    }

    let mut output = output.for_secrets().create_pgp_safe(
        &sq,
        binary,
        if certs.values().any(|c| c.as_ref().map(Cert::is_tsk).unwrap_or(false))
        {
            armor::Kind::SecretKey
        } else {
            armor::Kind::PublicKey
        },
    )?;

    for cert in certs.values().filter_map(|v| v.as_ref()) {
        cert.as_tsk().serialize(&mut output)?;
    }
    output.finalize()?;

    Ok(())
}

/// Sanitizes a string to a safe filename fragment.
fn to_filename_fragment<S: AsRef<str>>(s: S) -> Option<String> {
    let mut r = String::with_capacity(s.as_ref().len());

    s.as_ref().chars().filter_map(|c| match c {
        '/' | ':' | '\\' => None,
        c if c.is_ascii_whitespace() => None,
        c if c.is_ascii() => Some(c),
        _ => None,
    }).for_each(|c| r.push(c));

    if !r.is_empty() {
        Some(r)
    } else {
        None
    }
}
