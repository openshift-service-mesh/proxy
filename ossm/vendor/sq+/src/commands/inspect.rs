use std::convert::TryFrom;
use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use anyhow::Context;

use buffered_reader::{BufferedReader, Dup};

use sequoia_openpgp as openpgp;
use openpgp::{Fingerprint, KeyHandle, Packet, Result};
use openpgp::armor::ReaderMode;
use openpgp::cert::prelude::*;
use openpgp::packet::{
    Signature,
    key::PublicParts,
};
use openpgp::parse::{
    Cookie,
    Dearmor,
    Parse,
    PacketParserBuilder,
    PacketParserResult,
};
use openpgp::policy::{Policy, HashAlgoSecurity};
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::types::{
    KeyFlags,
    ReasonForRevocation,
    SignatureType,
};
use openpgp::serialize::Serialize;

use crate::Convert;

use crate::Sq;
use crate::one_line_error_chain;
use crate::SECONDS_IN_YEAR;
use crate::SECONDS_IN_DAY;

use crate::cli::inspect;
use crate::cli::types::FileOrStdout;
use crate::commands::packet::dump::PacketDumper;
use crate::common::NULL_POLICY;
use crate::common::PreferredUserID;
use crate::common::ui;
use crate::sq::TrustThreshold;

/// Width of the largest key of any key, value pair we emit.
const WIDTH: usize = 17;

pub fn dispatch(mut sq: Sq, c: inspect::Command)
    -> Result<()>
{
    // sq inspect does not have --output, but commands::inspect does.
    // Work around this mismatch by always creating a stdout output.
    let output_type = FileOrStdout::default();
    let output = &mut output_type.create_unsafe(&sq)?;

    let print_certifications = c.certifications;

    let input = c.input;
    let dump_bad_signatures = c.dump_bad_signatures;

    let mut bytes: Vec<u8> = Vec::new();
    if c.certs.is_empty() {
        if let Some(path) = input.inner() {
            if ! path.exists() &&
                format!("{}", input).parse::<KeyHandle>().is_ok()
            {
                weprintln!("The file {} does not exist, \
                            did you mean \"sq inspect --cert {}\"?",
                           input, input);
            }
        }

        inspect(&mut sq, input.open("OpenPGP or autocrypt data")?,
                Some(&input.to_string()), output,
                print_certifications, dump_bad_signatures)?;
    } else {
        for cert in sq.resolve_certs_or_fail(&c.certs, TrustThreshold::Full)? {
            // Include non-exportable signatures, etc.
            cert.serialize(&mut bytes).context("Serializing certificate")?;
        }

        let br = buffered_reader::Memory::with_cookie(
            &bytes, sequoia_openpgp::parse::Cookie::default());
        inspect(&mut sq, br, None, output,
                print_certifications, dump_bad_signatures)?;
    }

    Ok(())
}

/// Inspects OpenPGP data.
///
/// The data is read from `input`.  `input_filename` is the name of
/// the file, if available.  This is only used for display purposes.
/// The output is written to `output`.
///
/// If `print_certifications` is set, also shows information about
/// certifications.
pub fn inspect<'a, R>(sq: &mut Sq,
                      input: R,
                      input_filename: Option<&str>,
                      output: &mut Box<dyn std::io::Write + Send + Sync>,
                      print_certifications: bool,
                      dump_bad_signatures: bool)
    -> Result<Kind>
where
    R: BufferedReader<sequoia_openpgp::parse::Cookie> + 'a,
{
    let mut ppr =
        match openpgp::parse::PacketParser::from_buffered_reader(input)
    {
        Ok(pp) => pp,
        Err(e) => if e.downcast_ref()
            .map(|e: &io::Error| e.kind() == io::ErrorKind::UnexpectedEof)
            .unwrap_or(false)
        {
            if let Some(input_filename) = input_filename {
                write!(output, "{}: ", input_filename)?;
            }

            writeln!(output, "No OpenPGP data.")?;
            return Ok(Kind::NotOpenPGP);
        } else {
            return Err(e);
        }
    };

    let mut type_called = None;   // Did we print the type yet?

  loop {
    if let Some(input_filename) = input_filename {
        write!(output, "{}: ", input_filename)?;
    }

    let mut encrypted = false;    // Is it an encrypted message?
    let mut packets = Vec::new(); // Accumulator for packets.
    let mut pkesks = Vec::new();  // Accumulator for PKESKs.
    let mut n_skesks = 0;         // Number of SKESKs.
    let mut sigs = Vec::new();    // Accumulator for signatures.
    let mut literal_prefix = Vec::new();

    while let PacketParserResult::Some(mut pp) = ppr {
        match pp.packet {
            Packet::PublicKey(_) | Packet::SecretKey(_) => {
                if pp.possible_cert().is_err()
                    && pp.possible_keyring().is_ok()
                {
                    if type_called.is_none() {
                        writeln!(output, "OpenPGP Keyring.")?;
                        writeln!(output)?;
                        type_called = Some(Kind::Keyring);
                    }
                    let pp = openpgp::PacketPile::from(
                        std::mem::take(&mut packets));
                    let cert = openpgp::Cert::try_from(pp)?;
                    inspect_cert(
                        sq,
                        output,
                        &cert,
                        print_certifications,
                        dump_bad_signatures,
                    )?;
                }
            },
            Packet::Literal(_) => {
                pp.by_ref().take(40).read_to_end(&mut literal_prefix)?;
            },
            Packet::SEIP(_) => {
                encrypted = true;
            },
            _ => (),
        }

        let possible_keyring = pp.possible_keyring().is_ok();
        let (packet, ppr_) = pp.recurse()?;
        ppr = ppr_;

        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            Packet::SKESK(_) => n_skesks += 1,
            Packet::Signature(s) => if possible_keyring {
                packets.push(Packet::Signature(s))
            } else {
                sigs.push(s)
            },
            _ => packets.push(packet),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        let is_message = eof.is_message();
        let is_cert = eof.is_cert();
        let is_keyring = eof.is_keyring();

        // Now, the parser is exhausted, but we may find another
        // armored blob.  Note that this can only happen if the first
        // set of packets was also armored.
        let next_ppr =
            PacketParserBuilder::from_buffered_reader(eof.into_reader())
            .and_then(
                |builder| builder
                    .dearmor(Dearmor::Enabled(
                        ReaderMode::Tolerant(None)))
                    .build());

        if is_message.is_ok() {
            type_called = if encrypted {
                Some(Kind::EncryptedMessage)
            } else {
                Some(Kind::SignedMessage)
            };

            writeln!(output, "{}OpenPGP Message.",
                     match (encrypted, ! sigs.is_empty()) {
                         (false, false) => "",
                         (false, true) => "Signed ",
                         (true, false) => "Encrypted ",
                         (true, true) => "Encrypted and signed ",
                     })?;
            writeln!(output)?;
            if n_skesks > 0 {
                writeln!(output, "      Passwords: {}", n_skesks)?;
            }
            for pkesk in pkesks.iter() {
                writeln!(output, "      Recipient: {}",
                         pkesk.recipient().as_ref().map(ToString::to_string)
                         .unwrap_or_else(|| "<anonymous recipient>".into()))?;

                let recipient = if let Some(r) = pkesk.recipient() {
                    r
                } else {
                    continue;
                };

                // Lookup the certificate, if possible.  Prefer a
                // binding that is valid according to the current
                // policy.  Otherwise, fall back to the NULL policy.
                if let Ok(certs) = sq.lookup(Some(&recipient),
                                             None, true, true)
                    .or_else(|_| {
                        sq.lookup_with_policy(
                            Some(recipient),
                            None, true, true,
                            NULL_POLICY, sq.time)
                    })
                {
                    if certs.len() == 1 {
                        writeln!(output, "        Associated certificate:")?;
                    } else {
                        writeln!(output, "        Associated certificates:")?;
                    }

                    for cert in certs {
                        writeln!(output, "          {}",
                                 cert.fingerprint())?;
                        writeln!(output, "          {}",
                                 sq.best_userid(&cert, true).display())?;
                    }
                } else {
                    writeln!(output, "        Associated certificate not available")?;
                }
            }
            inspect_signatures(sq, output, &sigs)?;
            if ! literal_prefix.is_empty() {
                writeln!(output, "           Data: {}{}",
                         ui::Safe(&literal_prefix),
                         if literal_prefix.len() == 40 { "..." } else { "" })?;
            }

        } else if is_cert.is_ok() || is_keyring.is_ok() {
            let pp = openpgp::PacketPile::from(packets);
            let cert = openpgp::Cert::try_from(pp)?;

            type_called = if is_cert.is_ok() {
                if cert.is_tsk() {
                    Some(Kind::Key)
                } else {
                    Some(Kind::Cert)
                }
            } else {
                Some(Kind::Keyring)
            };

            inspect_cert(sq, output, &cert, print_certifications,
                         dump_bad_signatures)?;
        } else if packets.is_empty() && ! sigs.is_empty() {
            if sigs.iter().all(is_revocation_sig) {
                type_called = Some(Kind::RevocationCert);
                writeln!(output, "Revocation Certificate{}.",
                         if sigs.len() > 1 { "s" } else { "" })?;
                writeln!(output)?;
                for sig in sigs {
                    inspect_bare_revocation(sq, output, &sig)?;
                }
                writeln!(output, "           Note: \
                                  Signatures have NOT been verified!")?;
            } else {
                type_called = Some(Kind::DetachedSig);
                writeln!(output, "Detached signature{}.",
                         if sigs.len() > 1 { "s" } else { "" })?;
                writeln!(output)?;
                inspect_signatures(sq, output, &sigs)?;
            }
        } else if packets.is_empty() {
            type_called = Some(Kind::NotOpenPGP);
            writeln!(output, "No OpenPGP data.")?;
        } else {
            type_called = Some(Kind::Unknown);
            writeln!(output, "Unknown sequence of OpenPGP packets.")?;
            writeln!(output, "  Message: {}", is_message.as_ref().unwrap_err())?;
            writeln!(output, "  Cert: {}", is_cert.as_ref().unwrap_err())?;
            writeln!(output, "  Keyring: {}", is_keyring.as_ref().unwrap_err())?;
            writeln!(output)?;
            if let Some(filename) = input_filename {
                writeln!(output, "Hint: Try 'sq packet dump {}'",
                         filename)?;
            }
        }

        // See if there is another armor block.
        match next_ppr {
            Ok(ppr_) => {
                writeln!(output, "Note: There is another block of armored \
                                  OpenPGP data.")?;

                if is_message.is_ok() {
                    type_called = Some(Kind::NotOpenPGP);
                    writeln!(output, "Note: Data concatenated to a message is \
                                      likely an error.")?;
                } else if is_cert.is_ok() || is_keyring.is_ok() {
                    type_called = Some(Kind::Keyring);
                    writeln!(output, "Note: This is a non-standard extension \
                                      to OpenPGP.")?;
                }
                writeln!(output)?;

                ppr = ppr_;
                continue;
            },
            Err(_) => break,
        }
    } else {
        unreachable!()
    }
  }

    Ok(type_called.unwrap_or(Kind::Unknown))
}

/// Returns true iff all signatures in the cert are revocation
/// signatures.
fn is_revocation_sig(s: &Signature) -> bool {
    [
        SignatureType::KeyRevocation,
        SignatureType::SubkeyRevocation,
        SignatureType::CertificationRevocation,
    ].contains(&s.typ())
}

/// Returns true iff all signatures in the cert are revocation
/// signatures.
fn is_revocation_cert(c: &Cert) -> bool {
    c.primary_key().signatures().all(|s| s.typ() == SignatureType::KeyRevocation)
        && c.keys().subkeys().all(|skb| skb.signatures().all(
            |s| s.typ() == SignatureType::SubkeyRevocation))
        && c.userids().all(|uidb| uidb.signatures().all(
            |s| s.typ() == SignatureType::CertificationRevocation))
}

fn inspect_cert(
    sq: &mut Sq,
    output: &mut dyn io::Write,
    cert: &openpgp::Cert,
    print_certifications: bool,
    dump_bad_signatures: bool,
) -> Result<()> {
    if cert.is_tsk() {
        writeln!(output, "Transferable Secret Key.")?;
    } else if is_revocation_cert(&cert) {
        writeln!(output, "Revocation Certificate.")?;
    } else {
        writeln!(output, "OpenPGP Certificate.")?;
    }
    writeln!(output)?;
    writeln!(output, "{:>WIDTH$}: {}", "Fingerprint", cert.fingerprint())?;
    inspect_revocation(output, cert.revocation_status(sq.policy, sq.time))?;
    inspect_key(
        sq,
        output,
        cert.keys().next().unwrap(),
        print_certifications,
    )?;
    writeln!(output)?;

    for skb in cert.keys().subkeys() {
        writeln!(output, "{:>WIDTH$}: {}", "Subkey", skb.key().fingerprint())?;
        inspect_revocation(output, skb.revocation_status(sq.policy, sq.time))?;
        match skb.binding_signature(sq.policy, sq.time) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(sq.time, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_key(
            sq,
            output,
            skb.into(),
            print_certifications,
        )?;
        writeln!(output)?;
    }

    fn print_error_chain(output: &mut dyn io::Write, err: &anyhow::Error)
                         -> Result<()> {
        writeln!(output, "{:>WIDTH$}  Invalid: {}", "", err)?;
        for cause in err.chain().skip(1) {
            writeln!(output, "{:>WIDTH$}  because: {}", "", cause)?;
        }
        Ok(())
    }

    for uidb in cert.userids() {
        writeln!(output, "{:>WIDTH$}: {}", "UserID", uidb.userid())?;
        inspect_revocation(output, uidb.revocation_status(sq.policy, sq.time))?;
        match uidb.binding_signature(sq.policy, sq.time) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(sq.time, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(sq, output,
                               uidb.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for uab in cert.user_attributes() {
        writeln!(output, "{:>WIDTH$}: {:?}", "User attribute",
                 uab.user_attribute())?;
        inspect_revocation(output, uab.revocation_status(sq.policy, sq.time))?;
        match uab.binding_signature(sq.policy, sq.time) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(sq.time, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(sq, output,
                               uab.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for ub in cert.unknowns() {
        writeln!(output, "{:>WIDTH$}: {:?}", "Unknown component",
                 ub.unknown())?;
        match ub.binding_signature(sq.policy, sq.time) {
            Ok(sig) => {
                if let Err(e) = sig.signature_alive(sq.time, Duration::new(0, 0)) {
                    print_error_chain(output, &e)?;
                }
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(sq, output,
                               ub.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    if cert.bad_signatures().next().is_some() {
        if dump_bad_signatures {
            let width = terminal_size::terminal_size()
                .map(|(w, _)| w.0.into());

            let pd = PacketDumper::new(sq, width.unwrap_or(80), false);
            for bad in cert.bad_signatures() {
                writeln!(output, "{:>WIDTH$}:", "Bad Signature")?;
                pd.dump_signature(output, &format!("{:>WIDTH$}", ""), bad)?;
            }
        } else {
            writeln!(output, "{:>WIDTH$}: {}, use --dump-bad-signatures to list",
                     "Bad Signatures", cert.bad_signatures().count())?;
        }
    }

    Ok(())
}

fn inspect_key(
    sq: &mut Sq,
    output: &mut dyn io::Write,
    ka: ErasedKeyAmalgamation<PublicParts>,
    print_certifications: bool,
) -> Result<()> {
    let key = ka.key();
    let bundle = ka.bundle();

    let vka = match ka.with_policy(sq.policy, sq.time) {
        Ok(vka) => {
            if let Err(e) = vka.alive() {
                writeln!(output, "{:>WIDTH$}  Invalid: {}", "",
                         one_line_error_chain(&e))?;
            }
            Some(vka)
        },
        Err(e) => {
            writeln!(output, "{:>WIDTH$}  Invalid: {}", "",
                     one_line_error_chain(&e))?;
            None
        },
    };

    writeln!(output, "{:>WIDTH$}: {}", "Public-key algo", key.pk_algo())?;
    if let Some(bits) = key.mpis().bits() {
        writeln!(output, "{:>WIDTH$}: {} bits", "Public-key size", bits)?;
    }
    if let Some(secret) = key.optional_secret() {
        writeln!(output, "{:>WIDTH$}: {}", "Secret key",
                 if let SecretKeyMaterial::Unencrypted(_) = secret {
                     "Unencrypted"
                 } else {
                     "Encrypted"
                 })?;
    }
    writeln!(output, "{:>WIDTH$}: {}", "Creation time",
             key.creation_time().convert())?;
    if let Some(vka) = vka {
        if let Some(expires) = vka.key_validity_period() {
            let expiration_time = key.creation_time() + expires;
            writeln!(output, "{:>WIDTH$}: {} (creation time + {})",
                     "Expiration time",
                     expiration_time.convert(),
                     expires.convert())?;
        }

        if let Some(flags) = vka.key_flags().and_then(inspect_key_flags) {
            writeln!(output, "{:>WIDTH$}: {}", "Key flags", flags)?;
        }
    }
    inspect_certifications(sq, output,
                           bundle.certifications(),
                           print_certifications)?;

    Ok(())
}

/// Prints the revocation reasons.
fn print_reasons(output: &mut dyn io::Write,
                 third_party: bool, sigs: &[&Signature])
                 -> Result<()> {
    for sig in sigs {
        let (reason, message) = sig.reason_for_revocation()
            .map(|(r, m)| (r, Some(m)))
            .unwrap_or((ReasonForRevocation::Unspecified, None));

        writeln!(output, "{:>WIDTH$}   - {}", "", reason)?;
        writeln!(output, "{:>WIDTH$}     On: {}", "",
                 sig.signature_creation_time()
                 .expect("valid sigs have one").convert())?;
        if third_party {
            writeln!(output, "{:>WIDTH$}     Issued by{}", "",
                     if let Some(issuer)
                     = sig.get_issuers().into_iter().next()
                     {
                         format!(": {}", issuer)
                     } else {
                         " an unknown certificate".into()
                     })?;
        }
        if let Some(msg) = message {
            writeln!(output, "{:>WIDTH$}     Message: {}", "",
                     ui::Safe(msg))?;
        }
    }
    Ok(())
}

fn inspect_revocation(output: &mut dyn io::Write,
                      revoked: openpgp::types::RevocationStatus)
                      -> Result<()> {
    use openpgp::types::RevocationStatus::*;

    match revoked {
        Revoked(sigs) => {
            writeln!(output, "{:>WIDTH$}  Revoked:", "")?;
            print_reasons(output, false, &sigs)?;
        },
        CouldBe(sigs) => {
            writeln!(output, "{:>WIDTH$}  Possibly revoked:", "")?;
            print_reasons(output, true, &sigs)?;
        },
        NotAsFarAsWeKnow => (),
    }

    Ok(())
}

fn inspect_bare_revocation(sq: &mut Sq,
                           output: &mut dyn io::Write, sig: &Signature)
                           -> Result<()> {
    inspect_issuers(sq, output, &sig)?;
    writeln!(output, "{:>WIDTH$}  Possible revocation:", "")?;
    print_reasons(output, false, &[sig])?;
    writeln!(output)?;
    Ok(())
}

fn inspect_key_flags(flags: openpgp::types::KeyFlags) -> Option<String> {
    let mut capabilities = Vec::new();
    if flags.for_certification() {
        capabilities.push("certification")
    }
    if flags.for_signing() {
        capabilities.push("signing")
    }
    if flags.for_authentication() {
        capabilities.push("authentication")
    }
    if flags.for_transport_encryption() {
        capabilities.push("transport encryption")
    }
    if flags.for_storage_encryption() {
        capabilities.push("data-at-rest encryption")
    }
    if flags.is_group_key() {
        capabilities.push("group key")
    }
    if flags.is_split_key() {
        capabilities.push("split key")
    }

    if !capabilities.is_empty() {
        Some(capabilities.join(", "))
    } else {
        None
    }
}

fn inspect_signatures(sq: &mut Sq,
                      output: &mut dyn io::Write,
                      sigs: &[openpgp::packet::Signature]) -> Result<()> {
    use openpgp::types::SignatureType::*;
    for sig in sigs {
        match sig.typ() {
            Binary | Text => (),
            signature_type =>
                writeln!(output, "{:>WIDTH$}: {}", "Kind", signature_type)?,
        }

        inspect_issuers(sq, output, &sig)?;
    }
    if ! sigs.is_empty() {
        writeln!(output, "{:>WIDTH$}: {}", "Note",
                          "Signatures have NOT been verified!")?;
    }

    Ok(())
}

fn inspect_issuers(sq: &mut Sq,
                   output: &mut dyn io::Write,
                   sig: &Signature) -> Result<()> {
    emit_issuers(sq, |id| match id {
        Ok((kh, uid)) => {
            writeln!(output, "{:>WIDTH$}: {}", "Alleged signer", kh)?;
            writeln!(output, "{:>WIDTH$}  {}", "", uid.display())?;
            Ok(())
        },
        Err((kh, _, _)) => {
            writeln!(output, "{:>WIDTH$}: {}", "Alleged signer",
                     "signer's cert not found")?;
            writeln!(output, "{:>WIDTH$}  {}", "", kh)?;
            writeln!(output, "{:>WIDTH$}  {}", "", "(signature subkey)")?;
            Ok(())
        },
    }, sig)
}

fn emit_issuers<F>(sq: &mut Sq, mut emit: F, sig: &Signature)
                   -> Result<()>
where
    F: FnMut(std::result::Result<(Fingerprint, PreferredUserID),
                                 (KeyHandle, PreferredUserID, anyhow::Error)>)
             -> Result<()>,
{
    let for_signing = KeyFlags::empty().set_signing();

    let mut fps: Vec<_> = sig.issuer_fingerprints().collect();
    fps.sort();
    fps.dedup();
    let khs: Vec<KeyHandle> = fps.into_iter().map(|fp| fp.into()).collect();
    for kh in khs.iter() {
        match sq.best_userid_for(kh, for_signing.clone(), true) {
            (puid, Ok(cert)) => emit(Ok((cert.fingerprint(), puid)))?,
            (puid, Err(e)) => emit(Err((kh.clone(), puid, e)))?,
        }
    }

    let mut keyids: Vec<_> = sig.issuers().collect();
    keyids.sort();
    keyids.dedup();
    for keyid in keyids {
        let keyid = keyid.into();
        if ! khs.iter().any(|kh| kh.aliases(&keyid)) {
            match sq.best_userid_for(&keyid, for_signing.clone(), true) {
                (puid, Ok(cert)) => emit(Ok((cert.fingerprint(), puid)))?,
                (puid, Err(e)) => emit(Err((keyid, puid, e)))?,
            }
        }
    }

    Ok(())
}

fn inspect_certifications<'a, A>(sq: &mut Sq,
                                 output: &mut dyn io::Write,
                                 certs: A,
                                 print_certifications: bool)
    -> Result<()>
    where A: std::iter::Iterator<Item=&'a openpgp::packet::Signature>
{
    if print_certifications {
        let mut emit_warning = false;
        for sig in certs {
            let time = if let Some(time) = sig.signature_creation_time() {
                chrono::DateTime::<chrono::offset::Utc>::from(time)
            } else {
                // A signature must have a signature creation time
                // subpacket to be valid.  This signature is not
                // valid, so skip it.
                continue;
            };

            emit_warning = true;

            writeln!(output, "{:>WIDTH$}: Creation time: {}", "Certification",
                     time)?;

            if let Some(e) = sig.signature_expiration_time() {
                let e = chrono::DateTime::<chrono::offset::Utc>::from(e);
                let diff = e - time;
                let years = diff.num_seconds() / (SECONDS_IN_YEAR as i64);
                let rest = diff.num_seconds() - years * (SECONDS_IN_YEAR as i64);
                let days = rest / (SECONDS_IN_DAY as i64);
                let rest = rest - days * (SECONDS_IN_DAY as i64);

                writeln!(output, "{:>WIDTH$}  Expiration time: {} (after {}{}{}{}{})",
                         "",
                         e,
                         match years {
                             0 => "".into(),
                             1 => format!("{} year", years),
                             _ => format!("{} years", years),
                         },
                         if years != 0 && days != 0 { ", " } else { "" },
                         match days {
                             0 => "".into(),
                             1 => format!("{} day", days),
                             _ => format!("{} days", days),
                         },
                         if years == 0 && days != 0 && rest != 0 { ", " } else { "" },
                         if years == 0 {
                             match rest {
                                 0 => "".into(),
                                 1 => format!("{} second", rest),
                                 _ => format!("{} seconds", rest),
                             }
                         } else {
                             "".into()
                         })?;
            }

            if let Some((depth, amount)) = sig.trust_signature() {
                writeln!(output, "{:>WIDTH$}  Trust depth: {}", "",
                         depth)?;
                writeln!(output, "{:>WIDTH$}  Trust amount: {}", "",
                         amount)?;
            }
            for re in sig.regular_expressions() {
                if let Ok(re) = String::from_utf8(re.to_vec()) {
                    writeln!(output, "{:>WIDTH$}  Regular expression: {}", "",
                             ui::Safe(re))?;
                } else {
                    writeln!(output,
                             "{:>WIDTH$}  Regular expression (invalid UTF-8): {}",
                             "",
                             ui::Safe(re))?;
                }
            }

            emit_issuers(sq, |id| match id {
                Ok((kh, uid)) => {
                    writeln!(output, "{:>WIDTH$}  Alleged certifier: {}",
                             "", kh)?;
                    writeln!(output, "{:>WIDTH$}      {}", "", uid.display())?;
                    Ok(())
                },
                Err((kh, _, _)) => {
                    writeln!(output, "{:>WIDTH$}  Alleged certifier: {}",
                             "", "signer's cert not found")?;
                    writeln!(output, "{:>WIDTH$}      {}", "", kh)?;
                    writeln!(output, "{:>WIDTH$}      {}", "", "(signature subkey)")?;
                    Ok(())
                },
            }, sig)?;

            writeln!(output, "{:>WIDTH$}  Hash algorithm: {}",
                     "", sig.hash_algo())?;
            if let Err(err) = sq.policy.signature(
                sig, HashAlgoSecurity::CollisionResistance)
            {
                writeln!(output,
                         "{:>WIDTH$}  Certification is not valid according to \
                          the current policy:", "")?;
                writeln!(output, "{:>WIDTH$}  {}", "",
                         one_line_error_chain(&err))?;
            }
        }
        if emit_warning {
            writeln!(output,
                     "{:>WIDTH$}: Certifications have NOT been verified!",
                     "Note")?;
        }
    } else {
        let count = certs.count();
        if count > 0 {
            writeln!(output, "{:>WIDTH$}: {}, use --certifications to list",
                     "Certifications", count)?;
        }
    }

    Ok(())
}

/// Describes the data that `inspect` inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A certificate.
    Cert,

    /// A key.
    Key,

    /// A keyring.
    Keyring,

    /// A signed message.
    SignedMessage,

    /// An encrypted message.
    EncryptedMessage,

    /// A detached signature.
    DetachedSig,

    /// A revocation certificate.
    RevocationCert,

    /// Unknown packet sequence.
    Unknown,

    /// Data that could not be parsed as OpenPGP packets.
    NotOpenPGP,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Kind::Cert =>
                f.write_str("a certificate"),

            Kind::Key =>
                f.write_str("a key"),

            Kind::Keyring =>
                f.write_str("a keyring"),

            Kind::SignedMessage =>
                f.write_str("a signed message"),

            Kind::EncryptedMessage =>
                f.write_str("an encrypted message"),

            Kind::DetachedSig =>
                f.write_str("a detached signature"),

            Kind::RevocationCert =>
                f.write_str("a revocation certificate"),

            Kind::Unknown =>
                f.write_str("an unknown packet sequence"),

            Kind::NotOpenPGP =>
                f.write_str("non-OpenPGP data"),
        }
    }
}

impl Kind {
    /// Identifies OpenPGP data.
    ///
    /// Returns the kind and the original reader without any data
    /// consumed.
    pub fn identify<'a, T>(sq: &mut Sq, input: T)
                           -> Result<(Kind, Box<dyn BufferedReader<Cookie> + 'a>)>
    where
        T: BufferedReader<Cookie> + 'a,
    {
        let mut sink: Box<dyn io::Write + Send + Sync> =
            Box::new(io::Sink::default());
        let mut dup = Dup::with_cookie(input, Default::default());
        let kind = inspect(sq, &mut dup, None, &mut sink, false, false)?;
        Ok((kind, dup.into_boxed().into_inner().unwrap()))
    }

    /// Checks that `self` matches `expected`, or prints hints on what
    /// to do instead and returns an error.
    pub fn expect_or_else(&self,
                          sq: &Sq,
                          command: &str,
                          expected: Kind,
                          input_arg: &str,
                          input_path: Option<&Path>)
                          -> Result<()>
    {
        if self != &expected {
            let input_path_text =
                input_path.as_ref().map(|p| p.display().to_string())
                .unwrap_or_else(|| "stdin".into());
            let input_path_arg =
                input_path.map(|p| p.display().to_string())
                .unwrap_or_else(|| "-".into());

            let msg = format!(
                "Expected {} for {}, but {} is {}.",
                expected, input_arg, input_path_text, self);
            let mut hint = sq.hint(format_args!("{}", msg));

            match self {
                Kind::Cert => {
                    if command == "verify" {
                        hint = hint.hint(format_args!(
                            "To verify a message or signature using {}:",
                            input_path_text))
                            .sq().arg("verify")
                            .arg_value("--signer-file", &input_path_arg)
                        .done();
                    }

                    if command == "decrypt" {
                        hint = hint.hint(format_args!(
                            "To verify a message using {}:",
                            input_path_text))
                            .sq().arg("decrypt")
                            .arg_value("--signer-file", &input_path_arg)
                        .done();
                    }

                    hint.hint(format_args!(
                        "To import the cert {}:", input_path_text))
                        .sq().arg("cert").arg("import")
                        .arg(&input_path_arg)
                        .done();
                },

                Kind::Key => {
                    if command == "verify" {
                        hint = hint.hint(format_args!(
                            "To verify a message or signature using {}:",
                            input_path_text))
                            .sq().arg("verify")
                            .arg_value("--signer-file", &input_path_arg)
                        .done();
                    }

                    if command == "decrypt" {
                        hint = hint.hint(format_args!(
                            "To verify the signature on an encrypted message \
                             using {}:",
                            input_path_text))
                            .sq().arg("decrypt")
                            .arg_value("--signer-file", &input_path_arg)
                        .done();

                        hint = hint.hint(format_args!(
                            "To decrypt an encrypted message using {}:",
                            input_path_text))
                            .sq().arg("decrypt")
                            .arg_value("--recipient-file", &input_path_arg)
                        .done();
                    }

                    hint.hint(format_args!(
                        "To import the key {}:", input_path_text))
                        .sq().arg("key").arg("import")
                        .arg(&input_path_arg)
                        .done();
                },

                Kind::Keyring => {
                    hint.hint(format_args!(
                        "To import the certificates in {}:", input_path_text))
                        .sq().arg("cert").arg("import")
                        .arg(&input_path_arg)
                        .done();
                },

                Kind::SignedMessage => {
                    hint.hint(format_args!(
                        "To verify a signed message:"))
                        .sq().arg("verify")
                        .arg(&input_path_arg)
                        .done();
                },

                Kind::EncryptedMessage => {
                    hint.hint(format_args!(
                        "To decrypt an encrypted message:"))
                        .sq().arg("decrypt")
                        .arg(input_path_arg)
                        .done();
                },

                Kind::DetachedSig => {
                    hint.hint(format_args!(
                        "To verify the detached signature {}:",
                        input_path_text))
                        .sq().arg("verify")
                        .arg_value("--signature-file", &input_path_arg)
                        .arg("the-data-file")
                        .done();
                },

                Kind::RevocationCert => {
                    hint.hint(format_args!(
                        "To import the revocation certificate {}:",
                        input_path_text))
                        .sq().arg("cert").arg("import")
                        .arg(&input_path_arg)
                        .done();
                },

                Kind::Unknown => {
                    hint.hint(format_args!(
                        "To inspect the packet sequence in {}:",
                        input_path_text))
                        .sq().arg("packet").arg("dump")
                        .arg(&input_path_arg)
                        .done();
                },

                Kind::NotOpenPGP => {
                    if command == "verify" {
                        hint.hint(format_args!(
                            "To verify the detached signature \
                             over the data in {}:", input_path_text))
                            .sq().arg("verify")
                            .arg_value("--signature-file", "the-signature-file")
                            .arg(&input_path_arg)
                            .done();
                    }
                },
            }

            Err(anyhow::anyhow!("{}", msg))
        } else {
            Ok(())
        }
    }
}
