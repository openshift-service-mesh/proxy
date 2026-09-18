use anyhow::Context as _;
use std::fs;
use std::io;
use std::path::PathBuf;
use tempfile::NamedTempFile;

use buffered_reader::BufferedReader;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::crypto;
use openpgp::{Packet, Result};
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::parse::{
    Cookie,
    Parse,
    PacketParserResult,
};
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{
    Message, Armorer, Signer, LiteralWriter,
};
use openpgp::types::SignatureType;


use crate::Sq;

use crate::cli;
use crate::cli::sign::Mode;
use crate::cli::types::FileOrStdin;
use crate::cli::types::FileOrStdout;
use crate::sq::TrustThreshold;

mod merge_signatures;
use merge_signatures::merge_signatures;

pub fn dispatch(sq: Sq, command: cli::sign::Command) -> Result<()> {
    tracer!(TRACE, "sign::dispatch");

    let mut input = command.input.open("the data to sign")?;
    let output = &command.output;
    let detached = &command.detached;
    let binary = command.binary;
    let append = command.append;
    let notarize = command.notarize;
    if notarize {
        return Err(anyhow::anyhow!("Notarizing messages is not supported."));
    }

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;
    let signers = sq.get_signing_keys(&signers, None)?;
    if signers.is_empty() && command.merge.is_none() {
        return Err(anyhow::anyhow!("No signing keys found"));
    }

    let notations = command.signature_notations.parse()?;

    if let Some(merge) = command.merge {
        let output = output.create_pgp_safe(
            &sq,
            binary,
            armor::Kind::Message,
        )?;
        let data: FileOrStdin = merge.into();
        let mut input2 = data.open("OpenPGP signatures")?;
        return merge_signatures(&mut input, &mut input2, output);
    }

    if command.cleartext {
        let output = output.create_safe(&sq)?;
        clearsign(sq, input, output, signers, &notations)?;
    } else {
        sign(sq,
             &mut input,
             detached.as_ref().unwrap_or(output),
             signers,
             command.mode,
             detached.is_some(),
             binary,
             append,
             notarize,
             &notations)?;
    }

    Ok(())
}

pub fn sign<'a, 'store, 'rstore>(
    sq: Sq<'store, 'rstore>,
    input: &'a mut (dyn BufferedReader<Cookie> + Sync + Send),
    output: &'a FileOrStdout,
    signers: Vec<(openpgp::Cert, Box<dyn crypto::Signer + Send + Sync>)>,
    mode: Mode,
    detached: bool,
    binary: bool,
    append: bool,
    notarize: bool,
    notations: &'a [(bool, NotationData)])
    -> Result<()>
{
    match (detached, append|notarize) {
        (_, false) | (true, true) =>
            sign_data(sq,
                      input,
                      output,
                      signers,
                      mode,
                      detached,
                      binary,
                      append,
                      notations),
        (false, true) =>
            sign_message(sq,
                         input,
                         output,
                         signers,
                         mode,
                         binary,
                         notarize,
                         notations),
    }
}

fn sign_data<'a, 'store, 'rstore>(
    sq: Sq<'store, 'rstore>,
    input: &'a mut (dyn BufferedReader<Cookie> + Sync + Send),
    output_path: &'a FileOrStdout,
    mut signers: Vec<(openpgp::Cert, Box<dyn crypto::Signer + Send + Sync>)>,
    mode: Mode,
    detached: bool,
    binary: bool,
    append: bool,
    notations: &'a [(bool, NotationData)])
    -> Result<()>
{
    let (mut output, prepend_sigs, tmp_path):
    (Box<dyn io::Write + Sync + Send>, Vec<Signature>, Option<PathBuf>) =
        if detached && append && output_path.path().is_some() {
            let output_path = output_path.path().unwrap();
            // First, read the existing signatures.
            let mut sigs = Vec::new();
            let mut ppr =
                openpgp::parse::PacketParser::from_file(output_path)?;

            while let PacketParserResult::Some(pp) = ppr {
                let (packet, ppr_tmp) = pp.recurse()?;
                ppr = ppr_tmp;

                match packet {
                    Packet::Signature(sig) => sigs.push(sig),
                    p => return Err(
                        anyhow::anyhow!(
                            format!("{} in detached signature", p.tag()))
                            .context("Invalid detached signature")),
                }
            }

            // Then, create a temporary file to write to.  If we are
            // successful with adding our signature(s), we rename the
            // file replacing the old one.
            let tmp_file = NamedTempFile::new_in(
                PathBuf::from(output_path).parent()
                    .unwrap_or(&PathBuf::from(".")))?;
            let tmp_path = tmp_file.path().into();
            (Box::new(tmp_file), sigs, Some(tmp_path))
        } else {
            (output_path.create_safe(&sq)?, Vec::new(), None)
        };

    // Stream an OpenPGP message.
    // The sink may be a NamedTempFile.  Carefully keep a reference so
    // that we can rename it.
    let mut message = Message::new(&mut output);
    if ! binary {
        message = Armorer::new(message)
            .kind(if detached {
                armor::Kind::Signature
            } else {
                armor::Kind::Message
            })
            .build()?;
    }

    // When extending a detached signature, prepend any existing
    // signatures first.
    for sig in prepend_sigs.into_iter() {
        Packet::Signature(sig).serialize(&mut message)?;
    }

    let mut builder = SignatureBuilder::new(mode.into());
    for (critical, n) in notations.iter() {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            Some(n.flags().clone()),
            *critical)?;
    }

    let mut signer = Signer::with_template(
        message,
        signers.pop().unwrap().1,
        builder)?;
    signer = signer.creation_time(sq.time);
    for s in signers {
        signer = signer.add_signer(s.1)?;
    }
    if detached {
        signer = signer.detached();
    }
    let signer = signer.build().context("Failed to create signer")?;

    let mut writer = if detached {
        // Detached signatures do not need a literal data packet, just
        // hash the data as is.
        signer
    } else {
        // We want to wrap the data in a literal data packet.
        LiteralWriter::new(signer).build()
            .context("Failed to create literal writer")?
    };

    // Finally, copy stdin to our writer stack to sign the data.
    input.copy(&mut writer)
        .context("Failed to sign")?;

    writer.finalize()
        .context("Failed to sign")?;

    if let Some(path) = tmp_path {
        // Atomically replace the old file.
        fs::rename(
            path,
            output_path.path().expect("must be Some if tmp_path is Some"),
        )?;
    }
    Ok(())
}

fn sign_message<'a, 'store, 'rstore>(
    sq: Sq<'store, 'rstore>,
    input: &'a mut (dyn BufferedReader<Cookie> + Sync + Send),
    output: &'a FileOrStdout,
    signers: Vec<(openpgp::Cert, Box<dyn crypto::Signer + Send + Sync>)>,
    mode: Mode,
    binary: bool,
    notarize: bool,
    notations: &'a [(bool, NotationData)])
    -> Result<()>
{
    let mut output = output.create_pgp_safe(
        &sq,
        binary,
        armor::Kind::Message,
    )?;
    sign_message_(sq,
                  input,
                  signers,
                  mode,
                  notarize,
                  notations,
                  &mut output)?;
    output.finalize()?;
    Ok(())
}

fn sign_message_<'a, 'store, 'rstore>(
    sq: Sq<'store, 'rstore>,
    input: &'a mut (dyn BufferedReader<Cookie> + Sync + Send),
    mut signers: Vec<(openpgp::Cert, Box<dyn crypto::Signer + Send + Sync>)>,
    mode: Mode,
    notarize: bool,
    notations: &'a [(bool, NotationData)],
    output: &mut (dyn io::Write + Sync + Send))
    -> Result<()>
{
    let mut sink = Message::new(output);

    // Create a parser for the message to be notarized.
    let mut ppr
        = openpgp::parse::PacketParser::from_reader(input)
        .context("Failed to build parser")?;

    // Once we see a signature, we can no longer strip compression.
    let mut seen_signature = false;
    #[derive(PartialEq, Eq, Debug)]
    enum State {
        InFirstSigGroup,
        AfterFirstSigGroup,
        Signing {
            // Counts how many signatures are being notarized.  If
            // this drops to zero, we pop the signer from the stack.
            signature_count: isize,
        },
        Done,
    }
    let mut state =
        if ! notarize {
            State::InFirstSigGroup
        } else {
            // Pretend we have passed the first signature group so
            // that we put our signature first.
            State::AfterFirstSigGroup
        };

    while let PacketParserResult::Some(mut pp) = ppr {
        if let Err(err) = pp.possible_message() {
            return Err(err.context("Malformed OpenPGP message"));
        }

        match pp.packet {
            Packet::PKESK(_) | Packet::SKESK(_) =>
                return Err(anyhow::anyhow!(
                    "Signing encrypted data is not implemented")),

            Packet::Literal(_) =>
                if let State::InFirstSigGroup = state {
                    // Cope with messages that have no signatures, or
                    // with a ops packet without the last flag.
                    state = State::AfterFirstSigGroup;
                },

            // To implement this, we'd need to stream the
            // compressed data packet inclusive framing, but
            // currently the partial body filter transparently
            // removes the framing.
            //
            // If you do implement this, there is a half-disabled test
            // in tests/sq-sign.rs.
            Packet::CompressedData(_) if seen_signature =>
                return Err(anyhow::anyhow!(
                    "Signing a compress-then-sign message is not implemented")),

            _ => (),
        }

        match state {
            State::AfterFirstSigGroup => {
                // After the first signature group, we push the signer
                // onto the writer stack.
                let mut builder = SignatureBuilder::new(mode.into());
                for (critical, n) in notations.iter() {
                    builder = builder.add_notation(
                        n.name(),
                        n.value(),
                        Some(n.flags().clone()),
                        *critical)?;
                }

                let mut signer = Signer::with_template(
                    sink, signers.pop().unwrap().1, builder)?;
                signer = signer.creation_time(sq.time);
                for s in signers.drain(..) {
                    signer = signer.add_signer(s.1)?;
                }
                sink = signer.build().context("Failed to create signer")?;
                state = State::Signing { signature_count: 0, };
            },

            State::Signing { signature_count } if signature_count == 0 => {
                // All signatures that are being notarized are
                // written, pop the signer from the writer stack.
                sink = sink.finalize_one()
                    .context("Failed to sign data")?
                    .unwrap();
                state = State::Done;
            },

            _ => (),
        }

        if let Packet::Literal(_) = pp.packet {
            let l = if let Packet::Literal(l) = pp.packet.clone() {
                l
            } else {
                unreachable!()
            };
            // Create a literal writer to wrap the data in a literal
            // message packet.
            let mut literal = LiteralWriter::new(sink).format(l.format());
            if let Some(f) = l.filename() {
                literal = literal.filename(f)?;
            }
            if let Some(d) = l.date() {
                literal = literal.date(d)?;
            }

            let mut literal = literal.build()
                .context("Failed to create literal writer")?;

            // Finally, just copy all the data.
            pp.copy(&mut literal)
                .context("Failed to sign data")?;

            // Pop the literal writer.
            sink = literal.finalize_one()
                .context("Failed to sign data")?
                .unwrap();
        }

        let (packet, ppr_tmp) = if seen_signature {
            // Once we see a signature, we can no longer strip
            // compression.
            pp.next()
        } else {
            pp.recurse()
        }.context("Parsing failed")?;
        ppr = ppr_tmp;

        match packet {
            Packet::OnePassSig(mut ops) => {
                let was_last = ops.last();
                match state {
                    State::InFirstSigGroup => {
                        // We want to append our signature here, hence
                        // we set last to false.
                        ops.set_last(false);

                        if was_last {
                            // The signature group ends here.
                            state = State::AfterFirstSigGroup;
                        }
                    },

                    State::Signing { ref mut signature_count } =>
                        *signature_count += 1,

                    _ => (),
                }

                Packet::OnePassSig(ops).serialize(&mut sink)?;
                seen_signature = true;
            },

            Packet::Signature(sig) => {
                Packet::Signature(sig).serialize(&mut sink)
                    .context("Failed to serialize")?;
                if let State::Signing { ref mut signature_count } = state {
                    *signature_count -= 1;
                }
            },
            _ => (),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        if let Err(err) = eof.is_message() {
            return Err(err.context("Malformed OpenPGP message"));
        }
    } else {
        unreachable!()
    }

    match state {
        State::Signing { signature_count } => {
            assert_eq!(signature_count, 0);
            sink.finalize()
                .context("Failed to sign data")?;
        },
        State::Done => (),
        _ => panic!("Unexpected state: {:?}", state),
    }

    Ok(())
}

pub fn clearsign(sq: Sq,
                 mut input: impl BufferedReader<Cookie> + Sync + Send,
                 mut output: impl io::Write + Sync + Send,
                 mut signers: Vec<(openpgp::Cert, Box<dyn crypto::Signer + Send + Sync>)>,
                 notations: &[(bool, NotationData)])
                 -> Result<()>
{
    // Prepare a signature template.
    let mut builder = SignatureBuilder::new(SignatureType::Text);
    for (critical, n) in notations.iter() {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            Some(n.flags().clone()),
            *critical)?;
    }

    let message = Message::new(&mut output);
    let mut signer = Signer::with_template(
        message, signers.pop().unwrap().1, builder)?
        .cleartext();
    signer = signer.creation_time(sq.time);
    for s in signers {
        signer = signer.add_signer(s.1)?;
    }
    let mut message = signer.build().context("Failed to create signer")?;

    // Finally, copy stdin to our writer stack to sign the data.
    input.copy(&mut message)
        .context("Failed to sign")?;

    message.finalize()
        .context("Failed to sign")?;

    Ok(())
}
