use anyhow::Result;

use buffered_reader::{BufferedReader, Dup};
use sequoia_openpgp as openpgp;
use openpgp::{
    packet::UserID,
    parse::{Cookie, Parse, stream::DecryptorBuilder},
};
use sequoia_autocrypt as autocrypt;

use crate::{
    Sq,
    commands::cert::import::import_and_report,
    output::import::ImportStats,
};

/// Imports certs encoded as Autocrypt headers.
///
/// We also try to decrypt the message, and collect the gossip headers.
pub fn import_certs(sq: &mut Sq, source: &mut Box<dyn BufferedReader<Cookie>>,
                    stats: &mut ImportStats)
                    -> Result<()>
{
    let o = &mut std::io::stdout();
    let mut acc = Vec::new();

    // First, get the Autocrypt headers from the outside.
    let mut dup = Dup::with_cookie(&mut *source, Cookie::default());
    let ac = autocrypt::AutocryptHeaders::from_reader(&mut dup)?;
    let from = UserID::from(
        ac.from.as_ref().ok_or(anyhow::anyhow!("no From: header"))?
            .as_str());
    let from_addr = from.email()?.ok_or(
        anyhow::anyhow!("no email address in From: header"))?;

    use autocrypt::AutocryptHeaderType::*;
    let mut sender_cert = None;
    let mut provenance_recorded = false;
    for h in ac.headers.into_iter().filter(|h| h.header_type == Sender) {
        if let Some(addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr"
                           && a.value.to_lowercase() == from_addr.to_lowercase())
                      .then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                sender_cert = Some(cert.clone());

                #[cfg(feature = "network")]
                if let Ok((ca, _)) = sq.certd_or_else()
                    .and_then(|certd| certd.shadow_ca_autocrypt())
                {
                    acc.append(&mut crate::commands::network::certify_downloads(
                        sq, false, ca,
                        vec![cert], Some(&addr[..])));
                    provenance_recorded = true;
                } else {
                    acc.push(cert);
                }

                #[cfg(not(feature = "network"))]
                {
                    acc.push(cert);
                }
            }
        }
    }

    import_and_report(o, sq, acc, None, stats, |o, _| {
        if provenance_recorded {
            wwriteln!(stream = o, initial_indent = "   - ",
                      "provenance information recorded");
        }

        Ok(())
    })?;

    // If there is no Autocrypt header, don't bother looking for
    // gossip.
    let sender_cert = match sender_cert {
        Some(c) => c,
        None => return Ok(()),
    };

    // Then, try to decrypt the message, and look for gossip headers.
    use crate::commands::decrypt::Helper;
    let mut helper = Helper::new(
        &sq,
        1, // Require one trusted signature...
        vec![sender_cert.clone()], // ... from this cert.
        vec![], vec![], false);
    helper.quiet(true);

    let policy = sq.policy.clone();
    let dup = Dup::with_cookie(source, Cookie::default());
    let mut decryptor = match DecryptorBuilder::from_buffered_reader(dup)?
        .with_policy(&policy, None, helper)
    {
        Ok(d) => d,
        Err(e) => {
            // The decryption failed, but we should still import the
            // Autocrypt header.
            if sq.verbose() {
                weprintln!("Note: Processing of message failed: {}", e);
            }

            return Ok(());
        },
    };

    let ac = autocrypt::AutocryptHeaders::from_reader(&mut decryptor)?;
    let helper = decryptor.into_helper();

    // We know there has been one good signature from the sender.  Now
    // check that the message was encrypted.  Note: it doesn't have to
    // be encrypted for the purpose of the certification, but
    // Autocrypt requires messages to be signed and encrypted.
    if helper.sym_algo.is_none() {
        if sq.verbose() {
            weprintln!("Note: Message is not encrypted, ignoring message");
        }

        return Ok(());
    }

    let mut acc = Vec::new();
    for h in ac.headers.into_iter().filter(|h| h.header_type == Gossip) {
        if let Some(_addr) = h.attributes.iter()
            .find_map(|a| (&a.key == "addr").then(|| a.value.clone()))
        {
            if let Some(cert) = h.key {
                acc.push(cert);
            }
        }
    }

    import_and_report(o, sq, acc, None, stats, |_, _| Ok(()))?;

    Ok(())
}
