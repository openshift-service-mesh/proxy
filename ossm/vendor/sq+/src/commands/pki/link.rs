use std::{
    time::Duration,
};

use anyhow::Result;

use crate::Sq;
use crate::common::NULL_POLICY;

use crate::cli::pki::link;
use crate::cli::types::Expiration;
use crate::cli::types::TrustAmount;
use crate::sq::TrustThreshold;

mod list;

pub fn link(sq: Sq, c: link::Command) -> Result<()> {
    use link::Subcommands::*;
    match c.subcommand {
        Add(c) => add(sq, c)?,
        Authorize(c) => authorize(sq, c)?,
        Retract(c) => retract(sq, c)?,
        List(c) => list::list(sq, c)?,
    }
    Ok(())
}

pub fn add(sq: Sq, c: link::AddCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = c.signature_notations.parse()?;

    let templates: Vec<(TrustAmount<_>, Expiration)> = if c.temporary {
        // Make the partially trusted link one second younger.  When
        // the fully trusted link expired, then this link will come
        // into effect.  If the user has fully linked the binding in
        // the meantime, then this won't override that, which is
        // exactly what we want.
        let week = Duration::new(7 * 24 * 60 * 60, 0);

        vec![
            (TrustAmount::Other(40), c.expiration.value()),
            (c.amount, Expiration::from_duration(week)),
        ]
    } else {
        vec![
            (c.amount, c.expiration.value()),
        ]
    };

    crate::common::pki::certify::certify(
        &mut std::io::stdout(),
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        ! c.userids.all().unwrap_or(false), // User-supplied user IDs.
        &templates,
        0, // Trust depth.
        &[][..], // Domain.
        &[][..], // Regex.
        true, // Local.
        false, // Non-revocable.
        &notations[..],
        None, // Output.
        false) // Binary.
}

pub fn authorize(sq: Sq, c: link::AuthorizeCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = c.signature_notations.parse()?;

    crate::common::pki::certify::certify(
        &mut std::io::stdout(),
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        ! c.userids.all().unwrap_or(false), // User-supplied user IDs.
        &[(c.amount, c.expiration.value())][..],
        c.depth,
        &c.domain[..],
        &c.regex[..],
        true, // Local.
        false, // Non-revocable.
        &notations[..],
        None, // Output.
        false) // Binary.
}

pub fn retract(sq: Sq, c: link::RetractCommand)
    -> Result<()>
{
    let trust_root = sq.local_trust_root()?;
    let trust_root = trust_root.to_cert()?;

    let (cert, _source)
        = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;

    let vc = cert.with_policy(NULL_POLICY, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = c.signature_notations.parse()?;

    crate::common::pki::certify::certify(
        &mut std::io::stdout(),
        &sq,
        c.recreate, // Recreate.
        &trust_root,
        &cert,
        &userids[..],
        ! c.userids.all().unwrap_or(false), // User-supplied user IDs.
        &[(TrustAmount::None, Expiration::Never)],
        0,
        &[][..], &[][..], // Domain, regex.
        true, // Local.
        false, // Non-revocable.
        &notations[..],
        None, // Output.
        false) // Binary.
}
