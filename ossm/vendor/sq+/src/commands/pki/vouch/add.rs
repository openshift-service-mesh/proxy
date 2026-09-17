use sequoia_openpgp as openpgp;
use openpgp::Result;

use crate::Sq;
use crate::cli::pki::vouch::add;
use crate::commands::FileOrStdout;
use crate::sq::TrustThreshold;

pub fn add(sq: Sq, mut c: add::Command)
    -> Result<()>
{
    let certifier =
        sq.resolve_cert(&c.certifier, TrustThreshold::Full)?.0;

    let (cert, source) = sq.resolve_cert(&c.cert, TrustThreshold::Full)?;
    if source.is_file() {
        // If the cert is read from a file, we default to stdout.
        // (None means write to the cert store.)
        if c.output.is_none() {
            c.output = Some(FileOrStdout::new(None));
        }
    }

    let vc = cert.with_policy(sq.policy, Some(sq.time))?;
    let userids = c.userids.resolve(&vc)?;

    let notations = c.signature_notations.parse()?;
    let expiration =
        sq.config.pki_vouch_expiration(&c.expiration, c.expiration_source);

    crate::common::pki::certify::certify(
        &mut std::io::stderr(),
        &sq,
        true, // Always recreate.
        &certifier,
        &cert,
        &userids[..],
        ! c.userids.all().unwrap_or(false), // User-supplied user IDs.
        &[(c.amount, expiration)],
        0,
        &[][..], &[][..], // Domain, regex.
        c.local,
        c.non_revocable,
        &notations[..],
        c.output,
        false)
}
