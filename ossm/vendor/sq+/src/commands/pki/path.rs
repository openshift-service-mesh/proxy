use sequoia_openpgp as openpgp;
use openpgp::Result;

use sequoia_wot as wot;

use crate::Sq;
use crate::cli::pki::path::Command;
use crate::common::pki::output::print_path;
use crate::common::pki::output::print_path_error;
use crate::common::pki::output::print_path_header;
use crate::common::pki::required_trust_amount;
use crate::sq::TrustThreshold;

pub fn path(sq: Sq, c: Command)
    -> Result<()>
{
    let Command {
        certification_network, trust_amount, path, userids,
    } = c;

    assert_eq!(userids.len(), 1, "guaranteed by clap");

    let target = path.last().expect("guaranteed by clap");
    let mut userid = None;
    // The trust threshold parameter is irrelevant, because we're only
    // considering fingerprints, and key IDs.
    if let Ok((cert, _cert_handle))
        = sq.resolve_cert(&target.into(), TrustThreshold::Full)
    {
        if let Ok(vc) = cert.with_policy(sq.policy, sq.time) {
            if let Ok(userids) = userids.resolve(&vc) {
                assert_eq!(userids.len(), 1);
                userid = Some(userids.into_iter().next().unwrap());
            }
        }
    }
    let userid = userid.unwrap_or_else(|| {
        userids.iter().next().unwrap().resolve_to_self()
    });

    // Build the network.
    let cert_store = sq.cert_store_or_else()?;
    let mut n = wot::NetworkBuilder::rooted(cert_store, &*sq.trust_roots());
    if *certification_network {
        n = n.certification_network();
    }
    let q = n.build();

    let required_amount =
        required_trust_amount(*trust_amount, *certification_network)?;

    assert!(path.len() > 0, "guaranteed by clap");

    let o = &mut std::io::stdout();

    let r = q.lint_path(&path, userid.userid(), required_amount, sq.policy);

    let target_kh = path.last().expect("have one");

    let trust_amount = match r {
        Ok(path) => {
            print_path_header(
                o,
                target_kh,
                userid.userid(),
                path.amount(),
                required_amount,
            );
            print_path(o, &path, userid.userid(), "  ")?;

            let trust_amount = path.amount();
            if trust_amount >= required_amount {
                return Ok(());
            }

            trust_amount
        }
        Err(err) => {
            print_path_header(
                o,
                target_kh,
                userid.userid(),
                0,
                required_amount,
            );

            print_path_error(o, err);

            0
        }
    };

    Err(anyhow::anyhow!(
        "The path is not sufficient to authenticate the binding.  \
         Its trust amount is {}, but a trust amount of {} is required.",
        trust_amount, required_amount))
}
