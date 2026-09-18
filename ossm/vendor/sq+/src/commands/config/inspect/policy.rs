//! Implements `sq config inspect policy`.

use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;

use sequoia_openpgp::{
    packet,
    policy::{
        AsymmetricAlgorithm,
        StandardPolicy,
    },
    types::{
	AEADAlgorithm,
        HashAlgorithm,
	SymmetricAlgorithm,
    },
};

use sequoia_policy_config::ConfiguredStandardPolicy;

use crate::{
    Convert,
    Sq,
    cli::config::inspect,
    config::ConfigFile,
    toml_edit_tree::Node,
};

/// Implements `sq config inspect policy`.
pub fn dispatch(sq: Sq, _: inspect::policy::Command) -> Result<()> {
    let sink = &mut std::io::stdout();

    explain(sink, "Asymmetric algorithms",
	    AsymmetricAlgorithm::variants(),
	    |a| sq.policy.asymmetric_algo_cutoff(a))?;

    explain(sink, "Symmetric algorithms",
	    SymmetricAlgorithm::variants(),
	    |a| sq.policy.symmetric_algo_cutoff(a))?;

    explain(sink, "AEAD algorithms",
	    AEADAlgorithm::variants(),
	    |a| sq.policy.aead_algo_cutoff(a))?;

    // Now the hashes, which are more complicated.
    explain_hashes(sink, sq.policy)?;

    // Then, the packets with their versions.
    explain_packets(sink, sq.policy)?;

    // Finally, explain where this policy was loaded from.
    explain_configuration(sink, &sq)?;

    Ok(())
}

/// Explains asymmetric algorithms, symmetric algorithms, and AEAD
/// modes.
fn explain<C, K, T>(sink: &mut dyn io::Write, what: &str, known: K, cutoff: C)
                    -> Result<()>
where
    T: Clone,
    T: std::fmt::Display,
    K: Iterator<Item = T>,
    C: Fn(T) -> Option<SystemTime>,
{
    wwriteln!(stream = sink, initial_indent = " - ", "{}", what);

    let variants = known.collect::<Vec<_>>();
    let unconstrained = variants.iter()
	.filter(|a| cutoff((*a).clone()).is_none())
	.map(|a| a.to_string())
	.collect::<Vec<_>>();
    wwriteln!(stream = sink, initial_indent = "   - Accepted: ", "{}",
	      unconstrained.join(", "));

    let mut constrained: BTreeMap<_, Vec<_>> = BTreeMap::default();
    for (cutoff, algo) in variants.iter()
	.filter_map(|a| cutoff((*a).clone()).map(|t| (t, a.to_string())))
    {
	constrained.entry(cutoff).or_default().push(algo);
    }
    for (cutoff, algos) in constrained.iter().rev() {
	if is_rejection(cutoff) {
	    wwriteln!(stream = sink, initial_indent = "   - Rejected: ", "{}",
		      algos.join(", "));
	} else {
	    wwriteln!(stream = sink, initial_indent = "   - ", "Accepted until {:?}: {}",
		      cutoff.convert(), algos.join(", "));
	}
    }

    wwriteln!(stream = sink);

    Ok(())
}

/// Explains hash algorithms.
fn explain_hashes(sink: &mut dyn io::Write, p: &StandardPolicy)
                  -> Result<()>
{
    use sequoia_openpgp::policy::HashAlgoSecurity::*;

    wwriteln!(stream = sink, initial_indent = " - ", "Hash algorithms");

    let variants = HashAlgorithm::variants().collect::<Vec<_>>();
    let mut unconstrained = Vec::new();
    let mut constrained: BTreeMap<_, Vec<_>> = BTreeMap::default();

    for (spr_cutoff, cr_cutoff, algo) in variants.iter()
	.map(|a| {
            let spr = p.hash_cutoff((*a).clone(), SecondPreImageResistance);
            let cr = p.hash_cutoff((*a).clone(), CollisionResistance);
            (spr, cr, a.to_string())
        })
    {
        match (spr_cutoff, cr_cutoff) {
            (None, None) => unconstrained.push(algo),
            (Some(spr), None) => {
                constrained.entry(spr).or_default().push(
                    format!("{} requiring second-preimage-resistance", algo));
                unconstrained.push(
                    format!("{} requiring collision-resistance", algo));
            },
            (None, Some(cr)) => {
                unconstrained.push(
                    format!("{} requiring second-preimage-resistance", algo));
                constrained.entry(cr).or_default().push(
                    format!("{} requiring collision-resistance", algo));
            },
            (Some(spr), Some(cr)) => if spr == cr {
                constrained.entry(spr).or_default().push(algo);
            } else {
                constrained.entry(spr).or_default().push(
                    format!("{} requiring second-preimage-resistance", algo));
                constrained.entry(cr).or_default().push(
                    format!("{} requiring collision-resistance", algo));
            },
        }
    }

    wwriteln!(stream = sink, initial_indent = "   - Accepted: ", "{}",
	      unconstrained.join(", "));

    for (cutoff, algos) in constrained.iter().rev() {
	if is_rejection(cutoff) {
	    wwriteln!(stream = sink, initial_indent = "   - Rejected: ", "{}",
		      algos.join(", "));
	} else {
	    wwriteln!(stream = sink, initial_indent = "   - ", "Accepted until {:?}: {}",
		      cutoff.convert(), algos.join(", "));
	}
    }

    wwriteln!(stream = sink);

    Ok(())
}

/// Explains versioned packets.
fn explain_packets(sink: &mut dyn io::Write, p: &StandardPolicy)
                   -> Result<()>
{
    wwriteln!(stream = sink, initial_indent = " - ", "OpenPGP packets");

    let variants = packet::Tag::variants().collect::<Vec<_>>();
    let mut constrains: BTreeMap<_, Vec<_>> = BTreeMap::default();

    for tag in variants.iter().cloned() {
        if (0..=255).into_iter()
            .all(|v| p.packet_tag_version_cutoff(tag, v).is_none())
        {
            constrains.entry(None).or_default()
                .push(tag.to_string());
            continue;
        }

        if (0..=255).into_iter()
            .all(|v| p.packet_tag_version_cutoff(tag, v)
                 .map(|c| is_rejection(&c))
                 .unwrap_or(false))
        {
            constrains.entry(Some(REJECTION)).or_default()
                .push(tag.to_string());
            continue;
        }

        let default_disposition = p.packet_tag_version_cutoff(tag, 0);
        constrains.entry(default_disposition).or_default()
            .push(tag.to_string());

        for v in 0..=255 {
            let cutoff = p.packet_tag_version_cutoff(tag, v);
            if cutoff != default_disposition {
                constrains.entry(cutoff).or_default()
                    .push(format!("v{} {}", v, tag));
            }
        }
    }

    for (_, packets) in constrains.iter()
        .filter(|(cutoff, _)| cutoff.is_none())
    {
	wwriteln!(stream = sink, initial_indent = "   - Accepted: ",
                  "{}", packets.join(", "));
    }

    for (cutoff, packets) in constrains.iter().rev()
        .filter_map(|(cutoff, packet)| cutoff.map(|c| (c, packet)))
    {
        if is_rejection(&cutoff) {
	    wwriteln!(stream = sink, initial_indent = "   - Rejected: ",
                      "{}", packets.join(", "));
        } else {
	    wwriteln!(stream = sink, initial_indent = "   - ",
                      "Accepted until {:?}: {}",
		      cutoff.convert(), packets.join(", "));
	}
    }

    wwriteln!(stream = sink);

    Ok(())
}

/// Explains where the policy was loaded from.
fn explain_configuration(sink: &mut dyn io::Write, sq: &Sq)
                         -> Result<()>
{
    wwriteln!(stream = sink, initial_indent = " - ", "Policy configuration");

    // Whether any policy configuration has been read.
    let mut read_any = false;

    // The global configuration.
    let global = PathBuf::from(ConfigFile::global_crypto_policy_file());
    let global_var = ConfiguredStandardPolicy::ENV_VAR;
    if global.exists() {
        wwriteln!(stream = sink, initial_indent = "   - ",
                  "global cryptographic policy");
        wwriteln!(stream = sink, initial_indent = "     - ",
                  "{}", global.display());

        if std::env::var(global_var).is_ok() {
            wwriteln!(stream = sink, initial_indent = "     - ",
                      "overwritten via {}", global_var);
        } else {
            wwriteln!(stream = sink, initial_indent = "     - ",
                      "can be overwritten via {}", global_var);
        }

        read_any = true;
    }

    // The referenced policy, if any.
    if let Some(path) = sq.config.policy_path() {
        wwriteln!(stream = sink, initial_indent = "   - ",
                  "referenced cryptographic policy");
        wwriteln!(stream = sink, initial_indent = "     - ",
                  "{}", path.display());
        wwriteln!(stream = sink, initial_indent = "     - ",
                  "can be changed via the configuration setting \
                   `policy.path`");

        read_any = true;
    }

    // The inline policy, if any.
    let config_file = sq.home.as_ref().map(ConfigFile::file_name);
    if let Some(config) = &config_file {
        if config.exists() && [
            "policy.hash_algorithms",
            "policy.symmetric_algorithms",
            "policy.asymmetric_algorithms",
            "policy.aead_algorithms",
            "policy.packets",
        ].iter().any(|p| {
            sq.config_file.as_item().traverse(&p.parse().unwrap())
                .ok()
                .and_then(|n| n.iter().next())
                .map(|_| true)
                .unwrap_or(false)
        }) {
            wwriteln!(stream = sink, initial_indent = "   - ",
                      "inline cryptographic policy");
            wwriteln!(stream = sink, initial_indent = "     - ",
                      "can be changed in the configuration file \
                       {}", config.display());

            read_any = true;
        }
    }

    if ! read_any {
        wwriteln!(stream = sink, initial_indent = "   - ",
                  "default cryptographic policy");
        wwriteln!(stream = sink, initial_indent = "     - ",
                  "This is the default cryptographic policy.  \
                   It can be modified by:");
        wwriteln!(stream = sink, initial_indent = "     - ",
                  "providing a global policy in {}", global.display());
        wwriteln!(stream = sink, initial_indent = "     - ",
                  "referencing a policy via the configuration setting \
                   `policy.path`");
        if let Some(config) = &config_file {
            wwriteln!(stream = sink, initial_indent = "     - ",
                      "providing an inline policy in the configuration \
                       file {}", config.display());
        }
    }

    Ok(())
}

/// Whether the given cut-off time is an outright rejection.
fn is_rejection(cutoff: &SystemTime) -> bool {
    *cutoff == REJECTION
}

/// Cutoff marker for outright rejection.
const REJECTION: SystemTime = UNIX_EPOCH;
