use std::collections::{HashMap, HashSet, btree_map::{BTreeMap, Entry}};
use std::io;
use std::path::PathBuf;

use buffered_reader::File;

use sequoia_openpgp::{
    self as openpgp,
    KeyID,
    Cert,
    packet::UserID,
    parse::Cookie,
    parse::buffered_reader::BufferedReader,
    parse::stream::*,
    parse::Parse,
    types::{
        AEADAlgorithm,
        SymmetricAlgorithm,
    },
};

use sequoia_cert_store::Store;
use sequoia_wot::store::Store as _;

use crate::Sq;
use crate::Result;
use crate::cli;
use crate::commands::inspect::Kind;
use crate::common::{PreferredUserID, ui};
use crate::sq::TrustThreshold;

pub fn dispatch(sq: Sq, command: cli::verify::Command)
    -> Result<()>
{
    tracer!(TRACE, "verify::dispatch");

    let input = command.input.open("a signed message")?;
    let mut output = command.output.create_safe(&sq)?;
    let signatures = command.signatures;

    let signers =
        sq.resolve_certs_or_fail(&command.signers, TrustThreshold::Full)?;

    let result = verify(sq, input,
                        command.detached.clone(),
                        "--signature-file",
                        command.detached,
                        &mut output, signatures, signers);
    if result.is_err() {
        if let Some(path) = command.output.path() {
            // Drop output here so that the file is persisted and
            // can be deleted.
            drop(output);

            if let Err(err) = std::fs::remove_file(path) {
                weprintln!("Verification failed, failed to remove \
                            unverified output saved to {}: {}",
                           path.display(), err);
            }
        }
    }
    result
}

pub fn verify(mut sq: Sq,
              input: Box<dyn BufferedReader<Cookie>>,
              detached: Option<PathBuf>,
              detached_sig_arg: &str,
              detached_sig_value: Option<PathBuf>,
              output: &mut dyn io::Write,
              signatures: usize, certs: Vec<Cert>)
              -> Result<()> {
    let detached = if let Some(sig_path) = detached {
        let sig = File::with_cookie(&sig_path, Default::default())?;

        let (kind, sig) = Kind::identify(&mut sq, sig)?;
        kind.expect_or_else(&sq, "verify", Kind::DetachedSig,
                            detached_sig_arg,
                            detached_sig_value.as_deref())?;

        Some(sig)
    } else {
        None
    };

    let helper = VHelper::new(&sq, signatures, certs);
    let helper = if let Some(dsig) = detached {
        let mut v = DetachedVerifierBuilder::from_reader(dsig)?
            .with_policy(sq.policy, Some(sq.time), helper)?;
        v.verify_buffered_reader(input)?;
        v.into_helper()
    } else {
        let mut v = VerifierBuilder::from_reader(input)?
            .with_policy(sq.policy, Some(sq.time), helper)?;
        io::copy(&mut v, output)?;
        v.into_helper()
    };

    helper.print_status();
    Ok(())
}


pub struct VHelper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    #[allow(dead_code)]
    pub sq: &'c Sq<'store, 'rstore>,
    signatures: usize,

    /// Require signatures to be made by this set of certs.
    designated_signers: Vec<Cert>,

    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,

    /// Tracks the inner-most encryption container encountered.
    pub sym_algo: Option<SymmetricAlgorithm>,
    /// Tracks the inner-most encryption container encountered.
    aead_algo: Option<AEADAlgorithm>,

    // Tracks the signatures encountered.
    authenticated_signatures: usize,
    unauthenticated_signatures: usize,
    uncheckable_signatures: usize,
    bad_signatures: usize,
    broken_keys: usize,
    broken_signatures: usize,
    pub quiet: bool,
}

impl<'c, 'store, 'rstore> VHelper<'c, 'store, 'rstore> {
    pub fn new(sq: &'c Sq<'store, 'rstore>, signatures: usize,
               designated_signers: Vec<Cert>)
               -> Self
    {
        VHelper {
            sq: sq,
            signatures,
            designated_signers,
            labels: HashMap::new(),
            trusted: HashSet::new(),
            sym_algo: None,
            aead_algo: None,
            authenticated_signatures: 0,
            unauthenticated_signatures: 0,
            uncheckable_signatures: 0,
            broken_keys: 0,
            bad_signatures: 0,
            broken_signatures: 0,
            quiet: sq.quiet(),
        }
    }

    /// Enables or disables quiet operation.
    ///
    /// In quiet operation, only errors are emitted.
    pub fn quiet(&mut self, v: bool) {
        self.quiet = v;
    }

    pub fn print_status(&self) {
        fn p(s: &mut String, what: &str, threshold: usize, quantity: usize) {
            if quantity >= threshold {
                use std::fmt::Write;
                use crate::output::pluralize::Pluralize;
                let dirty = ! s.is_empty();
                write!(s, "{}{}",
                       if dirty { ", " } else { "" },
                       quantity.of(what))
                    .expect("writing to a string is infallible");
            }
        }

        let mut status = String::new();
        p(&mut status, "authenticated signature", 0, self.authenticated_signatures);
        p(&mut status, "unauthenticated signature", 1, self.unauthenticated_signatures);
        p(&mut status, "uncheckable signature", 1, self.uncheckable_signatures);
        p(&mut status, "bad signature", 1, self.bad_signatures);
        p(&mut status, "bad key", 1, self.broken_keys);
        p(&mut status, "broken signatures", 1, self.broken_signatures);
        if ! status.is_empty() {
            weprintln!("{}.", status);
        }
    }

    fn print_sigs(&mut self, results: &[VerificationResult]) -> Result<()> {
        make_qprintln!(self.quiet);
        use crate::common::pki::output::print_path;
        use crate::print_error_chain;

        let reference_time = self.sq.time;

        use self::VerificationError::*;
        for result in results {
            let (sig, ka) = match result {
                Ok(GoodChecksum { sig, ka, .. }) => (sig, ka),
                Err(MalformedSignature { error, .. }) => {
                    weprintln!("Malformed signature:");
                    print_error_chain(error);
                    self.broken_signatures += 1;
                    continue;
                },
                Err(MissingKey { sig, .. }) => {
                    let issuer = sig.get_issuers().get(0)
                        .expect("missing key checksum has an issuer")
                        .to_string();
                    let what = match sig.level() {
                        0 => "signature".into(),
                        n => format!("level {} notarization", n),
                    };
                    weprintln!("Can't authenticate {} allegedly made by {}: \
                                missing certificate.",
                               what, issuer);

                    self.sq.hint(format_args!(
                        "Consider searching for the certificate using:"))
                        .sq().arg("network").arg("search")
                        .arg(issuer)
                        .done();

                    self.uncheckable_signatures += 1;
                    continue;
                },
                Err(UnboundKey { cert, error, .. }) => {
                    weprintln!("Signing key on {} is not bound:",
                               cert.fingerprint());
                    print_error_chain(error);
                    self.broken_keys += 1;
                    continue;
                },
                Err(BadKey { ka, error, .. }) => {
                    weprintln!("Signing key on {} is bad:",
                               ka.cert().fingerprint());
                    print_error_chain(error);
                    self.broken_keys += 1;
                    continue;
                },
                Err(BadSignature { sig, ka, error }) => {
                    let issuer = ka.key().fingerprint().to_string();
                    let what = match sig.level() {
                        0 => "signature".into(),
                        n => format!("level {} notarizing signature", n),
                    };
                    weprintln!("Error verifying {} made by {}:",
                               what, issuer);
                    print_error_chain(error);
                    self.bad_signatures += 1;
                    continue;
                }
                Err(UnknownSignature { sig, .. }) => {
                    weprintln!("Error parsing signature: {}", sig.error());
                    print_error_chain(sig.error());
                    self.bad_signatures += 1;
                    continue;
                }
                Err(e) => {
                    weprintln!("Error parsing signature: {}", e);
                    self.bad_signatures += 1;
                    continue;
                }

            };

            let cert = ka.cert();
            let cert_fpr = cert.fingerprint();
            let issuer = ka.key().keyid();
            let mut signer_userid = self.sq.best_userid(ka.cert(), true);

            // Direct trust.
            let mut authenticated = self.trusted.contains(&issuer);
            let mut prefix = "";
            let trust_roots = self.sq.trust_roots();
            if ! authenticated && ! trust_roots.is_empty() {
                prefix = "  ";

                // Web of trust.
                qprintln!("Authenticating {} ({}) using the web of trust:",
                          cert_fpr, signer_userid.userid_lossy());

                if let Some(cert_store) = self.sq.cert_store()? {
                    // Build the network.
                    let cert_store = sequoia_wot::store::CertStore::from_store(
                        cert_store, self.sq.policy, reference_time);

                    let userids =
                        cert_store.certified_userids_of(&cert_fpr);

                    if userids.is_empty() {
                        weprintln!(indent=prefix,
                                   "{} cannot be authenticated.  \
                                    It has no User IDs",
                                   cert_fpr);
                    } else {
                        let n = sequoia_wot::NetworkBuilder::rooted(
                            &cert_store, &*trust_roots).build();

                        let authenticated_userids
                            = userids.into_iter().filter(|userid| {
                                let paths = n.authenticate(
                                    userid, cert.fingerprint(),
                                    // XXX: Make this user configurable.
                                    sequoia_wot::FULLY_TRUSTED);

                                let amount = paths.amount();
                                let authenticated = if amount >= sequoia_wot::FULLY_TRUSTED {
                                    weprintln!(indent=prefix,
                                               "Fully authenticated \
                                                ({} of {}) {}, {}",
                                               amount,
                                               TrustThreshold::Full,
                                               cert_fpr,
                                               ui::Safe(userid));
                                    true
                                } else if amount > 0 {
                                    weprintln!(indent=prefix,
                                               "Partially authenticated \
                                                ({} of {}) {}, {} ",
                                               amount,
                                               TrustThreshold::Full,
                                               cert_fpr,
                                               ui::Safe(userid));
                                    false
                                } else {
                                    weprintln!(indent=prefix,
                                               "{}: {} is unauthenticated \
                                                and may be an impersonation!",
                                               cert_fpr,
                                               ui::Safe(userid));
                                    false
                                };

                                for (i, (path, amount)) in paths.iter().enumerate() {
                                    let prefix = if paths.len() > 1 {
                                        qprintln!("{}  Path #{} of {}, \
                                                  trust amount {}:",
                                                 prefix,
                                                 i + 1, paths.len(), amount);
                                        format!("{}    ", prefix)
                                    } else {
                                        format!("{}  ", prefix)
                                    };

                                    if ! self.quiet {
                                        let _ =
                                            print_path(&mut std::io::stderr(),
                                                       &path.into(), userid,
                                                       &prefix);
                                    }
                                }

                                authenticated
                            })
                            .collect::<Vec<UserID>>();

                        if authenticated_userids.is_empty() {
                            authenticated = false;
                        } else {
                            authenticated = true;

                            // If we managed to authenticate the
                            // signers user ID, prefer that one.
                            if let Some(u) = sig.signers_user_id()
                                .and_then(|u| {
                                    authenticated_userids.contains(
                                        &UserID::from(u))
                                        .then_some(u)
                                })
                            {
                                signer_userid = PreferredUserID::from_string(
                                    String::from_utf8_lossy(u),
                                    TrustThreshold::Full.into());
                            } else {
                                // Else just pick the first one.
                                signer_userid = PreferredUserID::from_string(
                                    String::from_utf8_lossy(
                                        authenticated_userids[0].value()),
                                    TrustThreshold::Full.into());
                            }
                        }
                    }
                } else {
                    qprintln!("Skipping, certificate store has been disabled");
                }
            }

            let mut label_store = Default::default();
            let label = self.labels.get(&issuer).unwrap_or_else(|| {
                label_store = cert_fpr.to_string();
                &label_store
            });

            let level = sig.level();
            match (level == 0, authenticated) {
                (true,  true)  => {
                    weprintln!(indent=prefix,
                               "Authenticated signature made by {} ({})",
                               label, signer_userid.userid_lossy());
                }
                (false, true)  => {
                    weprintln!(indent=prefix,
                               "Authenticated level {} notarization \
                                made by {} ({})",
                               level, label, signer_userid.userid_lossy());
                }
                (true,  false) => {
                    weprintln!(indent=prefix,
                               "Can't authenticate signature made by {} ({}): \
                                the certificate can't be authenticated.",
                               label, signer_userid.userid_lossy());

                    if let Ok(u) = signer_userid.userid() {
                        self.sq.hint(format_args!(
                            "After checking that {} belongs to {}, \
                             you can mark it as authenticated using:",
                            cert_fpr, u))
                            .sq().arg("pki").arg("link").arg("add")
                            .arg_value("--cert", cert_fpr)
                            .arg_value("--userid", u)
                            .done();
                    }
                }
                (false, false) => {
                    weprintln!(indent=prefix,
                               "Can't authenticate level {} notarization \
                                made by {} ({}): the certificate \
                                can't be authenticated.",
                               level, label, signer_userid.userid_lossy());

                    if let Ok(u) = signer_userid.userid() {
                        self.sq.hint(format_args!(
                            "After checking that {} belongs to {}, \
                             you can mark it as authenticated using:",
                            cert_fpr, u))
                            .sq().arg("pki").arg("link").arg("add")
                            .arg_value("--cert", cert_fpr)
                            .arg_value("--userid", u)
                            .done();
                    }
                }
            };

            if authenticated {
                self.authenticated_signatures += 1;
            } else {
                self.unauthenticated_signatures += 1;
            }

            qprintln!("");
        }

        Ok(())
    }
}

impl<'c, 'store, 'rstore> VerificationHelper for VHelper<'c, 'store, 'rstore>
    where 'store: 'rstore
{
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let mut certs = BTreeMap::new();

        for c in std::mem::take(&mut self.designated_signers) {
            match certs.entry(c.fingerprint()) {
                Entry::Vacant(e) => {
                    e.insert(c);
                },
                Entry::Occupied(mut e) => {
                    let merged = e.get().clone().merge_public(c)?;
                    e.insert(merged);
                },
            }
        }

        // Get all keys.
        let seen: HashSet<_> = certs.values()
            .flat_map(|cert| {
                cert.keys().map(|ka| ka.key().fingerprint().into())
            }).collect();

        // Explicitly provided keys are trusted.
        self.trusted = seen;

        // If we have any designated signers, we do not consider
        // certificates in the cert store: we require all signatures
        // to be made by the set of designated signers.
        if ! self.trusted.is_empty() {
            return Ok(certs.into_values().collect());
        }

        // Otherwise, look up the issuer IDs in the certificate store.

        // Avoid initializing the certificate store if we don't actually
        // need to.
        if ! ids.is_empty() {
            if let Some(cert_store) = self.sq.cert_store()? {
                for id in ids.iter() {
                    for c in cert_store.lookup_by_cert_or_subkey(id)
                        .unwrap_or_default()
                    {
                        let c = c.to_cert()?.clone();
                        match certs.entry(c.fingerprint()) {
                            Entry::Vacant(e) => {
                                e.insert(c);
                            },
                            Entry::Occupied(mut e) => {
                                let merged = e.get().clone().merge_public(c)?;
                                e.insert(merged);
                            },
                        }
                    }
                }
            }
        }

        Ok(certs.into_values().collect())
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        make_qprintln!(self.quiet);
        for layer in structure {
            match layer {
                MessageLayer::Compression { algo } =>
                    qprintln!("Compressed using {}", algo),
                MessageLayer::Encryption { sym_algo, aead_algo } => {
                    self.sym_algo = Some(sym_algo);
                    self.aead_algo = aead_algo;

                    if let Some(aead_algo) = aead_algo {
                        qprintln!("Encrypted and protected using {}/{}",
                                  sym_algo, aead_algo);
                    } else {
                        qprintln!("Encrypted using {}", sym_algo);
                    }
                },
                MessageLayer::SignatureGroup { ref results } => {
                    self.print_sigs(results)?;
                },
            }
        }

        if self.authenticated_signatures >= self.signatures {
            Ok(())
        } else {
            if ! self.quiet {
                self.print_status();
            }
            Err(anyhow::anyhow!("Verification failed: could not \
                                 authenticate any signatures"))
        }
    }
}
