use std::{
    fmt::Write,
    time::SystemTime,
};

use anyhow::Error;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;

use sequoia_cert_store as cert_store;
use cert_store::Store;

use sequoia_wot as wot;
use wot::Path;
use wot::PathLints;
use wot::FULLY_TRUSTED;
use wot::PARTIALLY_TRUSTED;

use crate::Convert;
use crate::Sq;
use crate::Time;
use crate::common::ca_creation_time;
use crate::common::ui;
use crate::error_chain;
use crate::output::wrapping::NBSP;
use super::OutputType;

/// Prints a Path Error
pub fn print_path_error(output: &mut dyn std::io::Write, err: Error) {
    wwriteln!(stream=output, initial_indent = "└   ", "Checking path: {}", err);
}

/// Prints information of a Path for a target UserID associated with a KeyHandle
pub fn print_path_header(
    output: &mut dyn std::io::Write,
    target_kh: &KeyHandle,
    target_userid: &UserID,
    amount: usize,
    required_amount: usize,
) {
    wwriteln!(
        stream=output,
        initial_indent="",
        subsequent_indent="    ",
        "[{}] {} {}: {} authenticated ({}%)",
        if amount >= required_amount {
            "✓"
        } else {
            " "
        },
        target_kh,
        ui::Safe(target_userid),
        if amount >= 2 * FULLY_TRUSTED {
            "doubly"
        } else if amount >= FULLY_TRUSTED {
            "fully"
        } else if amount >= PARTIALLY_TRUSTED {
            "partially"
        } else if amount > 0 {
            "marginally"
        } else {
            "not"
        },
        (amount * 100) / FULLY_TRUSTED
    );
}

/// Prints information on a Path for a UserID
pub fn print_path(output: &mut dyn std::io::Write,
                  path: &PathLints, target_userid: &UserID, prefix: &str)
    -> Result<()>
{
    let certification_count = path.certifications().count();
    wwriteln!(stream=output, initial_indent=format!("{}◯─┬ ", prefix),
              subsequent_indent=format!("{}│ │ ", prefix),
              "{}", path.root().key_handle());
    wwriteln!(stream=output, initial_indent=format!("{}│ └ ", prefix),
              subsequent_indent=format!("{}│   ", prefix),
              "{}",
              if certification_count == 0 {
                  format!("{}", ui::Safe(target_userid))
              } else if let Some(userid) = path.root().primary_userid() {
                  format!("({})", ui::Safe(&userid))
              } else {
                  format!("")
              });

    if path.certifications().count() == 0 {
        wwriteln!(stream=output, indent=prefix, "│");
        wwriteln!(stream=output, initial_indent=format!("{}└── ", prefix),
                  subsequent_indent=format!("{}    ", prefix),
                  "Self-signed user ID.");
        return Ok(());
    }

    for (last, (cert, certification)) in path
        .certs()
        .zip(path.certifications())
        .enumerate()
        .map(|(j, c)| {
            if j + 1 == certification_count {
                (true, c)
            } else {
                (false, c)
            }
        })
    {
        let mut line = String::new();
        if let Some(certification) = certification.certification() {
            if certification.amount() < FULLY_TRUSTED {
                write!(&mut line,
                   "partially certified (amount: {}{}of{}120)",
                    certification.amount(), NBSP, NBSP,
                )?;
            } else {
                write!(&mut line, "certified")?;
            }

            if last {
                write!(&mut line, " the following binding")?;
            } else {
                write!(&mut line, " the following certificate")?;
            }

            if certification.creation_time() != ca_creation_time() {
                write!(&mut line,
                       " on {}",
                       chrono::DateTime::<chrono::Utc>::from(
                           certification.creation_time()
                       )
                       .format("%Y‑%m‑%d")
                )?;
            }

            if let Some(e) = certification.expiration_time() {
                write!(&mut line,
                    " (expiry: {})",
                    chrono::DateTime::<chrono::Utc>::from(e).format("%Y‑%m‑%d")
                )?;
            }
            if certification.depth() > 0.into() {
                write!(&mut line, " as a")?;
                if certification.depth() == 1.into() {
                    write!(&mut line, " introducer (depth: {})",
                           certification.depth())?;
                } else {
                    write!(&mut line,
                        " meta-introducer (depth: {})",
                        certification.depth()
                    )?;
                }
            }
        } else {
            write!(&mut line, " No adequate certification found.")?;
        }

        wwriteln!(stream=output, indent=prefix, "│");
        wwriteln!(stream=output, indent=format!("{}│  ", prefix), "{}", line);
        wwriteln!(stream=output, indent=prefix, "│");

        for err in cert.errors().iter().chain(cert.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                wwriteln!(
                    stream=output,
                    indent=format!(
                        "{}│  {}", prefix, if i == 0 { "" } else { "  " }),
                    "{}", msg);
            }
        }
        for err in certification.errors().iter().chain(certification.lints()) {
            for (i, msg) in error_chain(err).into_iter().enumerate() {
                wwriteln!(
                    stream=output,
                    indent=format!(
                        "{}│  {}", prefix, if i == 0 { "" } else { "  " }),
                    "{}", msg);
            }
        }

        wwriteln!(stream=output,
                  initial_indent=format!("{}{}─┬ ", prefix,
                                         if last { "└" } else { "├" }),
                  subsequent_indent=format!("{}{} │ ", prefix,
                                            if last { " " } else { "│" }),
                  "{}", certification.target());
        wwriteln!(stream=output,
                  initial_indent=format!("{}{} └ ", prefix,
                                         if last { " " } else { "│" }),
                  subsequent_indent=format!("{}{}   ", prefix,
                                            if last { " " } else { "│" }),
                  "{}",
                  if last {
                      format!("{}", ui::Safe(target_userid))
                  } else if let Some(userid) =
                  certification.target_cert().and_then(|c| c.primary_userid())
                  {
                      format!("({})", ui::Safe(userid.userid()))
                  } else {
                      "".into()
                  });

        if last {
            let target = path.certs().last().expect("have one");
            for err in target.errors().iter().chain(target.lints()) {
                for (i, msg) in error_chain(err).into_iter().enumerate() {
                    wwriteln!(
                        stream=output,
                        indent=format!(
                            "{}│  {}", prefix, if i == 0 { "" } else { "  " }),
                        "{}", msg);
                }
            }
        }
    }

    wwriteln!(stream=output, "");
    Ok(())
}

/// The concise human-readable specific implementation of an
/// OutputNetwork
pub struct ConciseHumanReadableOutputNetwork<'a, 'store, 'rstore> {
    output: &'a mut dyn std::io::Write,
    sq: &'a Sq<'store, 'rstore>,
    paths: bool,
    required_amount: usize,
    current_cert: Option<Cert>,
    bindings_shown: usize,
}

impl<'a, 'store, 'rstore> ConciseHumanReadableOutputNetwork<'a, 'store, 'rstore> {
    /// Creates a new ConciseHumanReadableOutputNetwork
    pub fn new(output: &'a mut dyn std::io::Write,
               sq: &'a Sq<'store, 'rstore>,
               required_amount: usize, paths: bool)
        -> Self
    {
        Self {
            output,
            sq,
            paths,
            required_amount,
            current_cert: None,
            bindings_shown: 0,
        }
    }
}

impl OutputType for ConciseHumanReadableOutputNetwork<'_, '_, '_> {
    fn add_cert(&mut self, fingerprint: &Fingerprint) -> Result<()> {
        let first_shown = self.current_cert.is_none();

        let current_fingerprint =
            self.current_cert.as_ref().map(|cert| cert.fingerprint());
        let show_cert = if current_fingerprint.as_ref() != Some(fingerprint) {
            let cert = if let Ok(store) = self.sq.cert_store_or_else() {
                store.lookup_by_cert_fpr(fingerprint)
                    .and_then(|lazy_cert| {
                        Ok(lazy_cert.to_cert()?.clone())
                    })
                    .ok()
            } else {
                None
            };
            self.current_cert = cert;
            true
        } else {
            false
        };

        let vc = self.current_cert.as_ref().map(|cert| {
            cert.with_policy(self.sq.policy, self.sq.time)
        });

        if show_cert {
            let cert = self.current_cert.as_ref()
                .expect("show_cert is true, there is a current cert");

            let mut extra_info = Vec::new();

            // To derive a valid cert, we need a valid binding
            // signature.  But even if we don't have that we may still
            // have a valid revocation certificate.  So be a bit more
            // careful.
            let rs = if let Some(Ok(ref vc)) = vc {
                vc.revocation_status()
            } else {
                cert.revocation_status(self.sq.policy, self.sq.time)
            };

            if let RevocationStatus::Revoked(sigs) = rs {
                let sig = sigs[0];
                let mut reason_;
                let reason = if let Some((reason, message))
                    = sig.reason_for_revocation()
                {
                    // Be careful to quote the message it is
                    // controlled by the certificate holder.
                    reason_ = reason.to_string();
                    if ! message.is_empty() {
                        reason_.push_str(": ");
                        reason_.push_str(&ui::Safe(message).to_string());
                    }
                    &reason_
                } else {
                    "no reason specified"
                };

                extra_info.push(format!(
                    "revoked {}, {}",
                    sig.signature_creation_time()
                        .unwrap_or(std::time::UNIX_EPOCH)
                        .convert(),
                    reason))
            }

            match &vc {
                Some(Ok(vc)) => {
                    if let Some(t) = vc.primary_key().key_expiration_time() {
                        if t < SystemTime::now() {
                            extra_info.push(
                                format!("expired {}",
                                        Time::try_from(t)
                                        .expect("is an OpenPGP timestamp")))
                        } else {
                            extra_info.push(
                                format!("will expire {}",
                                        Time::try_from(t)
                                        .expect("is an OpenPGP timestamp")))
                        }
                    }
                }
                Some(Err(err)) => {
                    extra_info.push(
                        format!("not valid: {}",
                                crate::one_line_error_chain(err)));
                }
                None => (),
            }

            if ! first_shown {
                wwriteln!(stream=self.output);
            }

            wwriteln!(stream=self.output, initial_indent = " - ",
                      "{}", fingerprint);

            if cert.primary_key().key().creation_time() != ca_creation_time() {
                wwriteln!(stream=self.output, initial_indent = "   - ",
                          "created {}",
                          cert.primary_key().key().creation_time().convert());
            }

            for info in extra_info.into_iter() {
                wwriteln!(stream=self.output, initial_indent = "   - ",
                          "{}", info);
            }
            wwriteln!(stream=self.output);
        }

        Ok(())
    }

    fn add_paths(
        &mut self,
        paths: Vec<(Path, usize)>,
        fingerprint: &Fingerprint,
        userid: &UserID,
        aggregated_amount: usize,
    ) -> Result<()> {
        let vc;
        if let Some(cert) = &self.current_cert {
            if cert.fingerprint() != *fingerprint {
                return Err(
                    anyhow::anyhow!("missing call to OutputFormat::add_cert"));
            }

            vc = cert.with_policy(self.sq.policy, self.sq.time);
        } else {
            return Err(
                anyhow::anyhow!("missing call to OutputFormat::add_cert"));
        };

        let revoked = if let Ok(ref vc) = vc {
            vc.userids()
                .filter_map(|u| {
                    if u.userid() != userid {
                        return None;
                    }

                    if let RevocationStatus::Revoked(_) = u.revocation_status() {
                        Some(())
                    } else {
                        None
                    }
                })
                .next()
        } else {
            None
        };

        wwriteln!(stream=self.output, initial_indent = "   - ", "[ {} ] {}",
                  if revoked.is_some() {
                      "revoked".to_string()
                  } else if aggregated_amount >= self.required_amount {
                      "   ✓   ".to_string()
                  } else {
                      format!("{:3}/120", aggregated_amount)
                  },
                  ui::Safe(userid));

        if self.paths {
            wwriteln!(stream=self.output);

            for (i, (path, amount)) in paths.iter().enumerate() {
                if paths.len() > 1 {
                    wwriteln!(
                        stream=self.output,
                        initial_indent="     ",
                        "Path #{}{}of{}{}, trust amount {}:",
                        i + 1, NBSP, NBSP,
                        paths.len(),
                        amount
                    );
                }

                print_path(self.output, &path.into(), userid, "     ")?;
            }
        }

        self.bindings_shown += 1;

        Ok(())
    }

    /// Write the HumanReadableOutputNetwork to output
    ///
    /// This function does in fact nothing as we are printing directly in
    /// add_paths().
    fn finalize(&mut self) -> Result<()> {
        if self.bindings_shown == 0 {
            return Ok(());
        }

        let cert =
            self.current_cert.as_ref().expect("have at least one");

        if ! self.paths {
            self.sq.hint(format_args!(
                "To view why a user ID is considered valid, pass \
                 `--show-paths`."));
        }

        self.sq.hint(format_args!(
            "To see more details about a certificate, for example {}, run:",
            cert.fingerprint()))
            .sq().arg("inspect")
            .arg_value("--cert", cert.fingerprint())
            .done();

        Ok(())
    }
}
