use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::io::IsTerminal;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;

use futures_util::StreamExt;

use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::task::LocalSet;

use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use indicatif::WeakProgressBar;

use sequoia_net as net;
use net::reqwest;

use tempfile::NamedTempFile;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::Fingerprint;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::parse::PacketParser;
use openpgp::parse::PacketParserResult;
use openpgp::parse::Parse;
use openpgp::parse::buffered_reader::{self, BufferedReader};
use openpgp::types::KeyFlags;

use crate::Result;
use crate::Sq;
use crate::cli::download;
use crate::cli::types::TrustAmount;
use crate::commands::network::CONNECT_TIMEOUT;
use crate::commands::network::USER_AGENT;
use crate::commands::verify::verify;
use crate::common::key_handle_dealias;
use crate::common::pki::authenticate::AuthenticateContext;
use crate::common::pki::authenticate::Query;
use crate::common::pki::authenticate;
use crate::common::ui;
use crate::sq::TrustThreshold;

// So we can deal with either named temp files or files.
enum SomeFile {
    Temp(NamedTempFile),
    File((File, PathBuf)),
}

impl SomeFile {
    fn as_ref(&self) -> &File {
        match self {
            SomeFile::Temp(t) => t.as_file(),
            SomeFile::File((f, _)) => &f,
        }
    }

    fn as_mut(&mut self) -> &mut File {
        match self {
            SomeFile::Temp(t) => t.as_file_mut(),
            SomeFile::File((ref mut f, _)) => f,
        }
    }

    fn path(&self) -> &Path {
        match self {
            SomeFile::Temp(t) => t.path(),
            SomeFile::File((_, p)) => p.as_path(),
        }
    }

    /// Writes a copy of the file to `new_path`.
    ///
    /// We optimize the case where this file is a temporary file, in
    /// which case we simply rename it.
    fn persist<P: AsRef<Path>>(self, new_path: P) -> Result<()> {
        match self {
            SomeFile::Temp(t) => {
                t.persist(new_path)?;
            },

            SomeFile::File((_, p)) => {
                // This was sourced from a local file, we cannot
                // rename that, but we can copy it.
                std::fs::copy(p, new_path)?;
            },
        }

        Ok(())
    }
}

// Spawn a task to download the `$url` to `$output` using `$http_client`.
//
// This is a macro rather than a function due to lifetimes.
//
// `$rt` is uninterpreted, and is returned as is.
//
// `$limit` causes the download to abort after that many bytes.
//
// `$file_name` is `$output`'s file name.  Its purely used for
// decorative purposes.
//
// `$pb` is a weak reference to a progress bar.
macro_rules! get {
    ($http_client:expr, $rt:expr, $url:expr, $limit:expr, $file_name:expr,
     $output: expr, $pb:expr) => {{
         let url: String = $url.into();
         let http_client: reqwest::Client = $http_client.clone();
         let limit: Option<usize> = $limit;
         let file_name: String = $file_name.into();
         let mut output = $output;
         let pb: WeakProgressBar = $pb;

         async move {
             if let Some(local_file_name) = url.strip_prefix("file://") {
                 let local_file_name = PathBuf::from(local_file_name);
                 match File::open(&local_file_name) {
                     Ok(file) => {
                         Ok(($rt, SomeFile::File((file, local_file_name))))
                     }
                     Err(err) => Err(err.into()),
                 }
             } else {
                 let mut bytes = 0;
                 let response = http_client.get(&url).send()
                     .await
                     .and_then(|r| r.error_for_status())
                     .with_context(|| format!("Fetching {}", url))?;

                 let len = response.content_length();
                 if let Some(pb) = pb.upgrade() {
                     if let Some(len) = len {
                         pb.inc_length(len);
                     } else {
                         // We don't know how much we need to download.  Switch
                         // to a spinner.
                         if ! pb.is_hidden() {
                             pb.set_style(ProgressStyle::default_spinner());
                         }
                     }
                 }

                 let mut stream = response.bytes_stream();
                 while let Some(item) = stream.next().await {
                     let item = item.with_context(|| {
                         format!("Fetching {}", url)
                     })?;
                     output.write_all(item.as_ref()).with_context(|| {
                         format!("Writing to {}", file_name)
                     })?;
                     bytes += item.len();
                     pb.upgrade().map(|pb| pb.inc(item.len() as u64));

                     if let Some(limit) = limit {
                         if bytes > limit {
                             return Err(anyhow::anyhow!(
                                 "{} exceeded download limit size ({} bytes)",
                                 url, limit));
                         }
                     }
                 }

                 output.flush()?;

                 Ok::<_, anyhow::Error>(($rt, SomeFile::Temp(output)))
             }
         }
    }}
}

pub fn dispatch(sq: Sq, c: download::Command)
    -> Result<()>
{
    let url = c.url;
    let signature_url = c.detached;
    let signatures = c.signatures;
    let signers =
        sq.resolve_certs_or_fail(&c.signers, TrustThreshold::Full)?;
    let output = c.output;

    if ! sq.quiet() && ! sq.batch {
        let output_is_terminal
            = output.path().is_none() && std::io::stdout().is_terminal();
        if output_is_terminal {
            weprintln!("Warning: will write the data to stdout, \
                        which appears to be a terminal.  Use --output \
                        to write to a file instead.");
        }
    }


    // Create the output file early.  Otherwise we may download a lot
    // of data and then fail to copy it.
    let mut output_file_;
    let mut stdout_;
    let mut output_file: &mut dyn Write = if let Some(file) = output.path() {
        output_file_ = if sq.overwrite {
            File::create(file)
                .with_context(|| format!("Opening {}", file.display()))?
        } else {
            File::options().write(true).create_new(true).open(file)
                .map_err(|err| {
                    if err.kind() == std::io::ErrorKind::AlreadyExists {
                        return anyhow::anyhow!(
                            "File {} exists, use \"sq --overwrite ...\" to overwrite",
                            file.display(),
                        );
                    }
                    err.into()
                })
                .with_context(|| format!("Opening {}", file.display()))?
        };
        &mut output_file_
    } else {
        stdout_ = std::io::stdout();
        &mut stdout_
    };


    // Create the progress bar.
    let progress_bar = if sq.verbose() || sq.batch {
        ProgressBar::hidden()
    } else {
        ProgressBar::new(0)
            .with_style(ProgressStyle::with_template(
                "{wide_bar} {decimal_bytes}/{decimal_total_bytes} ({eta} left)")
                        .expect("valid format"))
    };

    // A temporary file for the main data.  If output is not stdout,
    // we try and put it in the same directory as where it should end
    // up.
    let data_file = {
        let mut data_file = tempfile::Builder::new();
        data_file.prefix("sq-download");

        let partial;
        if let Some(path) = output.path() {
            if let Some(file_name) = path.file_name() {
                partial = format!(
                    "{}-partial",
                    String::from_utf8_lossy(file_name.as_encoded_bytes()));
                data_file.prefix(&partial);
            }

            if let Some(directory) = path.parent() {
                data_file.tempfile_in(directory)
            } else {
                let cwd = std::env::current_dir()?;
                data_file.tempfile_in(cwd)
            }
        } else {
            data_file.tempfile()
        }.context("Creating temporary file")?
    };

    let http_client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()?;

    let requests = LocalSet::new();
    let mut task_set = JoinSet::new();

    // Since JoinSet::join_next has to return the same type, we use
    // the following to discriminate the tasks.
    enum Task {
        Url,
        Signature,
    }

    // Schedule the download of the file.
    task_set.spawn_local_on(
        get!(http_client.clone(), Task::Url, url, None,
             data_file.path().display().to_string(), data_file,
             progress_bar.downgrade()),
        &requests);

    // We need to do some acrobatics!!!  After we download the
    // signature file, we want to make sure that we can authenticate a
    // signer.  This means we need to use sq.  But, we can't move sq
    // to an async task, because sq has a lifetime that is shorter
    // than 'static.  Instead, we set up a scoped thread, which can
    // use variables with lifetimes less than static, and then do the
    // processing there.
    let signature_url_ = signature_url.clone();
    let (mut data_file, signature_file) = std::thread::scope(|scope| {
        // Schedule the download of the signature.
        if let Some(ref url) = signature_url_ {
            let sig_file = tempfile::NamedTempFile::new()?;

            let getter = get!(
                http_client.clone(), Task::Signature, url, None,
                sig_file.path().display().to_string(), sig_file,
                progress_bar.downgrade());

            let (request_tx, request_rx) = oneshot::channel();
            let (response_tx, response_rx) = oneshot::channel();

            task_set.spawn_local_on(
                async move {
                    let (task, sig_file) = getter.await?;

                    // The processing is handled by the thread below.
                    if request_tx.send(sig_file).is_err() {
                        return Err(anyhow::anyhow!(
                            "internal error: protocol violation"));
                    }
                    let sig_file = response_rx.await??;
                    Ok((task, sig_file))
                },
                &requests);

            let progress_bar_ = progress_bar.downgrade();
            let sq_ = &sq;
            let signers_ = &signers;
            scope.spawn(move || {
                let result = (|| {
                    let progress_bar = progress_bar_;
                    let sq = sq_;
                    let signers = signers_;

                    let mut sig_file = if let Ok(sig_file)
                        = request_rx.blocking_recv()
                    {
                        sig_file
                    } else {
                        return Err(anyhow::anyhow!(
                            "internal error: protocol violation"));
                    };

                    // Read the signature data and make sure we can
                    // authenticate at least one issuer's certificate.
                    sig_file.as_mut().rewind()?;
                    let mut ppr = PacketParser::from_reader(sig_file.as_ref())
                        .context("Parsing detached signature: either the signature \
                                  file does not actually contain an OpenPGP \
                                  signature, or it is corrupted.")?;
                    let mut signatures = Vec::new();
                    while let PacketParserResult::Some(pp) = ppr {
                        let (packet, next_ppr) = pp.next()?;
                        ppr = next_ppr;

                        match packet {
                            Packet::Signature(sig) => {
                                signatures.push(sig);
                            }
                            Packet::Marker(_) => (),
                            _ => {
                                return Err(anyhow::anyhow!(
                                    "Signature file does not contain a detached \
                                     signature.  It includes a {}.",
                                    packet.tag()));
                            }
                        }
                    }

                    if signatures.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Signature file does not contain any signatures."));
                    }

                    let mut seen: BTreeMap<Fingerprint, Cert> = BTreeMap::new();
                    let mut authenticated = false;
                    for sig in signatures.iter() {
                        for issuer in sig.get_issuers() {
                            if let Some(cert)
                                = signers.iter().find(|c| c.key_handle().aliases(&issuer))
                            {
                                if seen.contains_key(&cert.fingerprint()) {
                                    // Already saw that certificate.
                                    continue;
                                }

                                authenticated = true;

                                if let Some(pb) = progress_bar.upgrade() {
                                    pb.suspend(|| {
                                        weprintln!(
                                            "Alleged signer {} is good listed.",
                                            cert.fingerprint());
                                    })
                                }
                            } else if let Ok(cert)
                                = sq.lookup_one(issuer,
                                                Some(KeyFlags::signing()),
                                                false)
                            {
                                if seen.contains_key(&cert.fingerprint()) {
                                    // Already saw that certificate.
                                    continue;
                                }

                                let mut auth = || {
                                    let result = authenticate(
                                        &mut std::io::stderr(),
                                        &sq,
                                        AuthenticateContext::Download,
                                        vec![
                                            Query::for_key_handle(
                                                None, cert.key_handle())
                                        ],
                                        false, // gossip
                                        false, // show unusable
                                        false, // certification network
                                        Some(TrustAmount::Full), // trust amount
                                        true, // show paths
                                    );

                                    if let Err(err) = result {
                                        weprintln!("Can't authenticate the \
                                                    alleged signer:");
                                        let _ = ui::emit_cert(
                                            &mut io::stderr(),
                                            sq, &cert);

                                        weprintln!(
                                            initial_indent = " - ",
                                            "{}",
                                            crate::one_line_error_chain(err));
                                        weprintln!();
                                    } else {
                                        authenticated = true;
                                    }
                                };

                                if let Some(pb) = progress_bar.upgrade() {
                                    pb.suspend(auth);
                                } else {
                                    auth();
                                }

                                seen.insert(cert.fingerprint(),
                                            cert);
                            }
                        }
                    }

                    if ! authenticated {
                        if let Some(pb) = progress_bar.upgrade() {
                            pb.finish_and_clear();
                        }

                        if seen.is_empty() {
                            weprintln!("We can't verify the signature, because \
                                        we don't have certificates for any of \
                                        the alleged signers:");
                        } else {
                            weprintln!("We can't verify the signature, because \
                                        we can't authenticate any of the \
                                        alleged signers:");
                        }

                        weprintln!();
                        let issuers = signatures.iter()
                            .flat_map(|sig| sig.get_issuers().into_iter())
                            .collect::<Vec<_>>();
                        let issuers
                            = key_handle_dealias(&issuers).collect::<Vec<_>>();

                        if issuers.is_empty() {
                            weprintln!(initial_indent = " - ",
                                       "No issuers (the signature may be \
                                       malformed)");
                        } else {
                            let mut missing = Vec::new();
                            for issuer in issuers.iter() {
                                if let KeyHandle::Fingerprint(fpr) = issuer {
                                    if let Some(cert) = seen.get(fpr) {
                                        weprintln!(initial_indent = " - ",
                                                   "{} {}",
                                                  issuer,
                                                   sq.best_userid(cert, true)
                                                   .display());
                                    } else {
                                        weprintln!(initial_indent = " - ",
                                                   "{} (missing certificate)",
                                                   issuer);
                                        missing.push(issuer);
                                    }
                                } else {
                                    weprintln!(initial_indent = " - ",
                                               "{} (missing certificate)",
                                               issuer);
                                    missing.push(issuer);
                                }
                            }

                            if ! missing.is_empty() {
                                let mut hint = sq.hint(format_args!(
                                    "Try searching public directories:"))
                                    .sq().arg("network").arg("search");
                                for issuer in issuers.into_iter() {
                                    hint = hint.arg(issuer.to_string());
                                }
                                hint.done();
                            }
                            if let Some(issuer) = seen.keys().next() {
                                sq.hint(format_args!(
                                    "Verify that one of the certificates is \
                                     authentic, and then link it:"))
                                .sq().arg("pki").arg("link").arg("add")
                                    .arg_value_hidden("--cert",
                                                      issuer,
                                                      "FINGERPRINT")
                                    .done();
                            }
                        }

                        return Err(anyhow::anyhow!("\
                            Can't authenticate any of the alleged signers"));
                    }

                    drop(ppr);

                    Ok(sig_file)
                })();

                if let Err(result) = response_tx.send(result) {
                    // (send returns result on failure.)  We failed to
                    // return the result.  Don't make things worse by
                    // swallowing any error.
                    if let Err(err) = result.as_ref() {
                        crate::print_error_chain(&err);
                    }

                    Err(anyhow::anyhow!("Internal error: failed to return \
                                         result to caller"))
                } else {
                    Ok(())
                }
            });
        }

        // And GO!!!
        let rt = tokio::runtime::Runtime::new()?;
        let (data_file, signature_file) = requests.block_on(&rt, async move {
            let mut data_file = None;
            let mut signature_file = None;
            let mut errors: Vec<anyhow::Error> = Vec::new();

            while let Some(result) = task_set.join_next().await {
                match result {
                    Ok(Ok((Task::Signature, file))) => signature_file = Some(file),
                    Ok(Ok((Task::Url, file))) => data_file = Some(file),
                    Ok(Err(err)) => {
                        // In case of an error abort all other (probably long
                        // running) tasks.
                        task_set.abort_all();
                        errors.push(err)
                    },
                    Err(err) => {
                        // In case of an error abort all other (probably long
                        // running) tasks.
                        task_set.abort_all();
                        // Ignore errors resulting from aborting tasks.
                        if ! err.is_cancelled() {
                            errors.push(err.into());
                        }
                    },
                }
            }

            let mut errors = errors.into_iter();
            if let Some(err) = errors.next() {
                eprintln!("Aborting download.");
                std::iter::once(&err)
                    .chain(errors.as_ref())
                    .for_each(|e| eprintln!("- {:?}", e));

                return Err(err);
            }

            let data_file = if let Some(data_file) = data_file {
                data_file
            } else {
                return Err(anyhow::anyhow!(
                    "Internal error while downloading data file"));
            };

            if signature_url_.is_some() && signature_file.is_none() {
                return Err(anyhow::anyhow!(
                    "Internal error while downloading signature file"));
            }

            Ok::<_, anyhow::Error>((data_file, signature_file))
        })?;

        Ok::<_, anyhow::Error>((data_file, signature_file))
    })?;

    drop(progress_bar);

    weprintln!();
    weprintln!("Finished downloading data.  Authenticating data.");
    weprintln!();

    data_file.as_mut().rewind()?;

    let result = verify(
        sq,
        buffered_reader::File::new_with_cookie(
            data_file.as_ref().try_clone()?, data_file.path(),
            Default::default())?.into_boxed(),
        signature_file.as_ref().map(|f| f.path().to_path_buf()),
        "--signature-url",
        signature_url.map(PathBuf::from),
        &mut output_file,
        signatures,
        signers);

    if let Err(err) = result {
        if let Some(path) = output.path() {
            if let Err(err) = std::fs::remove_file(path) {
                weprintln!("Verification failed, failed to remove \
                            unverified output saved to {}: {}",
                           path.display(), err);
            }
        }

        return Err(err);
    }

    if signature_file.is_some() {
        // Verify doesn't copy the data when checking detached
        // signatures.  Do it now.
        if let Some(p) = output.path() {
            data_file.persist(p)?;
        } else {
            // Copy the data to stdout.
            data_file.as_mut().rewind()?;
            std::io::copy(&mut data_file.as_ref(), output_file)?;
        }
    }

    result
}
