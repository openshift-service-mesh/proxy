//! Common file handling support.

use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::{
    fs, io::{self, stdout},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use anyhow::{Context, Result};

use tempfile::NamedTempFile;

use sequoia_openpgp::{
    self as openpgp,
    armor,
    serialize::stream::{Armorer, Message},
};

use openpgp::crypto::mem::Protected;

use crate::{
    cli::types::FileOrStdout,
    sq::Sq,
};

impl FileOrStdout {
    /// Returns whether the stream is stdout.
    pub fn is_stdout(&self) -> bool {
        self.path().is_none()
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use.
    ///
    /// This is suitable for any kind of OpenPGP data, decrypted or
    /// authenticated payloads.
    pub fn create_safe(
        &self,
        sq: &Sq,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(sq)
    }

    /// Opens the file (or stdout) for writing data that is NOT safe
    /// for non-interactive use.
    pub fn create_unsafe(
        &self,
        sq: &Sq,
    ) -> Result<Box<dyn Write + Sync + Send>> {
        self.create(sq)
    }

    /// Opens the file (or stdout) for writing data that is safe for
    /// non-interactive use because it is an OpenPGP data stream.
    ///
    /// Emitting armored data with the label `armor::Kind::SecretKey`
    /// implicitly configures this output to emit secret keys.
    pub fn create_pgp_safe<'a>(
        &self,
        sq: &Sq,
        binary: bool,
        kind: armor::Kind,
    ) -> Result<Message<'a>> {
        // Allow secrets to be emitted if the armor label says secret
        // key.
        let mut o = self.clone();
        if kind == armor::Kind::SecretKey {
            o = o.for_secrets();
        }
        let sink = o.create_safe(sq)?;

        let mut message = Message::new(sink);
        if ! binary {
            message = Armorer::new(message).kind(kind).build()?;
        }
        Ok(message)
    }

    /// Helper function, do not use directly. Instead, use create_or_stdout_safe
    /// or create_or_stdout_unsafe.
    fn create(&self, sq: &Sq) -> Result<Box<dyn Write + Sync + Send>> {
        let sink = self._create_sink(sq)?;
        if self.is_for_secrets() || ! cfg!(debug_assertions) {
            // We either expect secrets, or we are in release mode.
            Ok(sink)
        } else {
            // In debug mode, if we don't expect secrets, scan the
            // output for inadvertently leaked secret keys.
            Ok(Box::new(SecretLeakDetector::new(sink)))
        }
    }
    fn _create_sink(&self, sq: &Sq) -> Result<Box<dyn Write + Sync + Send>>
    {
        if let Some(path) = self.path() {
            if !path.exists() || sq.overwrite {
                Ok(Box::new(
                    PartFileWriter::create_with_restricted_permissions(
                        path, self.is_for_secrets())
                        .context("Failed to create output file")?,
                ))
            } else {
                // If path points to a special file (char device,
                // block device, fifo, socket) use it, even if
                // `overwrite` is `false`.
                #[cfg(unix)]
                if let Ok(p) = fs::metadata(path) {
                    if p.file_type().is_char_device()
                        || p.file_type().is_block_device()
                        || p.file_type().is_fifo()
                        || p.file_type().is_socket()
                    {
                        return Ok(Box::new(
                            PartFileWriter::create_with_restricted_permissions(
                                path, self.is_for_secrets())
                                .with_context(|| {
                                    format!("Failed to open special file {}",
                                            path.display())
                                })?,
                        ))
                    }
                }
                Err(anyhow::anyhow!(
                    "File {} exists, use \"sq --overwrite ...\" to overwrite",
                    path.display(),
                ))
            }
        } else {
            Ok(Box::new(stdout()))
        }
    }
}

/// A writer that writes to a temporary file first, then persists the
/// file under the desired name.
///
/// This has two benefits.  First, consumers only see the file once we
/// are done writing to it, i.e. they don't see a partial file.
///
/// Second, we guarantee not to overwrite the file until the operation
/// is finished.  Therefore, it is safe to use the same file as input
/// and output.
pub struct PartFileWriter {
    path: PathBuf,
    sink: Option<NamedTempFile>,
    // If true, copy the temporary file instead of renaming it.
    copy: bool,
    restricted_permissions: bool,
}

impl io::Write for PartFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sink()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink()?.flush()
    }
}

impl Drop for PartFileWriter {
    fn drop(&mut self) {
        if let Err(e) = self.persist() {
            weprintln!(initial_indent = "Error: ", "{}", e);
            std::process::exit(1);
        }
    }
}

impl PartFileWriter {
    /// Opens a file for writing.
    ///
    /// The file will be created under a different name in the target
    /// directory, and will only be renamed to `path` once
    /// [`PartFileWriter::persist`] is called or the object is
    /// dropped.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<PartFileWriter> {
        Self::create_with_restricted_permissions(path, false)
    }

    /// Opens a file for writing.
    ///
    /// The file will be created under a different name in the target
    /// directory, and will only be renamed to `path` once
    /// [`PartFileWriter::persist`] is called or the object is
    /// dropped. If `restricted` is set to true, the Unix permissions
    /// will be limited to the user before applying a umask.
    pub fn create_with_restricted_permissions<P: AsRef<Path>>(
        path: P, restricted: bool)
        -> Result<PartFileWriter>
    {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent()
            .ok_or(anyhow::anyhow!("cannot write to the root"))?;
        let file_name = path.file_name()
            .ok_or(anyhow::anyhow!("cannot write to .."))?;

        let mut sink = tempfile::Builder::new();

        // By default, temporary files are 0o600 on Unix. If
        // restricted is not true, we want newly created files to
        // respect umask fully.
        if ! restricted {
            platform! {
                unix => {
                    use std::os::unix::fs::PermissionsExt;
                    // The permissions will be masked by the user's umask.
                    sink.permissions(std::fs::Permissions::from_mode(0o666));
                },
                windows => {
                    // We cannot do the same on Windows.
                },
            }
        }

        // Try to create tempfile in parent, if that fails use the
        // default OS location (mostly /tmp).
        let mut copy = false;
        let sink = match sink
            .prefix(file_name)
            .suffix(".part")
            .tempfile_in(parent) {
                Ok(s) => s,
                Err(_) => {
                    // It seems that we have limited possibilities in
                    // `parent`, choose the default location for temp
                    // files and use copy for persisting as it is less
                    // invasive.  This also catches the case where we
                    // crossed filesystem boundaries.
                    copy = true;
                    sink
                        .prefix(file_name)
                        .suffix(".part")
                        .tempfile()?
                },
            };

        Ok(PartFileWriter {
            path,
            sink: Some(sink),
            copy,
            restricted_permissions: restricted,
        })
    }

    /// Returns a mutable reference to the file, or an error.
    fn sink(&mut self) -> io::Result<&mut NamedTempFile> {
        self.sink.as_mut().ok_or(io::Error::new(
            io::ErrorKind::Other,
            anyhow::anyhow!("file already persisted")))
    }

    const DEFAULT_BUF_SIZE: usize = 64 * 1024;

    /// Persists the file under its final name.
    pub fn persist(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.sink.take() {
            if self.copy {
                file.rewind()?;

                let mut open_options = OpenOptions::new();
                open_options.create(true)
                    .write(true)
                    .truncate(true);

                platform! {
                    unix => {
                        use std::os::unix::fs::FileTypeExt;
                        use std::os::unix::fs::OpenOptionsExt;
                        use std::os::unix::fs::PermissionsExt;

                        let mut modify_permissions = true;
                        let meta_result = std::fs::metadata(&self.path);
                        if let Ok(meta) = &meta_result {
                            let ft = meta.file_type();
                            // Don't modify permissions on special files as
                            // they (usually) are not owned by a non-privileged
                            // user and their permissions should stay the same.
                            if ft.is_char_device()
                                || ft.is_block_device()
                                || ft.is_fifo()
                                || ft.is_socket()
                            {
                                modify_permissions = false;
                            }
                        }

                        if modify_permissions && self.restricted_permissions {
                            // If output is an existing regular file, forbid
                            // group/other access if restricted is true.
                            if let Ok(meta) = &meta_result {
                                if meta.file_type().is_file() {
                                    std::fs::set_permissions(
                                        &self.path,
                                        PermissionsExt::from_mode(0o600))?;
                                }
                            }

                            // Overwrite default permissions for newly created
                            // files.
                            open_options.mode(0o600);
                        }
                        open_options.custom_flags(libc::O_NOFOLLOW);
                    },
                    windows => {
                        use std::fs::OpenOptions;
                        use std::os::windows::prelude::*;

                        // Do not allow others to read or modify this
                        // file while we have it open for writing.
                        open_options.share_mode(0);
                    },
                }

                let mut target = open_options.open(&self.path)?;

                // We use read()/write() instead of std::io::copy so
                // that we can zero the internal buffer.
                let mut buffer: Protected = [0; Self::DEFAULT_BUF_SIZE].into();

                while let Ok(len) = file.read(buffer.as_mut()) {
                    if len == 0 {
                        break;
                    }
                    target.write_all(&buffer[0..len])?;
                }
                target.flush()?;
            } else {
                file.persist(&self.path)?;
            }
        }
        Ok(())
    }
}

/// A writer that buffers all data, and scans for secret keys on drop.
///
/// This is used to assert that we only write secret keys in places
/// where we expect that.  As this buffers all data, and has a
/// performance impact, we only do this in debug builds.
struct SecretLeakDetector<W: io::Write + Send + Sync> {
    sink: W,
    data: Vec<u8>,
}

impl<W: io::Write + Send + Sync> io::Write for SecretLeakDetector<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.sink.write(buf)?;
        self.data.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

impl<W: io::Write + Send + Sync> Drop for SecretLeakDetector<W> {
    fn drop(&mut self) {
        let _ = self.detect_leaks();
    }
}

impl<W: io::Write + Send + Sync> SecretLeakDetector<W> {
    /// Creates a shim around `sink` that scans for inadvertently
    /// leaked secret keys.
    fn new(sink: W) -> Self {
        SecretLeakDetector {
            sink,
            data: Vec::with_capacity(4096),
        }
    }

    /// Scans the buffered data for secret keys, panic'ing if one is
    /// found.
    fn detect_leaks(&self) -> Result<()> {
        use openpgp::Packet;
        use openpgp::parse::{Parse, PacketParserResult, PacketParser};

        let mut ppr = PacketParser::from_bytes(&self.data)?;
        while let PacketParserResult::Some(pp) = ppr {
            match &pp.packet {
                Packet::SecretKey(_) | Packet::SecretSubkey(_) =>
                    panic!("Leaked secret key: {:?}", pp.packet),
                _ => (),
            }
            let (_, next_ppr) = pp.recurse()?;
            ppr = next_ppr;
        }

        Ok(())
    }
}
