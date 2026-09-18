//! Collection of functions to provide a unified user experience.

use anyhow::Result;

use sequoia_openpgp::{
    self as openpgp,
    KeyHandle,
    packet::UserID,
};

use crate::{
    Sq,
};

pub use crate::output::sanitize::Safe;

/// Emits a certificate header.
pub fn emit_cert(o: &mut dyn std::io::Write, sq: &Sq, cert: &openpgp::Cert)
                 -> Result<()>
{
    emit_cert_userid_str(
        o, cert, &sq.best_userid(cert, true).display().to_string())
}

/// Emits a certificate header.
pub fn emit_cert_indent(o: &mut dyn std::io::Write,
                        indent: &str,
                        sq: &Sq, cert: &openpgp::Cert)
                        -> Result<()>
{
    emit_cert_userid_str_indent(
        o, indent, cert, &sq.best_userid(cert, true).display().to_string())
}

/// Emits a certificate header.
pub fn emit_cert_userid(o: &mut dyn std::io::Write,
                        cert: &openpgp::Cert,
                        userid: &UserID)
                        -> Result<()>
{
    emit_cert_userid_str(o, cert, &String::from_utf8_lossy(userid.value()))
}

/// Emits a certificate header.
pub fn emit_cert_userid_indent(o: &mut dyn std::io::Write,
                               indent: &str,
                               cert: &openpgp::Cert,
                               userid: &UserID)
                        -> Result<()>
{
    emit_cert_userid_str_indent(
        o, indent, cert, &String::from_utf8_lossy(userid.value()))
}

/// Emits a certificate header.
pub fn emit_cert_userid_str(o: &mut dyn std::io::Write,
                            cert: &openpgp::Cert,
                            userid: &str)
                            -> Result<()>
{
    emit_cert_key_handle_userid_str(o, &cert.key_handle(), userid)
}

/// Emits a certificate header.
pub fn emit_cert_userid_str_indent(o: &mut dyn std::io::Write,
                                   indent: &str,
                                   cert: &openpgp::Cert,
                                   userid: &str)
                                   -> Result<()>
{
    emit_cert_key_handle_userid_str_indent(
        o, indent, &cert.key_handle(), userid)
}

/// Emits a certificate header.
pub fn emit_cert_key_handle_userid_str(o: &mut dyn std::io::Write,
                                       kh: &KeyHandle,
                                       userid: &str)
                                       -> Result<()>
{
    emit_cert_key_handle_userid_str_indent(o, "", kh, userid)
}

/// Emits a certificate header.
pub fn emit_cert_key_handle_userid_str_indent(o: &mut dyn std::io::Write,
                                              indent: &str,
                                              kh: &KeyHandle,
                                              userid: &str)
                                       -> Result<()>
{
    wwriteln!(stream = o,
              initial_indent = format!("{} - ┌ ", indent),
              subsequent_indent = format!("{}   │ ", indent),
              "{}", kh);
    wwriteln!(stream = o,
              initial_indent = format!("{}   └ ", indent),
              "{}", Safe(userid));
    Ok(())
}
