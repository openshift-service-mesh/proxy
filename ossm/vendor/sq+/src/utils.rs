//! Miscellaneous utilities.

use sequoia_openpgp::{
    Cert,
};

/// Checks if a cert is exportable *and* has an exportable user ID.
///
/// Note: Versions of sequoia-openpgp earlier than 1.19 didn't have a
/// nice way to create non-exportable direct key signatures using the
/// CertBuilder.  Therefore, we used to create shadow CAs with
/// exportable direct key signatures.  Hence, we also check that the
/// certificates have at least one exportable user ID.
pub fn cert_exportable(c: &Cert) -> bool {
    c.exportable()
        && c.userids().any(|uid| uid.self_signatures().any(
            |s| s.exportable().is_ok()))
}
