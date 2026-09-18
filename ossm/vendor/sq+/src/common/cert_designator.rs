//! Common functionality for cert designators.

use anyhow::Result;

use sequoia_cert_store::store::UserIDQueryParams;

use crate::cli::types::cert_designator::{
    CertDesignator,
};

impl CertDesignator {
    /// Returns the suitable [`UserIDQueryParams`] and pattern, if
    /// applicable.
    pub fn query_params(&self) -> Result<Option<(UserIDQueryParams, String)>> {
        match self {
            CertDesignator::Cert(_) => Ok(None),

            CertDesignator::UserID(u) =>
                Ok(Some((UserIDQueryParams::new(), u.clone()))),

            CertDesignator::Email(email) => {
                let email = UserIDQueryParams::is_email(email)?;
                let mut q = UserIDQueryParams::new();
                q.set_email(true);
                Ok(Some((q, email)))
            },

            CertDesignator::Domain(domain) => {
                let domain = UserIDQueryParams::is_domain(domain)?;
                let mut q = UserIDQueryParams::new();
                q.set_email(true)
                    .set_anchor_start(false);
                Ok(Some((q, format!("@{}", domain))))
            },

            CertDesignator::Grep(pattern) => {
                let mut q = UserIDQueryParams::new();
                q.set_anchor_start(false)
                    .set_anchor_end(false)
                    .set_ignore_case(true);
                Ok(Some((q, pattern.clone())))
            },

            CertDesignator::File(_) => Ok(None),
            CertDesignator::Stdin => Ok(None),
            CertDesignator::Special(_) => Ok(None),
            CertDesignator::Self_ => Ok(None),
        }
    }
}
