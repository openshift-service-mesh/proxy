//! Detailed version and output version information.

use crate::{
    Sq,
    Result,
    cli::version,
};

pub fn dispatch(_sq: Sq, _c: version::Command)
                -> Result<()>
{
    weprintln!("sq {}", env!("CARGO_PKG_VERSION"));
    weprintln!("using sequoia-openpgp {}", sequoia_openpgp::VERSION);
    weprintln!("with cryptographic backend {}",
               sequoia_openpgp::crypto::backend());

    Ok(())
}
