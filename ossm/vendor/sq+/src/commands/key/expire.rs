//! Changes key expiration.

use crate::Sq;
use crate::cli;
use crate::common::key::expire;
use crate::Result;

pub fn dispatch(sq: Sq, command: cli::key::expire::Command)
                -> Result<()>
{
    expire(sq, command.cert, None, command.expiration.value(),
           command.output, false)
}
