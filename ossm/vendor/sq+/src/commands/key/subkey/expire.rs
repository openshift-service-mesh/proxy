use crate::Result;
use crate::Sq;
use crate::common::key::expire;

pub fn dispatch(sq: Sq, command: crate::cli::key::subkey::expire::Command)
    -> Result<()>
{
    assert!(! command.keys.is_empty());

    expire(sq, command.cert, Some(command.keys),
           command.expiration.value(),
           command.output, false)
}
