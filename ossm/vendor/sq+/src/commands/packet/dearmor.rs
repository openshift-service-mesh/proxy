use std::io;

use sequoia_openpgp as openpgp;
use openpgp::armor;

use crate::Sq;
use crate::Result;
use crate::cli;

pub fn dispatch(sq: Sq, command: cli::packet::dearmor::Command)
    -> Result<()>
{
    tracer!(TRACE, "dearmor::dispatch");

    let mut input = command.input.open("the OpenPGP data")?;
    let mut output = command.output.create_safe(&sq)?;
    let mut filter = armor::Reader::from_buffered_reader(&mut input, None)?;
    io::copy(&mut filter, &mut output)?;

    Ok(())
}
