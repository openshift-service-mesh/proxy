//! Common argument for signature notations.

use anyhow::Result;

use sequoia_openpgp::packet::signature::subpacket::{
    NotationData,
    NotationDataFlags,
};

#[derive(Debug, clap::Args)]
pub struct SignatureNotationsArg {
    #[clap(
        long = "signature-notation",
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Add a notation to the signature",
        long_help = "Add a notation to the signature

A user-defined notation's name must be of the form \
`name@a.domain.you.control.org`. If the notation's name starts \
with a `!`, then the notation is marked as being critical.  If a \
consumer of a signature doesn't understand a critical notation, \
then it will ignore the signature.  The notation is marked as \
being human readable.",
    )]
    pub signature_notations: Vec<String>,
}

impl SignatureNotationsArg {
    /// Parses the notations.
    pub fn parse(&self) -> Result<Vec<(bool, NotationData)>> {
	let n = &self.signature_notations;
	assert_eq!(n.len() % 2, 0, "notations must be pairs of key and value");

	// Each --notation takes two values.  Iterate over them in chunks of 2.
	let notations: Vec<(bool, NotationData)> = n
            .chunks(2)
            .map(|arg_pair| {
		let name = &arg_pair[0];
		let value = &arg_pair[1];

		let (critical, name) = match name.strip_prefix('!') {
                    Some(name) => (true, name),
                    None => (false, name.as_str()),
		};

		let notation_data = NotationData::new(
                    name,
                    value,
                    NotationDataFlags::empty().set_human_readable(),
		);
		(critical, notation_data)
            })
            .collect();

	Ok(notations)
    }
}
