use openpgp::packet::UserID;
use openpgp::Fingerprint;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use sequoia_wot as wot;
use wot::Path;

pub use concise_human_readable::print_path;
pub use concise_human_readable::print_path_error;
pub use concise_human_readable::print_path_header;

mod concise_human_readable;
pub use concise_human_readable::ConciseHumanReadableOutputNetwork;

/// Trait to implement adding of Paths and outputting them in a specific format
///
/// This trait is implemented to consume a vector of Path, trust amount tuples,
/// a target Fingerprint, a target UserID, and aggregated trust amount (for the
/// target UserID) to allow further processing and eventual output in a desired
/// output format.
pub trait OutputType {
    /// Starts emitting a new cert.
    ///
    /// Must be called before calling [`OutputType::add_paths`] with a
    /// new fingerprint.
    fn add_cert(&mut self, fingerprint: &Fingerprint) -> Result<()>;

    /// Add Paths for a UserID associated with a Fingerprint
    ///
    /// Paths are provided in a vector of Path, trust amount tuples.
    /// The aggregated_amount represents the (total) trust amount (derived from
    /// the Paths) for the UserID associated with the Fingerprint
    fn add_paths(
        &mut self,
        paths: Vec<(Path, usize)>,
        fingerprint: &Fingerprint,
        userid: &UserID,
        aggregated_amount: usize,
    ) -> Result<()>;

    /// Output the data consumed via add_paths() in a specific output format
    fn finalize(&mut self) -> Result<()>;
}
