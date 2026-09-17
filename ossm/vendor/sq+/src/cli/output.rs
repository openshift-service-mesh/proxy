use clap::ValueEnum;

/// What output format to prefer, when there's an option?
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum OutputFormat {
    /// Output that is meant to be read by humans, instead of programs.
    ///
    /// This type of output has no version, and is not meant to be
    /// parsed by programs.
    HumanReadable,

    /// Output as JSON.
    Json,
}
