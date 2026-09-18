//! Command-line parser for `sq pki vouch replay`.

use clap::Parser;

use crate::cli::types::CertDesignators;
use crate::cli::types::ClapData;
use crate::cli::types::FileOrStdout;
use crate::cli::types::cert_designator;

use crate::cli::examples::*;

const REPLAY_EXAMPLES: Actions = Actions {
    actions: &[
        Action::setup().command(&[
            "sq", "key", "import",
            "alice-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "key", "import",
            "alice-new-secret.pgp",
        ]).build(),

        Action::setup().command(&[
            "sq", "pki", "vouch", "add",
            "--certifier=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--cert=511257EBBF077B7AEDAE5D093F68CB84CE537C9A",
            "--email=bob@example.org",
        ]).build(),

        Action::example().comment(
            "Alice generates a new certificate, and replays the certifications \
             she made with the old certificate using the new one.",
        ).command(&[
            "sq", "pki", "vouch", "replay",
            "--source=EB28F26E2739A4870ECC47726F0073F60FD0CBF0",
            "--target=C5999E8191BF7B503653BE958B1F7910D01F86E5",
        ]).build(),
    ],
};
test_examples!(sq_pki_vouch_replay, REPLAY_EXAMPLES);

#[derive(Parser, Debug)]
#[clap(
    name = "replay",
    about = "Replays vouches",
    long_about = format!(
"Replays vouches

This command replays the vouches made by one certificate using another \
certificate.  This is primarily useful when you replace a certificate, \
and you want the new certificate to have made the same certifications \
as you made with the old certificate.

Because certifications are associated with the certificated \
certificate, and not the certifier's certificate, this may not replay \
all of the certifications that the source ever made.

This command only copies the active certification for a given user ID \
and certificate.  This includes both exportable certifications \
(vouches) as well as non-exportable certifications (links).  It \
excludes expired certifications.  It also doesn't replay \
certifications made on invalid, expired or revoked certificates, or \
revoked user IDs.

This command replays all of the certifications parameters including \
any expiration time, but the creation time is set to the current time.

Stable since 1.2.0.
",
    ),
    after_help = REPLAY_EXAMPLES,
)]
pub struct Command {
    #[command(flatten)]
    pub source: CertDesignators<cert_designator::CertUserIDEmailFileArgs,
                                cert_designator::SourcePrefix,
                                cert_designator::OneValue>,
    #[command(flatten)]
    pub target: CertDesignators<cert_designator::CertUserIDEmailFileArgs,
                                cert_designator::TargetPrefix,
                                cert_designator::OneValue>,

    #[clap(
        long,
        help = "\
Don't check that the source and target share a self-signed user ID",
        long_help = "\
Don't check that the source and target share a self-signed user ID

Normally, this command checks that the source and target certificates
have a user ID in common.  This flag skips that check.",
    )]
    pub allow_dissimilar_userids: bool,

    #[clap(
        help = FileOrStdout::HELP_OPTIONAL,
        long,
        value_name = FileOrStdout::VALUE_NAME,
    )]
    pub output: Option<FileOrStdout>,
}
