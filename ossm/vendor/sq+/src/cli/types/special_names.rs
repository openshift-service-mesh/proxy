use std::fmt;

/// Special names are used to identify special certificates.
///
/// Special certificates are created by `sq`.  Currently, they
/// correspond to shadow CAs.  First, addressing them by fingerprint
/// is annoying.  But, since they are created by `sq`, they have a
/// different fingerprint on each system.  This makes it possible to
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecialName {
    PublicDirectories,
    KeysOpenpgpOrg,
    KeysMailvelopeCom,
    ProtonMe,
    WKD,
    DANE,
    Autocrypt,
    Web,
    // NB: If you add a new variant, be sure to update
    // SPECIAL_VARIANTS and SPECIAL_STRINGS!
}

// Ideally SPECIAL_VARIANTS and SPECIAL_VALUES would be a slice of
// tuples.  But, because clap needs a slice of names, we split it up.
const SPECIAL_VARIANTS: &'static [SpecialName] = &[
    SpecialName::PublicDirectories,
    SpecialName::KeysOpenpgpOrg,
    SpecialName::KeysMailvelopeCom,
    SpecialName::ProtonMe,
    SpecialName::WKD,
    SpecialName::DANE,
    SpecialName::Autocrypt,
    SpecialName::Web,
];

const SPECIAL_STRINGS: &'static [&'static str] = &[
    "public-directories",
    "keys.openpgp.org",
    "keys.mailvelope.com",
    "proton.me",
    "wkd",
    "dane",
    "autocrypt",
    "web",
];

impl fmt::Display for SpecialName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>)
        -> fmt::Result
    {
        assert_eq!(SPECIAL_VARIANTS.len(), SPECIAL_STRINGS.len());

        for (variant, string)
            in SPECIAL_VARIANTS.iter().zip(SPECIAL_STRINGS.iter())
        {
            if variant == self {
                return write!(f, "{}", string);
            }
        }
        panic!("You didn't update SPECIAL_VARIANTS");
    }
}

impl clap::ValueEnum for SpecialName {
    fn value_variants<'a>() -> &'a [Self] {
        SPECIAL_VARIANTS
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        assert_eq!(SPECIAL_VARIANTS.len(), SPECIAL_STRINGS.len());

        for (variant, string)
            in SPECIAL_VARIANTS.iter().zip(SPECIAL_STRINGS.iter())
        {
            if variant == self {
                return Some(string.into());
            }
        }
        panic!("You didn't update SPECIAL_VARIANTS");
    }
}
