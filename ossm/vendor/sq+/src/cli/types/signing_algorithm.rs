use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use clap::builder::PossibleValue;

use sequoia_openpgp as openpgp;
use openpgp::types::PublicKeyAlgorithmSpecification;

/// Public key algorithms that can be used for encryption.
///
/// This is a wrapper type for
/// [`sequoia_openpgp::types::PublicKeyAlgorithmSpecification`], which
/// only exposes algorithms that can be used for encryption.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(non_camel_case_types)]
pub enum SigningAlgorithm {
    /// RSA, 2 kbit
    ///
    /// According to RFC 9580, Section 9.1, RSA keys are deprecated
    /// and should not be generated, but may be interpreted.
    RSA2k,

    /// RSA, 3 kbit
    ///
    /// According to RFC 9580, Section 9.1, RSA keys are deprecated
    /// and should not be generated, but may be interpreted.
    RSA3k,

    /// RSA, 4 kbit
    ///
    /// According to RFC 9580, Section 9.1, RSA keys are deprecated
    /// and should not be generated, but may be interpreted.
    RSA4k,

    /// DSA, 2 kbit
    ///
    /// According to RFC 9580, Section 9.1, DSA keys are deprecated
    /// and must not be generated.
    ///
    /// This library still allows the generation of v4 DSA keys, but
    /// forbids the generation of v6 keys.
    DSA2k,

    /// DSA, 3 kbit
    ///
    /// According to RFC 9580, Section 9.1, DSA keys are deprecated
    /// and must not be generated.
    ///
    /// This library still allows the generation of v4 DSA keys, but
    /// forbids the generation of v6 keys.
    DSA3k,

    /// Legacy Ed25519
    ///
    /// D.J. Bernstein’s “Twisted” Edwards curve Ed25519.
    ///
    /// RFC 9580, Section 9.1 deprecates this legacy variant of
    /// Cv25519 in favor of a new Ed25519 variant. However, if you are
    /// using v4 instead of v6 keys due to interopability concerns,
    /// then you should prefer the legacy algorithm as well.
    Cv25519,

    /// Ed25519
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein’s
    /// Curve25519, new variant.
    ///
    /// This variant can be used with v4 keys, but if you are using v4
    /// instead of v6 keys due to interopability concerns, then you
    /// should prefer the legacy algorithm, [`Cv25519`].
    Ed25519,

    /// Ed448
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein’s Ed448.
    ///
    /// See RFC 9580, Section 11.1.
    Ed448,

    /// NIST P-256
    ///
    /// NIST curve P-256 for encryption.
    ///
    /// See RFC 9580, Section 11.1.
    NistP256,

    /// NIST P-384
    ///
    /// NIST curve P-384 for encryption.
    ///
    /// See RFC 9580, Section 11.1.
    NistP384,

    /// NIST P-521
    ///
    /// NIST curve P-521 for encryption.
    ///
    /// See RFC 9580, Section 11.1.
    NistP521,

    /// BrainpoolP256
    ///
    /// Brainpool curve P256r1 for signing.
    ///
    /// See RFC 9580, Section 11.1.
    BrainpoolP256,

    /// BrainpoolP384
    ///
    /// Brainpool curve P384r1 for signing.
    ///
    /// See RFC 9580, Section 11.1.
    BrainpoolP384,

    /// BrainpoolP512
    ///
    /// Brainpool curve P512r1 for encryption.
    ///
    /// See RFC 9580, Section 11.1.
    BrainpoolP512,

    /// MLDSA65+Ed25519.
    ///
    /// MLDSA65+Ed25519 is a post-quantum secure signing algorithm,
    /// which includes a fallback to classical Ed25519. It’s
    /// appropriate for use in general-purpose certificates.
    ///
    /// MLDSA65+Ed25519 is defined in RFC 9980.
    MLDSA65_Ed25519,

    /// MLDSA87+Ed448.
    ///
    /// MLDSA87+Ed448 is a post-quantum secure signing algorithm,
    /// which includes a fallback to classical Ed448. It has a higher
    /// security margin than than MLDSA65+Ed25519 and is consequently
    /// slower.
    ///
    /// MLDSA87+Ed448 is defined in RFC 9980.
    MLDSA87_Ed448,

    /// SLHDSA128s.
    ///
    /// SLHDSA128s is a post-quantum secure signing algorithm. There
    /// is more confidence that SLHDSA is secure than MLDSA and as
    /// such there is no classical fallback. SLHDSA is very slow and
    /// thus this algorithm is only recommended for infrequent signing
    /// (e.g., software releases) and asynchronous
    /// operations. SLHDSA128f is faster than SLHDSA128s (but still
    /// not recommended for frequent synchronous use), but it
    /// generates larger artifacts.
    ///
    /// SLHDSA128s is defined in RFC 9980.
    SLHDSA128s,

    /// SLHDSA128f.
    ///
    /// SLHDSA128f is a post-quantum secure signing algorithm. There
    /// is more confidence that SLHDSA is secure than MLDSA and as
    /// such there is no classical fallback. SLHDSA is very slow and
    /// thus this algorithm is only recommended for infrequent signing
    /// (e.g., software releases) and asynchronous
    /// operations. SLHDSA128f is faster than SLHDSA128s (but still
    /// not recommended for frequent synchronous use), but generates
    /// larger artifacts.
    ///
    /// SLHDSA128f is defined in RFC 9980.
    SLHDSA128f,

    /// SLHDSA256s.
    ///
    /// SLHDSA256s is a post-quantum secure signing algorithm. There
    /// is more confidence that SLHDSA is secure than MLDSA and as
    /// such there is no classical fallback. SLHDSA is very slow and
    /// thus this algorithm is only recommended for infrequent signing
    /// (e.g., software releases) and asynchronous
    /// operations. SLHDSA256s has a higher security margin than
    /// SLHDSA256s and SLHDSA256f and in consequently even slower.
    ///
    /// SLHDSA256s is defined in RFC 9980.
    SLHDSA256s,
}

const SIGNING_ALGORITHM_VARIANTS: [SigningAlgorithm; 19] = [
    SigningAlgorithm::RSA2k,
    SigningAlgorithm::RSA3k,
    SigningAlgorithm::RSA4k,
    SigningAlgorithm::DSA2k,
    SigningAlgorithm::DSA3k,
    SigningAlgorithm::Cv25519,
    SigningAlgorithm::Ed25519,
    SigningAlgorithm::Ed448,
    SigningAlgorithm::NistP256,
    SigningAlgorithm::NistP384,
    SigningAlgorithm::NistP521,
    SigningAlgorithm::BrainpoolP256,
    SigningAlgorithm::BrainpoolP384,
    SigningAlgorithm::BrainpoolP512,
    SigningAlgorithm::MLDSA65_Ed25519,
    SigningAlgorithm::MLDSA87_Ed448,
    SigningAlgorithm::SLHDSA128s,
    SigningAlgorithm::SLHDSA128f,
    SigningAlgorithm::SLHDSA256s,
];

impl SigningAlgorithm {
    /// Returns an iterator over CipherSuite’s variants.
    pub fn variants() -> impl Iterator<Item = Self> {
        SIGNING_ALGORITHM_VARIANTS.into_iter()
    }
}

impl From<&SigningAlgorithm> for PublicKeyAlgorithmSpecification {
    fn from(value: &SigningAlgorithm) -> Self {
        use PublicKeyAlgorithmSpecification as PK;

        match value {
            SigningAlgorithm::RSA2k => PK::rsa(2 * 1024),
            SigningAlgorithm::RSA3k => PK::rsa(3 * 1024),
            SigningAlgorithm::RSA4k => PK::rsa(4 * 1024),
            SigningAlgorithm::DSA2k => PK::dsa(2 * 1024),
            SigningAlgorithm::DSA3k => PK::dsa(3 * 1024),
            SigningAlgorithm::Cv25519 => PK::legacy_ed25519(),
            SigningAlgorithm::Ed25519 => PK::ed25519(),
            SigningAlgorithm::Ed448 => PK::ed448(),
            SigningAlgorithm::NistP256 => PK::nistp256_for_signing(),
            SigningAlgorithm::NistP384 => PK::nistp384_for_signing(),
            SigningAlgorithm::NistP521 => PK::nistp521_for_signing(),
            SigningAlgorithm::BrainpoolP256 => PK::brainpoolp256_for_signing(),
            SigningAlgorithm::BrainpoolP384 => PK::brainpoolp384_for_signing(),
            SigningAlgorithm::BrainpoolP512 => PK::brainpoolp512_for_signing(),
            SigningAlgorithm::MLDSA65_Ed25519 => PK::mldsa65_ed25519(),
            SigningAlgorithm::MLDSA87_Ed448 => PK::mldsa87_ed448(),
            SigningAlgorithm::SLHDSA128s => PK::slhdsa128s(),
            SigningAlgorithm::SLHDSA128f => PK::slhdsa128f(),
            SigningAlgorithm::SLHDSA256s => PK::slhdsa256s(),
        }
    }
}

impl From<SigningAlgorithm> for PublicKeyAlgorithmSpecification {
    fn from(value: SigningAlgorithm) -> Self {
        (&value).into()
    }
}

const SIGNING_ALGORITHM_MAP: &[(&str, SigningAlgorithm)] = &[
    // This must be sorted so that it can be used with
    // [`slice::binary_search`].
    ("brainpoolp256", SigningAlgorithm::BrainpoolP256),
    ("brainpoolp384", SigningAlgorithm::BrainpoolP384),
    ("brainpoolp512", SigningAlgorithm::BrainpoolP512),
    ("cv25519", SigningAlgorithm::Cv25519),
    ("dsa2k", SigningAlgorithm::DSA2k),
    ("dsa3k", SigningAlgorithm::DSA3k),
    ("ed25519", SigningAlgorithm::Ed25519),
    ("ed448", SigningAlgorithm::Ed448),
    ("mldsa65-ed25519", SigningAlgorithm::MLDSA65_Ed25519),
    ("mldsa87-ed448", SigningAlgorithm::MLDSA87_Ed448),
    ("nistp256", SigningAlgorithm::NistP256),
    ("nistp384", SigningAlgorithm::NistP384),
    ("nistp521", SigningAlgorithm::NistP521),
    ("rsa2k", SigningAlgorithm::RSA2k),
    ("rsa3k", SigningAlgorithm::RSA3k),
    ("rsa4k", SigningAlgorithm::RSA4k),
    ("slhdsa128f", SigningAlgorithm::SLHDSA128f),
    ("slhdsa128s", SigningAlgorithm::SLHDSA128s),
    ("slhdsa256s", SigningAlgorithm::SLHDSA256s),
];

impl Display for SigningAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (as_str, variant) in SIGNING_ALGORITHM_MAP.iter() {
            if variant == self {
                return write!(f, "{}", as_str);
            }
        }
        unreachable!("SIGNING_ALGORITHM_MAP is inconsistent");
    }
}

impl Debug for SigningAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl FromStr for SigningAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Make sure it is sorted.
        debug_assert!(
            SIGNING_ALGORITHM_MAP.windows(2).all(|window| {
                window[0].0 < window[1].0
            }),
            "SIGNING_ALGORITHM_MAP not sorted");

        match SIGNING_ALGORITHM_MAP.binary_search_by(|&(probe, _)| {
            probe.cmp(s)
        }) {
            Ok(i) => Ok(SIGNING_ALGORITHM_MAP[i].1.clone()),
            Err(_) => {
                Err(anyhow::anyhow!(
                    "{:?} is not a valid encryption algorithm", s))
            }
        }
    }
}

impl clap::ValueEnum for SigningAlgorithm {
    fn value_variants<'a>() -> &'a [Self] {
        &SIGNING_ALGORITHM_VARIANTS[..]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(PossibleValue::new(self.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str() {
        assert_eq!(SigningAlgorithm::from_str("rsa2k").expect("valid"),
                   SigningAlgorithm::RSA2k);
        assert_eq!(SigningAlgorithm::from_str("rsa3k").expect("valid"),
                   SigningAlgorithm::RSA3k);
        assert_eq!(SigningAlgorithm::from_str("rsa4k").expect("valid"),
                   SigningAlgorithm::RSA4k);
        assert_eq!(SigningAlgorithm::from_str("dsa2k").expect("valid"),
                   SigningAlgorithm::DSA2k);
        assert_eq!(SigningAlgorithm::from_str("dsa3k").expect("valid"),
                   SigningAlgorithm::DSA3k);
        assert_eq!(SigningAlgorithm::from_str("cv25519").expect("valid"),
                   SigningAlgorithm::Cv25519);
        assert_eq!(SigningAlgorithm::from_str("ed25519").expect("valid"),
                   SigningAlgorithm::Ed25519);
        assert_eq!(SigningAlgorithm::from_str("ed448").expect("valid"),
                   SigningAlgorithm::Ed448);
        assert_eq!(SigningAlgorithm::from_str("nistp256").expect("valid"),
                   SigningAlgorithm::NistP256);
        assert_eq!(SigningAlgorithm::from_str("nistp384").expect("valid"),
                   SigningAlgorithm::NistP384);
        assert_eq!(SigningAlgorithm::from_str("nistp521").expect("valid"),
                   SigningAlgorithm::NistP521);
        assert_eq!(SigningAlgorithm::from_str("brainpoolp256").expect("valid"),
                   SigningAlgorithm::BrainpoolP256);
        assert_eq!(SigningAlgorithm::from_str("brainpoolp384").expect("valid"),
                   SigningAlgorithm::BrainpoolP384);
        assert_eq!(SigningAlgorithm::from_str("brainpoolp512").expect("valid"),
                   SigningAlgorithm::BrainpoolP512);
        assert_eq!(SigningAlgorithm::from_str("mldsa65-ed25519").expect("valid"),
                   SigningAlgorithm::MLDSA65_Ed25519);
        assert_eq!(SigningAlgorithm::from_str("mldsa87-ed448").expect("valid"),
                   SigningAlgorithm::MLDSA87_Ed448);
        assert_eq!(SigningAlgorithm::from_str("slhdsa128s").expect("valid"),
                   SigningAlgorithm::SLHDSA128s);
        assert_eq!(SigningAlgorithm::from_str("slhdsa128f").expect("valid"),
                   SigningAlgorithm::SLHDSA128f);
        assert_eq!(SigningAlgorithm::from_str("slhdsa256s").expect("valid"),
                   SigningAlgorithm::SLHDSA256s);

        SigningAlgorithm::from_str("Brainpoolp256")
            .expect_err("case sensitive");
        SigningAlgorithm::from_str("BRAINPOOLP256")
            .expect_err("case sensitive");

        for v in SigningAlgorithm::variants() {
            // Roundtrip: display -> from_str
            assert_eq!(
                SigningAlgorithm::from_str(&format!("{}", v)).expect("can parse"),
                v);
        }
    }

    #[test]
    fn display() {
        // Make sure everything is lower case.
        assert_eq!(&SigningAlgorithm::RSA3k.to_string(), "rsa3k");

        for v in SigningAlgorithm::variants() {
            let s = format!("{}", v);
            assert!(s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
            }));
        }
    }

    #[test]
    fn for_signing() {
        // Make sure all the algorithms actually support signing.
        for v in SigningAlgorithm::variants() {
            let a = PublicKeyAlgorithmSpecification::from(v);
            assert!(a.for_signing(), "{:?}", a);
        }
    }
}
