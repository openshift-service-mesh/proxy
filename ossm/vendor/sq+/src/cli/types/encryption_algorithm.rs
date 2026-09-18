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
pub enum EncryptionAlgorithm {
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

    /// ElGamal, 2 kbit
    ///
    /// According to RFC 9580, Section 9.1, ElGamal keys are
    /// deprecated and must not be generated.
    ///
    /// This library still allows the generation of v4 Elgamal keys,
    /// but forbids the generation of v6 keys.
    ElGamal2k,

    /// ElGamal, 3 kbit
    ///
    /// According to RFC 9580, Section 9.1, ElGamal keys are
    /// deprecated and must not be generated.
    ///
    /// This library still allows the generation of v4 Elgamal keys,
    /// but forbids the generation of v6 keys.
    ElGamal3k,

    /// Legacy X25519
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein’s
    /// Curve25519, legacy variant.
    ///
    /// RFC 9580, Section 9.1 deprecates this legacy variant of
    /// Cv25519 in favor of a new X25519 variant. However, if you are
    /// using v4 instead of v6 keys due to interopability concerns,
    /// then you should prefer the legacy algorithm as well.
    Cv25519,

    /// X25519
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein’s
    /// Curve25519, new variant.
    ///
    /// This variant can be used with v4 keys, but if you are using v4
    /// instead of v6 keys due to interopability concerns, then you
    /// should prefer the legacy algorithm,
    /// PublicKeyAlgorithmSpecification::legacy_cv25519 as well.
    X25519,

    /// X448
    ///
    /// Elliptic curve Diffie-Hellman using D.J. Bernstein’s X448.
    ///
    /// See RFC 9580, Section 11.1.
    X448,

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

    /// MLKEM768+X25519
    ///
    /// MLKEM768+X25519 is a post-quantum secure encryption algorithm,
    /// which includes a fallback to classical X25519. It’s appropriate
    /// for use in general purpose certificates.
    ///
    /// MLKEM768+X25519 is defined in RFC 9980.
    MLKEM768_X25519,

    /// MLKEM1024+X448
    ///
    /// MLKEM1024+X448 is a post-quantum secure encryption algorithm,
    /// which includes a fallback to classical X448. It has a higher
    /// security margin than than MLKEM768+X25519 and is consequently
    /// slower.
    ///
    /// MLKEM1024+X448 is defined in RFC 9980.
    MLKEM1024_X448,
}

const ENCRYPTION_ALGORITHM_VARIANTS: [EncryptionAlgorithm; 16] = [
    EncryptionAlgorithm::RSA2k,
    EncryptionAlgorithm::RSA3k,
    EncryptionAlgorithm::RSA4k,
    EncryptionAlgorithm::ElGamal2k,
    EncryptionAlgorithm::ElGamal3k,
    EncryptionAlgorithm::Cv25519,
    EncryptionAlgorithm::X25519,
    EncryptionAlgorithm::X448,
    EncryptionAlgorithm::NistP256,
    EncryptionAlgorithm::NistP384,
    EncryptionAlgorithm::NistP521,
    EncryptionAlgorithm::BrainpoolP256,
    EncryptionAlgorithm::BrainpoolP384,
    EncryptionAlgorithm::BrainpoolP512,
    EncryptionAlgorithm::MLKEM768_X25519,
    EncryptionAlgorithm::MLKEM1024_X448,
];

impl EncryptionAlgorithm {
    /// Returns an iterator over CipherSuite’s variants.
    pub fn variants() -> impl Iterator<Item = Self> {
        ENCRYPTION_ALGORITHM_VARIANTS.into_iter()
    }
}

impl From<&EncryptionAlgorithm> for PublicKeyAlgorithmSpecification {
    fn from(value: &EncryptionAlgorithm) -> Self {
        use PublicKeyAlgorithmSpecification as PK;

        match value {
            EncryptionAlgorithm::RSA2k => PK::rsa(2 * 1024),
            EncryptionAlgorithm::RSA3k => PK::rsa(3 * 1024),
            EncryptionAlgorithm::RSA4k => PK::rsa(4 * 1024),
            EncryptionAlgorithm::ElGamal2k => PK::elgamal(2 * 1024),
            EncryptionAlgorithm::ElGamal3k => PK::elgamal(3 * 1024),
            EncryptionAlgorithm::Cv25519 => PK::legacy_cv25519(),
            EncryptionAlgorithm::X25519 => PK::x25519(),
            EncryptionAlgorithm::X448 => PK::x448(),
            EncryptionAlgorithm::NistP256 => PK::nistp256_for_encryption(),
            EncryptionAlgorithm::NistP384 => PK::nistp384_for_encryption(),
            EncryptionAlgorithm::NistP521 => PK::nistp521_for_encryption(),
            EncryptionAlgorithm::BrainpoolP256 => PK::brainpoolp256_for_encryption(),
            EncryptionAlgorithm::BrainpoolP384 => PK::brainpoolp384_for_encryption(),
            EncryptionAlgorithm::BrainpoolP512 => PK::brainpoolp512_for_encryption(),
            EncryptionAlgorithm::MLKEM768_X25519 => PK::mlkem768_x25519(),
            EncryptionAlgorithm::MLKEM1024_X448 => PK::mlkem1024_x448(),
        }
    }
}

impl From<EncryptionAlgorithm> for PublicKeyAlgorithmSpecification {
    fn from(value: EncryptionAlgorithm) -> Self {
        (&value).into()
    }
}

const ENCRYPTION_ALGORITHM_MAP: &[(&str, EncryptionAlgorithm)] = &[
    // This must be sorted so that it can be used with
    // [`slice::binary_search`].
    ("brainpoolp256", EncryptionAlgorithm::BrainpoolP256),
    ("brainpoolp384", EncryptionAlgorithm::BrainpoolP384),
    ("brainpoolp512", EncryptionAlgorithm::BrainpoolP512),
    ("cv25519", EncryptionAlgorithm::Cv25519),
    ("elgamal2k", EncryptionAlgorithm::ElGamal2k),
    ("elgamal3k", EncryptionAlgorithm::ElGamal3k),
    ("mlkem1024-x448", EncryptionAlgorithm::MLKEM1024_X448),
    ("mlkem768-x25519", EncryptionAlgorithm::MLKEM768_X25519),
    ("nistp256", EncryptionAlgorithm::NistP256),
    ("nistp384", EncryptionAlgorithm::NistP384),
    ("nistp521", EncryptionAlgorithm::NistP521),
    ("rsa2k", EncryptionAlgorithm::RSA2k),
    ("rsa3k", EncryptionAlgorithm::RSA3k),
    ("rsa4k", EncryptionAlgorithm::RSA4k),
    ("x25519", EncryptionAlgorithm::X25519),
    ("x448", EncryptionAlgorithm::X448),
];

impl Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (as_str, variant) in ENCRYPTION_ALGORITHM_MAP.iter() {
            if variant == self {
                return write!(f, "{}", as_str);
            }
        }
        unreachable!("ENCRYPTION_ALGORITHM_MAP is inconsistent");
    }
}

impl Debug for EncryptionAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl FromStr for EncryptionAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Make sure it is sorted.
        debug_assert!(
            ENCRYPTION_ALGORITHM_MAP.windows(2).all(|window| {
                window[0].0 < window[1].0
            }),
            "ENCRYPTION_ALGORITHM_MAP not sorted");

        match ENCRYPTION_ALGORITHM_MAP.binary_search_by(|&(probe, _)| {
            probe.cmp(s)
        }) {
            Ok(i) => Ok(ENCRYPTION_ALGORITHM_MAP[i].1.clone()),
            Err(_) => {
                Err(anyhow::anyhow!(
                    "{:?} is not a valid encryption algorithm", s))
            }
        }
    }
}

impl clap::ValueEnum for EncryptionAlgorithm {
    fn value_variants<'a>() -> &'a [Self] {
        &ENCRYPTION_ALGORITHM_VARIANTS[..]
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
        assert_eq!(EncryptionAlgorithm::from_str("brainpoolp256").expect("valid"),
                   EncryptionAlgorithm::BrainpoolP256);
        assert_eq!(EncryptionAlgorithm::from_str("brainpoolp384").expect("valid"),
                   EncryptionAlgorithm::BrainpoolP384);
        assert_eq!(EncryptionAlgorithm::from_str("brainpoolp512").expect("valid"),
                   EncryptionAlgorithm::BrainpoolP512);
        assert_eq!(EncryptionAlgorithm::from_str("cv25519").expect("valid"),
                   EncryptionAlgorithm::Cv25519);
        assert_eq!(EncryptionAlgorithm::from_str("elgamal2k").expect("valid"),
                   EncryptionAlgorithm::ElGamal2k);
        assert_eq!(EncryptionAlgorithm::from_str("elgamal3k").expect("valid"),
                   EncryptionAlgorithm::ElGamal3k);
        assert_eq!(EncryptionAlgorithm::from_str("mlkem1024-x448").expect("valid"),
                   EncryptionAlgorithm::MLKEM1024_X448);
        assert_eq!(EncryptionAlgorithm::from_str("mlkem768-x25519").expect("valid"),
                   EncryptionAlgorithm::MLKEM768_X25519);
        assert_eq!(EncryptionAlgorithm::from_str("nistp256").expect("valid"),
                   EncryptionAlgorithm::NistP256);
        assert_eq!(EncryptionAlgorithm::from_str("nistp384").expect("valid"),
                   EncryptionAlgorithm::NistP384);
        assert_eq!(EncryptionAlgorithm::from_str("nistp521").expect("valid"),
                   EncryptionAlgorithm::NistP521);
        assert_eq!(EncryptionAlgorithm::from_str("rsa2k").expect("valid"),
                   EncryptionAlgorithm::RSA2k);
        assert_eq!(EncryptionAlgorithm::from_str("rsa3k").expect("valid"),
                   EncryptionAlgorithm::RSA3k);
        assert_eq!(EncryptionAlgorithm::from_str("rsa4k").expect("valid"),
                   EncryptionAlgorithm::RSA4k);
        assert_eq!(EncryptionAlgorithm::from_str("x25519").expect("valid"),
                   EncryptionAlgorithm::X25519);
        assert_eq!(EncryptionAlgorithm::from_str("x448").expect("valid"),
                   EncryptionAlgorithm::X448);

        EncryptionAlgorithm::from_str("Brainpoolp256")
            .expect_err("case sensitive");
        EncryptionAlgorithm::from_str("BRAINPOOLP256")
            .expect_err("case sensitive");

        for v in EncryptionAlgorithm::variants() {
            // Roundtrip: display -> from_str
            assert_eq!(
                EncryptionAlgorithm::from_str(&format!("{}", v)).expect("can parse"),
                v);
        }
    }

    #[test]
    fn display() {
        // Make sure everything is lower case.
        assert_eq!(&EncryptionAlgorithm::RSA3k.to_string(), "rsa3k");

        for v in EncryptionAlgorithm::variants() {
            let s = format!("{}", v);
            assert!(s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
            }));
        }
    }

    #[test]
    fn for_encryption() {
        // Make sure all the algorithms actually support encryption.
        for v in EncryptionAlgorithm::variants() {
            let a = PublicKeyAlgorithmSpecification::from(v);
            assert!(a.for_encryption(), "{:?}", a);
        }
    }
}
