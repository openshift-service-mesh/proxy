use std::collections::BTreeSet;

use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::KeyHandle;
use openpgp::Result;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::parse::Parse;
use openpgp::types::RevocationStatus;

use super::common::NULL_POLICY;
use super::common::STANDARD_POLICY;
use super::common::Sq;
use super::common::UserIDArg;

#[test]
fn sha1_userid() {
    // Make sure we can revoke a user ID that is bound using SHA-1.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("sha1-userid-priv.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");

    // Make sure the user ID is there and really uses SHA-1.
    let vc = cert.with_policy(STANDARD_POLICY, sq.now())
        .expect("valid cert");
    let valid_userids: BTreeSet<_> = vc.userids()
        .map(|ua| ua.userid())
        .collect();
    let all_userids: BTreeSet<_> = cert.userids()
        .map(|ua| ua.userid())
        .collect();

    assert_eq!(valid_userids.len(), 1);
    assert_eq!(all_userids.len(), 2);

    let weak_userids: Vec<_>
        = all_userids.difference(&valid_userids).collect();
    let weak_userid
        = String::from_utf8_lossy(weak_userids[0].value()).to_string();

    let updated_path = sq.scratch_file("updated");
    assert!(
        sq.key_userid_revoke_maybe(&[],
                                   &cert_path,
                                   &weak_userid,
                                   "retired",
                                   "bye, bye",
                                   updated_path.as_path())
            .is_err());

    sq.key_userid_revoke(&[],
                         &cert_path,
                         UserIDArg::AddUserID(&weak_userid),
                         "retired",
                         "bye, bye",
                         updated_path.as_path());
}

#[test]
fn unbound_userid() {
    // Make sure we can't revoke a user ID that is unbound using
    // --userid.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("unbound-userid.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");

    // Make sure the user ID is there and is unbound.
    let vc = cert.with_policy(NULL_POLICY, sq.now())
        .expect("valid cert");
    let valid_userids: BTreeSet<_> = vc.userids()
        .map(|ua| ua.userid())
        .collect();
    let all_userids: BTreeSet<_> = cert.userids()
        .map(|ua| ua.userid())
        .collect();

    assert_eq!(valid_userids.len(), 0);
    assert_eq!(all_userids.len(), 1);

    let unbound_userids: Vec<_>
        = all_userids.difference(&valid_userids).collect();
    let unbound_userid
        = String::from_utf8_lossy(unbound_userids[0].value()).to_string();

    let updated_path = sq.scratch_file("updated");
    assert!(
        sq.key_userid_revoke_maybe(
            &[],
            &cert_path,
            &unbound_userid,
            "retired",
            "bye, bye",
            updated_path.as_path())
            .is_err());

    // But it should work with --add-userid.
    sq.key_userid_revoke(
        &[],
        &cert_path,
        UserIDArg::AddUserID(&unbound_userid),
        "retired",
        "bye, bye",
        updated_path.as_path());
}

#[test]
fn revoked_userid() {
    // Make sure we can revoke a user ID a second time.

    let sq = Sq::new();

    let cert_path = sq.test_data()
        .join("keys")
        .join("retired-userid.pgp");

    let cert = Cert::from_file(&cert_path).expect("can read");

    // Make sure the user ID is there and is revoked.
    let vc = cert.with_policy(NULL_POLICY, sq.now())
        .expect("valid cert");
    let mut revoked = None;
    for ua in vc.userids() {
        if let RevocationStatus::Revoked(_) = ua.revocation_status() {
            assert!(revoked.is_none(),
                    "Only expected a single revoked user ID");
            revoked = Some(ua.userid());
        }
    }
    let revoked = if let Some(revoked) = revoked {
        String::from_utf8(revoked.value().to_vec()).unwrap()
    } else {
        panic!("Expected a revoked user ID, but didn't fine one");
    };

    let updated_path = sq.scratch_file("updated");
    sq.key_userid_revoke(
        &[],
        &cert_path,
        UserIDArg::UserID(&revoked),
        "retired",
        "bye, bye",
        updated_path.as_path());
}

#[test]
fn allow_non_canonical_userid() {
    // Make sure we can revoke a user ID that is bound using SHA-1.

    let sq = Sq::new();

    let userid = "<a@b.com> <a@b.com>";

    let (_cert, cert_path, _rev_path) = sq.key_generate(
        &["--allow-non-canonical-userids"],
        &[userid]);

    // We should be able to revoke the non-canonical user ID, because
    // it is a self-signed user ID.
    let updated_path = sq.scratch_file("updated");
    sq.key_userid_revoke(&[],
                         &cert_path,
                         UserIDArg::AddUserID(userid),
                         "retired",
                         "bye, bye",
                         updated_path.as_path());

    // But we can't use a non-canonical user ID that is not
    // self-signed.
    let updated_path = sq.scratch_file("updated");
    assert!(
        sq.key_userid_revoke_maybe(
            &[],
            &cert_path,
            UserIDArg::AddUserID("<some@example.org> <some@example.org>"),
            "retired",
            "bye, bye",
            updated_path.as_path())
            .is_err());

    // Unless we include --allow
    let updated_path = sq.scratch_file("updated");
    sq.key_userid_revoke(
        &["--allow-non-canonical-userids"],
        &cert_path,
        UserIDArg::AddUserID("<some@example.org> <some@example.org>"),
        "retired",
        "bye, bye",
        updated_path.as_path());
}

#[test]
fn userid_designators() {
    let self_signed_email = "alice@example.org";
    let self_signed_userid
        = &format!("Alice <{}>", self_signed_email);

    let other_email = "alice@other.org";
    let other_userid = &format!("Alice <{}>", other_email);

    let setup = || {
        let mut sq = Sq::new();

        let (cert, cert_path, _rev_path)
            = sq.key_generate(&[], &[ self_signed_userid ]);
        sq.key_import(cert_path);

        // Link the self-signed user ID.
        sq.pki_link_add(&[], cert.key_handle(),
                        &[ self_signed_userid ]);

        // Link a non-self-signed user ID.
        sq.pki_link_add(&[], cert.key_handle(),
                        &[ UserIDArg::AddUserID(other_userid) ]);

        sq.tick(1);

        let fpr = cert.fingerprint().to_string();

        (cert, fpr, sq)
    };

    let revoke = |sq: &Sq, kh: KeyHandle, userid: UserIDArg|
        -> Result<()>
    {
        let rev_path = sq.scratch_file("revocation");
        sq.key_userid_revoke_maybe(
            &[], kh, userid,
            "retired", "xxx", rev_path.as_path())?;
        sq.cert_import(rev_path);
        Ok(())
    };

    // Currently, sq doesn't support first-party revocations on user
    // ID that are not self signed.  See:
    //
    // https://gitlab.com/sequoia-pgp/sequoia-sq/-/issues/499
    //
    // As such, we check by hand if there is a first-party revocation
    // for the specified user ID.
    let revocations = |sq: &Sq, kh: KeyHandle, userid: &str, count: usize|
    {
        let cert = sq.cert_export(&kh);
        for ua in cert.userids() {
            if &String::from_utf8_lossy(ua.userid().value()) == userid {
                assert_eq!(ua.self_revocations().count(), count);
                return;
            }
        }

        if count > 0 {
            panic!("{} does not contain {:?}", kh, userid);
        }
    };

    // 1. --user: use the specified self-signed user ID.
    let (cert, fpr, sq) = setup();

    // Self-signed and authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::UserID(self_signed_userid)).is_ok());
    revocations(&sq, cert.key_handle(), self_signed_userid, 1);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_err());

    // Authenticated, but not self-signed.
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::UserID(other_userid)).is_err());
    revocations(&sq, cert.key_handle(), other_userid, 0);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(other_userid)).is_ok());

    // 2. --add-userid: use the specified user ID.
    let (cert, fpr, sq) = setup();

    // Self-signed and authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::AddUserID(self_signed_userid)).is_ok());
    revocations(&sq, cert.key_handle(), self_signed_userid, 1);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_err());

    // Authenticated, but not self-signed.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(other_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::AddUserID(other_userid)).is_ok());
    revocations(&sq, cert.key_handle(), other_userid, 1);

    // 3. --userid-by-email: use the self-signed user ID with the
    // specified email address.
    let (cert, fpr, sq) = setup();

    // Self-signed and authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::ByEmail(self_signed_email)).is_ok());
    revocations(&sq, cert.key_handle(), self_signed_userid, 1);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_err());

    // Authenticated, but not self-signed.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(other_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::ByEmail(other_email)).is_err());
    revocations(&sq, cert.key_handle(), other_userid, 0);

    // 4. --email: use a user ID with just the email address if there
    // is a self-signed user ID with the specified email address.
    let (cert, fpr, sq) = setup();

    // Self-signed and authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::Email(self_signed_email)).is_ok());
    revocations(&sq, cert.key_handle(), self_signed_userid, 0);
    revocations(&sq, cert.key_handle(), &format!("<{}>", self_signed_email), 1);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_ok());

    // Authenticated, but not self-signed.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(other_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::Email(other_email)).is_err());
    revocations(&sq, cert.key_handle(), other_userid, 0);
    revocations(&sq, cert.key_handle(), &format!("<{}>", other_email), 0);

    // 5. --add-email: use a user ID with the email address.
    let (cert, fpr, sq) = setup();

    // Self-signed and authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(self_signed_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::AddEmail(self_signed_email)).is_ok());
    revocations(&sq, cert.key_handle(), self_signed_userid, 0);
    revocations(&sq, cert.key_handle(), &format!("<{}>", self_signed_email), 1);
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(&format!("<{}>", self_signed_email))).is_err());

    // Authenticated, but not self-signed.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(other_userid)).is_ok());
    assert!(revoke(&sq, cert.key_handle(),
                   UserIDArg::AddEmail(other_email)).is_ok());
    revocations(&sq, cert.key_handle(), other_userid, 0);
    revocations(&sq, cert.key_handle(), &format!("<{}>", other_email), 1);
}
