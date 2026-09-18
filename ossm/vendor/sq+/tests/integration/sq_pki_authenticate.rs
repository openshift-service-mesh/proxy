use super::common::Sq;
use super::common::UserIDArg;

#[test]
fn userid_designators() {
    // Check the different user ID designators.

    let sq = Sq::new();

    let good_self_signed_email = "alice@example.org";
    let good_self_signed_userid
        = &format!("Alice <{}>", good_self_signed_email);

    let other_email = "alice@other.org";
    let other_userid = &format!("Alice <{}>", other_email);

    let bad_self_signed_email = "alice@bad.org";
    let bad_self_signed_userid
        = &format!("Alice <{}>", bad_self_signed_email);

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ good_self_signed_userid ]);
    let fpr = &cert.fingerprint().to_string();
    sq.key_import(cert_path);


    // Link the good self-signed user ID.
    sq.pki_link_add(&[], cert.key_handle(), &[ good_self_signed_userid ]);

    // Link a non-self-signed user ID.
    sq.pki_link_add(&[], cert.key_handle(),
                    &[ UserIDArg::AddUserID(other_userid) ]);

    // --userid matches user IDs that are authenticated.  It doesn't
    // matter if they are self-signed.

    // Self signed and authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(good_self_signed_userid)).is_ok());
    // Not self signed, but authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(other_userid)).is_ok());
    // Self signed, but not authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(bad_self_signed_userid)).is_err());

    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(good_self_signed_email)).is_err());
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(other_email)).is_err());
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::UserID(bad_self_signed_email)).is_err());

    // --email matches user IDs that are authenticated.  It doesn't
    // matter if they are self-signed.

    // Self signed and authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::Email(good_self_signed_email)).is_ok());
    // Not self signed, but authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::Email(other_email)).is_ok());
    // Self signed, but not authenticated.
    assert!(sq.pki_authenticate(
        &[], &fpr, UserIDArg::Email(bad_self_signed_email)).is_err());
}
