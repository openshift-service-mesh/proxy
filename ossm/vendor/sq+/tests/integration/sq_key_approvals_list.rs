use super::common::Sq;
use super::common::UserIDArg;

#[test]
fn userid_designators() {
    let self_signed_email = "alice@example.org";
    let self_signed_userid
        = &format!("Alice <{}>", self_signed_email);

    let other_email = "alice@other.org";
    let other_userid = &format!("Alice <{}>", other_email);

    let sq = Sq::new();

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ self_signed_userid ]);
    sq.key_import(cert_path);

    // 1. --userid: use the specified self-signed user ID.
    sq.key_approvals_list(
        &[], cert.key_handle(), &[ UserIDArg::UserID(self_signed_userid) ]);
    assert!(sq.try_key_approvals_list(
        &[], cert.key_handle(), &[ UserIDArg::UserID(other_userid) ]).is_err());

    // 2. --email: use the self-signed user ID with the specified
    // email address.
    sq.key_approvals_list(
        &[], cert.key_handle(), &[ UserIDArg::Email(self_signed_email) ]);
    assert!(sq.try_key_approvals_list(
        &[], cert.key_handle(), &[ UserIDArg::Email(other_email) ]).is_err());
}
