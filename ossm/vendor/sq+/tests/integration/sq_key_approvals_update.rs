use std::ffi::OsStr;
use std::path::Path;

use super::common::{artifact, NO_USERIDS, Sq, STANDARD_POLICY, UserIDArg};

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Result,
    cert::amalgamation::ValidateAmalgamation,
    parse::Parse,
};

#[test]
fn update_files() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let sq = Sq::at(now);

    let alice_userid = "<alice@example.org>";
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &["<alice@example.org>"]);
    let (_bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &["<bob@example.org>"]);

    // Attest the certifications.
    //
    // public is first merged into private.
    let attest = |sq: &Sq, public: &Path| {
        let priv_file = sq.scratch_file(
            &*format!("{}-priv",
                      public.file_name()
                      .unwrap_or(OsStr::new(""))
                      .to_str().unwrap_or("")));

        sq.keyring_merge(
            &[ public, &alice_pgp ][..], None,
            &*priv_file);

        let approval_file = sq.scratch_file(
            &*format!("{}-approval", public.display()));

        let approval = sq.key_approvals_update(
            &["--add-all"], &priv_file, NO_USERIDS, &*approval_file);

        eprintln!("{}", sq.inspect(&approval_file));

        assert_eq!(approval.bad_signatures().count(), 0);

        let approval_ua = approval.userids().next().unwrap();
        assert_eq!(approval_ua.approvals().count(), 1);

    };

    // Attest nothing.
    attest(&sq, &alice_pgp);

    // Have Bob certify Alice.
    let alice2_pub_pgp = sq.scratch_file("alice2_pub");
    let alice2 = sq.pki_vouch_add(&[],
                                      &bob_pgp,
                                      &alice_pgp,
                                      &[alice_userid],
                                      &*alice2_pub_pgp);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest Bob's certification.
    attest(&sq, &alice2_pub_pgp);

    Ok(())
}

const ALICE_USERID: &str = "<alice@example.org>";
const BOB_USERID: &str = "<bob@example.org>";

fn make_keys(sq: &mut Sq) -> Result<(Cert, Cert)> {
    let (alice, alice_pgp, _alice_rev)
        = sq.key_generate(&[], &[ALICE_USERID]);
    let (bob, bob_pgp, _bob_rev)
        = sq.key_generate(&[], &[BOB_USERID]);

    sq.key_import(alice_pgp);
    sq.key_import(bob_pgp);

    // Give Sequoia a little space to backdate the signatures.  Note:
    // It will not backdate them past the key creation time.
    sq.tick(10);

    Ok((alice, bob))
}


#[test]
fn update_all() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let mut sq = Sq::at(now);
    let (alice, bob) = make_keys(&mut sq)?;

    // Attest the zero certifications.
    let approval = sq.key_approvals_update(
        &["--add-all"], alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 1);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 0);

    // Have Bob certify Alice.
    let alice2 = sq.pki_vouch_add(&[],
                                      bob.key_handle(),
                                      alice.key_handle(),
                                      &[ALICE_USERID],
                                      None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest Bob's certification.
    let approval = sq.key_approvals_update(
        &["--add-all"], &alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 2);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 1);

    // Drop the approval of Bob's certification.
    let approval = sq.key_approvals_update(
        &["--remove-all"], &alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 3);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 0);

    Ok(())
}

#[test]
fn update_by() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let mut sq = Sq::at(now);
    let (alice, bob) = make_keys(&mut sq)?;
    let bob_fp = bob.fingerprint().to_string();

    // Attest the zero certifications.
    let approval = sq.key_approvals_update(
        &["--add-by", &bob_fp], alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 1);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 0);

    // Have Bob certify Alice.
    let alice2 = sq.pki_vouch_add(&[],
                                      bob.key_handle(),
                                      alice.key_handle(),
                                      &[ALICE_USERID],
                                      None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest Bob's certification.
    let approval = sq.key_approvals_update(
        &["--add-by", &bob_fp], &alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 2);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 1);

    // Drop the approval of Bob's certification.
    let approval = sq.key_approvals_update(
        &["--remove-by", &bob_fp], &alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 3);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 0);

    Ok(())
}


#[test]
fn update_authenticated() -> Result<()> {
    // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1111
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let mut sq = Sq::at(now);
    let (alice, bob) = make_keys(&mut sq)?;
    let bob_fp = bob.fingerprint().to_string();

    // Have Bob certify Alice.
    let alice2 = sq.pki_vouch_add(&[],
                                      bob.key_handle(),
                                      alice.key_handle(),
                                      &[ALICE_USERID],
                                      None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest the zero certifications.
    let approval = sq.key_approvals_update(
        &["--add-authenticated"], alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 1);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 0);

    // Link Bob's cert to his user ID.
    let mut link = sq.command();
    link.args(&["pki", "link", "add",
                "--cert", &bob_fp,
                "--userid", BOB_USERID]);
    sq.run(link, true);

    // Attest Bob's certification.
    let approval = sq.key_approvals_update(
        &["--add-authenticated"], &alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    assert_eq!(approval_ua.approvals().count(), 2);
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 1);

    Ok(())
}

#[test]
fn ignore_shadow_ca() {
    // Check that update ignores certificates made by shadow CAs.
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let mut sq = Sq::at(now);
    let (alice, bob) = make_keys(&mut sq).unwrap();

    // Have Bob certify Alice.
    let alice2 = sq.pki_vouch_add(&[],
                                      bob.key_handle(),
                                      alice.key_handle(),
                                      &[ALICE_USERID],
                                      None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    let shadow_ca = artifact("keys/_sequoia_ca_keys.openpgp.org.pgp");
    sq.key_import(&shadow_ca);
    let shadow_ca = Cert::from_file(&shadow_ca).unwrap();

    // Have the shadow CA certify Alice.
    let alice2 = sq.pki_vouch_add(&[],
                                      &shadow_ca.key_handle(),
                                      alice.key_handle(),
                                      &[ALICE_USERID],
                                      None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest to all certifications.  This should ignore the shadow
    // CA's certification.
    let approval = sq.key_approvals_update(
        &["--add-all"], &alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    // We have an approval key signature.
    assert_eq!(approval_ua.approvals().count(), 1);
    // With one approval (not two!).
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 1);
}

#[test]
fn ignore_unexportable_certifications() {
    // Check that update ignores certificates that are not exportable.
    let now = std::time::SystemTime::now()
        - std::time::Duration::new(60 * 60, 0);

    let mut sq = Sq::at(now);
    let (alice, bob) = make_keys(&mut sq).unwrap();

    // Have Bob create a non-exportable certification for Alice.
    let alice2 = sq.pki_vouch_add(&["--local"],
                                      bob.key_handle(),
                                      alice.key_handle(),
                                      &[ALICE_USERID],
                                      None);
    assert_eq!(alice2.fingerprint(), alice.fingerprint());

    // Attest to all certifications.  This should ignore
    // non-exportable certifications.
    let approval = sq.key_approvals_update(
        &["--add-all"], &alice.key_handle(), NO_USERIDS, None);

    assert_eq!(approval.bad_signatures().count(), 0);
    let approval_ua = approval.userids().next().unwrap();
    for approval in approval_ua.approvals() {
        eprintln!(" - {:?}", approval);
    }
    // We have an approval key signature.
    assert_eq!(approval_ua.approvals().count(), 1);
    // With zero approvals.
    assert_eq!(approval_ua.with_policy(STANDARD_POLICY, None).unwrap()
               .approved_certifications().count(), 0);
}

#[test]
fn userid_designators() {
    let self_signed_email = "alice@example.org";
    let self_signed_userid
        = &format!("Alice <{}>", self_signed_email);

    let other_email = "alice@other.org";
    let other_userid = &format!("Alice <{}>", other_email);

    let mut sq = Sq::new();

    let (cert, cert_path, _rev_path)
        = sq.key_generate(&[], &[ self_signed_userid ]);
    sq.key_import(cert_path);

    // Give Sequoia a little space to backdate the signatures.  Note:
    // It will not backdate them past the key creation time.
    sq.tick(10);

    // 1. --userid: use the specified self-signed user ID.
    sq.key_approvals_update(
        &["--add-all"], cert.key_handle(),
        &[ UserIDArg::UserID(self_signed_userid) ], None);
    assert!(sq.try_key_approvals_update(
        &["--add-all"], cert.key_handle(),
        &[ UserIDArg::UserID(other_userid) ], None).is_err());

    // 2. --email: use the self-signed user ID with the specified
    // email address.
    sq.key_approvals_update(
        &["--add-all"], cert.key_handle(),
        &[ UserIDArg::Email(self_signed_email) ], None);
    assert!(sq.try_key_approvals_update(
        &["--add-all"], cert.key_handle(),
        &[ UserIDArg::Email(other_email) ], None).is_err());
}
