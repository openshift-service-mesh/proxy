use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

/// A canonical user ID.
#[derive(thiserror::Error, Debug)]
pub enum UserIDLint {
    /// Not UTF-8 Encoded.
    #[error("{:?} is not UTF-8 encoded",
            String::from_utf8_lossy(.0.value()))]
    NotUTF8Encoded(UserID, #[source] std::str::Utf8Error),

    /// Not in canonical form.
    ///
    /// Canonical form is: `Display Name (Comment)
    /// <email@example.org>` where either the display name, comment or
    /// email address is required.
    #[error("The user ID {:?} is not in canonical form{}",
            String::from_utf8_lossy(.0.value()),
            .1.as_ref()
                .map(|u| {
                    format!(", try {:?}",
                            String::from_utf8_lossy(u.value()))
                })
            .unwrap_or_else(|| "".to_string()))]
    NotCanonical(UserID, Option<UserID>),

    /// Bare emails are technically in canonical form, but are not
    /// advisable.
    ///
    /// Bare emails are problematic, because regular expressions that
    /// match on email addresses usually assume the email address is
    /// in angle brackets.
    #[error("{:?} is a bare email address, try \"<{}>\"",
            String::from_utf8_lossy(.0.value()),
            String::from_utf8_lossy(.0.value()))]
    BareEmail(UserID),

    /// The name has excessive space characters at the beginning or
    /// end.
    #[error("{:?} has spaces at the beginning or the end, try {:?}",
            .0, .0.trim())]
    NameHasExcessSpaces(String),

    /// The name contains a comment.
    #[error("{:?} contains a comment {:?}, remove it or use --userid",
            .0, .1)]
    NameContainsComment(String, String),

    /// The name contains an email address.
    #[error("{:?} contains an email address {:?}, remove it or use --userid",
            .0, .1)]
    NameContainsEmail(String, String),

    /// The name is a bare email address.
    #[error("{:?} is a bare email address, use --email", .0)]
    NameIsBareEmail(String),

    /// The email has excessive space characters at the beginning or
    /// end.
    #[error("{:?} is not a bare email address; it has spaces at the \
             beginning or the end, try {:?}",
            .0, .0.trim())]
    EmailHasExcessSpaces(String),

    /// The email contains a comment.
    #[error("{:?} is not a bare email address: it contains a comment {:?}; \
             remove it or use --userid", .0, .1)]
    EmailContainsComment(String, String),

    /// The email contains a name.
    #[error("{:?} is not a bare email address: it contains a name {:?}; \
             remove it or use --userid",
            .0, .1)]
    EmailContainsName(String, String),

    /// The email is not a bare email address.
    #[error("{:?} is not a bare email address, try {:?}",
            .0, &.0[1..(.0.len()-1)])]
    EmailIsNotBare(String),
}

/// Returns an error if the user ID is not in canonical form.
pub(crate) fn lint_userid(uid: &UserID)
    -> std::result::Result<(), UserIDLint>
{
    let mut components = Vec::new();

    let map_err = |err: anyhow::Error| {
        if let Ok(err) = err.downcast::<std::str::Utf8Error>() {
            return UserIDLint::NotUTF8Encoded(uid.clone(), err);
        }

        UserIDLint::NotCanonical(uid.clone(), None)
    };

    // Returning the name (or comment or email address) means
    // checking that the user ID is in canonical form.  Thus,
    // if this fails, the user ID is not in canonical form.
    if let Some(name) = uid.name().map_err(map_err)? {
        components.push(name.to_string());
    }

    if let Some(comment) = uid.comment().map_err(map_err)? {
        components.push(format!("({})", comment));
    }

    let email = if let Some(email) = uid.email().map_err(map_err)? {
        components.push(format!("<{}>", email));
        Some(email)
    } else {
        None
    };

    let userid_canonical = UserID::from(components.join(" "));
    if &userid_canonical != uid {
        if email.map(|e| e.as_bytes()) == Some(&uid.value()) {
            // Bare email address.
            return Err(UserIDLint::BareEmail(uid.clone()));
        } else {
            return Err(UserIDLint::NotCanonical(
                uid.clone(), Some(userid_canonical)));
        }
    }

    Ok(())
}

/// Lints user IDs and displays the lints.
///
/// Returns an error if any of the user IDs have lints.
pub(crate) fn lint_userids(uids: &[UserID]) -> Result<(), anyhow::Error> {
    let mut non_canonical = Vec::new();
    for uid in uids.into_iter() {
        if let Err(err) = lint_userid(&uid) {
            non_canonical.push(err)
        }
    }

    if non_canonical.is_empty() {
        Ok(())
    } else {
        if non_canonical.len() == 1 {
            weprintln!("{}.", non_canonical[0]);
            weprintln!();
        } else {
            weprintln!("The following user IDs are not in canonical form:");
            weprintln!();
            for err in non_canonical.iter() {
                weprintln!(initial_indent = "  - ", "{}", err);
            }
            weprintln!();
        }

        let bare_email = non_canonical.iter()
            .filter_map(|err| {
                if let UserIDLint::BareEmail(uid) = err {
                    Some(uid.clone())
                } else {
                    None
                }
            })
            .next();

        weprintln!("Canonical user IDs are of the form \
                    `Name <localpart@example.org>`.  {}\
                    Consider fixing the user IDs or passing \
                    `--allow-non-canonical-userids`.",
                   if let Some(uid) = bare_email {
                       format!("Bare email addresses should be wrapped in angle \
                                brackets like so `<{}>`.  ",
                               String::from_utf8_lossy(uid.value()))
                   } else {
                       "".to_string()
                   });
        weprintln!();

        Err(anyhow::anyhow!("\
            Some user IDs are not in canonical form"))
    }
}

/// Returns an error if the given name is anything but a name.
pub fn lint_name(n: &str) -> Result<(), UserIDLint> {
    let u = UserID::from(n);

    // Check for various problems for which we can give concrete
    // advice.
    let e = UserID::from(format!("x <{}>", n));
    if e.email().ok().flatten() == Some(n) {
        return Err(UserIDLint::NameIsBareEmail(n.into()));
    }

    if u.name().ok().flatten() == Some(n.trim()) && n != n.trim() {
        return Err(UserIDLint::NameHasExcessSpaces(n.into()));
    }

    let c = UserID::from(format!("x {}", n));
    if let Some(comment) = c.comment().ok().flatten() {
        return Err(UserIDLint::NameContainsComment(n.into(), comment.into()));
    }

    if let Some(email) = u.email().ok().flatten() {
        return Err(UserIDLint::NameContainsEmail(n.into(), email.into()));
    }

    // This is the only acceptable path, really.
    if u.name().ok().flatten() == Some(n) {
        return Ok(());
    }

    // For a final sanity check, defer to lint_userid.
    lint_userid(&u)
}

/// Lints names and displays the lints.
///
/// Returns an error if any of the names have lints.
pub fn lint_names(names: &[String]) -> Result<(), anyhow::Error> {
    let non_canonical =
        names.iter().filter_map(|n| lint_name(&n).err()).collect::<Vec<_>>();

    if non_canonical.is_empty() {
        Ok(())
    } else {
        if non_canonical.len() == 1 {
            weprintln!("{}.", non_canonical[0]);
            weprintln!();
        } else {
            weprintln!("The following names have issues:");
            weprintln!();
            for err in non_canonical.iter() {
                weprintln!(initial_indent = "  - ", "{}", err);
            }
            weprintln!();
        }

        Err(anyhow::anyhow!("Some names had issues"))
    }
}

/// Returns an error if the given email is anything but a email.
pub fn lint_email(n: &str) -> Result<(), UserIDLint> {
    let u = UserID::from(format!("<{}>", n));

    // Check for various problems for which we can give concrete
    // advice.
    if n.starts_with('<') && n.ends_with('>') {
        return Err(UserIDLint::EmailIsNotBare(n.into()));
    }

    if n != n.trim() {
        return Err(UserIDLint::EmailHasExcessSpaces(n.into()));
    }

    let c = UserID::from(format!("x {}", n));
    if let Some(comment) = c.comment().ok().flatten() {
        return Err(UserIDLint::EmailContainsComment(n.into(), comment.into()));
    }

    let un = UserID::from(n);
    if let Some(name) = un.name().ok().flatten() {
        return Err(UserIDLint::EmailContainsName(n.into(), name.into()));
    }

    // This is the only acceptable path, really.
    if u.email().ok().flatten() == Some(n) {
        return Ok(());
    }

    // For a final sanity check, defer to lint_userid.
    lint_userid(&u)
}

/// Lints email addresses and displays the lints.
///
/// Returns an error if any of the emails have lints.
pub fn lint_emails(emails: &[String]) -> Result<(), anyhow::Error> {
    let non_canonical =
        emails.iter().filter_map(|n| lint_email(&n).err()).collect::<Vec<_>>();

    if non_canonical.is_empty() {
        Ok(())
    } else {
        if non_canonical.len() == 1 {
            weprintln!("{}.", non_canonical[0]);
            weprintln!();
        } else {
            weprintln!("The following email addresses have issues:");
            weprintln!();
            for err in non_canonical.iter() {
                weprintln!(initial_indent = "  - ", "{}", err);
            }
            weprintln!();
        }

        Err(anyhow::anyhow!("Some email addresses had issues"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn userid_lint() {
        // Invalid UTF-8.
        match lint_userid(&UserID::from(vec![0, 159, 146, 150])) {
            Err(UserIDLint::NotUTF8Encoded(_, _)) => (),
            Err(err) => {
                panic!("User ID with invalid UTF-8 resulted in wrong error: {}",
                       err);
            }
            Ok(()) => {
                panic!("User ID with invalid UTF-8 was not rejected");
            }
        }

        // Bare email.
        match lint_userid(&UserID::from("alice@example.org")) {
            Err(UserIDLint::BareEmail(_)) => (),
            Err(err) => {
                panic!("User ID with bare email address \
                        resulted in wrong error: {}",
                       err);
            }
            Ok(()) => {
                panic!("User ID with bare email address was not rejected");
            }
        }

        for uid in [
            "<foo@bar@example.com>",
            "<foo@example.org",
        ].into_iter() {
            match lint_userid(&UserID::from(uid)) {
                Err(UserIDLint::NotCanonical(_, _)) => (),
                Err(err) => {
                    panic!("Non-canonical User ID ({}) \
                            resulted in wrong error: {}",
                           uid, err);
                }
                Ok(()) => {
                    panic!("Non-canonical User ID ({}) was not rejected",
                           uid);
                }
            }
        }
    }

    #[test]
    fn name_lint() {
        use UserIDLint::*;
        // XXX: Use assert_matches! once available.
        assert!(matches!(dbg!(lint_name("Foo Bar")), Ok(())));
        assert!(matches!(dbg!(lint_name("Foo Bar ")),
                         Err(NameHasExcessSpaces(..))));
        assert!(matches!(dbg!(lint_name(" Foo Bar")),
                         Err(NameHasExcessSpaces(..))));
        assert!(matches!(dbg!(lint_name("Foo Bar (comment)")),
                         Err(NameContainsComment(..))));
        assert!(matches!(dbg!(lint_name("Foo Bar <foo@bar.example.org>")),
                         Err(NameContainsEmail(..))));
        assert!(matches!(dbg!(lint_name("<foo@bar.example.org>")),
                         Err(NameContainsEmail(..))));
        assert!(matches!(dbg!(lint_name("foo@bar.example.org")),
                         Err(NameIsBareEmail(..))));
        assert!(matches!(dbg!(lint_name("(comment)")),
                         Err(NameContainsComment(..))));
        assert!(matches!(dbg!(lint_name("(comment) <foo@bar.example.org>")),
                         Err(NameContainsComment(..))));
    }

    #[test]
    fn email_lint() {
        use UserIDLint::*;
        // XXX: Use assert_matches! once available.
        assert!(matches!(dbg!(lint_email("foo@bar.example.org")), Ok(())));
        assert!(matches!(dbg!(lint_email("foo@bar.example.org ")),
                         Err(EmailHasExcessSpaces(..))));
        assert!(matches!(dbg!(lint_email(" foo@bar.example.org")),
                         Err(EmailHasExcessSpaces(..))));
        assert!(matches!(dbg!(lint_email("foo@bar.example.org (comment)")),
                         Err(EmailContainsComment(..))));
        assert!(matches!(dbg!(lint_email("Foo Bar <foo@bar.example.org>")),
                         Err(EmailContainsName(..))));
        assert!(matches!(dbg!(lint_email("foo@bar.example.org <foo@bar.example.org>")),
                         Err(EmailContainsName(..))));
        assert!(matches!(dbg!(lint_email("<foo@bar.example.org>")),
                         Err(EmailIsNotBare(..))));
        assert!(matches!(dbg!(lint_email("(comment)")),
                         Err(EmailContainsComment(..))));
        assert!(matches!(dbg!(lint_email("(comment) <foo@bar.example.org>")),
                         Err(EmailContainsComment(..))));
    }
}
