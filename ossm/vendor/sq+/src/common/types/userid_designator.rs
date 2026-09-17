use std::collections::BTreeSet;
use std::collections::HashSet;

use typenum::Unsigned;

use sequoia_openpgp as openpgp;
use openpgp::cert::amalgamation::ValidAmalgamation;
use openpgp::cert::ValidCert;
use openpgp::packet::UserID;
use openpgp::types::RevocationStatus;
use openpgp::cert::amalgamation::ValidateAmalgamation;

use crate::Result;
use crate::cli::types::UserIDDesignators;
use crate::cli::types::userid_designator::AddArgs;
use crate::cli::types::userid_designator::PlainIsAdd;
use crate::cli::types::userid_designator::ResolvedUserID;
use crate::cli::types::userid_designator::UserIDDesignator;
use crate::cli::types::userid_designator::UserIDDesignatorSemantics;
use crate::common::ui;
use crate::common::userid::lint_email;
use crate::common::userid::lint_name;
use crate::common::userid::lint_userid;
use crate::sq::NULL_POLICY;

const TRACE: bool = false;

impl<Arguments, Options, Documentation>
    UserIDDesignators<Arguments, Options, Documentation>
where
    Arguments: typenum::Unsigned,
{
    /// Resolve the user ID designators.
    ///
    /// We first match on self-signed user IDs.  We return an error if
    /// a match is ambiguous (e.g., when matching on an email address,
    /// and there are multiple user IDs with the specified email
    /// address).
    ///
    /// If there are no matches, and we don't require a match (e.g.,
    /// UserIDArg, EmailArg, NameArg), then we create a new user ID.
    ///
    /// This will match on revoked user IDs.
    ///
    /// When `--all` is provided, returns all non-revoked, self-signed
    /// user IDs.  If there are none, an error is returned.
    ///
    /// The returned `ResolvedUserID` are deduped by user ID.  That
    /// is, if multiple designators resolve to the same user ID, only
    /// one is kept.
    pub fn resolve(&self, vc: &ValidCert) -> Result<Vec<ResolvedUserID>> {
        tracer!(TRACE, "UserIDDesignators::resolve");
        t!("{:?}", self.designators);

        let arguments = Arguments::to_usize();
        let add_args = (arguments & AddArgs::to_usize()) > 0;
        let plain_is_add = (arguments & PlainIsAdd::to_usize()) > 0;

        // Find the matching User IDs.
        let mut userids = Vec::new();

        // Don't stop at the first error.
        let mut missing = false;
        let mut ambiguous_email = false;
        let mut ambiguous_name = false;
        let mut bad = None;

        if let Some(true) = self.all() {
            let mut revoked_userids = BTreeSet::new();
            let valid_userids = vc.userids()
                .filter_map(|ua| {
                    if let RevocationStatus::Revoked(_) = ua.revocation_status() {
                        revoked_userids.insert(ua.userid());
                        None
                    } else {
                        Some(ua.userid().clone())
                    }
                })
                .collect::<BTreeSet<_>>();

            let non_self_signed_userids = vc.cert().userids()
                .filter(|_| self.all_matches_non_self_signed())
                .filter(|u| ! revoked_userids.contains(u.userid()))
                .filter(|u| ! valid_userids.contains(u.userid()))
                .map(|u| u.userid().clone())
                .collect::<Vec<_>>();

            let all_userids = valid_userids.into_iter()
                .chain(non_self_signed_userids.into_iter())
                .map(|userid| ResolvedUserID::implicit(userid))
                .collect::<Vec<_>>();

            if all_userids.is_empty() {
                return Err(anyhow::anyhow!(
                    "{} has no {}user IDs",
                    vc.cert().fingerprint(),
                    if self.all_matches_non_self_signed() {
                        ""
                    } else {
                        "valid self-signed "
                    }));
            }

            userids.extend(all_userids);
        }

        for designator in self.iter() {
            use UserIDDesignatorSemantics::*;
            match designator {
                UserIDDesignator::UserID(semantics, userid) => {
                    let userid = UserID::from(&userid[..]);

                    if let Some(_) = vc.userids()
                        .find(|ua| {
                            ua.userid() == &userid
                        })
                    {
                        userids.push(designator.resolve_to(userid.clone()));
                    } else if semantics == &Add {
                        if ! self.allow_non_canonical_userids {
                            // We're going to add a user ID.  Lint it
                            // first.
                            lint_userid(&userid)?;
                        }
                        userids.push(designator.resolve_to(userid));
                    } else {
                        weprintln!("{} is not a self-signed user ID.",
                                   ui::Safe(&userid));
                        missing = true;
                    }
                }
                UserIDDesignator::Email(semantics, email) => {
                    // Validate the email address.
                    let email_userid = match UserID::from_address(None, None, email) {
                        Ok(userid) => userid,
                        Err(err) => {
                            weprintln!("{:?} is not a valid email address: {}",
                                       email, err);
                            bad = Some(err);
                            continue;
                        }
                    };

                    // Extract a normalized version for comparison
                    // purposes.
                    let email_normalized = match email_userid.email_normalized() {
                        Ok(Some(email)) => email,
                        Ok(None) => {
                            weprintln!("{:?} is not a valid email address", email);
                            bad = Some(anyhow::anyhow!(format!(
                                "{:?} is not a valid email address", email)));
                            continue;
                        }
                        Err(err) => {
                            weprintln!("{:?} is not a valid email address: {}",
                                       email, err);
                            bad = Some(err);
                            continue;
                        }
                    };

                    // Find any matching self-signed user IDs.
                    let mut found = false;
                    for ua in vc.userids() {
                        if Some(&email_normalized)
                            == ua.userid().email_normalized().unwrap_or(None).as_ref()
                        {
                            if found {
                                weprintln!("{} is ambiguous: it matches \
                                            multiple self-signed user IDs.",
                                           email);
                                ambiguous_email = true;
                            }

                            found = true;

                            if semantics == &By {
                                userids.push(designator.clone()
                                             .resolve_to(ua.userid().clone()));
                            } else {
                                userids.push(designator.clone()
                                             .resolve_to(email_userid.clone()));
                                // Since we're not returning the
                                // matching self-signed user ID, we
                                // don't need to worry about ambiguous
                                // matches.
                                break;
                            }
                        }
                    }

                    if ! found {
                        match semantics {
                            Exact | By => {
                                eprintln!("None of the self-signed user IDs \
                                           are for the email address {:?}.",
                                          email);
                                missing = true;
                            }
                            Add => {
                                if ! self.allow_non_canonical_userids {
                                    // We're going to add a user ID.  Lint it
                                    // first.
                                    lint_email(email)?;
                                }
                                userids.push(
                                    designator.clone().resolve_to(email_userid));
                            }
                        }
                    }
                }
                UserIDDesignator::Name(semantics, name) => {
                    let name_userid = UserID::from(&name[..]);
                    if name_userid.name().ok() != Some(Some(&name[..])) {
                        let err = format!("{:?} is not a valid display name",
                                          name);
                        weprintln!("{}", err);
                        bad = Some(anyhow::anyhow!(err));
                        continue;
                    };

                    let mut found = false;
                    for ua in vc.userids() {
                        if let Ok(Some(n)) = ua.userid().name() {
                            if n == name {
                                if found {
                                    weprintln!("{:?} is ambiguous: it matches \
                                                multiple self-signed user IDs.",
                                               name);
                                    ambiguous_name = true;
                                }

                                found = true;

                                if semantics == &By {
                                    userids.push(designator.clone()
                                                 .resolve_to(ua.userid().clone()));
                                } else {
                                    userids.push(designator.clone()
                                                 .resolve_to(name_userid.clone()));
                                    // Since we're not returning the
                                    // matching self-signed user ID, we
                                    // don't need to worry about ambiguous
                                    // matches.
                                    break;
                                }
                            }
                        }
                    }

                    if ! found {
                        match semantics {
                            Exact | By => {
                                eprintln!("None of the self-signed user IDs \
                                           are for the display name {:?}.",
                                          name);
                                missing = true;
                            }
                            Add => {
                                if ! self.allow_non_canonical_userids {
                                    // We're going to add a user ID.  Lint it
                                    // first.
                                    lint_name(&name[..])?;
                                }
                                userids.push(designator.resolve_to(
                                    name_userid));
                            }
                        }
                    }
                }
            }
        }

        if missing || ambiguous_email || ambiguous_name {
            weprintln!("{}'s self-signed user IDs:", vc.cert().fingerprint());
            let mut have_valid = false;
            for ua in vc.userids() {
                if std::str::from_utf8(ua.userid().value()).is_ok() {
                    have_valid = true;
                    weprintln!(initial_indent="  - ",
                               subsequent_indent="    ",
                               "{}", ui::Safe(ua.userid()));
                }
            }
            if ! have_valid {
                weprintln!("  - Certificate has no valid self-signed user IDs.");
            }

            if let Ok(null) = vc.clone().with_policy(&NULL_POLICY, vc.time()) {
                if vc.userids().count() < null.userids().count() {
                    weprintln!("Invalid self-signed user IDs:");
                    let valid: BTreeSet<_>
                        = vc.userids().map(|ua| ua.userid().clone()).collect();
                    for ua in null.userids() {
                        if valid.contains(ua.userid()) {
                            continue;
                        }

                        if std::str::from_utf8(ua.userid().value()).is_ok() {
                            let userid = ui::Safe(ua.userid());
                            if let Err(err) = ua.with_policy(vc.policy(), vc.time()) {
                                weprintln!(initial_indent="  - ",
                                           subsequent_indent="    ",
                                           "{}: {}",
                                           userid, err);
                            }
                        }
                    }
                }
            }
        }

        if missing {
            if add_args && ! plain_is_add {
                weprintln!("Use `--add-userid` or `--add-email` to use \
                            a user ID even if it isn't self signed, or has \
                            an invalid self signature.");
            }
            return Err(anyhow::anyhow!("No matching self-signed user ID"));
        }
        if ambiguous_email {
            if add_args && ! plain_is_add {
                weprintln!("Use `--userid` with the full user ID, or \
                            `--add-userid` to add a new user ID.");
            } else {
                weprintln!("Use `--userid` with the full user ID.");
            }
            return Err(anyhow::anyhow!("\
                An email address does not unambiguously designate a \
                self-signed user ID"));
        }
        if ambiguous_name {
            if add_args && ! plain_is_add {
                weprintln!("Use `--userid` with the full user ID, or \
                            `--add-userid` to add a new user ID.");
            } else {
                weprintln!("Use `--userid` with the full user ID.");
            }
            return Err(anyhow::anyhow!("\
                A name does not unambiguously designate a \
                self-signed user ID"));
        }

        if let Some(err) = bad {
            return Err(err);
        }

        // Dedup while preserving order.
        let mut seen = HashSet::new();
        userids.retain(|userid| seen.insert(userid.userid().clone()));

        t!(" => {:?}",
           userids.iter()
               .map(|u| {
                   ui::Safe(u.userid()).to_string()
               })
               .collect::<Vec<String>>()
               .join(", "));
        Ok(userids)
    }
}
