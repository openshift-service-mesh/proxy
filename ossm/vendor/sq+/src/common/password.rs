//! Common password-related functionality such as prompting.

use openpgp::crypto::Password;
use openpgp::Result;
use sequoia_openpgp as openpgp;

use crate::Sq;

/// Prompt to repeat a password.
const REPEAT_PROMPT: &str = "Please repeat the password";


/// Wraps `rpassword::prompt_password`.
fn prompt_password(sq: &Sq, prompt: impl ToString) -> Result<String> {
    if sq.batch {
        Err(anyhow::anyhow!("cannot prompt for password in batch mode"))
    } else {
        Ok(rpassword::prompt_password(prompt)?)
    }
}


/// Prompts the user to enter a new password.
///
/// This function is intended for creating artifacts.  For example, if
/// a new key or subkey is generated, or a message should be encrypted
/// using a password.  The cost of mistyping is high, so we prompt
/// twice.
///
/// If the two entered passwords match, the result is returned.
///
/// If the passwords differ or no password was entered, an error
/// message is printed and the process is repeated.
pub fn prompt_for_new(sq: &Sq, reason: &str) -> Result<Password> {
    prompt_for_new_internal(sq, reason, false)
        .map(|p| p.expect("is not None"))
}

/// Prompts the user to enter an optional new password.
///
/// This function is intended for creating artifacts.  For example, if
/// a new key or subkey is generated, or a message should be encrypted
/// using a password.  The cost of mistyping is high, so we prompt
/// twice.
///
/// If the two entered passwords match, the result is returned.  If no
/// password was entered, `Ok(None)` is returned.
///
/// If the passwords differ, an error message is printed and the
/// process is repeated.
pub fn prompt_for_new_or_none(sq: &Sq, reason: &str)
                              -> Result<Option<Password>>
{
    prompt_for_new_internal(sq, reason, true)
}

/// Prompts the user to enter a new password.
///
/// This function is intended for creating artifacts.  For example, if
/// a new key or subkey is generated, or a message should be encrypted
/// using a password.  The cost of mistyping is high, so we prompt
/// twice.
///
/// If the two entered passwords match, the result is returned.  If
/// `allow_none` is `true`, and no password was entered, `Ok(None)` is
/// returned.
///
/// If the passwords differ or `allow_none` is `false` and no password
/// was entered, an error message is printed and the process is
/// repeated.
fn prompt_for_new_internal(
    sq: &Sq,
    reason: &str,
    allow_none: bool,
) -> Result<Option<Password>> {
    let mut prompt = format!("Please enter the password to protect {}", reason);
    if allow_none {
        prompt.push_str(" (press enter to not use a password)");
    }

    let width = prompt.len().max(REPEAT_PROMPT.len());
    let p0 = format!("{:>1$}: ", prompt, width);
    let p1 = format!("{:>1$}: ", REPEAT_PROMPT, width);

    loop {
        let password = prompt_password(sq, &p0)?;

        if password.is_empty() && ! allow_none {
            weprintln!("Password required.  Please try again.");
            weprintln!();
            continue;
        }

        let password_repeat = prompt_password(sq, &p1)?;

        if password != password_repeat {
            weprintln!("The passwords do not match.  Please try again.");
            weprintln!();
            continue;
        }

        return if password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(password.into()))
        };
    }
}

/// Prompts once for a password to unlock an existing object.
///
/// This function is intended for consuming artifacts.  For example,
/// if a key or subkey is locked and must be unlocked, or a message
/// should be decrypted using a password.
pub fn prompt_to_unlock(sq: &Sq, reason: &str) -> Result<Password> {
    let prompt =
        format!("Please enter the password to decrypt {}: ", reason);
    let password = prompt_password(sq, &prompt)?;
    Ok(password.into())
}

/// Prompts once for a password to unlock an existing object.
///
/// This function is intended for consuming artifacts.  For example,
/// if a key or subkey is locked and must be unlocked, or a message
/// should be decrypted using a password.
pub fn prompt_to_unlock_or_cancel(sq: &Sq, reason: &str)
                                  -> Result<Option<Password>>
{
    let password =
        prompt_to_unlock(sq, &format!("{} (blank to skip)", reason))?;
    Ok(if password.map(|p| p.is_empty()) { None } else { Some(password) })
}
