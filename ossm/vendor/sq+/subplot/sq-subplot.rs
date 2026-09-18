// Rust support for running sq-subplot.md scenarios.

use subplotlib::file::SubplotDataFile;
use subplotlib::steplibrary::datadir::Datadir;
use subplotlib::steplibrary::runcmd::Runcmd;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[step]
#[context(Runcmd)]
#[context(Datadir)]
fn install_sq(context: &ScenarioContext) {
    // The SQ_DIR variable can be set to test an installed sq rather
    // than the one built from the source tree.
    if let Some(bindir) = std::env::var_os("SQ_DIR") {
        println!("Found SQ_DIR environment variable, using that");
        context.with_mut(
            |rc: &mut Runcmd| {
                rc.prepend_to_path(bindir);
                Ok(())
            },
            false,
        )?;
    } else {
        let target_exe = env!("CARGO_BIN_EXE_sq");
        let target_path = Path::new(target_exe);
        let target_path = target_path.parent().ok_or("No parent?")?;

        context.with_mut(
            |context: &mut Runcmd| {
                context.prepend_to_path(target_path);
                Ok(())
            },
            false,
        )?;
    }

    // Create a state directory and set SEQUOIA_HOME so that sq will
    // use it.
    let home = PathBuf::from(".sequoia-home");
    let mut absolute_home = Default::default();
    context.with_mut(
        |datadir: &mut Datadir| {
            datadir.create_dir_all(&home)?;
            absolute_home = datadir.base_path().join(home);
            Ok(())
        }, false)?;
    context.with_mut(
        |runcmd: &mut Runcmd| {
            runcmd.setenv("SEQUOIA_HOME", absolute_home);
            Ok(())
        }, false)?;
}

/// Remember values between steps.
#[derive(Default, Debug, Clone)]
struct Memory {
    map: HashMap<String, String>,
}

impl ContextElement for Memory {
    fn scenario_starts(&mut self) -> StepResult {
        self.map.clear();
        Ok(())
    }
}

impl Memory {
    /// Remember a key, value pair.
    pub fn remember(&mut self, key: &str, value: &str) {
        eprintln!("remember {}={:?}", key, value);
        self.map.insert(key.into(), value.into());
    }

    /// Retrieve the value for a key. Panics if key hasn't been set.
    pub fn get(&self, key: &str) -> &str {
        eprintln!("recall {}: {:?}", key, self.map.get(key));
        self.map.get(key).unwrap()
    }
}

#[step]
#[context(Memory)]
#[context(Runcmd)]
fn remember_fingerprint_in_variable(context: &ScenarioContext, name: &str) {
    let stdout = context.with(|runcmd: &Runcmd| Ok(runcmd.stdout_as_string()), false)?;
    const PAT: &str = "Fingerprint: ";
    if let Some(i) = stdout.find(PAT) {
        let s = &stdout[i + PAT.len()..];
        if let Some(j) = s.find('\n') {
            let fpr = &s[..j];
            context.with_mut(|memory: &mut Memory| Ok(memory.remember(name, fpr)), false)?;
        } else {
            panic!("stdout didn't include newline after {:?}", PAT);
        }
    } else {
        panic!("STDOUT didn't include {:?}", PAT);
    }
}

#[cfg(all(unix, not(unix)))] // Bottom.
#[step]
#[context(Memory)]
#[context(Runcmd)]
fn stdout_matches_json_template(context: &ScenarioContext, file: SubplotDataFile) {
    let memory = context.with(|memory: &Memory| Ok(memory.clone()), false)?;
    let template = String::from_utf8_lossy(file.data());
    let wanted = expand_from_memory(&template, &memory);
    eprintln!("parsing JSON");
    let wanted: serde_json::Value = serde_json::from_str(&wanted)?;
    eprintln!("matches JSON template: wanted: {:#?}", wanted);

    let stdout = context.with(|runcmd: &Runcmd| Ok(runcmd.stdout_as_string()), false)?;
    let actual: serde_json::Value = serde_json::from_str(&stdout)?;
    eprintln!("matches JSON template: actual: {:#?}", actual);

    assert_eq!(actual, wanted);
}

#[allow(unused)]
fn expand_from_memory(mut s: &str, memory: &Memory) -> String {
    let mut result = String::new();
    while !s.is_empty() {
        let before = s;
        if let Some(i) = s.find("${") {
            result.push_str(&s[..i]);
            s = &s[i..];
            if let Some(j) = s.find("}") {
                let name = &s[2..j];
                result.push_str(memory.get(name));
                s = &s[j+1..];
            } else {
                result.push_str(&s[..2]);
                s = &s[2..];
            }
        } else {
            result.push_str(s);
            s = "";
        }
        assert!(s != before);
    }
    result
}
