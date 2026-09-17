use crate::integration::common::Sq;

/// Check that invalid syntax is caught.
#[test]
fn version() {
    let sq = Sq::new();

    let version = format!(
        "{}.{}.{}",
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH"));

    // Make sure "--cli-version" works.
    let cmd = sq.command_args(&[
        "--cli-version", &version,
        "version"
    ][..]);
    sq.run(cmd, true);

    // Unsupported versions should be rejected.
    let cmd = sq.command_args(&[
        "--cli-version", "0.0.0",
        "version"
    ]);
    sq.run(cmd, false);

    // --cli-version must be the first argument.
    let cmd = sq.command_args(&[
        "version",
        "--cli-version", &version
    ]);
    sq.run(cmd, false);

    // Invalid versions should be rejected.
    let cmd = sq.command_args(&[
        "--cli-version", &version[1..],
        "version"
    ]);
    sq.run(cmd, false);
}

#[test]
fn check_compatibility() {
    let sq = Sq::new();

    let mut die = 0;
    let mut check = |major, minor, patch, success: bool| {
        let version = &format!("{}.{}.{}", major, minor, patch);

        eprintln!("Checking {}", version);

        let cmd = sq.command_args(&["--cli-version", version, "version"][..]);
        let output = sq.run(cmd, None);
        match (output.status.success(), success) {
            (true, true) => {
                eprintln!("PASSED: Version correctly considered compatible.");
            }
            (false, false) => {
                eprintln!("PASSED: Version correctly considered incompatible.");
            }
            (true, false) => {
                eprintln!("FAILED: Version incorrectly considered compatible.");
                die += 1;
            }
            (false, true) => {
                eprintln!("FAILED: Version incorrectly considered incompatible.");
                die += 1;
            }
        }
    };

    // Get the current version.
    let major: u32 = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap();
    let minor: u32 = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap();
    let patch: u32 = env!("CARGO_PKG_VERSION_PATCH").parse().unwrap();

    // Make sure the current version works.
    check(major, minor, patch, true);

    // Make sure selecting an earlier major version fails.
    if major > 0 {
        check(major - 1, minor, patch, false);
        check(major - 1, 0, 0, false);
        check(major - 1, 999, 999, false);
    }

    // Make sure selecting a later major version fails.
    check(major + 1, minor, patch, false);
    check(major + 1, 0, 0, false);
    check(major + 1, 999, 999, false);

    // Make sure selecting an earlier minor version succeeds.
    if minor > 0 {
        check(major, minor - 1, patch, true);
        check(major, minor - 1, 0, true);
        check(major, minor - 1, 999, true);
    }

    // Make sure selecting a later minor version fails.
    check(major, minor + 1, patch, false);
    check(major, minor + 1, 0, false);
    check(major, minor + 1, 999, false);

    // Make sure selecting an earlier patch version succeeds.
    if patch > 0 {
        check(major, minor, patch - 1, true);
    }

    // Make sure selecting a later patch version fails.
    check(major, minor, patch + 1, false);

    if die > 0 {
        panic!("{} checks failed", die);
    }
}
