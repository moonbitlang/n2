//! Tests around regenerating the build.ninja file.

use crate::e2e::*;

#[cfg(unix)]
#[test]
fn generate_build_file() -> anyhow::Result<()> {
    // Run a project where a build rule generates the build.ninja.
    let space = TestSpace::new()?;
    space.write(
        "gen.sh",
        "
echo 'regenerating build.ninja'
cat >build.ninja <<EOT
rule regen
  command = sh ./gen.sh
  generator = 1
build build.ninja: regen gen.sh
rule touch
  command = touch \\$out
build out: touch
EOT
",
    )?;

    // Generate the initial build.ninja.
    space.run_expect(std::process::Command::new("sh").args(vec!["./gen.sh"]))?;

    // Run: expect to regenerate because we don't know how the file was made.
    let out = space.run_expect(&mut n2_command(vec!["out"]))?;
    assert_output_contains(&out, "regenerating build.ninja");
    assert_output_contains(&out, "ran 2 tasks");

    // Run: everything should be up to date.
    let out = space.run_expect(&mut n2_command(vec!["out"]))?;
    assert_output_not_contains(&out, "regenerating build.ninja");
    assert_output_contains(&out, "no work");

    Ok(())
}

#[cfg(unix)]
#[test]
fn generate_specified_build_file() -> anyhow::Result<()> {
    // Run a project where a build rule generates specified_build.ninja.
    let space = TestSpace::new()?;
    space.write(
        "gen.sh",
        "
echo 'regenerating specified_build.ninja'
cat >specified_build.ninja <<EOT
rule regen
  command = sh ./gen.sh
  generator = 1
build specified_build.ninja: regen gen.sh
rule touch
  command = touch \\$out
build out: touch
EOT
",
    )?;

    // Generate the initial specified_build.ninja.
    space.run_expect(std::process::Command::new("sh").args(vec!["./gen.sh"]))?;

    // Run: expect to regenerate because we don't know how the file was made.
    let out = space.run_expect(&mut n2_command(vec!["-f", "specified_build.ninja", "out"]))?;
    assert_output_contains(&out, "regenerating specified_build.ninja");
    assert_output_contains(&out, "ran 2 tasks");

    // Run: everything should be up to date.
    let out = space.run_expect(&mut n2_command(vec!["-f", "specified_build.ninja", "out"]))?;
    assert_output_not_contains(&out, "regenerating");
    assert_output_contains(&out, "no work");

    Ok(())
}

#[cfg(unix)]
#[test]
fn generate_build_file_failure() -> anyhow::Result<()> {
    // Run a project where a build rule generates the build.ninja but it fails.
    let space = TestSpace::new()?;
    space.write(
        "build.ninja",
        &[
            TOUCH_RULE,
            "build out: touch",
            "
rule regen
  command = sh ./gen.sh
  generator = 1",
            "build build.ninja: regen gen.sh",
            "",
        ]
        .join("\n"),
    )?;
    space.write("gen.sh", "exit 1")?;

    // Run: regenerate and fail.
    let out = space.run(&mut n2_command(vec!["out"]))?;
    assert_output_contains(&out, "failed:");

    Ok(())
}

/// Use "-t restat" to mark the build.ninja up to date ahead of time.
#[cfg(unix)] // TODO: this ought to work on Windows, hrm.
#[test]
fn restat() -> anyhow::Result<()> {
    let space = TestSpace::new()?;
    space.write(
        "build.ninja",
        &[TOUCH_RULE, "build build.ninja: touch in", ""].join("\n"),
    )?;
    space.write("in", "")?;

    let out = space.run_expect(&mut n2_command(vec![
        "-d",
        "ninja_compat",
        "-t",
        "restat",
        "build.ninja",
    ]))?;
    assert_output_not_contains(&out, "touch build.ninja");

    // Building the build file should do nothing, because restat marked it up to date.
    let out = space.run_expect(&mut n2_command(vec!["build.ninja"]))?;
    assert_output_not_contains(&out, "touch build.ninja");

    std::thread::sleep(std::time::Duration::from_millis(100));

    space.write("in", "")?;
    let out = space.run_expect(&mut n2_command(vec!["build.ninja"]))?;
    assert_output_contains(&out, "touch build.ninja");

    Ok(())
}
