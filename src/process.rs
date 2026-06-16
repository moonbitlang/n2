//! Exposes process::run_command, a wrapper around platform-native process execution.

#[cfg(unix)]
pub use crate::process_posix::run_command;
#[cfg(windows)]
pub use crate::process_win::run_command;

#[cfg(target_arch = "wasm32")]
pub fn run_command(
    _cmdline: &str,
    _cwd: Option<&std::path::Path>,
    _output_cb: impl FnMut(&[u8]),
) -> anyhow::Result<Termination> {
    anyhow::bail!("wasm cannot run commands");
}

#[derive(Debug, PartialEq)]
pub enum Termination {
    Success,
    Interrupted,
    Failure,
}
