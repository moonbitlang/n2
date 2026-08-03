//! Implements run_command on posix using posix_spawn.
//! See run_command comments for why.

use crate::process::Termination;
use std::io::{Error, Read};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
#[cfg(not(target_os = "macos"))]
use std::process::{Command, Stdio};

// https://github.com/rust-lang/libc/issues/2520
// libc crate doesn't expose the 'environ' pointer.
extern "C" {
    static environ: *const *mut libc::c_char;
}

#[cfg(target_os = "macos")]
extern "C" {
    // libc does not expose this Apple extension. Apple added a non-_np
    // replacement in newer SDKs, but this older symbol keeps cwd support
    // working on older macOS runtimes too.
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

fn check_posix_spawn(func: &str, ret: libc::c_int) -> anyhow::Result<()> {
    if ret != 0 {
        let err_str = unsafe { std::ffi::CStr::from_ptr(libc::strerror(ret)) };
        anyhow::bail!("{}: {}", func, err_str.to_str().unwrap());
    }
    Ok(())
}

fn check_ret_errno(func: &str, ret: libc::c_int) -> anyhow::Result<()> {
    if ret < 0 {
        let errno = Error::last_os_error().raw_os_error().unwrap();
        let err_str = unsafe { std::ffi::CStr::from_ptr(libc::strerror(errno)) };
        anyhow::bail!("{}: {}", func, err_str.to_str().unwrap());
    }
    Ok(())
}

fn validate_env(env: &[(String, String)]) -> anyhow::Result<()> {
    for (key, value) in env {
        if key.is_empty() {
            anyhow::bail!("environment variable name is empty");
        }
        if key.contains('=') {
            anyhow::bail!("environment variable name {:?} contains '='", key);
        }
        if key.contains('\0') || value.contains('\0') {
            anyhow::bail!("environment variable {:?} contains NUL", key);
        }
    }
    Ok(())
}

/// Wraps libc::posix_spawnattr_t, in particular to implement Drop.
struct PosixSpawnAttr(libc::posix_spawnattr_t);

impl PosixSpawnAttr {
    fn new() -> anyhow::Result<Self> {
        unsafe {
            let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
            check_posix_spawn(
                "posix_spawnattr_init",
                libc::posix_spawnattr_init(&mut attr),
            )?;
            Ok(Self(attr))
        }
    }

    fn as_ptr(&mut self) -> *mut libc::posix_spawnattr_t {
        &mut self.0
    }

    #[allow(unused)]
    fn setflags(&mut self, flags: libc::c_short) -> anyhow::Result<()> {
        unsafe {
            check_posix_spawn(
                "posix_spawnattr_setflags",
                libc::posix_spawnattr_setflags(self.as_ptr(), flags),
            )
        }
    }
}

impl Drop for PosixSpawnAttr {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawnattr_destroy(self.as_ptr());
        }
    }
}

/// Wraps libc::posix_spawn_file_actions_t, in particular to implement Drop.
struct PosixSpawnFileActions(libc::posix_spawn_file_actions_t);

impl PosixSpawnFileActions {
    fn new() -> anyhow::Result<Self> {
        unsafe {
            let mut actions: libc::posix_spawn_file_actions_t = std::mem::zeroed();
            check_posix_spawn(
                "posix_spawn_file_actions_init",
                libc::posix_spawn_file_actions_init(&mut actions),
            )?;
            Ok(Self(actions))
        }
    }

    fn as_ptr(&mut self) -> *mut libc::posix_spawn_file_actions_t {
        &mut self.0
    }

    fn addopen(
        &mut self,
        fd: i32,
        path: &std::ffi::CStr,
        oflag: i32,
        mode: libc::mode_t,
    ) -> anyhow::Result<()> {
        unsafe {
            check_posix_spawn(
                "posix_spawn_file_actions_addopen",
                libc::posix_spawn_file_actions_addopen(
                    self.as_ptr(),
                    fd,
                    path.as_ptr(),
                    oflag,
                    mode,
                ),
            )
        }
    }

    fn adddup2(&mut self, fd: i32, newfd: i32) -> anyhow::Result<()> {
        unsafe {
            check_posix_spawn(
                "posix_spawn_file_actions_adddup2",
                libc::posix_spawn_file_actions_adddup2(self.as_ptr(), fd, newfd),
            )
        }
    }

    fn addclose(&mut self, fd: i32) -> anyhow::Result<()> {
        unsafe {
            check_posix_spawn(
                "posix_spawn_file_actions_addclose",
                libc::posix_spawn_file_actions_addclose(self.as_ptr(), fd),
            )
        }
    }

    #[cfg(target_os = "macos")]
    fn addchdir(&mut self, path: &std::ffi::CStr) -> anyhow::Result<()> {
        let ret = unsafe { posix_spawn_file_actions_addchdir_np(self.as_ptr(), path.as_ptr()) };
        check_posix_spawn("posix_spawn_file_actions_addchdir_np", ret)
    }
}

impl Drop for PosixSpawnFileActions {
    fn drop(&mut self) {
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}

struct Envp {
    /// Owns the strings that `ptrs` points into.
    storage: Vec<std::ffi::CString>,
    ptrs: Vec<*mut libc::c_char>,
}

impl Envp {
    fn new(env: &[(String, String)], inherit_env: bool) -> anyhow::Result<Option<Self>> {
        if inherit_env && env.is_empty() {
            return Ok(None);
        }

        validate_env(env)?;

        let mut vars: Vec<(Vec<u8>, Vec<u8>)> = if inherit_env {
            std::env::vars_os()
                .map(|(key, value)| {
                    (
                        key.as_os_str().as_bytes().to_vec(),
                        value.as_os_str().as_bytes().to_vec(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };

        for (key, value) in env {
            let key = key.as_bytes();
            let value = value.as_bytes();
            if let Some((_, existing_value)) = vars
                .iter_mut()
                .find(|(existing_key, _)| existing_key == key)
            {
                *existing_value = value.to_vec();
            } else {
                vars.push((key.to_vec(), value.to_vec()));
            }
        }

        let vars: Vec<std::ffi::CString> = vars
            .into_iter()
            .map(|(key, value)| {
                let mut entry = Vec::with_capacity(key.len() + value.len() + 1);
                entry.extend_from_slice(&key);
                entry.push(b'=');
                entry.extend_from_slice(&value);
                std::ffi::CString::new(entry)
            })
            .collect::<Result<_, _>>()?;

        let mut ptrs: Vec<*mut libc::c_char> =
            vars.iter().map(|var| var.as_ptr() as *mut _).collect();
        ptrs.push(std::ptr::null_mut());

        Ok(Some(Envp {
            storage: vars,
            ptrs,
        }))
    }

    fn as_ptr(&self) -> *const *mut libc::c_char {
        debug_assert_eq!(self.ptrs.len(), self.storage.len() + 1);
        self.ptrs.as_ptr()
    }
}

/// Create an anonymous pipe as in libc::pipe(), but using pipe2() when available
/// to set CLOEXEC flag.
fn pipe2() -> anyhow::Result<[libc::c_int; 2]> {
    // Compare to: https://doc.rust-lang.org/src/std/sys/unix/pipe.rs.html
    unsafe {
        let mut pipe: [libc::c_int; 2] = std::mem::zeroed();

        // Mac: specially handled below with POSIX_SPAWN_CLOEXEC_DEFAULT
        #[cfg(target_os = "macos")]
        check_ret_errno("pipe", libc::pipe(pipe.as_mut_ptr()))?;

        // Assume all non-Mac have pipe2; we can refine this on user feedback.
        #[cfg(all(unix, not(target_os = "macos")))]
        check_ret_errno("pipe", libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC))?;

        Ok(pipe)
    }
}

pub fn run_command(
    cmdline: &str,
    cwd: Option<&Path>,
    env: &[(String, String)],
    inherit_env: bool,
    mut output_cb: impl FnMut(&[u8]),
) -> anyhow::Result<Termination> {
    #[cfg(not(target_os = "macos"))]
    if let Some(cwd) = cwd {
        // Portable spawn chdir actions are not available on older libcs, so
        // let std handle the cwd-specific spawn path.
        return run_command_with_std_process(cmdline, cwd, env, inherit_env, output_cb);
    }

    // Spawn the subprocess using posix_spawn with output redirected to the pipe.
    // We don't use Rust's process spawning because of issue #14 and because
    // we want to feed both stdout and stderr into the same pipe, which cannot
    // be done with the existing std::process API.
    let envp = Envp::new(env, inherit_env)?;
    let (pid, mut pipe) = unsafe {
        let pipe = pipe2()?;

        let mut attr = PosixSpawnAttr::new()?;

        // Apple-specific extension: close any open fds.
        #[cfg(target_os = "macos")]
        attr.setflags(libc::POSIX_SPAWN_CLOEXEC_DEFAULT as _)?;

        let mut actions = PosixSpawnFileActions::new()?;
        // open /dev/null over stdin
        actions.addopen(
            0,
            std::ffi::CStr::from_bytes_with_nul_unchecked(b"/dev/null\0"),
            libc::O_RDONLY,
            0,
        )?;
        // stdout/stderr => pipe
        actions.adddup2(pipe[1], 1)?;
        actions.adddup2(pipe[1], 2)?;
        // close pipe in child
        actions.addclose(pipe[0])?;
        actions.addclose(pipe[1])?;

        #[cfg(target_os = "macos")]
        if let Some(cwd) = cwd {
            let cwd_nul = std::ffi::CString::new(cwd.as_os_str().as_bytes())?;
            actions.addchdir(&cwd_nul)?;
        }

        let envp_ptr = envp.as_ref().map_or(environ, |envp| envp.as_ptr());

        let mut pid: libc::pid_t = 0;
        let path = std::ffi::CStr::from_bytes_with_nul_unchecked(b"/bin/sh\0");
        let cmdline_nul = std::ffi::CString::new(cmdline).unwrap();
        let argv: [*const libc::c_char; 4] = [
            path.as_ptr(),
            b"-c\0".as_ptr() as *const _,
            cmdline_nul.as_ptr(),
            std::ptr::null(),
        ];

        check_posix_spawn(
            "posix_spawn",
            libc::posix_spawn(
                &mut pid,
                path.as_ptr(),
                actions.as_ptr(),
                attr.as_ptr(),
                // posix_spawn wants mutable argv:
                // https://stackoverflow.com/questions/50596439/can-string-literals-be-passed-in-posix-spawns-argv
                argv.as_ptr() as *const *mut _,
                envp_ptr,
            ),
        )?;
        check_ret_errno("close", libc::close(pipe[1]))?;

        (pid, std::fs::File::from_raw_fd(pipe[0]))
    };

    let mut buf: [u8; 4 << 10] = [0; 4 << 10];
    loop {
        let n = pipe.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output_cb(&buf[0..n]);
    }
    drop(pipe);

    let status = unsafe {
        let mut status: i32 = 0;
        check_ret_errno("waitpid", libc::waitpid(pid, &mut status, 0))?;
        std::process::ExitStatus::from_raw(status)
    };

    let termination = if status.success() {
        Termination::Success
    } else if let Some(sig) = status.signal() {
        match sig {
            libc::SIGINT => {
                output_cb("interrupted".as_bytes());
                Termination::Interrupted
            }
            _ => {
                output_cb(format!("signal {}", sig).as_bytes());
                Termination::Failure
            }
        }
    } else {
        Termination::Failure
    };

    Ok(termination)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid_env_rejected(cwd: Option<&Path>) {
        for (env, expected) in [
            (
                vec![("".to_owned(), "value".to_owned())],
                "environment variable name is empty",
            ),
            (vec![("A=B".to_owned(), "value".to_owned())], "contains '='"),
            (
                vec![("N2_PROCESS_TEST_ENV".to_owned(), "value\0tail".to_owned())],
                "contains NUL",
            ),
        ] {
            let mut output = Vec::new();
            let err = run_command("printf unexpected", cwd, &env, true, |buf| {
                output.extend_from_slice(buf)
            })
            .expect_err("expected invalid environment entry");
            assert!(
                err.to_string().contains(expected),
                "expected error containing {:?}, got {}",
                expected,
                err
            );
            assert!(output.is_empty());
        }
    }

    #[test]
    fn command_env() -> anyhow::Result<()> {
        let mut output = Vec::new();
        let env = [("N2_PROCESS_TEST_ENV".to_owned(), "hello".to_owned())];
        run_command(
            "printf %s \"$N2_PROCESS_TEST_ENV\"",
            None,
            &env,
            true,
            |buf| output.extend_from_slice(buf),
        )?;
        assert_eq!(output, b"hello");
        Ok(())
    }

    #[test]
    fn command_env_can_disable_inheritance() -> anyhow::Result<()> {
        let env = [("N2_PROCESS_TEST_EXPLICIT".to_owned(), "child".to_owned())];
        let envp = Envp::new(&env, false)?.expect("isolated environment block");
        assert_eq!(envp.storage.len(), 1);
        assert_eq!(
            envp.storage[0].to_bytes(),
            b"N2_PROCESS_TEST_EXPLICIT=child"
        );
        Ok(())
    }

    #[test]
    fn command_env_rejects_invalid_entries() {
        assert_invalid_env_rejected(None);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn command_env_with_cwd() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut output = Vec::new();
        let env = [("N2_PROCESS_TEST_ENV".to_owned(), "hello".to_owned())];
        run_command(
            "printf %s \"$N2_PROCESS_TEST_ENV\"",
            Some(dir.path()),
            &env,
            true,
            |buf| output.extend_from_slice(buf),
        )?;
        assert_eq!(output, b"hello");
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn command_env_with_cwd_rejects_invalid_entries() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        assert_invalid_env_rejected(Some(dir.path()));
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
fn run_command_with_std_process(
    cmdline: &str,
    cwd: &Path,
    env: &[(String, String)],
    inherit_env: bool,
    mut output_cb: impl FnMut(&[u8]),
) -> anyhow::Result<Termination> {
    validate_env(env)?;

    let pipe = pipe2()?;
    let stderr_fd = unsafe { libc::fcntl(pipe[1], libc::F_DUPFD_CLOEXEC, 3) };
    if stderr_fd < 0 {
        let err = Error::last_os_error();
        let _ = unsafe { libc::close(pipe[0]) };
        let _ = unsafe { libc::close(pipe[1]) };
        return Err(err.into());
    }

    let mut pipe_read = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
    let stdout = unsafe { std::fs::File::from_raw_fd(pipe[1]) };
    let stderr = unsafe { std::fs::File::from_raw_fd(stderr_fd) };

    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(cmdline).current_dir(cwd);
    if !inherit_env {
        command.env_clear();
    }
    let mut child = command
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    // Command retains its configured stdio handles after spawning. Drop the
    // parent-side pipe writers before waiting for EOF on the read end.
    drop(command);

    let mut buf: [u8; 4 << 10] = [0; 4 << 10];
    loop {
        let n = pipe_read.read(&mut buf)?;
        if n == 0 {
            break;
        }
        output_cb(&buf[0..n]);
    }
    drop(pipe_read);

    let status = child.wait()?;
    let termination = if status.success() {
        Termination::Success
    } else if let Some(sig) = status.signal() {
        match sig {
            libc::SIGINT => {
                output_cb("interrupted".as_bytes());
                Termination::Interrupted
            }
            _ => {
                output_cb(format!("signal {}", sig).as_bytes());
                Termination::Failure
            }
        }
    } else {
        Termination::Failure
    };

    Ok(termination)
}
