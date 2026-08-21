use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_LIMIT: usize = 16 * 1024;
const MAX_PENDING: usize = 1024 * 1024;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const ESCAPED_PIPE_GRACE: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub(crate) struct Error {
    pub(crate) code: &'static str,
    pub(crate) detail: String,
}

impl Error {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn io(code: &'static str, context: &str, error: io::Error) -> Self {
        Self::new(code, format!("{context}: {error}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy)]
pub(crate) enum AuditConfig {
    Isolated,
    Authority,
}

#[derive(Debug)]
pub(crate) struct Output {
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) status: ExitStatus,
}

/// The sole owner of a Git child, its process group, pipes, and wait capability.
pub(crate) struct GitChild {
    child: Child,
    wait_capability: Option<u32>,
    process_group: Option<u32>,
    direct: bool,
    exit_observed: bool,
    status: Option<ExitStatus>,
    stdout: Option<Pipe<std::process::ChildStdout>>,
    stderr: Option<Pipe<std::process::ChildStderr>>,
    stdin: Option<Input>,
    stdout_pending: Vec<u8>,
    deadline: Instant,
    hard_deadline: Option<Instant>,
    progress_timeout: Option<Duration>,
    settled: bool,
}

impl GitChild {
    pub(crate) fn spawn_for(
        args: &[OsString],
        cwd: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, Error> {
        Self::spawn_with_env_for(args, cwd, &[], false, timeout, AuditConfig::Isolated)
    }

    pub(crate) fn spawn_for_progress(
        args: &[OsString],
        cwd: Option<&Path>,
        idle_timeout: Duration,
        hard_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::spawn_with_env_for_progress(
            args,
            cwd,
            &[],
            false,
            idle_timeout,
            hard_timeout,
            AuditConfig::Isolated,
        )
    }

    pub(crate) fn spawn_audit(
        args: &[OsString],
        cwd: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, Error> {
        Self::spawn_with_env_for(args, cwd, &[], false, timeout, AuditConfig::Authority)
    }

    pub(crate) fn spawn_direct(
        program: &OsStr,
        args: &[OsString],
        cwd: &Path,
        lease_fd: RawFd,
    ) -> Result<Self, Error> {
        require_waitable_sigchld()?;
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for (name, _) in env::vars_os() {
            if name.as_bytes().starts_with(b"GIT_") {
                command.env_remove(name);
            }
        }
        unsafe {
            command.pre_exec(move || {
                let inherited = libc::fcntl(lease_fd, libc::F_DUPFD, 3);
                if inherited < 0 {
                    return Err(io::Error::last_os_error());
                }
                let flags = libc::fcntl(inherited, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(inherited, libc::F_SETFD, flags & !libc::FD_CLOEXEC) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command
            .spawn()
            .map_err(|error| Error::io("EXEC_FAILED", "cannot execute session program", error))?;
        let pid = child.id();
        Ok(Self {
            child,
            wait_capability: Some(pid),
            process_group: None,
            direct: true,
            exit_observed: false,
            status: None,
            stdout: None,
            stderr: None,
            stdin: None,
            stdout_pending: Vec::new(),
            deadline: Instant::now() + CLEANUP_TIMEOUT,
            hard_deadline: None,
            progress_timeout: None,
            settled: false,
        })
    }

    pub(crate) fn spawn_with_env_for(
        args: &[OsString],
        cwd: Option<&Path>,
        extra_env: &[(OsString, OsString)],
        piped_stdin: bool,
        timeout: Duration,
        audit: AuditConfig,
    ) -> Result<Self, Error> {
        Self::spawn_program_with_env_for(
            OsStr::new("git"),
            args,
            cwd,
            extra_env,
            piped_stdin,
            timeout,
            audit,
        )
    }

    pub(crate) fn spawn_with_env_for_progress(
        args: &[OsString],
        cwd: Option<&Path>,
        extra_env: &[(OsString, OsString)],
        piped_stdin: bool,
        idle_timeout: Duration,
        hard_timeout: Duration,
        audit: AuditConfig,
    ) -> Result<Self, Error> {
        let hard_deadline = Instant::now() + hard_timeout;
        let mut child = Self::spawn_with_env_for(
            args,
            cwd,
            extra_env,
            piped_stdin,
            idle_timeout.min(hard_timeout),
            audit,
        )?;
        child.deadline = child.deadline.min(hard_deadline);
        child.hard_deadline = Some(hard_deadline);
        child.progress_timeout = Some(idle_timeout);
        Ok(child)
    }

    fn spawn_program_with_env_for(
        program: &OsStr,
        args: &[OsString],
        cwd: Option<&Path>,
        extra_env: &[(OsString, OsString)],
        piped_stdin: bool,
        timeout: Duration,
        audit: AuditConfig,
    ) -> Result<Self, Error> {
        require_waitable_sigchld()?;
        let deadline = Instant::now() + timeout;
        let mut command = Command::new(program);
        command.args(args);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        for (name, _) in env::vars_os() {
            if name.as_bytes().starts_with(b"GIT_") {
                command.env_remove(name);
            }
        }
        command
            .env("LC_ALL", "C")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_MAINTENANCE_AUTO", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1");
        if matches!(audit, AuditConfig::Isolated | AuditConfig::Authority) {
            command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null");
        }
        if matches!(audit, AuditConfig::Isolated) {
            command.env("GIT_ATTR_NOSYSTEM", "1");
        }
        for (name, value) in extra_env {
            command.env(name, value);
        }
        command
            .stdin(if piped_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let child = command
            .spawn()
            .map_err(|error| Error::io("GIT_PROBE_FAILED", "cannot execute git", error))?;
        let pid = child.id();
        let mut spawned = Self {
            child,
            wait_capability: Some(pid),
            process_group: Some(pid),
            direct: false,
            exit_observed: false,
            status: None,
            stdout: None,
            stderr: None,
            stdin: None,
            stdout_pending: Vec::new(),
            deadline,
            hard_deadline: None,
            progress_timeout: None,
            settled: false,
        };
        let stdout = match spawned.child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                return Err(spawned
                    .probe_failure(Error::new("GIT_PROBE_FAILED", "Git stdout was unavailable")))
            }
        };
        spawned.stdout = match Pipe::new(stdout) {
            Ok(stdout) => Some(stdout),
            Err(error) => {
                return Err(spawned.probe_failure(Error::io(
                    "GIT_PROBE_FAILED",
                    "cannot configure Git stdout",
                    error,
                )))
            }
        };
        let stderr = match spawned.child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                return Err(spawned
                    .probe_failure(Error::new("GIT_PROBE_FAILED", "Git stderr was unavailable")))
            }
        };
        spawned.stderr = match Pipe::new(stderr) {
            Ok(stderr) => Some(stderr),
            Err(error) => {
                return Err(spawned.probe_failure(Error::io(
                    "GIT_PROBE_FAILED",
                    "cannot configure Git stderr",
                    error,
                )))
            }
        };
        if piped_stdin {
            let stdin = match spawned.child.stdin.take() {
                Some(stdin) => stdin,
                None => {
                    return Err(spawned.probe_failure(Error::new(
                        "GIT_PROBE_FAILED",
                        "Git stdin was unavailable",
                    )))
                }
            };
            spawned.stdin = match Input::new(stdin) {
                Ok(stdin) => Some(stdin),
                Err(error) => {
                    return Err(spawned.probe_failure(Error::io(
                        "GIT_PROBE_FAILED",
                        "cannot configure Git stdin",
                        error,
                    )))
                }
            };
        }
        Ok(spawned)
    }

    pub(crate) fn wait_direct(mut self) -> Result<ExitStatus, Error> {
        if !self.direct {
            return Err(Error::new(
                "EXEC_FAILED",
                "direct wait was requested for a captured child",
            ));
        }
        match self.child.wait() {
            Ok(status) => {
                self.wait_capability = None;
                self.exit_observed = true;
                self.status = Some(status);
                self.settled = true;
                Ok(status)
            }
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                self.wait_capability = None;
                self.process_group = None;
                self.settled = true;
                Err(Error::new(
                    "EXEC_CLEANUP_FAILED",
                    "lost ownership of session program",
                ))
            }
            Err(error) => Err(self.cleanup(
                Error::io("EXEC_FAILED", "cannot wait for session program", error),
                "EXEC_CLEANUP_FAILED",
            )),
        }
    }

    pub(crate) fn capture(mut self, limit: usize) -> Result<Output, Error> {
        if !self.stdout_pending.is_empty() {
            let pending = std::mem::take(&mut self.stdout_pending);
            let stdout = self.stdout.as_mut().expect("Git stdout is attached");
            stdout.retained.extend_from_slice(&pending);
        }
        let mut pipe_grace = None;
        loop {
            let exceeded = self
                .stdout
                .as_mut()
                .expect("Git stdout is attached")
                .drain(limit)
                .map_err(|error| {
                    self.probe_failure(Error::io(
                        "GIT_PROBE_FAILED",
                        "cannot read Git stdout",
                        error,
                    ))
                })?;
            let stderr_exceeded = self
                .stderr
                .as_mut()
                .expect("Git stderr is attached")
                .drain(limit)
                .map_err(|error| {
                    self.probe_failure(Error::io(
                        "GIT_PROBE_FAILED",
                        "cannot read Git stderr",
                        error,
                    ))
                })?;
            if exceeded || stderr_exceeded {
                return Err(self.probe_failure(Error::new(
                    "GIT_PROBE_FAILED",
                    "Git child output exceeded the limit",
                )));
            }
            let exited = self
                .observe_exit()
                .map_err(|error| self.probe_failure(error))?;
            if exited && pipe_grace.is_none() && !self.pipes_closed() {
                pipe_grace = Some(Instant::now() + ESCAPED_PIPE_GRACE);
            }
            if self.pipes_closed() {
                let reaped = self
                    .reap_if_exited()
                    .map_err(|error| self.probe_failure(error))?;
                if reaped {
                    return self.take_output();
                }
            }
            if Instant::now() >= self.deadline {
                return Err(self.probe_failure(Error::new(
                    "GIT_PROBE_FAILED",
                    "Git child exceeded its shared deadline",
                )));
            }
            if pipe_grace.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(self.probe_failure(Error::new(
                    "GIT_PROBE_FAILED",
                    "Git child exited but an escaped pipe remained open",
                )));
            }
            let wait_until = pipe_grace.map_or(self.deadline, |grace| grace.min(self.deadline));
            wait_for_activity(
                self.stdout_fd(),
                self.stderr_fd(),
                wait_until
                    .saturating_duration_since(Instant::now())
                    .min(POLL_INTERVAL),
            )
            .map_err(|error| {
                self.probe_failure(Error::io(
                    "GIT_PROBE_FAILED",
                    "cannot poll Git pipes",
                    error,
                ))
            })?;
        }
    }

    pub(crate) fn write_stdin(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut written = 0;
        while written != bytes.len() {
            if self.expired() {
                return Err(self.batch_failure(Error::new(
                    "GIT_BATCH_FAILED",
                    "Git batch stream exceeded its shared deadline",
                )));
            }
            let result = self
                .stdin
                .as_mut()
                .ok_or_else(|| Error::new("GIT_BATCH_FAILED", "Git stdin was not piped"))?
                .pipe
                .write(&bytes[written..]);
            match result {
                Ok(0) => {
                    return Err(self.batch_failure(Error::new(
                        "GIT_BATCH_FAILED",
                        "Git batch stdin closed before a request was written",
                    )));
                }
                Ok(count) => {
                    written += count;
                    self.note_progress()?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_batch_write()?;
                }
                Err(error) => {
                    return Err(self.batch_failure(Error::io(
                        "GIT_BATCH_FAILED",
                        "cannot write Git stdin",
                        error,
                    )));
                }
            }
            self.drain_batch_stderr()?;
        }
        Ok(())
    }

    pub(crate) fn close_stdin(&mut self) {
        self.stdin.take();
    }

    pub(crate) fn note_progress(&mut self) -> Result<(), Error> {
        if self
            .hard_deadline
            .is_some_and(|hard_deadline| Instant::now() >= hard_deadline)
        {
            return Err(self.batch_failure(Error::new(
                "GIT_BATCH_FAILED",
                "Git batch stream exceeded its hard deadline",
            )));
        }
        let Some(progress_timeout) = self.progress_timeout else {
            return Ok(());
        };
        let deadline = Instant::now() + progress_timeout;
        self.deadline = self
            .hard_deadline
            .map_or(deadline, |hard_deadline| deadline.min(hard_deadline));
        Ok(())
    }

    pub(crate) fn read_exact_stdout(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        let mut offset = 0;
        while offset < bytes.len() {
            if self.expired() {
                return Err(self.batch_failure(Error::new(
                    "GIT_BATCH_FAILED",
                    "Git batch stream exceeded its shared deadline",
                )));
            }
            let copied = (bytes.len() - offset).min(self.stdout_pending.len());
            if copied != 0 {
                bytes[offset..offset + copied].copy_from_slice(&self.stdout_pending[..copied]);
                self.stdout_pending.drain(..copied);
                offset += copied;
                self.note_progress()?;
                continue;
            }
            let result = self
                .stdout
                .as_mut()
                .expect("Git stdout is attached")
                .pipe
                .read(&mut bytes[offset..]);
            match result {
                Ok(0) => {
                    return Err(self.batch_failure(Error::new(
                        "GIT_BATCH_FAILED",
                        "Git batch output was truncated",
                    )));
                }
                Ok(count) => {
                    offset += count;
                    self.note_progress()?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_batch_activity()?;
                }
                Err(error) => {
                    return Err(self.batch_failure(Error::io(
                        "GIT_BATCH_FAILED",
                        "cannot read Git stdout",
                        error,
                    )));
                }
            }
            self.drain_batch_stderr()?;
        }
        Ok(())
    }

    pub(crate) fn read_nul_record(&mut self, limit: usize) -> Result<Option<Vec<u8>>, Error> {
        loop {
            if let Some(index) = self.stdout_pending.iter().position(|byte| *byte == 0) {
                if index > limit {
                    return Err(self.batch_failure(Error::new(
                        "GIT_BATCH_FAILED",
                        "Git stream record exceeded the limit",
                    )));
                }
                let record = self.stdout_pending.drain(..index).collect();
                self.stdout_pending.drain(..1);
                return Ok(Some(record));
            }
            if self.stdout_pending.len() > limit {
                return Err(self.batch_failure(Error::new(
                    "GIT_BATCH_FAILED",
                    "Git stream record exceeded the limit",
                )));
            }
            if self.expired() {
                return Err(self.batch_failure(Error::new(
                    "GIT_BATCH_FAILED",
                    "Git stream exceeded its shared deadline",
                )));
            }
            let mut buffer = [0_u8; 8192];
            let result = self
                .stdout
                .as_mut()
                .expect("Git stdout is attached")
                .pipe
                .read(&mut buffer);
            match result {
                Ok(0) => {
                    self.stdout.as_mut().expect("Git stdout is attached").eof = true;
                    if self.stdout_pending.is_empty() {
                        return Ok(None);
                    }
                    return Err(self.batch_failure(Error::new(
                        "GIT_BATCH_FAILED",
                        "Git stream ended with a partial record",
                    )));
                }
                Ok(count) => {
                    self.stdout_pending.extend_from_slice(&buffer[..count]);
                    self.note_progress()?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_batch_activity()?
                }
                Err(error) => {
                    return Err(self.batch_failure(Error::io(
                        "GIT_BATCH_FAILED",
                        "cannot read Git stdout",
                        error,
                    )));
                }
            }
            self.drain_batch_stderr()?;
        }
    }

    pub(crate) fn read_byte_stdout(&mut self) -> Result<u8, Error> {
        let mut byte = [0_u8; 1];
        self.read_exact_stdout(&mut byte)?;
        Ok(byte[0])
    }

    pub(crate) fn read_line_stdout(&mut self, limit: usize) -> Result<Vec<u8>, Error> {
        let mut line = Vec::with_capacity(limit.min(128));
        while line.len() < limit {
            let byte = self.read_byte_stdout()?;
            if byte == b'\n' {
                return Ok(line);
            }
            line.push(byte);
        }
        Err(self.batch_failure(Error::new(
            "GIT_BATCH_FAILED",
            "Git batch header exceeded the limit",
        )))
    }

    pub(crate) fn finish(mut self) -> Result<Output, Error> {
        self.close_stdin();
        self.capture(DEFAULT_LIMIT)
    }

    fn drain_batch_stderr(&mut self) -> Result<(), Error> {
        let exceeded = self
            .stderr
            .as_mut()
            .expect("Git stderr is attached")
            .drain(DEFAULT_LIMIT)
            .map_err(|error| {
                self.batch_failure(Error::io(
                    "GIT_BATCH_FAILED",
                    "cannot drain Git stderr",
                    error,
                ))
            })?;
        if exceeded {
            Err(self.batch_failure(Error::new(
                "GIT_BATCH_FAILED",
                "Git batch stderr exceeded the limit",
            )))
        } else {
            Ok(())
        }
    }

    fn wait_batch_activity(&mut self) -> Result<(), Error> {
        wait_for_activity(
            self.stdout_fd(),
            self.stderr_fd(),
            self.deadline
                .saturating_duration_since(Instant::now())
                .min(POLL_INTERVAL),
        )
        .map_err(|error| {
            self.batch_failure(Error::io(
                "GIT_BATCH_FAILED",
                "cannot poll Git batch pipes",
                error,
            ))
        })
    }

    fn wait_batch_write(&mut self) -> Result<(), Error> {
        let stdin = self.stdin.as_ref().expect("Git stdin is attached").fd();
        let mut fds = [
            libc::pollfd {
                fd: self.stdout_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.stderr_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stdin,
                events: libc::POLLOUT,
                revents: 0,
            },
        ];
        let timeout = self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL);
        poll_ready(&mut fds, timeout).map_err(|error| {
            self.batch_failure(Error::io(
                "GIT_BATCH_FAILED",
                "cannot poll Git batch stdin",
                error,
            ))
        })?;
        if fds[0].revents != 0 {
            self.drain_batch_stdout()?;
        }
        if fds[1].revents != 0 {
            self.drain_batch_stderr()?;
        }
        Ok(())
    }

    fn drain_batch_stdout(&mut self) -> Result<(), Error> {
        let mut buffer = [0_u8; 8192];
        loop {
            let result = self
                .stdout
                .as_mut()
                .expect("Git stdout is attached")
                .pipe
                .read(&mut buffer);
            match result {
                Ok(0) => {
                    self.stdout.as_mut().expect("Git stdout is attached").eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    if self.stdout_pending.len().saturating_add(count) > MAX_PENDING {
                        return Err(self.batch_failure(Error::new(
                            "GIT_BATCH_FAILED",
                            "Git batch output exceeded its bounded pending buffer",
                        )));
                    }
                    self.stdout_pending.extend_from_slice(&buffer[..count]);
                    self.note_progress()?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => {
                    return Err(self.batch_failure(Error::io(
                        "GIT_BATCH_FAILED",
                        "cannot drain Git batch stdout",
                        error,
                    )));
                }
            }
        }
    }

    fn take_output(&mut self) -> Result<Output, Error> {
        if self.status.is_none() {
            self.reap_if_exited()?;
        }
        let status = self.status.ok_or_else(|| {
            Error::new(
                "GIT_PROBE_CLEANUP_FAILED",
                "Git child closed its pipes without a wait result",
            )
        })?;
        self.process_group = None;
        self.settled = true;
        Ok(Output {
            stdout: self
                .stdout
                .take()
                .expect("Git stdout is attached")
                .into_bytes(),
            stderr: self
                .stderr
                .take()
                .expect("Git stderr is attached")
                .into_bytes(),
            status,
        })
    }

    fn observe_exit(&mut self) -> Result<bool, Error> {
        if self.exit_observed {
            return Ok(true);
        }
        let Some(pid) = self.wait_capability else {
            return Ok(false);
        };
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
        let result = loop {
            let result = unsafe { libc::waitid(libc::P_PID, pid, &mut info, flags) };
            if result == 0 {
                break Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                break Err(error);
            }
        };
        match result {
            Ok(()) if unsafe { info.si_pid() } == 0 => Ok(false),
            Ok(()) => {
                self.exit_observed = true;
                Ok(true)
            }
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                self.wait_capability = None;
                self.process_group = None;
                Err(Error::new(
                    "GIT_PROBE_CLEANUP_FAILED",
                    "lost ownership of Git child",
                ))
            }
            Err(error) => Err(Error::io(
                "GIT_PROBE_CLEANUP_FAILED",
                "cannot observe Git child",
                error,
            )),
        }
    }

    fn reap_if_exited(&mut self) -> Result<bool, Error> {
        if self.status.is_some() {
            return Ok(true);
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                self.wait_capability = None;
                self.exit_observed = true;
                self.status = Some(status);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                self.wait_capability = None;
                self.process_group = None;
                Err(Error::new(
                    "GIT_PROBE_CLEANUP_FAILED",
                    "lost ownership of Git child",
                ))
            }
            Err(error) => Err(Error::io(
                "GIT_PROBE_CLEANUP_FAILED",
                "cannot reap Git child",
                error,
            )),
        }
    }

    fn probe_failure(&mut self, primary: Error) -> Error {
        self.cleanup(primary, "GIT_PROBE_CLEANUP_FAILED")
    }

    fn batch_failure(&mut self, primary: Error) -> Error {
        self.cleanup(primary, "GIT_BATCH_CLEANUP_FAILED")
    }

    fn cleanup(&mut self, primary: Error, code: &'static str) -> Error {
        let mut cleanup_error = None;
        self.stdin.take();
        match self.observe_exit() {
            Ok(false) => {
                if let Err(error) = self.terminate() {
                    retain_error(
                        &mut cleanup_error,
                        Error::io(code, "cannot terminate Git process group", error),
                    );
                }
            }
            Ok(true) => {
                if !self.pipes_closed() {
                    if let Err(error) = self.terminate() {
                        retain_error(
                            &mut cleanup_error,
                            Error::io(code, "cannot terminate Git pipe-holder group", error),
                        );
                    }
                }
            }
            Err(error) => {
                retain_error(&mut cleanup_error, Error::new(code, error.detail));
                if let Err(error) = self.terminate() {
                    retain_error(
                        &mut cleanup_error,
                        Error::io(code, "cannot terminate Git process group", error),
                    );
                }
            }
        }
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        loop {
            if let Some(pipe) = self.stdout.as_mut() {
                if let Err(error) = pipe.drain(DEFAULT_LIMIT) {
                    retain_error(
                        &mut cleanup_error,
                        Error::io(code, "cannot drain Git cleanup stdout", error),
                    );
                }
            }
            if let Some(pipe) = self.stderr.as_mut() {
                if let Err(error) = pipe.drain(DEFAULT_LIMIT) {
                    retain_error(
                        &mut cleanup_error,
                        Error::io(code, "cannot drain Git cleanup stderr", error),
                    );
                }
            }
            let reaped = match self.reap_if_exited() {
                Ok(reaped) => reaped,
                Err(error) => {
                    retain_error(&mut cleanup_error, Error::new(code, error.detail));
                    self.process_group = None;
                    self.close_pipes();
                    break;
                }
            };
            if reaped {
                self.process_group = None;
                self.close_pipes();
                break;
            }
            if Instant::now() >= deadline {
                if self.status.is_none() {
                    retain_error(
                        &mut cleanup_error,
                        Error::new(code, "Git child was not reaped before its cleanup deadline"),
                    );
                }
                if !self.pipes_closed() {
                    retain_error(
                        &mut cleanup_error,
                        Error::new(code, "Git pipes remained open after cleanup termination"),
                    );
                }
                self.process_group = None;
                self.close_pipes();
                break;
            }
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(POLL_INTERVAL);
            if let Err(error) = self.wait_cleanup_activity(wait) {
                retain_error(
                    &mut cleanup_error,
                    Error::io(code, "cannot poll Git cleanup pipes", error),
                );
            }
        }
        self.settled = true;
        if let Some(error) = cleanup_error {
            return Error::new(error.code, format!("{}; primary: {primary}", error.detail));
        }
        primary
    }

    fn close_pipes(&mut self) {
        self.stdin.take();
        self.stdout.take();
        self.stderr.take();
        self.stdout_pending.clear();
    }

    fn terminate(&mut self) -> io::Result<()> {
        if self.direct {
            return self.child.kill();
        }
        let Some(process_group) = self.process_group else {
            return Ok(());
        };
        kill_process_group(process_group)
    }

    fn pipes_closed(&self) -> bool {
        self.stdout.as_ref().is_none_or(Pipe::eof) && self.stderr.as_ref().is_none_or(Pipe::eof)
    }

    fn stdout_fd(&self) -> RawFd {
        self.stdout.as_ref().expect("Git stdout is attached").fd()
    }

    fn stderr_fd(&self) -> RawFd {
        self.stderr.as_ref().expect("Git stderr is attached").fd()
    }

    fn wait_cleanup_activity(&self, timeout: Duration) -> io::Result<()> {
        let mut pipes = [
            libc::pollfd {
                fd: self.stdout.as_ref().map_or(-1, Pipe::fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.stderr.as_ref().map_or(-1, Pipe::fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        poll_ready(&mut pipes, timeout).map(|_| ())
    }

    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

pub(crate) fn capture(
    args: &[OsString],
    cwd: Option<&Path>,
    timeout: Duration,
    audit: AuditConfig,
) -> Result<Output, Error> {
    capture_with_limit(args, cwd, timeout, audit, DEFAULT_LIMIT)
}

pub(crate) fn capture_with_limit(
    args: &[OsString],
    cwd: Option<&Path>,
    timeout: Duration,
    audit: AuditConfig,
    limit: usize,
) -> Result<Output, Error> {
    let child = match audit {
        AuditConfig::Isolated => GitChild::spawn_for(args, cwd, timeout),
        AuditConfig::Authority => GitChild::spawn_audit(args, cwd, timeout),
    }?;
    child.capture(limit)
}

impl Drop for GitChild {
    fn drop(&mut self) {
        if !self.settled {
            let _ = self.cleanup(
                Error::new(
                    "GIT_PROBE_CLEANUP_FAILED",
                    "Git child dropped before completion",
                ),
                "GIT_PROBE_CLEANUP_FAILED",
            );
        }
    }
}

fn retain_error(slot: &mut Option<Error>, error: Error) {
    if let Some(previous) = slot {
        previous.detail = format!("{}; {error}", previous.detail);
    } else {
        *slot = Some(error);
    }
}

struct Input {
    pipe: ChildStdin,
}

impl Input {
    fn new(pipe: ChildStdin) -> io::Result<Self> {
        set_nonblocking(pipe.as_raw_fd())?;
        Ok(Self { pipe })
    }

    fn fd(&self) -> RawFd {
        self.pipe.as_raw_fd()
    }
}

struct Pipe<R> {
    pipe: R,
    retained: Vec<u8>,
    eof: bool,
}

impl<R: Read + AsRawFd> Pipe<R> {
    fn new(pipe: R) -> io::Result<Self> {
        set_nonblocking(pipe.as_raw_fd())?;
        Ok(Self {
            pipe,
            retained: Vec::new(),
            eof: false,
        })
    }

    fn drain(&mut self, limit: usize) -> io::Result<bool> {
        let mut buffer = [0_u8; 8192];
        loop {
            match self.pipe.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(false);
                }
                Ok(count) => {
                    let available = limit.saturating_sub(self.retained.len());
                    let accepted = available.min(count);
                    self.retained.extend_from_slice(&buffer[..accepted]);
                    if accepted != count {
                        return Ok(true);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn eof(&self) -> bool {
        self.eof
    }

    fn fd(&self) -> RawFd {
        self.pipe.as_raw_fd()
    }

    fn into_bytes(self) -> Vec<u8> {
        self.retained
    }
}

fn wait_for_activity(stdout: RawFd, stderr: RawFd, timeout: Duration) -> io::Result<()> {
    let mut pipes = [
        libc::pollfd {
            fd: stdout,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stderr,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    poll_ready(&mut pipes, timeout).map(|_| ())
}

fn poll_ready(pipes: &mut [libc::pollfd], timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let milliseconds = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        if unsafe {
            libc::poll(
                pipes.as_mut_ptr(),
                pipes.len() as libc::nfds_t,
                milliseconds,
            )
        } >= 0
        {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn kill_process_group(pid: u32) -> io::Result<()> {
    if unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

fn require_waitable_sigchld() -> Result<(), Error> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(Error::io(
            "GIT_PROBE_CLEANUP_FAILED",
            "cannot inspect SIGCHLD disposition",
            io::Error::last_os_error(),
        ));
    }
    if !sigchld_allows_waiting(action.sa_sigaction, action.sa_flags as libc::c_ulong) {
        return Err(Error::new(
            "GIT_PROBE_CLEANUP_FAILED",
            "SIGCHLD disposition does not permit reliable child cleanup",
        ));
    }
    Ok(())
}

pub(crate) fn sigchld_allows_waiting(handler: libc::sighandler_t, flags: libc::c_ulong) -> bool {
    handler == libc::SIG_DFL && flags & libc::SA_NOCLDWAIT as libc::c_ulong == 0
}

#[cfg(test)]
pub(crate) fn lose_probe_ownership(capability: &mut Option<u32>) -> Error {
    *capability = None;
    Error::new("GIT_PROBE_CLEANUP_FAILED", "lost ownership of Git child")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::thread;

    fn process_alive(pid: u32) -> bool {
        (unsafe { libc::kill(pid as libc::pid_t, 0) }) == 0
            || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[test]
    fn same_group_pipe_holder_is_terminated_with_its_direct_child() {
        let mut child = GitChild::spawn_program_with_env_for(
            OsStr::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("sleep 30 & printf '%s\\n' \"$!\"; exec /usr/bin/true"),
            ],
            None,
            &[],
            false,
            Duration::from_secs(1),
            AuditConfig::Isolated,
        )
        .expect("spawn direct child with a same-group pipe-holder");
        let deadline = Instant::now() + Duration::from_millis(250);
        while child
            .stdout
            .as_mut()
            .expect("direct stdout")
            .retained
            .is_empty()
        {
            child
                .stdout
                .as_mut()
                .expect("direct stdout")
                .drain(1024)
                .expect("drain direct stdout");
            assert!(Instant::now() < deadline, "shell did not report its child");
            thread::sleep(Duration::from_millis(5));
        }
        let pid = std::str::from_utf8(&child.stdout.as_ref().expect("direct stdout").retained)
            .expect("pipe-holder pid is UTF-8")
            .trim()
            .parse::<u32>()
            .expect("parse pipe-holder pid");
        while !child.observe_exit().expect("observe direct child exit") {
            assert!(Instant::now() < deadline, "direct child did not exit");
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !child.pipes_closed(),
            "background pipe-holder closed too early"
        );
        let error = child.cleanup(
            Error::new("GIT_PROBE_FAILED", "force same-group cleanup"),
            "GIT_PROBE_CLEANUP_FAILED",
        );
        assert_eq!(error.code, "GIT_PROBE_FAILED");
        for _ in 0..100 {
            if !process_alive(pid) {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !process_alive(pid),
            "same-group pipe holder survived cleanup"
        );
    }

    #[test]
    fn delayed_same_group_pipe_close_is_accepted_within_the_grace_period() {
        let output = GitChild::spawn_program_with_env_for(
            OsStr::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("sleep 0.1 & exec /usr/bin/true"),
            ],
            None,
            &[],
            false,
            Duration::from_secs(2),
            AuditConfig::Isolated,
        )
        .expect("spawn child with a briefly inherited pipe")
        .capture(DEFAULT_LIMIT)
        .expect("brief same-group pipe holder must drain within the grace period");
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }

    #[test]
    fn cleanup_echild_precedes_primary_after_direct_child_is_reaped() {
        let mut child = GitChild::spawn_program_with_env_for(
            OsStr::new("/usr/bin/true"),
            &[],
            None,
            &[],
            false,
            Duration::from_secs(1),
            AuditConfig::Isolated,
        )
        .expect("spawn direct child");
        let pid = child.child.id();
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) },
            pid as libc::pid_t
        );
        let error = child.cleanup(
            Error::new("GIT_PROBE_FAILED", "force cleanup after waitpid"),
            "GIT_PROBE_CLEANUP_FAILED",
        );
        assert_eq!(error.code, "GIT_PROBE_CLEANUP_FAILED");
        assert!(error.detail.contains("GIT_PROBE_FAILED"));
        assert_eq!(child.wait_capability, None);
        assert_eq!(child.process_group, None);
        assert!(!process_alive(pid), "reaped child remained alive");
    }

    #[test]
    fn blocked_batch_stdin_obeys_the_shared_deadline() {
        let mut child = GitChild::spawn_program_with_env_for(
            OsStr::new("/bin/sh"),
            &[OsString::from("-c"), OsString::from("exec sleep 30")],
            None,
            &[],
            true,
            Duration::from_millis(250),
            AuditConfig::Isolated,
        )
        .expect("spawn blocked batch child");
        let started = Instant::now();
        let error = child
            .write_stdin(&vec![b'x'; 1024 * 1024])
            .expect_err("blocked batch stdin must fail");
        assert_eq!(error.code, "GIT_BATCH_FAILED");
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
