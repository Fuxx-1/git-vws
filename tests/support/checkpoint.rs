use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const M4_CONTROL_DESTINATION_FD: RawFd = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointTarget {
    pub operation: String,
    pub stage: String,
}

impl CheckpointTarget {
    pub fn new(operation: &str, stage: &str) -> Self {
        assert!(matches!(
            operation,
            "template" | "create" | "remove" | "publish" | "gc"
        ));
        assert!(valid_token(stage));
        Self {
            operation: operation.to_owned(),
            stage: stage.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub sequence: u64,
    pub operation: String,
    pub sid: String,
    pub key: String,
    pub stage: String,
}

pub struct ControlRun {
    pub events: Vec<Checkpoint>,
    pub output: Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: libc::pid_t,
    pgid: libc::pid_t,
    start: (u64, u64),
}

pub enum ArmReply {
    Exact,
    Wrong,
}

pub enum ProtocolFault {
    BadFrame,
    WrongSequence,
    Eof,
    Timeout,
}

pub struct CheckpointController {
    pub(crate) child: Option<Child>,
    pub(crate) stream: Option<UnixStream>,
    nonce: String,
    process: ProcessIdentity,
    target: CheckpointTarget,
    next_sequence: u64,
    pub(crate) events: Vec<Checkpoint>,
}

impl CheckpointController {
    pub fn start(
        mut command: Command,
        target: CheckpointTarget,
        arm: ArmReply,
    ) -> Result<Self, Output> {
        let nonce = random_nonce().expect("read controller nonce");
        let (mut stream, child_stream) = UnixStream::pair().expect("create AF_UNIX socketpair");
        assert!(fd_cloexec(stream.as_raw_fd()).expect("inspect parent CLOEXEC"));
        assert!(fd_cloexec(child_stream.as_raw_fd()).expect("inspect child CLOEXEC"));
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set controller read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set controller write timeout");
        let control_fd = child_stream.as_raw_fd();
        command
            .env(
                "GIT_VWS_M4_CONTROL_FD",
                M4_CONTROL_DESTINATION_FD.to_string(),
            )
            .env("GIT_VWS_M4_NONCE", &nonce)
            .env(
                "GIT_VWS_M4_TARGET",
                format!("{}/{}", target.operation, target.stage),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(control_fd, M4_CONTROL_DESTINATION_FD) < 0
                    || libc::fcntl(M4_CONTROL_DESTINATION_FD, libc::F_SETFD, 0) != 0
                {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let child = command.spawn().expect("spawn instrumented git-vws");
        drop(child_stream);
        let pid = child.id() as libc::pid_t;
        let hello = match read_control_frame(&mut stream) {
            Ok(hello) => hello,
            Err(error) => {
                drop(stream);
                let output = child
                    .wait_with_output()
                    .expect("reap CLI after HELLO failure");
                panic!("read controller HELLO: {error}; child={output:?}");
            }
        };
        let fields: Vec<_> = hello
            .strip_suffix('\n')
            .expect("HELLO newline")
            .split(' ')
            .collect();
        assert_eq!(fields.len(), 5, "HELLO field count: {hello:?}");
        assert_eq!(fields[0], "M4CP/1", "HELLO protocol: {hello:?}");
        assert_eq!(fields[1], "HELLO", "HELLO kind: {hello:?}");
        assert_eq!(fields[2], nonce, "HELLO nonce: {hello:?}");
        let claimed_pid = parse_pid(fields[3], "HELLO pid");
        let claimed_pgid = parse_pid(fields[4], "HELLO pgid");
        let process = process_identity(claimed_pid).expect("inspect HELLO process identity");
        assert_eq!(claimed_pid, pid, "HELLO PID did not name direct CLI child");
        assert_eq!(claimed_pgid, claimed_pid, "HELLO PGID was not private");
        assert_eq!(process.pid, claimed_pid, "kernel PID changed during HELLO");
        assert_eq!(
            process.pgid, claimed_pgid,
            "kernel PGID changed during HELLO"
        );
        let reply = match arm {
            ArmReply::Exact => format!(
                "M4CP/1 ARM {nonce} {claimed_pid} {claimed_pgid} {}/{}\n",
                target.operation, target.stage
            ),
            ArmReply::Wrong => {
                format!("M4CP/1 ARM {nonce} {claimed_pid} {claimed_pgid} create/wrong-stage\n")
            }
        };
        write_control_frame(&mut stream, &reply).expect("write controller ARM");
        if matches!(arm, ArmReply::Wrong) {
            drop(stream);
            return Err(child.wait_with_output().expect("reap rejected ARM child"));
        }
        let revalidated = process_identity(claimed_pid).expect("revalidate armed process identity");
        assert_eq!(revalidated, process, "process identity changed during ARM");
        Ok(Self {
            child: Some(child),
            stream: Some(stream),
            nonce,
            process,
            target,
            next_sequence: 1,
            events: Vec::new(),
        })
    }

    pub fn run_all(self) -> ControlRun {
        self.finish()
    }

    pub fn pause_at_target(&mut self) -> Checkpoint {
        loop {
            let checkpoint = self.next_checkpoint().expect("read target checkpoint");
            if checkpoint.operation == self.target.operation
                && checkpoint.stage == self.target.stage
            {
                return checkpoint;
            }
            self.go(&checkpoint);
        }
    }

    pub fn release_target(&mut self, checkpoint: &Checkpoint) {
        assert_eq!(
            checkpoint.operation, self.target.operation,
            "paused checkpoint operation changed"
        );
        assert_eq!(
            checkpoint.stage, self.target.stage,
            "paused checkpoint stage changed"
        );
        self.go(checkpoint);
    }

    pub fn finish(mut self) -> ControlRun {
        loop {
            match self.next_checkpoint() {
                Ok(checkpoint)
                    if checkpoint.operation == self.target.operation
                        && checkpoint.stage == self.target.stage =>
                {
                    self.release_target(&checkpoint);
                }
                Ok(checkpoint) => self.go(&checkpoint),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => panic!("controller read before normal exit: {error}"),
            }
        }
        let output = self
            .child
            .take()
            .expect("normal controller child")
            .wait_with_output()
            .expect("reap normal instrumented CLI");
        self.stream.take();
        ControlRun {
            events: std::mem::take(&mut self.events),
            output,
        }
    }

    pub fn crash_at_target(mut self) -> ControlRun {
        let checkpoint = self.pause_at_target();
        let revalidated = process_identity(self.process.pid).expect("revalidate target process");
        assert_eq!(
            revalidated, self.process,
            "target process start identity changed"
        );
        let mut members = process_group_members(self.process.pgid).expect("inspect target group");
        members.sort_unstable();
        assert_eq!(
            members,
            vec![self.process.pid],
            "Git child survived checkpoint: {members:?}"
        );
        assert_eq!(
            unsafe { libc::kill(-self.process.pgid, libc::SIGKILL) },
            0,
            "kill exact instrumented process group"
        );
        let output = self
            .child
            .take()
            .expect("target controller child")
            .wait_with_output()
            .expect("reap killed CLI");
        assert!(
            !output.status.success(),
            "SIGKILL target unexpectedly succeeded"
        );
        wait_for_group_gone(self.process.pgid);
        self.stream.take();
        assert_eq!(
            checkpoint.operation, self.target.operation,
            "crash checkpoint operation changed"
        );
        ControlRun {
            events: std::mem::take(&mut self.events),
            output,
        }
    }

    pub fn fault_at_first(mut self, fault: ProtocolFault) -> Output {
        let checkpoint = self
            .next_checkpoint()
            .expect("read protocol-fault checkpoint");
        match fault {
            ProtocolFault::BadFrame => {
                write_control_frame(
                    self.stream.as_mut().expect("control stream"),
                    "M4CP/1 BAD\n",
                )
                .expect("write malformed protocol response");
            }
            ProtocolFault::WrongSequence => {
                let sequence = checkpoint.sequence + 1;
                let tx = format!("{}.{}", self.nonce, sequence);
                let frame = checkpoint_message(
                    "GO",
                    &self.nonce,
                    self.process.pid,
                    self.process.pgid,
                    sequence,
                    &tx,
                    &checkpoint,
                );
                write_control_frame(self.stream.as_mut().expect("control stream"), &frame)
                    .expect("write wrong sequence");
            }
            ProtocolFault::Eof => {
                self.stream.take();
            }
            ProtocolFault::Timeout => {
                thread::sleep(Duration::from_secs(31));
            }
        }
        let output = self
            .child
            .take()
            .expect("protocol-fault child")
            .wait_with_output()
            .expect("reap protocol-fault child");
        self.stream.take();
        output
    }

    fn next_checkpoint(&mut self) -> io::Result<Checkpoint> {
        let frame = read_control_frame(self.stream.as_mut().expect("controller stream"))?;
        let fields: Vec<_> = frame
            .strip_suffix('\n')
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
            .split(' ')
            .collect();
        if fields.len() != 11
            || fields.iter().any(|field| field.is_empty())
            || fields[0] != "M4CP/1"
            || fields[1] != "CP"
            || fields[2] != self.nonce
        {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let pid = parse_pid(fields[3], "checkpoint pid");
        let pgid = parse_pid(fields[4], "checkpoint pgid");
        let sequence = fields[5]
            .parse::<u64>()
            .ok()
            .filter(|value| *value == self.next_sequence)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        if pid != self.process.pid
            || pgid != self.process.pgid
            || fields[6] != format!("{}.{}", self.nonce, sequence)
            || !matches!(
                fields[7],
                "template" | "create" | "remove" | "publish" | "gc"
            )
            || !(fields[8] == "-" || lower_hex(fields[8], 64))
            || !(fields[9] == "-" || lower_hex(fields[9], 64))
            || !valid_token(fields[10])
        {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.next_sequence += 1;
        let checkpoint = Checkpoint {
            sequence,
            operation: fields[7].to_owned(),
            sid: fields[8].to_owned(),
            key: fields[9].to_owned(),
            stage: fields[10].to_owned(),
        };
        self.events.push(checkpoint.clone());
        Ok(checkpoint)
    }

    fn go(&mut self, checkpoint: &Checkpoint) {
        let tx = format!("{}.{}", self.nonce, checkpoint.sequence);
        let go = checkpoint_message(
            "GO",
            &self.nonce,
            self.process.pid,
            self.process.pgid,
            checkpoint.sequence,
            &tx,
            checkpoint,
        );
        write_control_frame(self.stream.as_mut().expect("controller stream"), &go)
            .expect("write exact GO");
        let ack = read_control_frame(self.stream.as_mut().expect("controller stream"))
            .expect("read exact ACK");
        let expected = checkpoint_message(
            "ACK",
            &self.nonce,
            self.process.pid,
            self.process.pgid,
            checkpoint.sequence,
            &tx,
            checkpoint,
        );
        assert_eq!(ack, expected, "controller received non-exact ACK");
    }
}

impl Drop for CheckpointController {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        match process_identity(self.process.pid) {
            Ok(current) if current == self.process => {
                let _ = unsafe { libc::kill(-self.process.pgid, libc::SIGKILL) };
            }
            _ => {
                let _ = child.kill();
            }
        }
        let _ = child.wait();
        self.stream.take();
    }
}

fn checkpoint_message(
    kind: &str,
    nonce: &str,
    pid: libc::pid_t,
    pgid: libc::pid_t,
    sequence: u64,
    tx: &str,
    checkpoint: &Checkpoint,
) -> String {
    format!(
        "M4CP/1 {kind} {nonce} {pid} {pgid} {sequence} {tx} {} {} {} {}\n",
        checkpoint.operation, checkpoint.sid, checkpoint.key, checkpoint.stage
    )
}

fn write_control_frame(stream: &mut UnixStream, frame: &str) -> io::Result<()> {
    if frame.is_empty() || frame.len() > 1024 || !frame.is_ascii() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    stream.write_all(&(frame.len() as u32).to_be_bytes())?;
    stream.write_all(frame.as_bytes())
}

fn read_control_frame(stream: &mut UnixStream) -> io::Result<String> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 1024 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut frame = vec![0_u8; length];
    stream.read_exact(&mut frame)?;
    let text = String::from_utf8(frame).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if !text.is_ascii() {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(text)
}

fn random_nonce() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let digits = b"0123456789abcdef";
    let mut nonce = String::with_capacity(32);
    for byte in bytes {
        nonce.push(digits[(byte >> 4) as usize] as char);
        nonce.push(digits[(byte & 0x0f) as usize] as char);
    }
    Ok(nonce)
}

fn fd_cloexec(fd: RawFd) -> io::Result<bool> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags & libc::FD_CLOEXEC != 0)
    }
}

pub fn lower_hex(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn parse_pid(value: &str, label: &str) -> libc::pid_t {
    value
        .parse::<libc::pid_t>()
        .ok()
        .filter(|pid| *pid > 1)
        .unwrap_or_else(|| panic!("invalid {label}: {value}"))
}

#[cfg(target_os = "macos")]
fn process_identity(pid: libc::pid_t) -> io::Result<ProcessIdentity> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
        )
    };
    let pgid = unsafe { libc::getpgid(pid) };
    if size != std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int || pgid < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ProcessIdentity {
        pid,
        pgid,
        start: (info.pbi_start_tvsec, info.pbi_start_tvusec),
    })
}

#[cfg(target_os = "linux")]
fn process_identity(pid: libc::pid_t) -> io::Result<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
        .1
        .split_ascii_whitespace()
        .collect();
    if fields.len() <= 19 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let parse = |value: &str| {
        value
            .parse::<u64>()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    };
    let pgid = unsafe { libc::getpgid(pid) };
    if pgid < 0 || pgid != parse(fields[2])? as libc::pid_t {
        return Err(io::Error::last_os_error());
    }
    Ok(ProcessIdentity {
        pid,
        pgid,
        start: (parse(fields[19])?, 0),
    })
}

fn process_group_members(pgid: libc::pid_t) -> io::Result<Vec<libc::pid_t>> {
    let mut command = Command::new(find_executable("ps"));
    #[cfg(target_os = "macos")]
    command.args(["-ax", "-o", "pid=", "-o", "pgid="]);
    #[cfg(target_os = "linux")]
    command.args(["-e", "-o", "pid=", "-o", "pgid="]);
    let output = command.output()?;
    if !output.status.success() {
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    let mut members = Vec::new();
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        let fields: Vec<_> = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|value| !value.is_empty())
            .collect();
        if fields.len() != 2 {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let parse = |value: &[u8]| {
            std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<libc::pid_t>().ok())
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
        };
        let pid = parse(fields[0])?;
        if parse(fields[1])? == pgid {
            members.push(pid);
        }
    }
    Ok(members)
}

fn wait_for_group_gone(pgid: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if unsafe { libc::kill(-pgid, 0) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "instrumented process group {pgid} survived cleanup"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn find_executable(name: &str) -> std::path::PathBuf {
    env::split_paths(&env::var_os("PATH").expect("PATH"))
        .map(|directory| directory.join(name))
        .find(|candidate| {
            candidate.is_file()
                && candidate.metadata().is_ok_and(|metadata| {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.permissions().mode() & 0o111 != 0
                })
        })
        .and_then(|candidate| fs::canonicalize(candidate).ok())
        .unwrap_or_else(|| panic!("resolve {name} from PATH"))
}
