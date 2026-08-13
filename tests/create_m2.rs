use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

static NEXT_SANDBOX: AtomicUsize = AtomicUsize::new(0);
static NATIVE_COW_PROBE: OnceLock<Output> = OnceLock::new();
#[cfg(target_os = "linux")]
const FILE_TYPE_MASK: u32 = libc::S_IFMT;
#[cfg(target_os = "linux")]
const DIRECTORY_TYPE: u32 = libc::S_IFDIR;
#[cfg(target_os = "linux")]
const REGULAR_TYPE: u32 = libc::S_IFREG;
#[cfg(target_os = "linux")]
const SYMLINK_TYPE: u32 = libc::S_IFLNK;
#[cfg(target_os = "macos")]
const FILE_TYPE_MASK: u32 = libc::S_IFMT as u32;
#[cfg(target_os = "macos")]
const DIRECTORY_TYPE: u32 = libc::S_IFDIR as u32;
#[cfg(target_os = "macos")]
const REGULAR_TYPE: u32 = libc::S_IFREG as u32;
#[cfg(target_os = "macos")]
const SYMLINK_TYPE: u32 = libc::S_IFLNK as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Node {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    kind: u32,
}

impl Node {
    fn from_stat(stat: &libc::stat) -> Self {
        #[cfg(target_os = "linux")]
        let (dev, mode) = (stat.st_dev, stat.st_mode);
        #[cfg(target_os = "macos")]
        let (dev, mode) = (stat.st_dev as u64, stat.st_mode as u32);
        Self {
            dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            mode: mode & 0o7777,
            kind: mode & FILE_TYPE_MASK,
        }
    }
}

struct Sandbox {
    parent: File,
    name: CString,
    root: Option<File>,
    path: PathBuf,
    node: Node,
}

impl Sandbox {
    fn new() -> Self {
        let parent_path = fs::canonicalize(env::temp_dir()).expect("canonical test parent");
        let parent = File::open(&parent_path).expect("open test parent");
        let name = CString::new(format!(
            "git-vws-m2-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("sandbox basename");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) },
            0
        );
        let root = open_directory(parent.as_raw_fd(), &name).expect("open sandbox");
        assert_eq!(unsafe { libc::fchmod(root.as_raw_fd(), 0o700) }, 0);
        let node = node(&root).expect("stat sandbox");
        Self {
            parent,
            path: parent_path.join(name.to_string_lossy().as_ref()),
            name,
            root: Some(root),
            node,
        }
    }

    fn child(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        clear_owned(root.as_raw_fd(), self.node.dev)?;
        if stat_at(self.parent.as_raw_fd(), &self.name)? != self.node {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.root.take();
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if self.root.is_some() && !std::thread::panicking() {
            self.cleanup().expect("descriptor sandbox cleanup");
        }
    }
}

fn open_directory(parent: RawFd, name: &CStr) -> io::Result<File> {
    let raw = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

fn node(file: &File) -> io::Result<Node> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Node::from_stat(&stat))
    }
}

fn stat_at(parent: RawFd, name: &CStr) -> io::Result<Node> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Node::from_stat(&stat))
    }
}

fn names(fd: RawFd) -> io::Result<Vec<Vec<u8>>> {
    let stream_fd = unsafe {
        libc::openat(
            fd,
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if stream_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { libc::fdopendir(stream_fd) };
    if directory.is_null() {
        unsafe { libc::close(stream_fd) };
        return Err(io::Error::last_os_error());
    }
    let mut result = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().unwrap_or_default() != 0 {
                unsafe { libc::closedir(directory) };
                return Err(error);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            result.push(name.to_vec());
        }
    }
    if unsafe { libc::closedir(directory) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

fn clear_owned(parent: RawFd, device: u64) -> io::Result<()> {
    for bytes in names(parent)? {
        let name = CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let before = stat_at(parent, &name)?;
        if before.dev != device || before.uid != unsafe { libc::geteuid() } {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if before.kind == DIRECTORY_TYPE {
            let child = open_directory(parent, &name)?;
            let mut expected = node(&child)?;
            if expected != before {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            if expected.mode & 0o300 != 0o300 {
                if unsafe { libc::fchmod(child.as_raw_fd(), 0o700) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                expected = node(&child)?;
            }
            clear_owned(child.as_raw_fd(), device)?;
            drop(child);
            if stat_at(parent, &name)? != expected {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(io::Error::last_os_error());
            }
        } else if before.kind == REGULAR_TYPE || before.kind == SYMLINK_TYPE {
            if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: libc::pid_t,
    pgid: libc::pid_t,
    ppid: libc::pid_t,
    start: (u64, u64),
    argv: Vec<Vec<u8>>,
}

impl ProcessIdentity {
    fn reparented_from(&self, other: &Self, outer_pid: libc::pid_t) -> bool {
        self.pid == other.pid
            && self.pgid == other.pgid
            && self.ppid == outer_pid
            && other.ppid > 0
            && other.ppid != outer_pid
            && self.start == other.start
            && self.argv == other.argv
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessCapability {
    process: ProcessIdentity,
    script: Node,
}

struct CrashPrefixOwner {
    outer: Option<Child>,
    outer_pid: libc::pid_t,
    control: UnixStream,
    script: File,
    script_identity: Node,
    capability: Option<ProcessCapability>,
    reparented_ppid: Option<libc::pid_t>,
    result: Option<Result<(), String>>,
}

impl CrashPrefixOwner {
    fn spawn(mut command: Command, script: &Path) -> Result<Self, String> {
        let script_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(script)
            .map_err(|error| format!("open wrapper descriptor: {error}"))?;
        let script_identity = node(&script_file).map_err(|error| error.to_string())?;
        if script_identity != path_node(script).map_err(|error| error.to_string())? {
            return Err("wrapper path did not match its descriptor".to_owned());
        }
        let script_arg = script.as_os_str().as_encoded_bytes().to_vec();
        let nonce = random_nonce().map_err(|error| error.to_string())?;
        let (control, child_control) =
            UnixStream::pair().map_err(|error| format!("create control socket: {error}"))?;
        if !fd_cloexec(control.as_raw_fd()).map_err(|error| error.to_string())?
            || !fd_cloexec(child_control.as_raw_fd()).map_err(|error| error.to_string())?
        {
            return Err("control socket did not start CLOEXEC".to_owned());
        }
        control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| error.to_string())?;
        let control_fd = child_control.as_raw_fd();
        command.env("VWS_TEST_NONCE", &nonce);
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(control_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let outer = command
            .spawn()
            .map_err(|error| format!("spawn paused create: {error}"))?;
        drop(child_control);
        let outer_pid = outer.id() as libc::pid_t;
        let mut owner = Self {
            outer: Some(outer),
            outer_pid,
            control,
            script: script_file,
            script_identity,
            capability: None,
            reparented_ppid: None,
            result: None,
        };
        let handshake = (|| {
            if !fd_cloexec(owner.control.as_raw_fd()).map_err(|error| error.to_string())? {
                return Err("owner control socket lost CLOEXEC".to_owned());
            }
            let frame = read_frame(&mut owner.control).map_err(|error| error.to_string())?;
            if frame.len() != 4 || frame[0] != "HELLO" || frame[1] != nonce {
                return Err(format!("invalid wrapper HELLO: {frame:?}"));
            }
            let pid = parse_pid(&frame[2])?;
            let claimed_pgid = parse_pid(&frame[3])?;
            let first = process_identity(pid).map_err(|error| error.to_string())?;
            validate_process(&first, claimed_pgid, owner.outer_pid, &script_arg)?;
            owner.revalidate_script(owner.script_identity)?;
            owner.capability = Some(ProcessCapability {
                process: first.clone(),
                script: owner.script_identity,
            });
            writeln!(owner.control, "ARM {nonce}").map_err(|error| error.to_string())?;
            let paused = read_frame(&mut owner.control).map_err(|error| error.to_string())?;
            if paused != ["PAUSED", nonce.as_str()] {
                return Err(format!("invalid wrapper PAUSED: {paused:?}"));
            }
            let armed = process_identity(pid).map_err(|error| error.to_string())?;
            if armed != first {
                return Err("wrapper identity changed during handshake".to_owned());
            }
            owner.revalidate_script(owner.script_identity)
        })();
        match handshake {
            Ok(()) => Ok(owner),
            Err(error) => owner.setup_failure(error),
        }
    }

    fn finish(&mut self) -> Result<(), String> {
        if let Some(result) = &self.result {
            return result.clone();
        }
        let result = self.finish_once();
        self.result = Some(result.clone());
        result
    }

    fn setup_failure(mut self, primary: String) -> Result<Self, String> {
        match self.finish() {
            Ok(()) => Err(format!("crash-prefix setup failed: {primary}")),
            Err(cleanup) => Err(format!(
                "crash-prefix setup failed: {primary}; cleanup failed: {cleanup}"
            )),
        }
    }

    fn finish_once(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        let outer_reaped = self.reap_outer(&mut errors);
        let wrapper = if outer_reaped {
            self.cleanup_wrapper()
        } else {
            Err("outer git-vws was not reaped; refusing wrapper signal".to_owned())
        };
        if let Err(error) = wrapper {
            errors.push(error);
        }
        if let Err(error) = self.control.shutdown(std::net::Shutdown::Both) {
            if error.kind() != io::ErrorKind::NotConnected {
                errors.push(format!("close owner control socket: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn reap_outer(&mut self, errors: &mut Vec<String>) -> bool {
        let Some(mut outer) = self.outer.take() else {
            errors.push("outer child capability was absent".to_owned());
            return false;
        };
        if let Err(error) = outer.kill() {
            errors.push(format!("kill outer git-vws: {error}"));
        }
        match outer.wait() {
            Ok(status) => {
                if status.success() {
                    errors.push("killed outer git-vws reported success".to_owned());
                }
                true
            }
            Err(error) => {
                errors.push(format!("reap outer git-vws: {error}"));
                false
            }
        }
    }

    fn cleanup_wrapper(&mut self) -> Result<(), String> {
        let pgid = self
            .capability
            .as_ref()
            .ok_or("wrapper capability was incomplete; refusing group cleanup")?
            .process
            .pgid;
        if group_gone(pgid)? {
            return Ok(());
        }
        self.revalidate_for_signal()?;
        signal_group(pgid, libc::SIGTERM)?;
        if !wait_group_gone(pgid, Duration::from_secs(2))? {
            self.revalidate_for_signal()?;
            signal_group(pgid, libc::SIGKILL)?;
            if !wait_group_gone(pgid, Duration::from_secs(2))? {
                return Err("wrapper process group survived SIGKILL".to_owned());
            }
        }
        if group_gone(pgid)? {
            Ok(())
        } else {
            Err("wrapper process group was not gone".to_owned())
        }
    }

    fn revalidate_for_signal(&mut self) -> Result<(), String> {
        let capability = self
            .capability
            .as_ref()
            .ok_or("wrapper capability was incomplete; refusing group cleanup")?
            .clone();
        let current =
            process_identity(capability.process.pid).map_err(|error| error.to_string())?;
        self.revalidate_script(capability.script)?;
        if !capability.process.reparented_from(&current, self.outer_pid) {
            Err("wrapper process identity changed".to_owned())
        } else if let Some(parent) = self.reparented_ppid {
            if parent == current.ppid {
                Ok(())
            } else {
                Err("wrapper reparent identity changed".to_owned())
            }
        } else {
            self.reparented_ppid = Some(current.ppid);
            Ok(())
        }
    }

    fn revalidate_script(&self, expected: Node) -> Result<(), String> {
        if node(&self.script).map_err(|error| error.to_string())? == expected {
            Ok(())
        } else {
            Err("wrapper descriptor identity changed".to_owned())
        }
    }
}

impl Drop for CrashPrefixOwner {
    fn drop(&mut self) {
        if self.result.is_some() {
            return;
        }
        match self.finish() {
            Ok(()) if !std::thread::panicking() => {
                panic!("CrashPrefixOwner dropped without explicit finish")
            }
            Ok(()) => {}
            Err(error) if std::thread::panicking() => {
                eprintln!("CrashPrefixOwner cleanup failed during unwind: {error}")
            }
            Err(error) => panic!("CrashPrefixOwner cleanup failed: {error}"),
        }
    }
}

fn path_node(path: &Path) -> io::Result<Node> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(Node {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        kind: metadata.mode() & FILE_TYPE_MASK,
    })
}

fn fd_cloexec(fd: RawFd) -> io::Result<bool> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(flags & libc::FD_CLOEXEC != 0)
    }
}

fn random_nonce() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let digits = b"0123456789abcdef";
    let mut nonce = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        nonce.push(digits[(byte >> 4) as usize] as char);
        nonce.push(digits[(byte & 0x0f) as usize] as char);
    }
    Ok(nonce)
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<String>> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() == 255 || !byte[0].is_ascii_graphic() && byte[0] != b' ' {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        bytes.push(byte[0]);
    }
    let line = String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidData)?;
    Ok(line.split(' ').map(str::to_owned).collect())
}

fn parse_pid(value: &str) -> Result<libc::pid_t, String> {
    value
        .parse::<libc::pid_t>()
        .ok()
        .filter(|pid| *pid > 1)
        .ok_or_else(|| format!("invalid wrapper pid: {value}"))
}

fn validate_process(
    process: &ProcessIdentity,
    claimed_pgid: libc::pid_t,
    outer_pid: libc::pid_t,
    script: &[u8],
) -> Result<(), String> {
    let script_arg = process
        .argv
        .windows(2)
        .any(|args| args[0] == script && args[1] == b"init");
    if process.pid == claimed_pgid
        && process.pgid == claimed_pgid
        && process.ppid == outer_pid
        && script_arg
    {
        Ok(())
    } else {
        Err(format!("wrapper kernel identity was invalid: {process:?}"))
    }
}

fn signal_group(pgid: libc::pid_t, signal: libc::c_int) -> Result<(), String> {
    if unsafe { libc::kill(-pgid, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) && group_gone(pgid)? {
        Ok(())
    } else {
        Err(format!("signal wrapper process group: {error}"))
    }
}

fn group_gone(pgid: libc::pid_t) -> Result<bool, String> {
    if unsafe { libc::kill(-pgid, 0) } == 0 {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(true),
        Some(libc::EPERM) => Ok(false),
        _ => Err(format!("inspect wrapper process group: {error}")),
    }
}

fn wait_group_gone(pgid: libc::pid_t, timeout: Duration) -> Result<bool, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if group_gone(pgid)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
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
    if size != std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int {
        return Err(io::Error::last_os_error());
    }
    let pgid = unsafe { libc::getpgid(pid) };
    if pgid < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ProcessIdentity {
        pid,
        pgid,
        ppid: info.pbi_ppid as libc::pid_t,
        start: (info.pbi_start_tvsec, info.pbi_start_tvusec),
        argv: macos_argv(pid)?,
    })
}

#[cfg(target_os = "macos")]
fn macos_argv(pid: libc::pid_t) -> io::Result<Vec<Vec<u8>>> {
    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&argmax);
    let mut argmax_mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    if unsafe {
        libc::sysctl(
            argmax_mib.as_mut_ptr(),
            argmax_mib.len() as u32,
            (&mut argmax as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || argmax <= 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = vec![0_u8; argmax as usize];
    size = bytes.len();
    let mut args_mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    if unsafe {
        libc::sysctl(
            args_mib.as_mut_ptr(),
            args_mib.len() as u32,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size < std::mem::size_of::<libc::c_int>()
    {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(size);
    let argc = libc::c_int::from_ne_bytes(bytes[..4].try_into().unwrap());
    if argc <= 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    let mut cursor = 4;
    while cursor < bytes.len() && bytes[cursor] != 0 {
        cursor += 1;
    }
    while cursor < bytes.len() && bytes[cursor] == 0 {
        cursor += 1;
    }
    let mut argv = Vec::new();
    for _ in 0..argc {
        let end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| cursor + offset)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        argv.push(bytes[cursor..end].to_vec());
        cursor = end + 1;
    }
    Ok(argv)
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
    let ppid = parse(fields[1])? as libc::pid_t;
    let pgid = unsafe { libc::getpgid(pid) };
    if pgid < 0 || pgid != parse(fields[2])? as libc::pid_t {
        return Err(io::Error::last_os_error());
    }
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
    let argv = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    Ok(ProcessIdentity {
        pid,
        pgid,
        ppid,
        start: (parse(fields[19])?, 0),
        argv,
    })
}

fn git(cwd: &Path, args: &[OsString]) -> Output {
    let mut command = Command::new("git");
    for (name, _) in env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(name);
        }
    }
    let output = command
        .current_dir(cwd)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("run fixture git");
    assert!(output.status.success(), "git {args:?}: {output:?}");
    output
}

fn git_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn vws_command(home: &Path, args: Vec<OsString>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_git-vws"));
    for (name, _) in env::vars_os() {
        if name.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(name);
        }
    }
    command.args(args).env("HOME", home);
    command
}

fn vws(home: &Path, args: Vec<OsString>) -> Output {
    vws_command(home, args).output().expect("run git-vws")
}

fn fixture_repo(sandbox: &Sandbox, attributes: bool) -> PathBuf {
    let bare = sandbox.child("authority.git");
    git(
        &sandbox.path,
        &[
            OsString::from("init"),
            OsString::from("--bare"),
            bare.as_os_str().to_os_string(),
        ],
    );
    let source = sandbox.child("source");
    git(
        &sandbox.path,
        &[OsString::from("init"), source.as_os_str().to_os_string()],
    );
    git(&source, &git_args(&["config", "user.name", "M2 Test"]));
    git(
        &source,
        &git_args(&["config", "user.email", "m2@example.invalid"]),
    );
    fs::create_dir(source.join("nested")).expect("create source nested directory");
    fs::write(source.join("nested/data"), b"template content\n").expect("write source file");
    fs::write(source.join("run"), b"#!/bin/sh\nprintf 'ok\\n'\n").expect("write executable");
    fs::set_permissions(source.join("run"), fs::Permissions::from_mode(0o755))
        .expect("protect executable");
    symlink("nested/data", source.join("link")).expect("create source symlink");
    if attributes {
        fs::write(source.join(".gitattributes"), b"* text=auto\n").expect("write attributes");
    }
    git(&source, &git_args(&["add", "-A"]));
    git(&source, &git_args(&["commit", "-m", "fixture"]));
    git(
        &source,
        &[
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            bare.as_os_str().to_os_string(),
        ],
    );
    git(
        &source,
        &git_args(&["push", "origin", "HEAD:refs/heads/main"]),
    );
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(bare.as_os_str());
    git(
        &sandbox.path,
        &[
            git_dir,
            OsString::from("symbolic-ref"),
            OsString::from("HEAD"),
            OsString::from("refs/heads/main"),
        ],
    );
    bare
}

fn home(sandbox: &Sandbox) -> PathBuf {
    let home = sandbox.child("home");
    fs::create_dir(&home).expect("create home");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect home");
    home
}

fn create(home: &Path, bare: &Path, name: &str) -> Output {
    vws(home, create_args(bare, name))
}

fn create_args(bare: &Path, name: &str) -> Vec<OsString> {
    vec![
        OsString::from("--repo"),
        bare.as_os_str().to_os_string(),
        OsString::from("create"),
        OsString::from(name),
    ]
}

fn snapshot(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    snapshot_entry(path, path, &mut bytes);
    bytes
}

fn snapshot_entry(root: &Path, path: &Path, output: &mut Vec<u8>) {
    let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
    output.extend_from_slice(
        path.strip_prefix(root)
            .expect("relative snapshot path")
            .as_os_str()
            .as_encoded_bytes(),
    );
    output.extend_from_slice(&metadata.mode().to_be_bytes());
    output.extend_from_slice(&metadata.nlink().to_be_bytes());
    if metadata.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("snapshot entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            snapshot_entry(root, &entry, output);
        }
    } else if metadata.is_file() {
        let mut file = File::open(path).expect("open snapshot file");
        file.read_to_end(output).expect("read snapshot file");
    } else if metadata.file_type().is_symlink() {
        output.extend_from_slice(
            fs::read_link(path)
                .expect("read snapshot symlink")
                .as_os_str()
                .as_encoded_bytes(),
        );
    }
}

fn only_child(parent: &Path, suffix: &str) -> PathBuf {
    let entries = children_with_suffix(parent, suffix);
    assert_eq!(entries.len(), 1, "unexpected state children: {entries:?}");
    entries.into_iter().next().expect("one state child")
}

fn children_with_suffix(parent: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut entries: Vec<_> = fs::read_dir(parent)
        .expect("read state children")
        .map(|entry| entry.expect("state child").path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.as_encoded_bytes().ends_with(suffix.as_bytes()))
        })
        .collect();
    entries.sort();
    entries
}

fn native_cow_available() -> bool {
    NATIVE_COW_PROBE
        .get_or_init(|| {
            let mut sandbox = Sandbox::new();
            let bare = fixture_repo(&sandbox, false);
            let home = home(&sandbox);
            let initialized = vws(
                &home,
                vec![OsString::from("init"), bare.as_os_str().to_os_string()],
            );
            assert!(
                initialized.status.success(),
                "native COW probe init: {initialized:?}"
            );
            let output = create(&home, &bare, "native-cow-probe");
            assert!(
                output.status.success()
                    || String::from_utf8_lossy(&output.stderr).contains("STORAGE_UNSUPPORTED"),
                "unexpected native COW probe result: {output:?}"
            );
            sandbox.cleanup().expect("cleanup native COW probe");
            output
        })
        .status
        .success()
}

fn require_native_cow() {
    if !native_cow_available() {
        let output = NATIVE_COW_PROBE.get().expect("native COW probe output");
        panic!("NOT_EXECUTED: native COW unavailable: {output:?}");
    }
}

#[test]
fn create_seals_raw_tree_reuses_ready_receipt_and_isolates_cow() {
    require_native_cow();
    let mut sandbox = Sandbox::new();
    let bare = fixture_repo(&sandbox, false);
    let home = home(&sandbox);
    let before_authority = snapshot(&bare);
    let initialized = vws(
        &home,
        vec![OsString::from("init"), bare.as_os_str().to_os_string()],
    );
    assert!(initialized.status.success(), "init: {initialized:?}");
    let first = create(&home, &bare, "alpha");
    assert!(first.status.success(), "create: {first:?}");
    let state = home.join(".git-vws");
    let session_root = only_child(&state.join("sessions"), ".root");
    let template_root = only_child(&state.join("templates"), ".root");
    let record = only_child(&state.join("sessions"), ".record");
    assert!(fs::read(&record)
        .expect("read session record")
        .windows(7)
        .any(|part| part == b"\"READY\""));
    let worktree = session_root.join("worktree");
    let status = git(
        &worktree,
        &git_args(&["status", "--porcelain=v1", "--untracked-files=all"]),
    );
    assert!(
        status.stdout.is_empty(),
        "worktree was not clean: {status:?}"
    );
    assert_eq!(
        fs::read(worktree.join("nested/data")).expect("read worktree file"),
        b"template content\n"
    );
    assert_eq!(
        fs::read_link(worktree.join("link")).expect("read worktree symlink"),
        PathBuf::from("nested/data")
    );
    assert_eq!(
        fs::metadata(worktree.join("run"))
            .expect("stat executable")
            .mode()
            & 0o111,
        0o111
    );
    let second = create(&home, &bare, "alpha");
    assert!(second.status.success(), "READY reuse: {second:?}");
    let template_file = template_root.join("nested/data");
    let alpha_file = worktree.join("nested/data");
    assert_ne!(
        fs::metadata(&template_file)
            .expect("stat sealed template")
            .ino(),
        fs::metadata(&alpha_file).expect("stat cloned file").ino(),
        "native clone reused the template inode"
    );
    let beta = create(&home, &bare, "beta");
    assert!(beta.status.success(), "second isolated session: {beta:?}");
    let roots = children_with_suffix(&state.join("sessions"), ".root");
    assert_eq!(roots.len(), 2);
    let beta_root = roots
        .into_iter()
        .find(|root| root != &session_root)
        .expect("second session root");
    let beta_file = beta_root.join("worktree/nested/data");
    assert_eq!(
        fs::read(&beta_file).expect("read beta worktree"),
        b"template content\n"
    );
    fs::write(worktree.join("nested/data"), b"session mutation\n").expect("mutate worktree");
    assert_eq!(
        fs::read(template_root.join("nested/data")).expect("read sealed template"),
        b"template content\n"
    );
    assert_eq!(
        fs::read(beta_file).expect("read isolated worktree"),
        b"template content\n"
    );
    let changed = create(&home, &bare, "alpha");
    assert!(
        !changed.status.success()
            && String::from_utf8_lossy(&changed.stderr).contains("STORAGE_UNSUPPORTED"),
        "READY content receipt was not revalidated: {changed:?}"
    );
    assert_eq!(
        snapshot(&bare),
        before_authority,
        "create wrote the authority"
    );
    sandbox.cleanup().expect("cleanup create fixture");
}

#[test]
fn unsupported_attributes_reject_create_without_authority_write() {
    let mut sandbox = Sandbox::new();
    let bare = fixture_repo(&sandbox, true);
    let home = home(&sandbox);
    let before = snapshot(&bare);
    let initialized = vws(
        &home,
        vec![OsString::from("init"), bare.as_os_str().to_os_string()],
    );
    assert!(initialized.status.success(), "init: {initialized:?}");
    let output = create(&home, &bare, "blocked");
    assert!(
        !output.status.success(),
        "unexpected create success: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("TEMPLATE_UNSUPPORTED"),
        "unexpected rejected create: {output:?}"
    );
    assert_eq!(snapshot(&bare), before, "rejected create wrote authority");
    sandbox.cleanup().expect("cleanup rejected fixture");
}

#[test]
fn unsupported_filter_config_rejects_create_without_authority_write() {
    let mut sandbox = Sandbox::new();
    let bare = fixture_repo(&sandbox, false);
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(bare.as_os_str());
    git(
        &sandbox.path,
        &[
            git_dir,
            OsString::from("config"),
            OsString::from("filter.inject.clean"),
            OsString::from("cat"),
        ],
    );
    let home = home(&sandbox);
    let before = snapshot(&bare);
    let initialized = vws(
        &home,
        vec![OsString::from("init"), bare.as_os_str().to_os_string()],
    );
    assert!(initialized.status.success(), "init: {initialized:?}");
    let output = create(&home, &bare, "blocked-filter");
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("TEMPLATE_UNSUPPORTED"),
        "unexpected rejected create: {output:?}"
    );
    assert_eq!(
        snapshot(&bare),
        before,
        "rejected filter create wrote authority"
    );
    sandbox.cleanup().expect("cleanup rejected filter fixture");
}

#[test]
fn create_cleans_known_status_failure_and_retains_unknown_git_failure() {
    require_native_cow();
    for (mode, expected_record, expected_root, code) in [
        ("dirty", false, false, "SESSION_DIRTY"),
        ("gitfail", true, true, "SESSION_IO_FAILED"),
    ] {
        let mut sandbox = Sandbox::new();
        let bare = fixture_repo(&sandbox, false);
        let home = home(&sandbox);
        let before = snapshot(&bare);
        let initialized = vws(
            &home,
            vec![OsString::from("init"), bare.as_os_str().to_os_string()],
        );
        assert!(initialized.status.success(), "init: {initialized:?}");
        let wrapper = sandbox.child("git-wrapper");
        fs::create_dir(&wrapper).expect("create Git wrapper");
        let script = wrapper.join("git");
        fs::write(
            &script,
            "#!/bin/sh\ncase \"$VWS_TEST_MODE:$1\" in\ndirty:status) printf '%s\\n' '?? injected'; exit 0 ;;\ngitfail:init) exit 77 ;;\nesac\nexec /usr/bin/git \"$@\"\n",
        )
        .expect("write Git wrapper");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .expect("protect Git wrapper");
        let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
        let output = vws_command(&home, create_args(&bare, mode))
            .env("PATH", path)
            .env("VWS_TEST_MODE", mode)
            .output()
            .expect("run injected create");
        assert!(
            !output.status.success() && String::from_utf8_lossy(&output.stderr).contains(code),
            "unexpected {mode} create result: {output:?}"
        );
        let sessions = home.join(".git-vws/sessions");
        let records = children_with_suffix(&sessions, ".record");
        let roots = children_with_suffix(&sessions, ".root");
        assert_eq!(
            records.len(),
            usize::from(expected_record),
            "unexpected {mode} records"
        );
        assert_eq!(
            roots.len(),
            usize::from(expected_root),
            "unexpected {mode} roots"
        );
        if expected_record {
            assert!(
                fs::read(&records[0])
                    .expect("read retained record")
                    .windows(b"\"MATERIALIZING\"".len())
                    .any(|part| part == b"\"MATERIALIZING\""),
                "unknown Git failure did not retain the CREATING receipt"
            );
        }
        assert_eq!(snapshot(&bare), before, "{mode} create wrote authority");
        sandbox.cleanup().expect("cleanup injected fixture");
    }
}

fn fsync_parent(path: &Path) {
    File::open(path)
        .and_then(|parent| parent.sync_all())
        .expect("sync fixture parent");
}

fn atomic_replace(path: &Path, bytes: &[u8]) {
    let parent = path.parent().expect("record parent");
    let temporary = parent.join(format!(
        ".d278-{}-{}.tmp",
        std::process::id(),
        NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .expect("create atomic record replacement");
    file.write_all(bytes)
        .expect("write atomic record replacement");
    file.sync_all().expect("sync atomic record replacement");
    drop(file);
    fs::rename(&temporary, path).expect("rename atomic record replacement");
    fsync_parent(parent);
}

fn rename_and_sync(from: &Path, to: &Path) {
    assert_eq!(from.parent(), to.parent(), "rename crossed fixture parents");
    fs::rename(from, to).expect("rename fixture namespace");
    fsync_parent(from.parent().expect("fixture parent"));
}

fn ready_template_parts(record: &[u8], checkpoint: &str) -> (String, String, Vec<u8>, String) {
    let value: Value = serde_json::from_slice(record).expect("parse canonical READY record");
    let key = value
        .get("key")
        .and_then(Value::as_str)
        .expect("READY record key");
    let ready_name = value
        .pointer("/payload/READY/root_name")
        .and_then(Value::as_str)
        .expect("READY record root name")
        .to_owned();
    let sealed = value
        .pointer("/payload/READY/sealed")
        .expect("READY record sealed receipt");
    let identity = sealed
        .get("root")
        .and_then(Value::as_object)
        .expect("READY record root identity");
    let number = |field| {
        identity
            .get(field)
            .and_then(Value::as_u64)
            .expect("READY record identity field")
    };
    assert_eq!(number("mode"), 0o555, "READY root was not sealed");
    let marker = b"\"sealed\":";
    let start = record
        .windows(marker.len())
        .rposition(|window| window == marker)
        .expect("READY record sealed marker")
        + marker.len();
    assert!(record.ends_with(b"}}}"), "READY record suffix");
    let sealed_bytes = record[start..record.len() - 3].to_vec();
    let raw: Value = serde_json::from_slice(&sealed_bytes).expect("parse raw sealed receipt");
    assert_eq!(
        &raw, sealed,
        "sealed receipt did not match canonical record"
    );
    let preseal_identity = format!(
        "{{\"dev\":{},\"ino\":{},\"uid\":{},\"mode\":448,\"kind\":{},\"nlink\":{}}}",
        number("dev"),
        number("ino"),
        number("uid"),
        number("kind"),
        number("nlink"),
    );
    (
        ready_name,
        format!("template-{key}.d278-{checkpoint}.building"),
        sealed_bytes,
        preseal_identity,
    )
}

fn replace_payload(record: &[u8], payload: &str) -> Vec<u8> {
    let marker = b",\"payload\":";
    let start = record
        .windows(marker.len())
        .rposition(|window| window == marker)
        .expect("canonical payload marker");
    let mut replacement = record[..start + marker.len()].to_vec();
    replacement.extend_from_slice(payload.as_bytes());
    replacement.push(b'}');
    serde_json::from_slice::<Value>(&replacement).expect("parse replacement record");
    replacement
}

#[test]
fn template_crash_prefix_recovery_table_keeps_exact_receipts() {
    require_native_cow();
    let mut cases = vec![
        ("post-mkdir", "PREPARED", "READY"),
        ("post-seal", "MATERIALIZING", "TEMPLATE_INCOMPLETE"),
        ("post-rename", "PUBLISHING", "READY"),
    ];
    #[cfg(target_os = "macos")]
    cases.extend([
        ("post-unseal", "PUBLISHING", "READY"),
        ("post-rename-unsealed", "PUBLISHING", "READY"),
    ]);
    for (checkpoint, stage, expected) in cases {
        let mut sandbox = Sandbox::new();
        let bare = fixture_repo(&sandbox, false);
        let home = home(&sandbox);
        let authority_before = snapshot(&bare);
        let initialized = vws(
            &home,
            vec![OsString::from("init"), bare.as_os_str().to_os_string()],
        );
        assert!(
            initialized.status.success(),
            "{checkpoint} init: {initialized:?}"
        );
        let seed = create(&home, &bare, &format!("seed-{checkpoint}"));
        assert!(seed.status.success(), "{checkpoint} seed: {seed:?}");
        let state = home.join(".git-vws");
        let templates = state.join("templates");
        let record = only_child(&templates, ".record");
        let ready_record = fs::read(&record).expect("read seeded READY record");
        let (ready_name, building, sealed, preseal_identity) =
            ready_template_parts(&ready_record, checkpoint);
        let ready_root = templates.join(&ready_name);
        assert_eq!(ready_root, only_child(&templates, ".root"));

        let wrapper = sandbox.child("pause-wrapper");
        fs::create_dir(&wrapper).expect("create pause wrapper");
        let script = wrapper.join("git");
        fs::write(
            &script,
            "#!/bin/sh\nif [ \"$1\" = init ]; then\n  printf 'HELLO %s %s %s\\n' \"$VWS_TEST_NONCE\" \"$$\" \"$$\" >&3 || exit 90\n  IFS=' ' read -r action nonce <&3 || exit 91\n  [ \"$action\" = ARM ] && [ \"$nonce\" = \"$VWS_TEST_NONCE\" ] || exit 92\n  printf 'PAUSED %s\\n' \"$nonce\" >&3 || exit 93\n  IFS= read -r _ <&3\n  exit 94\nfi\nexec /usr/bin/git \"$@\"\n",
        )
        .expect("write pause wrapper");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .expect("protect pause wrapper");
        let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
        let mut command = vws_command(&home, create_args(&bare, &format!("paused-{checkpoint}")));
        command.env("PATH", path);
        let mut owner = CrashPrefixOwner::spawn(command, &script).expect("arm crash prefix owner");
        let observed = catch_unwind(AssertUnwindSafe(|| {
            let sessions = state.join("sessions");
            assert!(
                children_with_suffix(&sessions, ".record").len() >= 2
                    && children_with_suffix(&sessions, ".root").len() >= 2,
                "{checkpoint} did not pause at session Git init"
            );
        }));
        let cleanup = owner.finish();
        match (observed, cleanup) {
            (Ok(()), Ok(())) => {}
            (Ok(()), Err(error)) => panic!("{checkpoint} crash-prefix cleanup failed: {error}"),
            (Err(payload), Ok(())) => resume_unwind(payload),
            (Err(payload), Err(error)) => {
                eprintln!("{checkpoint} crash-prefix cleanup also failed: {error}");
                resume_unwind(payload)
            }
        }

        let building_root = templates.join(&building);
        let building_json = serde_json::to_string(&building).expect("encode building name");
        let ready_json = serde_json::to_string(&ready_name).expect("encode READY name");
        let sealed = String::from_utf8(sealed).expect("sealed receipt UTF-8");
        let payload = match stage {
            "PREPARED" => format!("{{\"PREPARED\":{{\"building_name\":{building_json}}}}}"),
            "MATERIALIZING" => format!(
                "{{\"MATERIALIZING\":{{\"building_name\":{building_json},\"root_identity\":{preseal_identity}}}}}"
            ),
            "PUBLISHING" => format!(
                "{{\"PUBLISHING\":{{\"building_name\":{building_json},\"ready_name\":{ready_json},\"sealed\":{sealed}}}}}"
            ),
            _ => unreachable!("table stage"),
        };
        match stage {
            "PREPARED" => {
                rename_and_sync(&ready_root, &building_root);
                fs::set_permissions(&building_root, fs::Permissions::from_mode(0o700))
                    .expect("restore prepared root mode");
                let root = File::open(&building_root).expect("open prepared root");
                clear_owned(
                    root.as_raw_fd(),
                    node(&root).expect("stat prepared root").dev,
                )
                .expect("empty prepared root");
                root.sync_all().expect("sync prepared root");
                fsync_parent(&templates);
            }
            "MATERIALIZING" => rename_and_sync(&ready_root, &building_root),
            "PUBLISHING" if checkpoint == "post-unseal" => {
                rename_and_sync(&ready_root, &building_root);
                fs::set_permissions(&building_root, fs::Permissions::from_mode(0o755))
                    .expect("unseal publishing root");
                fsync_parent(&templates);
            }
            "PUBLISHING" if checkpoint == "post-rename-unsealed" => {
                fs::set_permissions(&ready_root, fs::Permissions::from_mode(0o755))
                    .expect("unseal renamed publishing root");
                fsync_parent(&templates);
            }
            "PUBLISHING" => {}
            _ => unreachable!("table stage"),
        }
        atomic_replace(&record, &replace_payload(&ready_record, &payload));

        let root = if stage != "PUBLISHING" || checkpoint == "post-unseal" {
            &building_root
        } else {
            &ready_root
        };
        let record_before = fs::read(&record).expect("read crash-prefix record");
        let root_before = snapshot(root);
        let identity_before = path_node(root).expect("stat crash-prefix root");
        let recovered = create(&home, &bare, &format!("recover-{checkpoint}"));
        if expected == "TEMPLATE_INCOMPLETE" {
            assert!(
                !recovered.status.success()
                    && String::from_utf8_lossy(&recovered.stderr).contains(expected),
                "{checkpoint} recovery: {recovered:?}"
            );
            assert_eq!(
                fs::read(&record).expect("read retained record"),
                record_before
            );
            assert_eq!(snapshot(root), root_before);
            assert_eq!(
                path_node(root).expect("stat retained root"),
                identity_before
            );
        } else {
            assert!(
                recovered.status.success(),
                "{checkpoint} recovery: {recovered:?}"
            );
            assert!(
                fs::read(&record)
                    .expect("read recovered READY record")
                    .windows(b"\"READY\"".len())
                    .any(|part| part == b"\"READY\""),
                "{checkpoint} did not commit READY"
            );
            assert!(ready_root.is_dir(), "{checkpoint} READY root was absent");
            if checkpoint == "post-rename" {
                assert_eq!(snapshot(&ready_root), root_before);
                assert_eq!(
                    path_node(&ready_root).expect("stat READY root"),
                    identity_before
                );
            } else if matches!(checkpoint, "post-unseal" | "post-rename-unsealed") {
                let mut expected_snapshot = root_before;
                expected_snapshot[..4].copy_from_slice(&(DIRECTORY_TYPE | 0o555).to_be_bytes());
                assert_eq!(snapshot(&ready_root), expected_snapshot);
                let recovered = path_node(&ready_root).expect("stat resealed READY root");
                assert_eq!(recovered.dev, identity_before.dev);
                assert_eq!(recovered.ino, identity_before.ino);
                assert_eq!(recovered.uid, identity_before.uid);
                assert_eq!(recovered.kind, identity_before.kind);
                assert_eq!(recovered.mode, 0o555);
                assert!(!building_root.exists(), "unsealed building root survived");
            } else {
                assert!(!building_root.exists(), "prepared building root survived");
            }
        }
        assert_eq!(
            snapshot(&bare),
            authority_before,
            "{checkpoint} wrote the authority"
        );
        sandbox
            .cleanup()
            .expect("cleanup crash-prefix recovery fixture");
    }
}

#[test]
fn session_record_outbound_gate_rejects_invalid_names_without_state() {
    require_native_cow();
    let mut sandbox = Sandbox::new();
    let bare = fixture_repo(&sandbox, false);
    let home = home(&sandbox);
    let target = "record-gate";
    let create_target = |name: &str| {
        let mut args = create_args(&bare, name);
        args.extend([OsString::from("--target"), OsString::from(target)]);
        vws(&home, args)
    };
    let initialized = vws(
        &home,
        vec![OsString::from("init"), bare.as_os_str().to_os_string()],
    );
    assert!(initialized.status.success(), "init: {initialized:?}");
    let seed = create_target("seed");
    assert!(seed.status.success(), "seed: {seed:?}");
    let state = home.join(".git-vws");
    let sessions = state.join("sessions");
    assert!(only_child(&state.join("templates"), ".root").is_dir());
    assert!(only_child(&sessions, ".record").is_file());
    assert!(only_child(&sessions, ".root").is_dir());
    let before = [snapshot(&home), snapshot(&bare), snapshot(&sessions)];
    let oversized = "n".repeat(9 * 1024);
    for name in ["", oversized.as_str()] {
        let rejected = create_target(name);
        assert!(
            !rejected.status.success()
                && String::from_utf8_lossy(&rejected.stderr).contains("SESSION_CORRUPT"),
            "unexpected rejected create: {rejected:?}"
        );
        assert_eq!(
            [snapshot(&home), snapshot(&bare), snapshot(&sessions)],
            before,
            "state changed after {name:?}"
        );
    }
    let reentry = create_target("seed");
    assert!(reentry.status.success(), "READY reentry: {reentry:?}");
    assert_eq!(
        [snapshot(&home), snapshot(&bare), snapshot(&sessions)],
        before,
        "READY reentry changed state"
    );
    sandbox
        .cleanup()
        .expect("cleanup outbound record gate fixture");
}
