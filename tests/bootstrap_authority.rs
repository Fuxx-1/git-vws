use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_SANDBOX: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
const FILE_TYPE_MASK: u32 = libc::S_IFMT;
#[cfg(target_os = "linux")]
const DIRECTORY_TYPE: u32 = libc::S_IFDIR;
#[cfg(target_os = "macos")]
const FILE_TYPE_MASK: u32 = libc::S_IFMT as u32;
#[cfg(target_os = "macos")]
const DIRECTORY_TYPE: u32 = libc::S_IFDIR as u32;

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
    parent_path: PathBuf,
    name: CString,
    root: Option<File>,
    root_path: PathBuf,
    node: Node,
}

impl Sandbox {
    fn new() -> Self {
        let parent_path = fs::canonicalize(env::temp_dir()).expect("canonical temp parent");
        let parent = File::open(&parent_path).expect("open temp parent");
        let basename = format!(
            "git-vws-r0-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        );
        let name = CString::new(basename.as_bytes()).expect("sandbox name");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) },
            0
        );
        let root = open_dir(parent.as_raw_fd(), &name).expect("open sandbox");
        assert_eq!(unsafe { libc::fchmod(root.as_raw_fd(), 0o700) }, 0);
        let node = fstat(&root).expect("stat sandbox");
        assert!(node.kind == DIRECTORY_TYPE && node.mode == 0o700);
        Self {
            parent,
            parent_path: parent_path.clone(),
            name,
            root: Some(root),
            root_path: parent_path.join(basename),
            node,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root_path.join(name)
    }

    fn cleanup(&mut self) -> io::Result<()> {
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        clear_directory(root.as_raw_fd(), self.node.dev)?;
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

    fn cleanup_named(&self, name: &CString) -> io::Result<()> {
        let root = open_dir(self.parent.as_raw_fd(), name)?;
        let node = fstat(&root)?;
        if stat_at(self.parent.as_raw_fd(), name)? != node {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        clear_directory(root.as_raw_fd(), node.dev)?;
        if stat_at(self.parent.as_raw_fd(), name)? != node {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        drop(root);
        Ok(())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if self.root.is_some() {
            self.cleanup().unwrap_or_else(|error| {
                eprintln!("sandbox cleanup failed: {error}");
                if !std::thread::panicking() {
                    panic!("sandbox cleanup failed");
                }
            });
        }
    }
}

fn clear_directory(fd: RawFd, device: u64) -> io::Result<()> {
    for bytes in names(fd)? {
        let name = CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let before = stat_at(fd, &name)?;
        if before.dev != device || before.uid != unsafe { libc::geteuid() } {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if before.kind == DIRECTORY_TYPE {
            let child = open_dir(fd, &name)?;
            if fstat(&child)? != before {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            clear_directory(child.as_raw_fd(), device)?;
            drop(child);
            if stat_at(fd, &name)? != before {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            if unsafe { libc::unlinkat(fd, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(io::Error::last_os_error());
            }
        } else {
            if stat_at(fd, &name)? != before {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            if unsafe { libc::unlinkat(fd, name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

fn open_dir(parent: RawFd, name: &CStr) -> io::Result<File> {
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

fn fstat(file: &File) -> io::Result<Node> {
    let mut stat = zeroed_stat();
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Node::from_stat(&stat))
    }
}

fn stat_at(parent: RawFd, name: &CStr) -> io::Result<Node> {
    let mut stat = zeroed_stat();
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Node::from_stat(&stat))
    }
}

fn names(fd: RawFd) -> io::Result<Vec<Vec<u8>>> {
    let dot = c".";
    let directory_fd = unsafe {
        libc::openat(
            fd,
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { libc::fdopendir(directory_fd) };
    if directory.is_null() {
        unsafe { libc::close(directory_fd) };
        return Err(io::Error::last_os_error());
    }
    let mut result = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                unsafe { libc::closedir(directory) };
                return Err(error);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." && !name.contains(&b'/') {
            result.push(name.to_vec());
        }
    }
    if unsafe { libc::closedir(directory) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

fn zeroed_stat() -> libc::stat {
    unsafe { std::mem::zeroed() }
}

fn git(cwd: &Path, args: &[&str]) {
    let mut command = Command::new("git");
    for (name, _) in env::vars_os() {
        if name.as_bytes().starts_with(b"GIT_") {
            command.env_remove(name);
        }
    }
    let output = command
        .current_dir(cwd)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("fixture git");
    assert!(output.status.success(), "git {:?}: {output:?}", args);
}

fn bare(sandbox: &Sandbox, name: &str) -> PathBuf {
    let path = sandbox.path(name);
    git(
        &sandbox.root_path,
        &["init", "--bare", path.to_str().expect("utf8 path")],
    );
    path
}

fn home(sandbox: &Sandbox, name: &str) -> PathBuf {
    let path = sandbox.path(name);
    fs::create_dir(&path).expect("create home");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("protect home");
    path
}

fn init(home: &Path, authority: &Path) -> Output {
    init_command(home, authority).output().expect("run git-vws")
}

fn init_command(home: &Path, authority: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_git-vws"));
    command.arg("init").arg(authority).env("HOME", home);
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_VWS_UNKNOWN",
    ] {
        command.env(name, "/definitely/not/usable");
    }
    command
}

fn snapshot(path: &Path) -> String {
    let mut output = String::new();
    snapshot_entry(path, path, &mut output);
    output
}

fn snapshot_entry(root: &Path, path: &Path, output: &mut String) {
    let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
    writeln!(
        output,
        "{:?}|{:o}|{}:{}:{}:{}",
        path.strip_prefix(root).expect("relative"),
        metadata.mode() & 0o7777,
        metadata.uid(),
        metadata.nlink(),
        metadata.mtime(),
        metadata.file_type().is_symlink()
    )
    .expect("snapshot write");
    if metadata.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("snapshot dir")
            .map(|entry| entry.expect("snapshot entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            snapshot_entry(root, &entry, output);
        }
    } else if metadata.is_file() {
        writeln!(
            output,
            "{:016x}",
            hash(&fs::read(path).expect("snapshot file"))
        )
        .expect("snapshot write");
    }
}

fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325, |value, byte| {
        (value ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn assert_rejected(home: &Path, authority: &Path) {
    let before_home = snapshot(home);
    let before_authority = snapshot(authority);
    let output = init(home, authority);
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert_eq!(snapshot(home), before_home, "state changed on reject");
    assert_eq!(
        snapshot(authority),
        before_authority,
        "authority changed on reject"
    );
}

fn only_record(home: &Path) -> PathBuf {
    let entries: Vec<_> = fs::read_dir(home.join(".git-vws"))
        .expect("state root")
        .map(|entry| entry.expect("record entry").path())
        .collect();
    assert_eq!(entries.len(), 1);
    entries.into_iter().next().expect("one record")
}

fn record_name(path: &Path) -> String {
    format!(
        "authority-{:016x}.record",
        hash(path.as_os_str().as_bytes())
    )
}

fn wait_until(timeout: Duration, label: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn write_private_file_at(parent: RawFd, name: &CStr, bytes: &[u8]) -> Node {
    let raw = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert!(
        raw >= 0,
        "create private file: {}",
        io::Error::last_os_error()
    );
    let mut file = unsafe { File::from_raw_fd(raw) };
    assert_eq!(unsafe { libc::fchmod(file.as_raw_fd(), 0o600) }, 0);
    file.write_all(bytes).expect("write private file");
    file.sync_data().expect("sync private file");
    fstat(&file).expect("stat private file")
}

fn process_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

struct ProbeProcessCleanup {
    escaped_ready: Option<PathBuf>,
    escaped_release: Option<PathBuf>,
    escaped_pid: Option<PathBuf>,
    unrelated: Option<Child>,
}

impl ProbeProcessCleanup {
    fn release_only(&self) -> io::Result<()> {
        if let Some(release) = self.escaped_release.as_ref() {
            let ready = self
                .escaped_ready
                .as_ref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
            wait_for(Duration::from_secs(2), || ready.is_file())?;
            fs::write(release, b"release\n")?;
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        let escaped = match (
            self.escaped_ready.is_some(),
            self.escaped_release.is_some(),
            self.escaped_pid.is_some(),
        ) {
            (false, false, false) => Ok(()),
            (true, true, true) => self.release_only().and_then(|_| {
                let path = self
                    .escaped_pid
                    .as_ref()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                wait_for(Duration::from_secs(2), || path.is_file())?;
                let pid = fs::read_to_string(path).and_then(|pid| {
                    pid.trim()
                        .parse::<i32>()
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
                })?;
                if pid <= 0 {
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                }
                if process_alive(pid as u32) && unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(io::Error::other(format!(
                            "cannot terminate escaped PID {pid}: {error}",
                        )));
                    }
                }
                wait_for(Duration::from_secs(10), || !process_alive(pid as u32)).map_err(
                    |error| io::Error::other(format!("escaped PID {pid} remained alive: {error}")),
                )?;
                self.escaped_ready.take();
                self.escaped_release.take();
                self.escaped_pid.take();
                Ok(())
            }),
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        };
        let unrelated = if let Some(child) = self.unrelated.as_mut() {
            let killed = child.kill().err();
            let waited = child.wait().map(|_| ());
            if waited.is_ok() {
                self.unrelated.take();
            }
            match (killed, waited) {
                (Some(error), _) => Err(error),
                (None, result) => result,
            }
        } else {
            Ok(())
        };
        match (escaped, unrelated) {
            (Err(escaped), Err(unrelated)) => Err(io::Error::other(format!(
                "{escaped}; unrelated cleanup: {unrelated}",
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
            _ => Ok(()),
        }
    }
}

impl Drop for ProbeProcessCleanup {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("probe process cleanup failed: {error}");
            if !std::thread::panicking() {
                panic!("probe process cleanup failed");
            }
        }
    }
}

fn wait_for(timeout: Duration, mut ready: impl FnMut() -> bool) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    while !ready() {
        if Instant::now() >= deadline {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn merge_cleanup(process: io::Result<()>, sandbox: io::Result<()>) -> io::Result<()> {
    match (process, sandbox) {
        (Err(process), Err(sandbox)) => Err(io::Error::other(format!(
            "{process}; sandbox cleanup: {sandbox}",
        ))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

fn directory_fsync_failure_preload(sandbox: &Sandbox) -> PathBuf {
    let source = sandbox.path("fail-directory-fsync.c");
    let library = sandbox.path(if cfg!(target_os = "macos") {
        "fail-directory-fsync.dylib"
    } else {
        "fail-directory-fsync.so"
    });
    #[cfg(target_os = "macos")]
    let source_text = concat!(
        "#include <errno.h>\n#include <fcntl.h>\n#include <stdarg.h>\n",
        "#include <stdlib.h>\n#include <string.h>\n#include <sys/stat.h>\n",
        "#include <sys/syscall.h>\n#include <unistd.h>\nstatic int calls;\n",
        "static int fail_directory(int fd) {\n  struct stat node;\n",
        "  const char *nth = getenv(\"VWS_TEST_DIRECTORY_FSYNC_N\");\n",
        "  const char *program = getenv(\"VWS_TEST_FSYNC_PROGRAM\");\n",
        "  return nth && program && !strcmp(getprogname(), program) &&\n",
        "    fstat(fd, &node) == 0 && S_ISDIR(node.st_mode) && ++calls == atoi(nth);\n}\n",
        "static int fail_fcntl(int fd, int command, ...) {\n",
        "  if (command == F_FULLFSYNC && fail_directory(fd)) { errno = EIO; return -1; }\n",
        "  long argument = 0;\n  if (command != F_GETFD && command != F_GETFL && command != F_GETOWN && command != F_FULLFSYNC) {\n",
        "    va_list args; va_start(args, command); argument = va_arg(args, long); va_end(args);\n  }\n",
        "  return (int)syscall(SYS_fcntl, fd, command, argument);\n}\n",
        "#define DYLD_INTERPOSE(a, b) __attribute__((used)) static struct { const void *a; const void *b; } i_##b __attribute__((section(\"__DATA,__interpose\"))) = { (const void *)&a, (const void *)&b };\n",
        "DYLD_INTERPOSE(fail_fcntl, fcntl);\n"
    );
    #[cfg(target_os = "linux")]
    let source_text = concat!(
        "#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <errno.h>\n",
        "#include <stdlib.h>\n#include <string.h>\n#include <sys/stat.h>\n#include <unistd.h>\n",
        "typedef int (*fsync_fn)(int);\nextern char *program_invocation_short_name;\nstatic int calls;\n",
        "static int fail_directory(int fd) {\n  struct stat node;\n",
        "  const char *nth = getenv(\"VWS_TEST_DIRECTORY_FSYNC_N\");\n",
        "  const char *program = getenv(\"VWS_TEST_FSYNC_PROGRAM\");\n",
        "  return nth && program && program_invocation_short_name &&\n",
        "    !strcmp(program_invocation_short_name, program) && fstat(fd, &node) == 0 &&\n",
        "    S_ISDIR(node.st_mode) && ++calls == atoi(nth);\n}\n",
        "int fsync(int fd) {\n  static fsync_fn real_fsync;\n",
        "  if (fail_directory(fd)) { errno = EIO; return -1; }\n",
        "  if (!real_fsync) real_fsync = (fsync_fn)dlsym(RTLD_NEXT, \"fsync\");\n",
        "  if (!real_fsync) { errno = EIO; return -1; }\n  return real_fsync(fd);\n}\n"
    );
    fs::write(&source, source_text).expect("write fsync preload source");
    let mut compiler = Command::new("cc");
    #[cfg(target_os = "macos")]
    compiler.args(["-dynamiclib", "-o"]);
    #[cfg(target_os = "linux")]
    compiler.args(["-shared", "-fPIC", "-o"]);
    compiler.arg(&library).arg(&source);
    #[cfg(target_os = "linux")]
    compiler.arg("-ldl");
    let output = compiler.output().expect("compile fsync preload");
    assert!(
        output.status.success(),
        "fsync preload compiler failed: {output:?}"
    );
    library
}

fn init_with_directory_fsync_failure(
    home: &Path,
    authority: &Path,
    preload: &Path,
    nth: usize,
) -> Output {
    let mut command = init_command(home, authority);
    command
        .env("VWS_TEST_DIRECTORY_FSYNC_N", nth.to_string())
        .env("VWS_TEST_FSYNC_PROGRAM", "git-vws");
    #[cfg(target_os = "macos")]
    command
        .env("DYLD_INSERT_LIBRARIES", preload)
        .env("DYLD_FORCE_FLAT_NAMESPACE", "1");
    #[cfg(target_os = "linux")]
    command.env("LD_PRELOAD", preload);
    command.output().expect("run fsync failure init")
}

fn inject_final_collision(
    sandbox: &Sandbox,
    home: &Path,
    authority: &Path,
    label: &str,
    contents: &[u8],
) -> (Output, Node, Node, PathBuf) {
    let wrapper = sandbox.path(&format!("{label}-collision-wrapper"));
    let counter = sandbox.path(&format!("{label}-collision-count"));
    let ready = sandbox.path(&format!("{label}-collision-ready"));
    let release = sandbox.path(&format!("{label}-collision-release"));
    fs::create_dir(&wrapper).expect("collision wrapper dir");
    let script = wrapper.join("git");
    fs::write(
        &script,
        "#!/bin/sh\nn=$(cat \"$VWS_TEST_COUNTER\" 2>/dev/null || echo 0)\nn=$((n + 1))\nprintf '%s\\n' \"$n\" > \"$VWS_TEST_COUNTER\"\nif [ \"$n\" -eq 4 ]; then\n  for candidate in \"$HOME/.git-vws\"/.*.tmp; do\n    if [ -f \"$candidate\" ]; then : > \"$VWS_TEST_COLLISION_READY\"; break; fi\n  done\n  [ -f \"$VWS_TEST_COLLISION_READY\" ] || exit 97\n  while [ ! -f \"$VWS_TEST_COLLISION_RELEASE\" ]; do sleep 0.01; done\nfi\nexec /usr/bin/git \"$@\"\n",
    )
    .expect("collision wrapper");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
        .expect("collision wrapper mode");
    let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
    let expected = record_name(&fs::canonicalize(authority).expect("canonical authority"));
    let child = init_command(home, authority)
        .env("PATH", path)
        .env("VWS_TEST_COUNTER", &counter)
        .env("VWS_TEST_COLLISION_READY", &ready)
        .env("VWS_TEST_COLLISION_RELEASE", &release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn collision init");
    wait_until(Duration::from_secs(5), "armed collision temporary", || {
        ready.is_file()
    });
    let home_fd = File::open(home).expect("open collision HOME");
    let root_name = CString::new(".git-vws").expect("state root name");
    let root = open_dir(home_fd.as_raw_fd(), &root_name).expect("open collision root");
    let root_node = fstat(&root).expect("collision root identity");
    let final_name = CString::new(expected.as_bytes()).expect("final record name");
    let final_node = write_private_file_at(root.as_raw_fd(), &final_name, contents);
    fs::write(&release, b"release\n").expect("release collision probe");
    let output = child.wait_with_output().expect("collision output");
    assert_eq!(
        fstat(&root).expect("collision root identity after run"),
        root_node
    );
    assert_eq!(
        stat_at(home_fd.as_raw_fd(), &root_name).expect("collision root entry after run"),
        root_node
    );
    drop(root);
    drop(home_fd);
    (
        output,
        root_node,
        final_node,
        home.join(".git-vws").join(expected),
    )
}

fn assert_preserved_collision(
    home: &Path,
    record_path: &Path,
    root_node: Node,
    record_node: Node,
    contents: &[u8],
) {
    let home_fd = File::open(home).expect("open collision HOME for preservation");
    let root_name = CString::new(".git-vws").expect("state root name");
    let root = open_dir(home_fd.as_raw_fd(), &root_name).expect("preserved collision root");
    let name = CString::new(
        record_path
            .file_name()
            .expect("preserved record basename")
            .as_bytes(),
    )
    .expect("preserved record cstring");
    assert_eq!(fstat(&root).expect("preserved root node"), root_node);
    assert_eq!(
        stat_at(root.as_raw_fd(), &name).expect("preserved record node"),
        record_node
    );
    assert_eq!(
        fs::read(record_path).expect("preserved record content"),
        contents
    );
    assert_eq!(
        names(root.as_raw_fd()).expect("preserved root entries"),
        vec![name.into_bytes()]
    );
}

fn assert_duplicate_reopen(home: &Path, authority: &Path, root: &Path) {
    let before = snapshot(root);
    let output = init(home, authority);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("AUTHORITY_DUPLICATE"),
        "unexpected duplicate reopen: {output:?}"
    );
    assert_eq!(snapshot(root), before);
}

fn assert_probe_failure(output: &Output, home: &Path, expected: &str, mode: &str) {
    assert!(
        !output.status.success(),
        "unexpected {mode} success: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "unexpected {mode} probe error: {output:?}"
    );
    assert!(
        !home.join(".git-vws").exists(),
        "state root remained: {output:?}"
    );
}

fn assert_collision_error(output: &Output, code: &str, label: &str) {
    assert!(
        !output.status.success(),
        "unexpected {label} collision success: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(code),
        "unexpected {label} collision error: {output:?}"
    );
}

#[test]
fn record_commit_syncs_its_parent_and_preserves_known_commit_on_sync_failure() {
    let mut sandbox = Sandbox::new();
    let authority = bare(&sandbox, "authority.git");

    let success_home = home(&sandbox, "success-home");
    let success = init(&success_home, &authority);
    assert!(success.status.success(), "successful init: {success:?}");
    let success_root = success_home.join(".git-vws");
    assert_duplicate_reopen(&success_home, &authority, &success_root);

    let preload = directory_fsync_failure_preload(&sandbox);
    for (name, nth, detail) in [
        ("root-parent-home", 1, "state record parent directory"),
        ("home-parent-home", 2, "HOME after new state root commit"),
    ] {
        let failed_home = home(&sandbox, name);
        let failed = init_with_directory_fsync_failure(&failed_home, &authority, &preload, nth);
        assert!(
            !failed.status.success(),
            "unexpected fsync-failure success: {failed:?}"
        );
        let stderr = String::from_utf8_lossy(&failed.stderr);
        assert!(
            stderr.contains("STATE_COMMITTED_UNSYNCED") && stderr.contains(detail),
            "unexpected fsync-failure error: {failed:?}"
        );
        let failed_root = failed_home.join(".git-vws");
        let record = only_record(&failed_home);
        assert_eq!(
            fs::metadata(&record)
                .expect("failed record metadata")
                .mode()
                & 0o777,
            0o600
        );
        assert_duplicate_reopen(&failed_home, &authority, &failed_root);
    }
    let third_home = home(&sandbox, "no-third-sync-home");
    assert!(
        init_with_directory_fsync_failure(&third_home, &authority, &preload, 3)
            .status
            .success()
    );
    sandbox.cleanup().expect("cleanup durable record test");
}

#[test]
fn invalid_authorities_and_external_storage_are_zero_write() {
    let mut sandbox = Sandbox::new();
    let plain = sandbox.path("plain");
    fs::create_dir(&plain).expect("plain");
    let normal = sandbox.path("normal");
    git(
        &sandbox.root_path,
        &["init", normal.to_str().expect("utf8")],
    );
    let registry = bare(&sandbox, "registry.git");
    fs::create_dir_all(registry.join("worktrees/linked")).expect("registry");
    let alternates = bare(&sandbox, "alternates.git");
    fs::write(alternates.join("objects/info/alternates"), b"/outside\n").expect("alternates");
    let storage_symlink = bare(&sandbox, "storage-symlink.git");
    let moved_objects = sandbox.path("moved-objects");
    fs::rename(storage_symlink.join("objects"), &moved_objects).expect("move objects");
    symlink(&moved_objects, storage_symlink.join("objects")).expect("objects symlink");
    for (name, authority) in [
        ("plain-home", &plain),
        ("registry-home", &registry),
        ("alternates-home", &alternates),
        ("storage-symlink-home", &storage_symlink),
    ] {
        assert_rejected(&home(&sandbox, name), authority);
    }
    let normal_home = home(&sandbox, "normal-home");
    let normal_before = snapshot(&normal);
    let normal_init = init(&normal_home, &normal);
    assert!(
        normal_init.status.success(),
        "normal project init: {normal_init:?}"
    );
    assert_eq!(
        snapshot(&normal),
        normal_before,
        "normal project was modified"
    );
    assert!(normal_home.join(".git-vws").exists());
    sandbox.cleanup().expect("cleanup");
}

#[test]
fn duplicate_alias_corrupt_state_and_identity_replacement_fail_closed() {
    let mut sandbox = Sandbox::new();
    let primary_home = home(&sandbox, "home");
    let authority = bare(&sandbox, "authority.git");
    assert!(init(&primary_home, &authority).status.success());
    let alias = sandbox.path("alias.git");
    symlink(&authority, &alias).expect("alias");
    assert_rejected(&primary_home, &alias);
    assert_rejected(&primary_home, &authority.join("."));
    let record = only_record(&primary_home);
    fs::write(&record, b"broken\n").expect("truncated record");
    assert_rejected(&primary_home, &authority);

    let unknown_home = home(&sandbox, "unknown-home");
    assert!(init(&unknown_home, &authority).status.success());
    let unknown_record = only_record(&unknown_home);
    let unknown = String::from_utf8(fs::read(&unknown_record).expect("read record"))
        .expect("record utf8")
        .replacen("version=1", "version=2", 1);
    fs::write(&unknown_record, unknown).expect("unknown version record");
    assert_rejected(&unknown_home, &authority);

    let record_mode_home = home(&sandbox, "record-mode-home");
    assert!(init(&record_mode_home, &authority).status.success());
    fs::set_permissions(
        only_record(&record_mode_home),
        fs::Permissions::from_mode(0o644),
    )
    .expect("weaken record mode");
    assert_rejected(&record_mode_home, &authority);

    let drift_home = home(&sandbox, "drift-home");
    let drift = bare(&sandbox, "drift.git");
    assert!(init(&drift_home, &drift).status.success());
    fs::rename(&drift, sandbox.path("previous-drift.git")).expect("move authority");
    git(
        &sandbox.root_path,
        &["init", "--bare", drift.to_str().expect("utf8")],
    );
    assert_rejected(&drift_home, &drift);
    sandbox.cleanup().expect("cleanup");
}

#[test]
fn common_desktop_metadata_is_ignored_but_unsafe_shapes_fail_closed() {
    let mut sandbox = Sandbox::new();
    let home = home(&sandbox, "metadata-home");
    let authority = bare(&sandbox, "metadata-authority.git");
    assert!(init(&home, &authority).status.success());
    let root = home.join(".git-vws");
    for name in [
        b".DS_Store".as_slice(),
        b".directory",
        b".hidden",
        b".localized",
        b"Icon\r",
        b".AppleDouble",
        b"._finder-metadata",
    ] {
        let path = root.join(OsStr::from_bytes(name));
        if name == b".AppleDouble" {
            fs::create_dir(&path).expect("create AppleDouble metadata directory");
        } else {
            fs::write(path, b"desktop metadata\n").expect("write desktop metadata");
        }
    }
    assert_duplicate_reopen(&home, &authority, &root);

    let link = root.join(".DS_Store");
    fs::remove_file(&link).expect("remove regular metadata fixture");
    symlink(&authority, &link).expect("create metadata symlink");
    assert_rejected(&home, &authority);
    fs::remove_file(&link).expect("remove metadata symlink");
    fs::create_dir(&link).expect("create metadata directory");
    assert_rejected(&home, &authority);
    sandbox.cleanup().expect("cleanup");
}

#[test]
fn state_symlink_and_concurrent_init_do_not_create_two_truths() {
    let mut sandbox = Sandbox::new();
    let authority = bare(&sandbox, "authority.git");
    let bad_home = home(&sandbox, "bad-home");
    let target = sandbox.path("state-target");
    fs::create_dir(&target).expect("state target");
    symlink(&target, bad_home.join(".git-vws")).expect("state symlink");
    assert_rejected(&bad_home, &authority);

    let home_target = home(&sandbox, "home-target");
    let home_alias = sandbox.path("home-alias");
    symlink(&home_target, &home_alias).expect("HOME symlink");
    let before_home_target = snapshot(&home_target);
    let output = init(&home_alias, &authority);
    assert!(
        !output.status.success(),
        "unexpected HOME symlink success: {output:?}"
    );
    assert_eq!(snapshot(&home_target), before_home_target);

    let empty_home = home(&sandbox, "empty-home");
    let empty_root = empty_home.join(".git-vws");
    fs::create_dir(&empty_root).expect("empty state root");
    fs::set_permissions(&empty_root, fs::Permissions::from_mode(0o700))
        .expect("protect empty state root");
    assert_rejected(&empty_home, &authority);

    let mode_home = home(&sandbox, "mode-home");
    let mode_root = mode_home.join(".git-vws");
    fs::create_dir(&mode_root).expect("mode state root");
    fs::set_permissions(&mode_root, fs::Permissions::from_mode(0o755)).expect("weaken state root");
    assert_rejected(&mode_home, &authority);

    let link_home = home(&sandbox, "link-count-home");
    let link_root = link_home.join(".git-vws");
    fs::create_dir(&link_root).expect("link-count root");
    fs::set_permissions(&link_root, fs::Permissions::from_mode(0o700))
        .expect("protect link-count root");
    fs::create_dir(link_root.join("child")).expect("increase root link count");
    assert_rejected(&link_home, &authority);

    struct ConcurrentInitOwner {
        children: [Option<Child>; 2],
        statuses: [Option<std::process::ExitStatus>; 2],
        home_lease: Option<File>,
        gate: PathBuf,
        stderr: [PathBuf; 2],
        result: Option<Result<[std::process::ExitStatus; 2], String>>,
    }

    impl ConcurrentInitOwner {
        fn spawn(
            mut first: Command,
            mut second: Command,
            home_lease: File,
            gate: PathBuf,
        ) -> Result<Self, String> {
            let stderr = [gate.join("first.stderr"), gate.join("second.stderr")];
            first.stdout(Stdio::null()).stderr(Stdio::from(
                File::create(&stderr[0])
                    .map_err(|error| format!("create first stderr: {error}"))?,
            ));
            second.stdout(Stdio::null()).stderr(Stdio::from(
                File::create(&stderr[1])
                    .map_err(|error| format!("create second stderr: {error}"))?,
            ));
            let first = first
                .spawn()
                .map_err(|error| format!("spawn first init: {error}"))?;
            let mut owner = Self {
                children: [Some(first), None],
                statuses: [None, None],
                home_lease: Some(home_lease),
                gate,
                stderr,
                result: None,
            };
            match second.spawn() {
                Ok(second) => owner.children[1] = Some(second),
                Err(error) => {
                    let cleanup = owner.finish();
                    return Err(format!("spawn second init: {error}; cleanup: {cleanup:?}"));
                }
            }
            Ok(owner)
        }

        fn markers(&self, prefix: &str) -> Result<Vec<String>, String> {
            let mut names = fs::read_dir(&self.gate)
                .map_err(|error| format!("read gate: {error}"))?
                .map(|entry| {
                    entry
                        .map_err(|error| format!("read gate entry: {error}"))?
                        .file_name()
                        .into_string()
                        .map_err(|_| "non-UTF-8 gate marker".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.retain(|name| name.starts_with(prefix));
            names.sort();
            Ok(names)
        }

        fn listed(&self, prefix: &str) -> String {
            self.markers(prefix)
                .map(|names| names.join(","))
                .unwrap_or_else(|error| format!("<{error}>"))
        }

        fn status(&mut self, index: usize) -> String {
            if let Some(status) = self.statuses[index].as_ref() {
                return format!("reaped {status}");
            }
            match self.children[index].as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(Some(status)) => format!("exited {status}"),
                    Ok(None) => "running".to_owned(),
                    Err(error) => format!("wait error: {error}"),
                },
                None => "missing".to_owned(),
            }
        }

        fn evidence(&mut self) -> String {
            let counts = self
                .markers("")
                .map(|names| {
                    names
                        .into_iter()
                        .filter(|name| name.ends_with(".count"))
                        .map(|name| match fs::read_to_string(self.gate.join(&name)) {
                            Ok(count) => format!("{name}={}", count.trim()),
                            Err(error) => format!("{name}=<{error}>"),
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_else(|error| format!("<{error}>"));
            let first = self.status(0);
            let second = self.status(1);
            let first_stderr =
                fs::read_to_string(&self.stderr[0]).unwrap_or_else(|error| format!("<{error}>"));
            let second_stderr =
                fs::read_to_string(&self.stderr[1]).unwrap_or_else(|error| format!("<{error}>"));
            format!(
                "entered=[{}]; ready=[{}]; counts=[{counts}]; exits=[{first}, {second}]; stderr=[{first_stderr:?}, {second_stderr:?}]",
                self.listed("entered."),
                self.listed("ready."),
            )
        }

        fn check_running(&mut self, label: &str) -> Result<(), String> {
            let mut exits = Vec::new();
            for index in 0..2 {
                if self.statuses[index].is_some() {
                    exits.push(format!("outer {index} was already reaped"));
                    continue;
                }
                match self.children[index].as_mut() {
                    Some(child) => match child.try_wait() {
                        Ok(Some(status)) => exits.push(format!("outer {index} exited {status}")),
                        Ok(None) => {}
                        Err(error) => exits.push(format!("outer {index} wait error: {error}")),
                    },
                    None => exits.push(format!("outer {index} was missing")),
                }
            }
            if exits.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "outer child exited before {label}: {}; {}",
                    exits.join(", "),
                    self.evidence()
                ))
            }
        }

        fn wait_markers(
            &mut self,
            prefix: &str,
            expected: usize,
            label: &str,
        ) -> Result<(), String> {
            let deadline = Instant::now() + Duration::from_secs(12);
            loop {
                self.check_running(label)?;
                let markers = self
                    .markers(prefix)
                    .map_err(|error| format!("read {label}: {error}; {}", self.evidence()))?;
                if markers.len() == expected {
                    return Ok(());
                }
                if markers.len() > expected || Instant::now() >= deadline {
                    return Err(format!(
                        "timed out waiting for {label}; {}",
                        self.evidence()
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn third_count(&self) -> Result<usize, String> {
            match fs::read_to_string(self.gate.join("third-events")) {
                Ok(events) => Ok(events.lines().count()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
                Err(error) => Err(format!("read third events: {error}")),
            }
        }

        fn wait_third(&mut self, expected: usize, label: &str) -> Result<(), String> {
            let deadline = Instant::now() + Duration::from_secs(12);
            loop {
                self.check_running(label)?;
                let count = self
                    .third_count()
                    .map_err(|error| format!("{error}; {}", self.evidence()))?;
                if count == expected {
                    return Ok(());
                }
                if count > expected || Instant::now() >= deadline {
                    return Err(format!(
                        "timed out waiting for {label}; {}",
                        self.evidence()
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn hold_winner(&mut self) -> Result<(), String> {
            let deadline = Instant::now() + Duration::from_millis(100);
            loop {
                self.check_running("winner third-probe hold")?;
                if self
                    .third_count()
                    .map_err(|error| format!("{error}; {}", self.evidence()))?
                    != 1
                {
                    return Err(format!(
                        "loser entered before winner release; {}",
                        self.evidence()
                    ));
                }
                if Instant::now() >= deadline {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn release_home(&mut self) -> Result<(), String> {
            let Some(lease) = self.home_lease.take() else {
                return Ok(());
            };
            let result = unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_UN) };
            let error = io::Error::last_os_error();
            drop(lease);
            if result == 0 {
                Ok(())
            } else {
                Err(format!("release HOME lease: {error}"))
            }
        }

        fn reap(&mut self) -> Result<[std::process::ExitStatus; 2], String> {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                for index in 0..2 {
                    if self.statuses[index].is_some() {
                        continue;
                    }
                    let observed = match self.children[index].as_mut() {
                        Some(child) => child.try_wait(),
                        None => continue,
                    };
                    match observed {
                        Ok(Some(_)) => {
                            let Some(mut child) = self.children[index].take() else {
                                return Err(format!("outer {index} vanished; {}", self.evidence()));
                            };
                            self.statuses[index] = Some(
                                child
                                    .wait()
                                    .map_err(|error| format!("reap outer {index}: {error}"))?,
                            );
                        }
                        Ok(None) => {}
                        Err(error) => {
                            return Err(format!(
                                "inspect outer {index}: {error}; {}",
                                self.evidence()
                            ));
                        }
                    }
                }
                if let (Some(first), Some(second)) = (&self.statuses[0], &self.statuses[1]) {
                    return Ok([*first, *second]);
                }
                if self.children.iter().all(Option::is_none) {
                    return Err(format!("outer child was missing; {}", self.evidence()));
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timed out reaping outer children; {}",
                        self.evidence()
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn finish(&mut self) -> Result<[std::process::ExitStatus; 2], String> {
            if let Some(result) = &self.result {
                return result.clone();
            }
            let mut errors = Vec::new();
            if let Err(error) = fs::write(self.gate.join("winner-release"), b"release\n") {
                errors.push(format!("write winner release: {error}"));
            }
            if let Err(error) = self.release_home() {
                errors.push(error);
            }
            let result = match self.reap() {
                Ok(statuses) if errors.is_empty() => Ok(statuses),
                Ok(_) => Err(errors.join("; ")),
                Err(error) => {
                    errors.push(error);
                    Err(errors.join("; "))
                }
            };
            self.result = Some(result.clone());
            result
        }
    }

    let shared_home = home(&sandbox, "shared-home");
    let wrapper = sandbox.path("lease-wrapper");
    let gate = sandbox.path("lease-gate");
    fs::create_dir(&wrapper).expect("lease wrapper");
    fs::create_dir(&gate).expect("lease gate");
    let script = wrapper.join("git");
    fs::write(
        &script,
        "#!/bin/sh\nid=$PPID\ncount=\"$VWS_TEST_GATE/$id.count\"\nn=$(cat \"$count\" 2>/dev/null || echo 0)\nn=$((n + 1))\nprintf '%s\\n' \"$n\" > \"$count\"\nif [ \"$n\" -eq 2 ]; then\n  : > \"$VWS_TEST_GATE/entered.$id\"\n  /usr/bin/git \"$@\"\n  status=$?\n  : > \"$VWS_TEST_GATE/ready.$id\"\n  exit \"$status\"\nfi\nif [ \"$n\" -eq 3 ]; then\n  printf '%s\\n' \"$id\" >> \"$VWS_TEST_GATE/third-events\"\n  while [ ! -f \"$VWS_TEST_GATE/winner-release\" ]; do sleep 0.01; done\nfi\nexec /usr/bin/git \"$@\"\n",
    )
    .expect("lease wrapper script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("lease wrapper mode");
    let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
    let home_lease = File::open(&shared_home).expect("open HOME lease");
    assert_eq!(
        unsafe { libc::flock(home_lease.as_raw_fd(), libc::LOCK_EX) },
        0
    );
    let mut first = init_command(&shared_home, &authority);
    first.env("PATH", &path).env("VWS_TEST_GATE", &gate);
    let mut second = init_command(&shared_home, &authority);
    second.env("PATH", &path).env("VWS_TEST_GATE", &gate);
    let mut owner = match ConcurrentInitOwner::spawn(first, second, home_lease, gate.clone()) {
        Ok(owner) => owner,
        Err(error) => {
            sandbox.root.take();
            panic!("spawn concurrent init: {error}");
        }
    };
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner
            .wait_markers("entered.", 2, "two second-probe entered markers")
            .expect("wait for entered markers");
        owner
            .wait_markers("ready.", 2, "two second-probe ready markers")
            .expect("wait for ready markers");
        owner
            .release_home()
            .expect("release HOME lease after second probes");
        owner
            .wait_third(1, "winner third probe")
            .expect("wait for winner third probe");
        owner
            .hold_winner()
            .expect("only the lease holder may reach the third probe");
    }));
    let statuses = match (observed, owner.finish()) {
        (Ok(()), Ok(statuses)) => statuses,
        (Ok(()), Err(error)) => {
            sandbox.root.take();
            panic!(
                "concurrent init cleanup/reap failed: {error}; {}",
                owner.evidence()
            );
        }
        (Err(panic), Ok(_)) => {
            sandbox.root.take();
            std::panic::resume_unwind(panic);
        }
        (Err(panic), Err(error)) => {
            let primary = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            sandbox.root.take();
            panic!(
                "concurrent init assertion panic: {primary}; cleanup/reap failed: {error}; {}",
                owner.evidence()
            );
        }
    };
    let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(owner.markers("entered.").expect("entered markers").len(), 2);
        let ready = owner.markers("ready.").expect("ready markers");
        assert_eq!(ready.len(), 2);
        assert_eq!(statuses.iter().filter(|status| status.success()).count(), 1);
        let loser = statuses
            .iter()
            .position(|status| !status.success())
            .expect("one loser");
        assert!(
            fs::read_to_string(&owner.stderr[loser])
                .expect("loser stderr")
                .contains("AUTHORITY_DUPLICATE"),
            "unexpected concurrent init loser: {statuses:?}"
        );
        let mut probe_counts: Vec<usize> = ready
            .iter()
            .map(|name| {
                let id = name.strip_prefix("ready.").expect("ready marker id");
                fs::read_to_string(gate.join(format!("{id}.count")))
                    .expect("probe count")
                    .trim()
                    .parse()
                    .expect("numeric probe count")
            })
            .collect();
        probe_counts.sort();
        assert_eq!(probe_counts, [3, 4]);
        assert_eq!(
            fs::read_to_string(gate.join("third-events"))
                .expect("third events")
                .lines()
                .count(),
            2
        );
        assert!(owner.children.iter().all(Option::is_none));
        let home_fd = File::open(&shared_home).expect("open HOME for binding");
        let root_name = CString::new(".git-vws").expect("state root name");
        let root = open_dir(home_fd.as_raw_fd(), &root_name).expect("state root");
        assert_eq!(
            fstat(&root).expect("root identity"),
            stat_at(home_fd.as_raw_fd(), &root_name).expect("root entry")
        );
        let entries = names(root.as_raw_fd()).expect("state entries");
        assert_eq!(entries.len(), 1);
        assert!(entries
            .iter()
            .all(|name| !name.starts_with(b".") && !name.ends_with(b".lock")));
    }));
    if let Err(panic) = verified {
        sandbox.root.take();
        std::panic::resume_unwind(panic);
    }
    if let Err(error) = sandbox.cleanup() {
        sandbox.root.take();
        panic!("cleanup concurrent init sandbox: {error}");
    }
}

#[test]
fn armed_root_cleanup_handles_probe_failure_and_binding_drift() {
    let mut sandbox = Sandbox::new();
    let authority = bare(&sandbox, "authority.git");
    let wrapper = sandbox.path("wrapper");
    fs::create_dir(&wrapper).expect("wrapper dir");
    let script = wrapper.join("git");
    fs::write(
        &script,
        "#!/bin/sh\nn=$(cat \"$VWS_TEST_COUNTER\" 2>/dev/null || echo 0)\nn=$((n + 1))\nprintf '%s\\n' \"$n\" > \"$VWS_TEST_COUNTER\"\nif [ \"$VWS_TEST_MODE\" = first ] && [ \"$n\" -eq 3 ]; then\n  mv \"$VWS_TEST_AUTHORITY/objects\" \"$VWS_TEST_MOVED_OBJECTS\"\nfi\nif [ \"$VWS_TEST_MODE\" = binding ] && [ \"$n\" -eq 3 ]; then\n  mv \"$HOME/.git-vws\" \"$VWS_TEST_MOVED_ROOT\"\n  mkdir \"$HOME/.git-vws\"\n  chmod 700 \"$HOME/.git-vws\"\n  printf 'replacement\\n' > \"$HOME/.git-vws/sentinel\"\nfi\nif [ \"$VWS_TEST_MODE\" = final ] && [ \"$n\" -eq 4 ]; then\n  /usr/bin/git \"$@\"\n  status=$?\n  for candidate in \"$HOME/.git-vws\"/.*.tmp; do\n    if [ -f \"$candidate\" ]; then printf 'seen\\n' > \"$VWS_TEST_TEMP_SEEN\"; break; fi\n  done\n  [ -f \"$VWS_TEST_TEMP_SEEN\" ] || exit 97\n  mv \"$VWS_TEST_AUTHORITY/objects\" \"$VWS_TEST_MOVED_OBJECTS\"\n  exit \"$status\"\nfi\nexec /usr/bin/git \"$@\"\n",
    )
    .expect("wrapper script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("wrapper mode");
    let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
    for (mode, home_name) in [("first", "first-home"), ("final", "final-home")] {
        let home = home(&sandbox, home_name);
        let counter = sandbox.path(&format!("{mode}-probe-count"));
        let moved_objects = sandbox.path(&format!("{mode}-moved-objects"));
        let temporary_seen = sandbox.path(&format!("{mode}-temporary-seen"));
        let output = init_command(&home, &authority)
            .env("PATH", &path)
            .env("VWS_TEST_MODE", mode)
            .env("VWS_TEST_COUNTER", &counter)
            .env("VWS_TEST_AUTHORITY", &authority)
            .env("VWS_TEST_MOVED_OBJECTS", &moved_objects)
            .env("VWS_TEST_TEMP_SEEN", &temporary_seen)
            .output()
            .expect("run probe failure init");
        let expected_error = if mode == "first" {
            "GIT_PROBE_FAILED"
        } else {
            "AUTHORITY_INVALID"
        };
        assert_probe_failure(&output, &home, expected_error, mode);
        if mode == "final" {
            assert_eq!(fs::read(&counter).expect("fourth probe count"), b"4\n");
            assert_eq!(
                fs::read(&temporary_seen).expect("temporary marker"),
                b"seen\n"
            );
        } else {
            assert_eq!(fs::read(&counter).expect("third probe count"), b"3\n");
        }
        fs::rename(&moved_objects, authority.join("objects")).expect("restore objects");
    }

    let binding_home = home(&sandbox, "binding-home");
    let binding_counter = sandbox.path("binding-probe-count");
    let moved_root = sandbox.path("binding-moved-root");
    let output = init_command(&binding_home, &authority)
        .env("PATH", &path)
        .env("VWS_TEST_MODE", "binding")
        .env("VWS_TEST_COUNTER", &binding_counter)
        .env("VWS_TEST_AUTHORITY", &authority)
        .env("VWS_TEST_MOVED_ROOT", &moved_root)
        .output()
        .expect("run binding drift init");
    assert!(
        !output.status.success(),
        "unexpected binding success: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("STATE_COMMITTED_RECOVERY_REQUIRED"),
        "unexpected binding error: {output:?}"
    );
    assert_eq!(
        fs::read(binding_home.join(".git-vws/sentinel")).expect("replacement sentinel"),
        b"replacement\n"
    );
    assert!(
        moved_root.is_dir(),
        "armed root was not retained after binding drift"
    );
    assert!(
        fs::read_dir(&moved_root)
            .expect("moved root entries")
            .next()
            .is_some(),
        "known committed root was unexpectedly removed"
    );
    assert_eq!(
        fs::read(&binding_counter).expect("binding probe count"),
        b"4\n"
    );
    sandbox.cleanup().expect("cleanup");
}

#[test]
fn descriptor_cleanup_rejects_root_swap_and_never_follows_symlinks() {
    let cwd = env::current_dir().expect("cwd");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_cargo = fs::read(manifest.join("Cargo.toml")).expect("manifest sentinel");
    let mut sandbox = Sandbox::new();
    let rebuild_name = CString::new(format!(
        "{}-rebuild-stage-sentinel",
        sandbox.name.to_string_lossy()
    ))
    .expect("rebuild sentinel name");
    let rebuild = sandbox
        .parent_path
        .join(rebuild_name.to_string_lossy().as_ref());
    fs::create_dir(&rebuild).expect("rebuild sentinel dir");
    fs::write(rebuild.join("sentinel"), b"rebuild-safe").expect("rebuild sentinel");
    let sibling_name = CString::new(format!(
        "{}-sibling-disposer-sentinel",
        sandbox.name.to_string_lossy()
    ))
    .expect("sibling sentinel name");
    let sibling = sandbox
        .parent_path
        .join(sibling_name.to_string_lossy().as_ref());
    fs::create_dir(&sibling).expect("sibling sentinel dir");
    fs::write(sibling.join("sentinel"), b"sibling-safe").expect("sibling sentinel");
    let external_name = CString::new(format!("{}-external", sandbox.name.to_string_lossy()))
        .expect("external name");
    let external = sandbox
        .parent_path
        .join(external_name.to_string_lossy().as_ref());
    fs::create_dir(&external).expect("external");
    fs::write(external.join("sentinel"), b"safe").expect("sentinel");
    fs::create_dir(sandbox.path("nested")).expect("nested");
    symlink(&external, sandbox.path("nested/link")).expect("nested symlink");
    sandbox.cleanup().expect("cleanup nested symlink");
    assert_eq!(
        fs::read(external.join("sentinel")).expect("sentinel after cleanup"),
        b"safe"
    );
    sandbox
        .cleanup_named(&external_name)
        .expect("cleanup external by descriptor");

    let mut swapped = Sandbox::new();
    let moved = swapped
        .parent_path
        .join(format!("{}-moved", swapped.name.to_string_lossy()));
    fs::rename(&swapped.root_path, &moved).expect("move root");
    fs::create_dir(&swapped.root_path).expect("replacement root");
    fs::write(swapped.root_path.join("sentinel"), b"replacement").expect("replacement sentinel");
    assert!(swapped.cleanup().is_err());
    assert_eq!(
        fs::read(swapped.root_path.join("sentinel")).expect("replacement survives"),
        b"replacement"
    );
    swapped
        .cleanup_named(&swapped.name)
        .expect("cleanup replacement by descriptor");
    fs::rename(&moved, &swapped.root_path).expect("restore original root");
    swapped.cleanup().expect("cleanup restored root");
    assert_eq!(env::current_dir().expect("cwd after cleanup"), cwd);
    assert_eq!(
        fs::read(manifest.join("Cargo.toml")).expect("manifest after cleanup"),
        manifest_cargo
    );
    assert_eq!(
        fs::read(rebuild.join("sentinel")).expect("rebuild sentinel after cleanup"),
        b"rebuild-safe"
    );
    assert_eq!(
        fs::read(sibling.join("sentinel")).expect("sibling sentinel after cleanup"),
        b"sibling-safe"
    );
    sandbox
        .cleanup_named(&rebuild_name)
        .expect("cleanup rebuild sentinel");
    sandbox
        .cleanup_named(&sibling_name)
        .expect("cleanup sibling sentinel");
}

#[test]
fn nonregular_and_hardlinked_records_fail_closed_without_blocking() {
    let mut sandbox = Sandbox::new();
    let authority = bare(&sandbox, "authority.git");

    let fifo_home = home(&sandbox, "fifo-home");
    let fifo_root = fifo_home.join(".git-vws");
    fs::create_dir(&fifo_root).expect("fifo state root");
    fs::set_permissions(&fifo_root, fs::Permissions::from_mode(0o700)).expect("fifo root mode");
    let root = File::open(&fifo_root).expect("open fifo root");
    let fifo_name = CString::new("stalled.record").expect("fifo name");
    assert_eq!(
        unsafe { libc::mkfifoat(root.as_raw_fd(), fifo_name.as_ptr(), 0o600) },
        0,
        "mkfifoat: {}",
        io::Error::last_os_error()
    );
    drop(root);
    assert_rejected(&fifo_home, &authority);

    let hard_home = home(&sandbox, "hardlink-home");
    let hard_root = hard_home.join(".git-vws");
    fs::create_dir(&hard_root).expect("hardlink state root");
    fs::set_permissions(&hard_root, fs::Permissions::from_mode(0o700)).expect("hardlink root mode");
    fs::write(hard_root.join("one.record"), b"broken\n").expect("record");
    fs::set_permissions(
        hard_root.join("one.record"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("protect hardlink record");
    fs::hard_link(hard_root.join("one.record"), hard_root.join("two.record"))
        .expect("hardlink record");
    assert_rejected(&hard_home, &authority);
    sandbox.cleanup().expect("cleanup nonregular records");
}

#[test]
fn escaped_git_probe_writer_is_bounded_and_leaves_no_state() {
    struct PanicWindow;

    for panic_window in [false, true] {
        let mut sandbox = Sandbox::new();
        let home = home(&sandbox, "home");
        let authority = bare(&sandbox, "authority.git");
        let wrapper = sandbox.path("output-wrapper");
        fs::create_dir(&wrapper).expect("wrapper directory");
        let escaped = sandbox.path("escaped-writer");
        let escaped_ready = sandbox.path("escaped-writer.ready");
        let escaped_release = sandbox.path("escaped-writer.release");
        let escaped_pid = sandbox.path("escaped-writer.pid");
        let direct_pid = sandbox.path("direct-probe.pid");
        let unrelated_marker = sandbox.path("unrelated.marker");
        let script = wrapper.join("git");
        fs::write(
            &script,
            "#!/usr/bin/perl\nuse POSIX qw(setsid);\nopen my $direct, q(>), $ENV{VWS_TEST_DIRECT_PID} or die; print $direct $$; close $direct;\nmy $child = fork(); defined $child or die;\nif (!$child) { setsid() or die; open my $ready, q(>), $ENV{VWS_TEST_ESCAPED_READY} or die; print $ready qq(ready\\n); close $ready; while (!-f $ENV{VWS_TEST_ESCAPED_RELEASE}) { select undef, undef, undef, 0.001 } open my $pid, q(>), $ENV{VWS_TEST_ESCAPED_PID} or die; print $pid $$; close $pid; open my $marker, q(>), $ENV{VWS_TEST_ESCAPED} or die; print $marker qq(escaped\\n); close $marker; $SIG{PIPE}=q(IGNORE); while (1) { print q(x); select undef, undef, undef, 0.001 } }\nwhile (!-f $ENV{VWS_TEST_ESCAPED_READY}) { select undef, undef, undef, 0.001 }\nexit 0;\n",
        )
        .expect("output wrapper");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("wrapper mode");
        let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
        let unrelated = Command::new("/usr/bin/perl")
            .args([
                "-MPOSIX=setsid",
                "-e",
                "setsid() or die; open my $marker, q(>), $ENV{VWS_TEST_UNRELATED_MARKER} or die; print $marker qq(alive\\n); close $marker; sleep 10",
            ])
            .env("VWS_TEST_UNRELATED_MARKER", &unrelated_marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn unrelated sentinel");
        let mut cleanup = ProbeProcessCleanup {
            escaped_ready: Some(escaped_ready.clone()),
            escaped_release: Some(escaped_release.clone()),
            escaped_pid: Some(escaped_pid.clone()),
            unrelated: Some(unrelated),
        };
        wait_until(Duration::from_secs(2), "unrelated sentinel", || {
            unrelated_marker.is_file()
        });
        let before_home = snapshot(&home);
        let before_authority = snapshot(&authority);
        let mut command = init_command(&home, &authority);
        command
            .env("PATH", path)
            .env("VWS_TEST_ESCAPED", &escaped)
            .env("VWS_TEST_ESCAPED_READY", &escaped_ready)
            .env("VWS_TEST_ESCAPED_RELEASE", &escaped_release)
            .env("VWS_TEST_ESCAPED_PID", &escaped_pid)
            .env("VWS_TEST_DIRECT_PID", &direct_pid);
        let probe = thread::spawn(move || command.output());
        let ready = wait_for(Duration::from_secs(10), || escaped_ready.is_file());
        let started = Instant::now();
        let output = probe
            .join()
            .expect("join oversized probe")
            .expect("run oversized probe");
        ready.expect("escaped writer ready marker");
        let assertions = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_secs(2),
                "escaped writer kept the probe open for {elapsed:?} (panic_window={panic_window})"
            );
            assert!(!output.status.success(), "unexpected success: {output:?}");
            assert!(String::from_utf8_lossy(&output.stderr).contains("GIT_PROBE_FAILED"));
            let direct = fs::read_to_string(&direct_pid)
                .expect("direct child marker")
                .trim()
                .parse::<u32>()
                .expect("direct child pid");
            assert!(!process_alive(direct), "direct child was not reaped");
            if panic_window {
                wait_for(Duration::from_secs(2), || escaped_ready.is_file())
                    .expect("escaped writer ready marker");
                assert_eq!(
                    fs::read(&escaped_ready).expect("escaped writer ready"),
                    b"ready\n"
                );
                assert!(!escaped_release.exists(), "release existed before panic");
                assert!(!escaped_pid.exists(), "PID existed before panic");
                assert!(!escaped.exists(), "escaped marker existed before panic");
                std::panic::panic_any(PanicWindow);
            }
            cleanup.release_only().expect("release escaped writer");
            wait_for(Duration::from_secs(2), || {
                escaped_pid.is_file() && escaped.is_file()
            })
            .expect("escaped writer post-release markers");
            assert_eq!(
                fs::read(&escaped).expect("escaped writer marker"),
                b"escaped\n"
            );
            let escaped = fs::read_to_string(&escaped_pid)
                .expect("escaped writer pid")
                .parse::<u32>()
                .expect("escaped writer pid number");
            assert!(
                process_alive(escaped),
                "escaped descendant was killed through a stale process group"
            );
            assert!(
                process_alive(cleanup.unrelated.as_ref().expect("unrelated sentinel").id()),
                "unrelated sentinel was killed"
            );
            assert_eq!(snapshot(&home), before_home);
            assert_eq!(snapshot(&authority), before_authority);
        }));
        let process_cleanup = cleanup.finish();
        let postconditions = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(escaped_release.is_file(), "release missing after cleanup");
            let pid = fs::read_to_string(&escaped_pid)
                .expect("escaped writer PID after cleanup")
                .trim()
                .parse::<i32>()
                .expect("escaped writer PID number after cleanup");
            assert!(pid > 0, "escaped writer PID was not positive");
            assert!(!process_alive(pid as u32), "escaped writer remained alive");
            assert_eq!(
                fs::read(&escaped).expect("escaped writer marker after cleanup"),
                b"escaped\n"
            );
            assert!(
                cleanup.unrelated.is_none(),
                "unrelated sentinel was not reaped"
            );
            assert_eq!(snapshot(&home), before_home);
            assert_eq!(snapshot(&authority), before_authority);
        }));
        let sandbox_path = sandbox.root_path.clone();
        let sandbox_cleanup = sandbox.cleanup().and_then(|()| {
            if sandbox_path.exists() {
                Err(io::Error::other("sandbox path remained after cleanup"))
            } else {
                Ok(())
            }
        });
        let cleanup_result = merge_cleanup(process_cleanup, sandbox_cleanup);
        let expected_panic = match assertions {
            Ok(()) => false,
            Err(panic) if panic_window && panic.downcast_ref::<PanicWindow>().is_some() => true,
            Err(panic) => {
                if let Err(error) = cleanup_result {
                    eprintln!("probe cleanup failed after assertion panic: {error}");
                }
                if postconditions.is_err() {
                    eprintln!("probe postconditions failed after assertion panic");
                }
                std::panic::resume_unwind(panic);
            }
        };
        if panic_window && !expected_panic {
            if let Err(panic) = postconditions {
                std::panic::resume_unwind(panic);
            }
            cleanup_result.expect("cleanup escaped writer");
            panic!("panic window did not panic");
        }
        if let Err(panic) = postconditions {
            std::panic::resume_unwind(panic);
        }
        cleanup_result.expect("cleanup escaped writer");
    }
}

#[test]
fn output_limit_terminates_and_reaps_direct_probe_without_state() {
    let mut sandbox = Sandbox::new();
    let home = home(&sandbox, "home");
    let authority = bare(&sandbox, "authority.git");
    let wrapper = sandbox.path("output-limit-wrapper");
    let direct_pid = sandbox.path("output-limit-direct.pid");
    let release = sandbox.path("output-limit.release");
    fs::create_dir(&wrapper).expect("wrapper directory");
    let script = wrapper.join("git");
    fs::write(
        &script,
        "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$VWS_TEST_DIRECT_PID\"\nwhile [ ! -f \"$VWS_TEST_RELEASE\" ]; do /bin/sleep 0.01; done\n/usr/bin/yes xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx | /usr/bin/head -c 65536\nexec /bin/sleep 30\n",
    )
    .expect("output limit wrapper");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("wrapper mode");
    let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
    let worker_home = home.clone();
    let worker_authority = authority.clone();
    let worker_direct_pid = direct_pid.clone();
    let worker_release = release.clone();
    let worker = thread::spawn(move || {
        init_command(&worker_home, &worker_authority)
            .env("PATH", path)
            .env("VWS_TEST_DIRECT_PID", worker_direct_pid)
            .env("VWS_TEST_RELEASE", worker_release)
            .output()
    });
    let marker = wait_for(Duration::from_secs(2), || direct_pid.is_file());
    let started = Instant::now();
    fs::write(&release, b"release\n").expect("release output limit probe");
    let output = worker
        .join()
        .expect("join output limit probe")
        .expect("run output limit probe");
    marker.expect("output limit direct marker deadline");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "output limit was unbounded"
    );
    assert!(
        !output.status.success(),
        "unexpected output limit success: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("GIT_PROBE_FAILED"),
        "unexpected output limit error: {output:?}"
    );
    let direct = fs::read_to_string(&direct_pid)
        .expect("output limit direct marker")
        .trim()
        .parse::<u32>()
        .expect("output limit direct pid");
    assert!(!process_alive(direct), "output-limit child was not reaped");
    assert!(!home.join(".git-vws").exists());
    sandbox.cleanup().expect("cleanup output limit probe");
}

#[test]
fn malformed_git_probe_and_deadline_are_zero_write() {
    let mut sandbox = Sandbox::new();
    let authority = bare(&sandbox, "authority.git");
    let wrapper = sandbox.path("probe-wrapper");
    fs::create_dir(&wrapper).expect("wrapper directory");
    let script = wrapper.join("git");
    fs::write(
        &script,
        "#!/bin/sh\nvalid() { printf 'true\\n%s\\n%s\\nsha1\\nfiles\\n' \"$VWS_TEST_AUTHORITY\" \"$VWS_TEST_AUTHORITY\"; }\ncase \"$VWS_TEST_MODE\" in\nformat) printf 'true\\n%s\\n%s\\nsha3\\nfiles\\n' \"$VWS_TEST_AUTHORITY\" \"$VWS_TEST_AUTHORITY\" ;;\nmissing) printf 'true\\n%s\\n' \"$VWS_TEST_AUTHORITY\" ;;\nambiguous) valid; printf 'extra\\n' ;;\nstderr) valid; printf 'noise\\n' >&2 ;;\nsleep) printf '%s\\n' \"$$\" > \"$VWS_TEST_DIRECT_PID\"; sleep 10 ;;\nignored) : > \"$VWS_TEST_DIRECT_PID\"; valid ;;\nesac\n",
    )
    .expect("probe wrapper");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("wrapper mode");
    let path = format!("{}:{}", wrapper.display(), env::var("PATH").expect("PATH"));
    for mode in [
        "format",
        "missing",
        "ambiguous",
        "stderr",
        "sleep",
        "ignored",
    ] {
        let home = home(&sandbox, &format!("{mode}-home"));
        let direct_pid = sandbox.path(&format!("{mode}-direct.pid"));
        let before = [snapshot(&home), snapshot(&authority)];
        let mut command = init_command(&home, &authority);
        command
            .env("PATH", &path)
            .env("VWS_TEST_AUTHORITY", &authority)
            .env("VWS_TEST_MODE", mode)
            .env("VWS_TEST_DIRECT_PID", &direct_pid);
        if mode == "ignored" {
            unsafe {
                command.pre_exec(|| {
                    if libc::signal(libc::SIGCHLD, libc::SIG_IGN) == libc::SIG_ERR {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let output = command.output().expect("run malformed probe");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let expected = match mode {
            "format" => "FORMAT_UNSUPPORTED",
            "ignored" => "GIT_PROBE_CLEANUP_FAILED",
            _ => "GIT_PROBE_FAILED",
        };
        assert!(
            !output.status.success()
                && stderr.contains(expected)
                && (mode != "ignored" || !direct_pid.exists()),
            "unexpected {mode} probe result: {output:?}"
        );
        let after = [snapshot(&home), snapshot(&authority)];
        assert_eq!(after, before, "{mode} changed state");
        if mode == "sleep" {
            let direct = fs::read_to_string(&direct_pid)
                .expect("deadline direct marker")
                .trim()
                .parse::<u32>()
                .expect("deadline direct pid");
            assert!(!process_alive(direct), "deadline child was not reaped");
        }
    }
    sandbox.cleanup().expect("cleanup malformed probes");
}

#[test]
fn final_collision_accepts_only_an_exact_existing_record() {
    let mut sandbox = Sandbox::new();
    let authority = bare(&sandbox, "authority.git");
    let source_home = home(&sandbox, "source-home");
    assert!(init(&source_home, &authority).status.success());
    let exact_contents = fs::read(only_record(&source_home)).expect("exact record contents");

    let noncanonical_contents = String::from_utf8(exact_contents.clone())
        .expect("record utf8")
        .replacen("\ndev=", "\ndev=0", 1)
        .into_bytes();
    let foreign_authority = bare(&sandbox, "foreign-authority.git");
    let foreign_source_home = home(&sandbox, "foreign-source-home");
    assert!(init(&foreign_source_home, &foreign_authority)
        .status
        .success());
    let foreign_contents =
        fs::read(only_record(&foreign_source_home)).expect("foreign record contents");
    for (label, contents, code) in [
        ("exact", &exact_contents, "AUTHORITY_DUPLICATE"),
        ("noncanonical", &noncanonical_contents, "STATE_CORRUPT"),
        ("foreign", &foreign_contents, "STATE_CORRUPT"),
    ] {
        let home = home(&sandbox, &format!("{label}-collision-home"));
        let (output, root, record, path) =
            inject_final_collision(&sandbox, &home, &authority, label, contents);
        assert_collision_error(&output, code, label);
        assert_preserved_collision(&home, &path, root, record, contents);
    }
    sandbox.cleanup().expect("cleanup collision classification");
}
