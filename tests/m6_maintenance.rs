#[path = "support/checkpoint.rs"]
mod checkpoint;

use checkpoint::{ArmReply, CheckpointController, CheckpointTarget, ControlRun};
use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_SANDBOX: AtomicUsize = AtomicUsize::new(0);

const TYPE_MASK: libc::mode_t = libc::S_IFMT;
const DIRECTORY_TYPE: libc::mode_t = libc::S_IFDIR;
const REGULAR_TYPE: libc::mode_t = libc::S_IFREG;
const SYMLINK_TYPE: libc::mode_t = libc::S_IFLNK;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Node {
    dev: libc::dev_t,
    ino: u64,
    uid: u32,
    mode: libc::mode_t,
    kind: libc::mode_t,
}

impl Node {
    fn from_stat(stat: &libc::stat) -> Self {
        let mode = stat.st_mode;
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            mode: mode & 0o7777,
            kind: mode & TYPE_MASK,
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
        let parent_path = fs::canonicalize(env::temp_dir()).expect("canonical M6 test parent");
        let parent = File::open(&parent_path).expect("open M6 test parent");
        let name = CString::new(format!(
            "git-vws-m6-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("M6 sandbox basename");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) },
            0,
            "create descriptor-owned M6 sandbox"
        );
        let root = open_directory(parent.as_raw_fd(), &name).expect("open M6 sandbox");
        assert_eq!(unsafe { libc::fchmod(root.as_raw_fd(), 0o700) }, 0);
        let node = node(&root).expect("stat M6 sandbox");
        let path = parent_path.join(name.to_string_lossy().as_ref());
        Self {
            parent,
            name,
            root: Some(root),
            path,
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
        if self.root.is_none() {
            return;
        }
        if thread::panicking() {
            eprintln!(
                "M6 retained descriptor-owned evidence: {}",
                self.path.display()
            );
            return;
        }
        self.cleanup().expect("descriptor-owned M6 sandbox cleanup");
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

fn directory_names(fd: RawFd) -> io::Result<Vec<Vec<u8>>> {
    let raw = unsafe {
        libc::openat(
            fd,
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { libc::fdopendir(raw) };
    if directory.is_null() {
        unsafe { libc::close(raw) };
        return Err(io::Error::last_os_error());
    }
    let mut names = Vec::new();
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
            names.push(name.to_vec());
        }
    }
    if unsafe { libc::closedir(directory) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(names)
}

fn clear_owned(parent: RawFd, device: libc::dev_t) -> io::Result<()> {
    for bytes in directory_names(parent)? {
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

struct Fixture {
    sandbox: Sandbox,
    home: PathBuf,
    authority: PathBuf,
    source: PathBuf,
    cwd: PathBuf,
    sibling: PathBuf,
}

impl Fixture {
    fn new(initialize: bool) -> Self {
        let sandbox = Sandbox::new();
        let (authority, source) = fixture_repo(&sandbox);
        let home = sandbox.child("home");
        fs::create_dir(&home).expect("create isolated M6 home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect M6 home");
        let cwd = sandbox.child("cwd");
        fs::create_dir(&cwd).expect("create M6 cwd");
        fs::write(cwd.join("cwd-sentinel"), b"M6 protected cwd\n").expect("write M6 cwd sentinel");
        let sibling = sandbox.child("sibling-sentinel");
        fs::write(&sibling, b"M6 protected sibling\n").expect("write M6 sibling sentinel");
        let fixture = Self {
            sandbox,
            home,
            authority,
            source,
            cwd,
            sibling,
        };
        if initialize {
            assert_success(
                &fixture.vws(vec![
                    OsString::from("init"),
                    fixture.authority.as_os_str().to_os_string(),
                ]),
                "initialize M6 authority",
            );
        }
        fixture
    }

    fn state(&self) -> PathBuf {
        self.home.join(".git-vws")
    }

    fn sessions(&self) -> PathBuf {
        self.state().join("sessions")
    }

    fn templates(&self) -> PathBuf {
        self.state().join("templates")
    }

    fn command_for(&self, binary: &Path, args: Vec<OsString>) -> Command {
        let mut command = Command::new(binary);
        remove_git_environment(&mut command);
        command
            .args(args)
            .env("HOME", &self.home)
            .current_dir(&self.cwd);
        command
    }

    fn vws(&self, args: Vec<OsString>) -> Output {
        self.command_for(Path::new(env!("CARGO_BIN_EXE_git-vws")), args)
            .output()
            .expect("run M6 git-vws")
    }

    fn repo_args(&self, command: Vec<OsString>) -> Vec<OsString> {
        self.repo_args_for(&self.authority, command)
    }

    fn repo_args_for(&self, authority: &Path, mut command: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--repo"),
            authority.as_os_str().to_os_string(),
        ];
        args.append(&mut command);
        args
    }

    fn create_args(&self, name: OsString, target: &str) -> Vec<OsString> {
        self.repo_args(vec![
            OsString::from("create"),
            name,
            OsString::from("--target"),
            OsString::from(target),
        ])
    }

    fn create(&self, name: &str, target: &str) -> Output {
        self.vws(self.create_args(OsString::from(name), target))
    }

    fn create_for(&self, authority: &Path, name: &str, target: &str) -> Output {
        self.vws(self.repo_args_for(
            authority,
            vec![
                OsString::from("create"),
                OsString::from(name),
                OsString::from("--target"),
                OsString::from(target),
            ],
        ))
    }

    fn remove_args(&self, name: &str, force: bool) -> Vec<OsString> {
        let mut args = vec![OsString::from("remove"), OsString::from(name)];
        if force {
            args.push(OsString::from("--force"));
        }
        self.repo_args(args)
    }

    fn remove(&self, name: &str, force: bool) -> Output {
        self.vws(self.remove_args(name, force))
    }

    fn publish_args(&self, name: &str) -> Vec<OsString> {
        self.repo_args(vec![OsString::from("publish"), OsString::from(name)])
    }

    fn exec_args(&self, name: &str, program: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("exec"),
            OsString::from(name),
            OsString::from("--"),
        ];
        args.extend(program);
        self.repo_args(args)
    }

    fn gc(&self) -> Output {
        self.vws(vec![OsString::from("gc")])
    }

    fn doctor(&self) -> Output {
        self.vws(vec![OsString::from("doctor")])
    }

    fn list(&self, authority: &Path) -> Output {
        self.vws(self.repo_args_for(authority, vec![OsString::from("list")]))
    }

    fn records(&self) -> Vec<PathBuf> {
        let mut records: Vec<_> = fs::read_dir(self.sessions())
            .expect("read M6 sessions")
            .map(|entry| entry.expect("read M6 session entry").path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|entry| entry.as_bytes().ends_with(b".record"))
            })
            .collect();
        records.sort_by(|left, right| {
            left.as_os_str()
                .as_bytes()
                .cmp(right.as_os_str().as_bytes())
        });
        records
    }

    fn record_count(&self) -> usize {
        if self.sessions().is_dir() {
            self.records().len()
        } else {
            0
        }
    }

    fn record_path(&self, name: &[u8]) -> PathBuf {
        let expected = hex(name);
        let mut records: Vec<_> = fs::read_dir(self.sessions())
            .expect("read M6 sessions")
            .map(|entry| entry.expect("read M6 session entry").path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|entry| entry.as_bytes().ends_with(b".record"))
            })
            .collect();
        records.sort_by(|left, right| {
            left.as_os_str()
                .as_bytes()
                .cmp(right.as_os_str().as_bytes())
        });
        records
            .into_iter()
            .find(|path| {
                serde_json::from_slice::<Value>(&fs::read(path).expect("read M6 record"))
                    .ok()
                    .and_then(|record| {
                        record
                            .get("name")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(expected.as_str())
            })
            .unwrap_or_else(|| panic!("missing M6 record for {}", String::from_utf8_lossy(name)))
    }

    fn record(&self, name: &[u8]) -> Value {
        serde_json::from_slice(&fs::read(self.record_path(name)).expect("read M6 record"))
            .expect("parse M6 record")
    }

    fn root(&self, name: &[u8]) -> PathBuf {
        let record = self.record(name);
        let root_name = record
            .pointer("/payload/READY/root_name")
            .or_else(|| record.pointer("/payload/MATERIALIZING/root_name"))
            .or_else(|| record.pointer("/payload/TOMBSTONED/root_name"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("M6 record has no managed root"));
        self.sessions().join(root_name)
    }

    fn worktree(&self, name: &[u8]) -> PathBuf {
        self.root(name).join("worktree")
    }

    fn common(&self, name: &[u8]) -> PathBuf {
        self.root(name).join("common.git")
    }

    fn template_key(&self, name: &[u8]) -> String {
        self.record(name)
            .get("template_key")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("M6 record omitted template key"))
            .to_owned()
    }

    fn template_record(&self, key: &str) -> PathBuf {
        self.templates().join(format!("template-{key}.record"))
    }

    fn cleanup(&mut self) {
        self.sandbox.cleanup().expect("cleanup M6 fixture");
    }
}

fn fixture_repo(sandbox: &Sandbox) -> (PathBuf, PathBuf) {
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
    git(&source, &git_args(&["config", "user.name", "M6 Test"]));
    git(
        &source,
        &git_args(&["config", "user.email", "m6@example.invalid"]),
    );
    fs::write(source.join("history"), b"base\n").expect("write M6 history");
    fs::write(source.join(".gitignore"), b"ignored/\n").expect("write M6 ignore");
    git(&source, &git_args(&["add", "-A"]));
    git(&source, &git_args(&["commit", "-m", "M6 base"]));
    git(&source, &git_args(&["branch", "-M", "main"]));
    git(
        &source,
        &[
            OsString::from("remote"),
            OsString::from("add"),
            OsString::from("origin"),
            bare.as_os_str().to_os_string(),
        ],
    );
    git(&source, &git_args(&["push", "-u", "origin", "main"]));
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
    (bare, source)
}

fn find_executable(name: &str) -> PathBuf {
    env::split_paths(&env::var_os("PATH").expect("PATH"))
        .map(|directory| directory.join(name))
        .find(|candidate| {
            candidate.is_file()
                && candidate
                    .metadata()
                    .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
        })
        .and_then(|candidate| fs::canonicalize(candidate).ok())
        .unwrap_or_else(|| panic!("resolve {name} from PATH"))
}

fn real_git() -> PathBuf {
    find_executable("git")
}

fn remove_git_environment(command: &mut Command) {
    for (name, _) in env::vars_os() {
        if name.as_bytes().starts_with(b"GIT_") {
            command.env_remove(name);
        }
    }
}

fn git_command(cwd: &Path, args: &[OsString]) -> Command {
    let mut command = Command::new(real_git());
    remove_git_environment(&mut command);
    command
        .current_dir(cwd)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    command
}

fn git_output(cwd: &Path, args: &[OsString]) -> Output {
    git_command(cwd, args).output().expect("run M6 fixture Git")
}

fn git(cwd: &Path, args: &[OsString]) -> Output {
    let output = git_output(cwd, args);
    assert_success(&output, &format!("fixture Git {args:?}"));
    output
}

fn git_args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn assert_success(output: &Output, context: &str) {
    assert!(output.status.success(), "{context}: {output:?}");
}

fn assert_error(output: &Output, code: &str, context: &str) {
    assert!(
        !output.status.success() && String::from_utf8_lossy(&output.stderr).contains(code),
        "{context}: {output:?}"
    );
}

fn object_id(output: &Output, context: &str) -> String {
    assert_success(output, context);
    let body = output
        .stdout
        .strip_suffix(b"\n")
        .filter(|value| !value.contains(&b'\n'))
        .unwrap_or_else(|| panic!("{context} did not return one object ID: {output:?}"));
    let oid = std::str::from_utf8(body).expect("M6 object ID UTF-8");
    assert!(
        !oid.is_empty() && oid.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{context} returned an invalid object ID: {output:?}"
    );
    oid.to_owned()
}

fn commit_worktree(worktree: &Path, name: &str, body: &[u8]) -> String {
    git(worktree, &git_args(&["config", "user.name", "M6 Session"]));
    git(
        worktree,
        &git_args(&["config", "user.email", "m6-session@example.invalid"]),
    );
    fs::write(worktree.join(name), body).expect("write M6 worktree change");
    git(worktree, &git_args(&["add", name]));
    git(
        worktree,
        &git_args(&["-c", "commit.gpgSign=false", "commit", "-m", name]),
    );
    object_id(
        &git_output(worktree, &git_args(&["rev-parse", "HEAD"])),
        "M6 worktree HEAD",
    )
}

fn git_input(cwd: &Path, args: &[OsString], input: &[u8]) -> Output {
    let mut child = git_command(cwd, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn M6 fixture Git input command");
    child
        .stdin
        .take()
        .expect("M6 fixture Git stdin")
        .write_all(input)
        .expect("write M6 fixture Git stdin");
    child.wait_with_output().expect("reap M6 fixture Git input")
}

fn hash_object(cwd: &Path, git_dir: &Path, body: &[u8], write: bool) -> String {
    let mut args = vec![
        OsString::from("--git-dir"),
        git_dir.as_os_str().to_os_string(),
        OsString::from("hash-object"),
    ];
    if write {
        args.push(OsString::from("-w"));
    }
    args.push(OsString::from("--stdin"));
    object_id(&git_input(cwd, &args, body), "M6 hash-object")
}

fn real_shell() -> PathBuf {
    find_executable("sh")
}

fn wait_for(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn ndjson(output: &Output, context: &str) -> Vec<Value> {
    assert_success(output, context);
    assert!(
        output.stdout.ends_with(b"\n") || output.stdout.is_empty(),
        "{context} NDJSON lacked a final newline: {output:?}"
    );
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("parse M6 NDJSON"))
        .collect()
}

fn row_string<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("M6 listing omitted {field}: {row}"))
}

fn journal_state(record: &Value) -> &str {
    let journal = record
        .get("journal")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("M6 record omitted non-idle journal: {record}"));
    assert_eq!(
        journal.len(),
        1,
        "M6 journal was not a single state: {record}"
    );
    journal.keys().next().expect("M6 journal state")
}

fn payload_state(record: &Value) -> &str {
    let payload = record
        .get("payload")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("M6 record omitted payload: {record}"));
    assert_eq!(
        payload.len(),
        1,
        "M6 payload was not a single state: {record}"
    );
    payload.keys().next().expect("M6 payload state")
}

struct M6Binaries {
    instrumented: PathBuf,
    normal: PathBuf,
}

fn build_m6_binaries(sandbox: &Sandbox) -> M6Binaries {
    let instrumented = build_m6_binary(&sandbox.child("m6-instrumented-target"), true);
    let normal = build_m6_binary(&sandbox.child("m6-normal-target"), false);
    verify_normal_m6_binary(&normal);
    M6Binaries {
        instrumented,
        normal,
    }
}

fn build_m6_binary(target: &Path, instrumented: bool) -> PathBuf {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.current_dir(env!("CARGO_MANIFEST_DIR")).args([
        OsString::from("build"),
        OsString::from("--locked"),
        OsString::from("--release"),
        OsString::from("--all-features"),
        OsString::from("--bin"),
        OsString::from("git-vws"),
        OsString::from("--target-dir"),
        target.as_os_str().to_os_string(),
    ]);
    for variable in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
    ] {
        command.env_remove(variable);
    }
    if instrumented {
        command.env("RUSTFLAGS", "--cfg git_vws_m4_checkpoint");
    }
    let output = command.output().expect("build M6 binary");
    assert_success(
        &output,
        if instrumented {
            "build isolated instrumented M6 binary"
        } else {
            "build isolated normal M6 binary"
        },
    );
    let binary = target.join("release/git-vws");
    assert!(
        binary.is_file(),
        "M6 binary was absent: {}",
        binary.display()
    );
    binary
}

fn verify_normal_m6_binary(binary: &Path) {
    let bytes = fs::read(binary).expect("read normal M6 binary");
    for marker in [
        b"M4CP/1".as_slice(),
        b"GIT_VWS_M4_CONTROL_FD",
        b"GIT_VWS_M4_NONCE",
        b"GIT_VWS_M4_TARGET",
        b"m4_checkpoint",
    ] {
        assert!(
            !bytes.windows(marker.len()).any(|window| window == marker),
            "normal M6 binary retained checkpoint bytes: {}",
            String::from_utf8_lossy(marker)
        );
    }
    for program in ["strings", "nm"] {
        let mut command = Command::new(find_executable(program));
        if program == "nm" {
            command.arg("-a");
        }
        let output = command.arg(binary).output().expect("scan normal M6 binary");
        assert_success(&output, &format!("{program} normal M6 binary"));
        for marker in [
            b"M4CP/1".as_slice(),
            b"GIT_VWS_M4_CONTROL_FD",
            b"GIT_VWS_M4_NONCE",
            b"GIT_VWS_M4_TARGET",
            b"m4_checkpoint",
        ] {
            assert!(
                !output
                    .stdout
                    .windows(marker.len())
                    .any(|window| window == marker),
                "normal M6 {program} retained checkpoint marker: {}",
                String::from_utf8_lossy(marker)
            );
        }
    }
}

fn instrumented_command(fixture: &Fixture, binary: &Path, args: Vec<OsString>) -> Command {
    fixture.command_for(binary, args)
}

fn crash_at(fixture: &Fixture, binary: &Path, args: Vec<OsString>, operation: &str, stage: &str) {
    let target = CheckpointTarget::new(operation, stage);
    let run = CheckpointController::start(
        instrumented_command(fixture, binary, args),
        target.clone(),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("M6 controller ARM failed at {target:?}: {output:?}"))
    .crash_at_target();
    assert_eq!(
        run.events
            .last()
            .map(|event| (&event.operation, &event.stage)),
        Some((&target.operation, &target.stage)),
        "M6 controller did not stop at {target:?}: {:?}",
        run.events
    );
}

fn crash_create(fixture: &Fixture, binary: &Path, name: &str, stage: &str) {
    crash_at(
        fixture,
        binary,
        fixture.create_args(OsString::from(name), "main"),
        "create",
        stage,
    );
}

fn crash_remove(fixture: &Fixture, binary: &Path, name: &str, stage: &str) {
    crash_at(
        fixture,
        binary,
        fixture.remove_args(name, false),
        "remove",
        stage,
    );
}

fn crash_publish(fixture: &Fixture, binary: &Path, name: &str, stage: &str) {
    crash_at(
        fixture,
        binary,
        fixture.publish_args(name),
        "publish",
        stage,
    );
}

fn free_fanout(objects: &Path) -> String {
    for value in 0_u16..=255 {
        let name = format!("{value:02x}");
        if !objects.join(&name).exists() {
            return name;
        }
    }
    panic!("M6 fixture had no free loose-object fanout")
}

fn mkfifo_at(parent: &Path, name: &[u8]) -> PathBuf {
    let directory = File::open(parent).expect("open M6 FIFO parent");
    let name = CString::new(name).expect("M6 FIFO basename");
    assert_eq!(
        unsafe { libc::mkfifoat(directory.as_raw_fd(), name.as_ptr(), 0o600) },
        0,
        "create M6 FIFO: {}",
        io::Error::last_os_error()
    );
    parent.join(std::ffi::OsString::from_vec(name.as_bytes().to_vec()))
}

fn bind_socket_at(parent: &Path, name: &str) -> UnixListener {
    let original = File::open(".").expect("open M6 original cwd");
    let directory = File::open(parent).expect("open M6 socket parent");
    assert_eq!(
        unsafe { libc::fchdir(directory.as_raw_fd()) },
        0,
        "enter M6 socket parent: {}",
        io::Error::last_os_error()
    );
    let listener = UnixListener::bind(name);
    assert_eq!(
        unsafe { libc::fchdir(original.as_raw_fd()) },
        0,
        "restore M6 cwd after socket bind: {}",
        io::Error::last_os_error()
    );
    listener.expect("bind M6 tombstone socket")
}

fn prefixed_object(cwd: &Path, git_dir: &Path, prefix: &str) -> Vec<u8> {
    for attempt in 0_u32..16_384 {
        let body = format!("m6 loose duplicate {prefix} {attempt}\n").into_bytes();
        if hash_object(cwd, git_dir, &body, false).starts_with(prefix) {
            return body;
        }
    }
    panic!("could not produce an M6 {prefix} loose object")
}

fn atomic_replace(path: &Path, bytes: &[u8]) {
    let mut candidate = path.file_name().expect("M6 record basename").to_os_string();
    candidate.push(format!(".m6-{}", std::process::id()));
    let candidate = path.with_file_name(candidate);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&candidate)
        .expect("create controlled M6 record replacement");
    file.write_all(bytes)
        .expect("write controlled M6 record replacement");
    file.sync_all()
        .expect("sync controlled M6 record replacement");
    drop(file);
    fs::rename(&candidate, path).expect("install controlled M6 record replacement");
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

fn snapshot(path: &Path) -> Vec<u8> {
    let mut output = Vec::new();
    snapshot_entry(path, path, &mut output);
    output
}

fn snapshot_entry(root: &Path, path: &Path, output: &mut Vec<u8>) {
    let relative = path
        .strip_prefix(root)
        .expect("snapshot relative")
        .as_os_str()
        .as_bytes();
    let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
    output.extend_from_slice(relative);
    output.push(0);
    output.extend_from_slice(&metadata.mode().to_be_bytes());
    output.extend_from_slice(&metadata.nlink().to_be_bytes());
    if metadata.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("snapshot entry").path())
            .collect();
        entries.sort_by(|left, right| {
            left.as_os_str()
                .as_bytes()
                .cmp(right.as_os_str().as_bytes())
        });
        for entry in entries {
            snapshot_entry(root, &entry, output);
        }
    } else if metadata.is_file() {
        File::open(path)
            .expect("open snapshot file")
            .read_to_end(output)
            .expect("read snapshot file");
    } else if metadata.file_type().is_symlink() {
        output.extend_from_slice(
            fs::read_link(path)
                .expect("read snapshot symlink")
                .as_os_str()
                .as_bytes(),
        );
    }
}

fn maintenance_lines(output: &Output, label: &str) -> Vec<Value> {
    assert!(
        output.stdout.ends_with(b"\n"),
        "{label} NDJSON lacked final newline: {output:?}"
    );
    let lines: Vec<Value> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("parse M6 NDJSON"))
        .collect();
    assert!(!lines.is_empty(), "{label} omitted summary");
    let summary = lines.last().expect("M6 summary");
    assert_eq!(summary.get("version").and_then(Value::as_u64), Some(1));
    assert_eq!(summary.get("kind").and_then(Value::as_str), Some("summary"));
    let items = lines
        .iter()
        .filter(|line| line.get("kind").and_then(Value::as_str) == Some("item"))
        .count();
    let findings = lines
        .iter()
        .filter(|line| line.get("kind").and_then(Value::as_str) == Some("finding"))
        .count();
    assert_eq!(
        summary.get("items").and_then(Value::as_u64),
        Some(items as u64)
    );
    assert_eq!(
        summary.get("findings").and_then(Value::as_u64),
        Some(findings as u64)
    );
    for line in &lines[..lines.len() - 1] {
        assert!(matches!(
            line.get("kind").and_then(Value::as_str),
            Some("item" | "finding")
        ));
        for field in ["record_name_hex", "path_hex"] {
            let value = line
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{label} omitted {field}: {line}"));
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
                "{label} emitted a non-lowercase-hex {field}: {value:?}"
            );
        }
    }
    lines
}

#[test]
fn global_maintenance_cli_and_doctor_are_readonly() {
    let mut absent = Fixture::new(false);
    let absent_before = snapshot(&absent.home);
    for (label, output) in [("doctor", absent.doctor()), ("gc", absent.gc())] {
        assert_success(&output, &format!("missing-state {label}"));
        let lines = maintenance_lines(&output, &format!("missing-state {label}"));
        assert_eq!(lines.len(), 1, "missing-state {label} emitted a finding");
        assert_eq!(
            lines[0].get("recovery_required").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            snapshot(&absent.home),
            absent_before,
            "missing-state {label} wrote HOME"
        );
        assert!(
            !absent.state().exists(),
            "missing-state {label} created VWS state"
        );
    }
    assert_error(
        &absent.vws(vec![
            OsString::from("--repo"),
            absent.authority.as_os_str().to_os_string(),
            OsString::from("doctor"),
        ]),
        "SESSION_USAGE",
        "doctor accepted --repo",
    );
    assert_error(
        &absent.vws(vec![
            OsString::from("--repo"),
            absent.authority.as_os_str().to_os_string(),
            OsString::from("gc"),
        ]),
        "SESSION_USAGE",
        "gc accepted --repo",
    );
    let usage = absent.vws(vec![OsString::from("doctor"), OsString::from("unexpected")]);
    assert!(
        !usage.status.success(),
        "doctor accepted a positional argument"
    );
    assert_eq!(
        snapshot(&absent.home),
        absent_before,
        "global usage checks wrote HOME"
    );
    absent.cleanup();

    let mut fixture = Fixture::new(true);
    assert_success(&fixture.create("alpha", "main"), "create alpha for doctor");
    assert_success(&fixture.create("beta", "main"), "create beta for doctor");
    let state_before = snapshot(&fixture.state());
    let cwd_before = snapshot(&fixture.cwd);
    let sibling_before = snapshot(&fixture.sibling);
    let first = fixture.doctor();
    assert_success(&first, "doctor healthy state");
    let lines = maintenance_lines(&first, "doctor healthy state");
    assert!(
        lines[..lines.len() - 1]
            .iter()
            .all(|line| line.get("kind").and_then(Value::as_str) == Some("item")),
        "doctor reported a healthy state as a finding: {first:?}"
    );
    assert_eq!(
        snapshot(&fixture.state()),
        state_before,
        "doctor changed managed state"
    );
    assert_eq!(
        snapshot(&fixture.cwd),
        cwd_before,
        "doctor changed cwd sentinel"
    );
    assert_eq!(
        snapshot(&fixture.sibling),
        sibling_before,
        "doctor changed sibling sentinel"
    );
    let second = fixture.doctor();
    assert_success(&second, "repeat doctor healthy state");
    assert_eq!(
        first.stdout, second.stdout,
        "doctor NDJSON ordering was unstable"
    );
    assert_eq!(
        snapshot(&fixture.state()),
        state_before,
        "repeat doctor changed managed state"
    );

    assert_success(
        &fixture.create("template-key-binding", "main"),
        "create template-key binding source",
    );
    let record_path = fixture.record_path(b"template-key-binding");
    let record_before = fs::read(&record_path).expect("read template-key binding receipt");
    let original_key = fixture.template_key(b"template-key-binding");
    let absent_key = ["0", "1", "2", "3"]
        .into_iter()
        .map(|digit| digit.repeat(64))
        .find(|key| key != &original_key && !fixture.template_record(key).exists())
        .expect("find absent legal M6 template key");
    let prefix = b"\"template_key\":\"";
    let key_offset = record_before
        .windows(prefix.len())
        .position(|window| window == prefix)
        .expect("find canonical M6 template-key field")
        + prefix.len();
    assert_eq!(
        &record_before[key_offset..key_offset + original_key.len()],
        original_key.as_bytes(),
        "M6 canonical receipt changed template-key field layout"
    );
    let mut mismatched = record_before.clone();
    mismatched[key_offset..key_offset + original_key.len()].copy_from_slice(absent_key.as_bytes());
    assert_eq!(
        &mismatched[..key_offset],
        &record_before[..key_offset],
        "M6 template-key negative rewrote a receipt prefix"
    );
    assert_eq!(
        &mismatched[key_offset + original_key.len()..],
        &record_before[key_offset + original_key.len()..],
        "M6 template-key negative rewrote a receipt suffix"
    );
    let original_value: Value =
        serde_json::from_slice(&record_before).expect("parse original template-key receipt");
    let mismatched_value: Value =
        serde_json::from_slice(&mismatched).expect("parse mismatched template-key receipt");
    assert_eq!(
        original_value.get("template"),
        mismatched_value.get("template"),
        "M6 template-key negative changed the sealed template receipt"
    );
    assert_eq!(
        original_value.pointer("/payload/READY/worktree"),
        mismatched_value.pointer("/payload/READY/worktree"),
        "M6 template-key negative changed the READY worktree receipt"
    );
    atomic_replace(&record_path, &mismatched);
    let key_state_before = snapshot(&fixture.state());
    let key_templates_before = snapshot(&fixture.templates());
    let key_authority_before = snapshot(&fixture.authority);
    assert_error(
        &fixture.doctor(),
        "DOCTOR_RECOVERY_REQUIRED",
        "mismatched canonical template key must block doctor",
    );
    assert_eq!(snapshot(&fixture.state()), key_state_before);
    assert_eq!(snapshot(&fixture.templates()), key_templates_before);
    assert_eq!(snapshot(&fixture.authority), key_authority_before);
    assert_error(
        &fixture.gc(),
        "GC_RECOVERY_REQUIRED",
        "mismatched canonical template key must block GC",
    );
    assert_eq!(snapshot(&fixture.state()), key_state_before);
    assert_eq!(snapshot(&fixture.templates()), key_templates_before);
    assert_eq!(snapshot(&fixture.authority), key_authority_before);
    eprintln!("M6 doctor evidence: readonly=ok");
    fixture.cleanup();
}

fn temporary_entries(parent: &Path) -> Vec<PathBuf> {
    let directory = match fs::read_dir(parent) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("read M6 temporary entries: {error}"),
    };
    let mut entries: Vec<_> = directory
        .map(|entry| entry.expect("read M6 temporary entry").path())
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                let name = name.as_bytes();
                name.starts_with(b".") && name.ends_with(b".tmp")
            })
        })
        .collect();
    entries.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    entries
}

fn gc_stages(group: &str) -> &'static [&'static str] {
    match group {
        "session" => &[
            "session-tombstone-renamed",
            "session-tombstone-parent-synced",
            "session-owned-tree-removed",
            "record-deletion-unlinked",
            "record-deletion-parent-synced",
            "session-return",
        ],
        "template" => &[
            "template-tombstoned-record-temporary-synced",
            "template-tombstoned-record-namespace-applied",
            "template-tombstoned-record-exchange-old-unlinked",
            "template-tombstoned-record-parent-synced",
            "template-tombstoned-record",
            "template-tombstone-renamed",
            "template-tombstone-parent-synced",
            "template-owned-tree-removed",
            "record-deletion-unlinked",
            "record-deletion-parent-synced",
            "template-return",
        ],
        "loose" => &[
            "loose-object-unlinked",
            "loose-object-parent-synced",
            "loose-fanout-unlinked",
            "loose-fanout-parent-synced",
            "loose-return",
        ],
        "predecessor" => &[
            "predecessor-tmp-unlinked",
            "predecessor-tmp-parent-synced",
            "predecessor-tmp-removed",
        ],
        "global" => &["return"],
        _ => panic!("unknown M6 GC checkpoint group {group}"),
    }
}

fn gc_groups() -> [&'static str; 5] {
    ["session", "template", "loose", "predecessor", "global"]
}

fn gc_group_events(group: &str, events: &[checkpoint::Checkpoint]) -> Vec<String> {
    events
        .iter()
        .filter(|event| {
            event.operation == "gc"
                && match group {
                    "session" => {
                        event.sid != "-"
                            && (event.stage.starts_with("session-")
                                || event.stage.starts_with("record-deletion-"))
                    }
                    "template" => event.sid == "-" && event.key != "-",
                    "loose" => event.sid != "-" && event.stage.starts_with("loose-"),
                    "predecessor" => event.sid != "-" && event.stage.starts_with("predecessor-"),
                    "global" => event.sid == "-" && event.key == "-" && event.stage == "return",
                    _ => false,
                }
        })
        .map(|event| event.stage.clone())
        .collect()
}

fn prepare_gc_fixture(group: &str, binaries: &M6Binaries) -> Fixture {
    let fixture = Fixture::new(true);
    match group {
        "session" => {
            assert_success(&fixture.create("dead", "main"), "create M6 dead session");
            assert_success(
                &fixture.create("anchor", "main"),
                "create M6 session GC reachability anchor",
            );
            crash_remove(
                &fixture,
                &binaries.instrumented,
                "dead",
                "tombstoned-record-parent-synced",
            );
            assert_eq!(payload_state(&fixture.record(b"dead")), "TOMBSTONED");
        }
        "template" => {
            assert_success(&fixture.create("gone", "main"), "create M6 template source");
            assert_success(&fixture.remove("gone", false), "remove M6 template source");
            assert!(
                fixture.records().is_empty(),
                "removed M6 session retained a record"
            );
        }
        "loose" => {
            assert_success(&fixture.create("loose", "main"), "create M6 loose source");
            let private = fixture.common(b"loose");
            let body = b"M6 exact loose GC checkpoint object\n";
            assert_eq!(
                hash_object(&fixture.cwd, &private, body, true),
                hash_object(&fixture.cwd, &fixture.authority, body, true),
                "M6 checkpoint loose object did not duplicate exactly"
            );
        }
        "predecessor" => {
            crash_create(
                &fixture,
                &binaries.instrumented,
                "predecessor",
                "ready-record-namespace-applied",
            );
            assert_eq!(payload_state(&fixture.record(b"predecessor")), "READY");
            assert_eq!(
                temporary_entries(&fixture.sessions()).len(),
                1,
                "checkpoint did not leave a real RecordTxn predecessor temporary"
            );
        }
        "global" => {}
        _ => panic!("unknown M6 GC fixture group {group}"),
    }
    fixture
}

fn gc_command(fixture: &Fixture, binary: &Path) -> Command {
    fixture.command_for(binary, vec![OsString::from("gc")])
}

fn normal_gc(fixture: &Fixture, binary: &Path) -> Output {
    gc_command(fixture, binary)
        .env("GIT_VWS_M4_CONTROL_FD", "999")
        .env("GIT_VWS_M4_NONCE", "0")
        .env("GIT_VWS_M4_TARGET", "gc/return")
        .output()
        .expect("run normal M6 GC")
}

fn eof_after_target_go(mut controller: CheckpointController) -> ControlRun {
    let checkpoint = controller.pause_at_target();
    controller.release_target(&checkpoint);
    controller.stream.take();
    let output = controller
        .child
        .take()
        .expect("post-GO EOF child")
        .wait_with_output()
        .expect("reap post-GO EOF child");
    ControlRun {
        events: std::mem::take(&mut controller.events),
        output,
    }
}

fn assert_safe_gc_recovery(output: &Output, context: &str) {
    if output.status.success() {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("GC_RECOVERY_REQUIRED"),
        "{context} was neither completed nor retained safely: {output:?}"
    );
    assert!(
        !stderr.contains("M4_CHECKPOINT_FAILED"),
        "{context} used an instrumented recovery binary: {output:?}"
    );
}

fn loose_object_path(common: &Path, oid: &str) -> PathBuf {
    common.join("objects").join(&oid[..2]).join(&oid[2..])
}

#[test]
fn private_loose_and_predecessor_temporary_gc_contract() {
    let mut artifacts = Sandbox::new();
    let binaries = build_m6_binaries(&artifacts);

    let mut exact = Fixture::new(true);
    assert_success(
        &exact.create("exact", "main"),
        "create exact M6 loose session",
    );
    let private = exact.common(b"exact");
    let body = b"M6 exact private loose object\n";
    let oid = hash_object(&exact.cwd, &private, body, true);
    assert_eq!(
        hash_object(&exact.cwd, &exact.authority, body, true),
        oid,
        "exact M6 loose object OID drifted"
    );
    let private_loose = loose_object_path(&private, &oid);
    let authority_loose = loose_object_path(&exact.authority, &oid);
    assert!(private_loose.is_file() && authority_loose.is_file());
    let authority_before = snapshot(&exact.authority);
    let cleaned = exact.gc();
    assert_success(&cleaned, "clean exact private loose duplicate");
    assert!(
        maintenance_lines(&cleaned, "clean exact private loose duplicate")
            .iter()
            .any(|line| {
                line.get("scope").and_then(Value::as_str) == Some("loose")
                    && line.get("code").and_then(Value::as_str) == Some("REMOVED")
            }),
        "exact private loose duplicate was not reported removed: {cleaned:?}"
    );
    assert!(
        !private_loose.exists() && authority_loose.is_file(),
        "exact private loose cleanup touched the wrong object"
    );
    assert_eq!(
        snapshot(&exact.authority),
        authority_before,
        "exact private loose cleanup changed authority"
    );
    let exact_settled = snapshot(&exact.state());
    assert_success(&exact.gc(), "repeat exact private loose GC");
    assert_eq!(
        snapshot(&exact.state()),
        exact_settled,
        "repeat exact private loose GC was not idempotent"
    );
    exact.cleanup();

    let mut invalid_fanout = Fixture::new(true);
    assert_success(
        &invalid_fanout.create("fanout", "main"),
        "create M6 fanout negative session",
    );
    let fanout_common = invalid_fanout.common(b"fanout");
    let fanout_body = prefixed_object(&invalid_fanout.cwd, &fanout_common, "00");
    let fanout_oid = hash_object(&invalid_fanout.cwd, &fanout_common, &fanout_body, true);
    assert_eq!(
        hash_object(
            &invalid_fanout.cwd,
            &invalid_fanout.authority,
            &fanout_body,
            true,
        ),
        fanout_oid,
        "M6 authority fanout duplicate OID drifted"
    );
    let fanout_private = loose_object_path(&fanout_common, &fanout_oid);
    let fanout_authority = loose_object_path(&invalid_fanout.authority, &fanout_oid);
    let fanout_directory = fanout_authority
        .parent()
        .expect("M6 authority fanout directory");
    let unknown_child = fanout_directory.join("unexpected-child");
    fs::write(&unknown_child, b"M6 authority fanout unknown child\n")
        .expect("write M6 authority fanout unknown child");
    let special_child = mkfifo_at(fanout_directory, b"special-child");
    let fanout_before = snapshot(fanout_directory);
    let state_before = snapshot(&invalid_fanout.state());
    let blocked = invalid_fanout.gc();
    assert_error(
        &blocked,
        "GC_RECOVERY_REQUIRED",
        "authority fanout unknown or special child must fail closed",
    );
    assert!(
        fanout_private.is_file() && fanout_authority.is_file(),
        "authority fanout recovery removed the exact private duplicate"
    );
    assert_eq!(
        snapshot(fanout_directory),
        fanout_before,
        "authority fanout recovery changed unknown or special children"
    );
    assert_eq!(
        snapshot(&invalid_fanout.state()),
        state_before,
        "authority fanout recovery mutated managed state"
    );
    fs::remove_file(&special_child).expect("remove test-owned authority fanout FIFO");
    fs::remove_file(&unknown_child).expect("remove test-owned authority fanout child");
    invalid_fanout.cleanup();

    let mut predecessor = Fixture::new(true);
    crash_create(
        &predecessor,
        &binaries.instrumented,
        "predecessor",
        "ready-record-namespace-applied",
    );
    let predecessor_tmp = temporary_entries(&predecessor.sessions());
    assert_eq!(
        predecessor_tmp.len(),
        1,
        "real M6 RecordTxn checkpoint did not retain one predecessor temporary"
    );
    let successor_record_path = predecessor.record_path(b"predecessor");
    let successor_record_before =
        fs::read(&successor_record_path).expect("read M6 predecessor successor record");
    let successor_root = predecessor.root(b"predecessor");
    let successor_root_before = snapshot(&successor_root);
    let predecessor_before = snapshot(&predecessor.authority);
    let reclaimed = normal_gc(&predecessor, &binaries.normal);
    assert_success(&reclaimed, "reclaim real M6 predecessor temporary");
    let reclaimed_lines = maintenance_lines(&reclaimed, "reclaim real M6 predecessor temporary");
    let predecessor_tmp_hex = hex(predecessor_tmp[0]
        .file_name()
        .expect("M6 predecessor temporary basename")
        .as_bytes());
    assert!(
        reclaimed_lines.iter().any(|line| {
            row_string(line, "scope") == "session"
                && row_string(line, "path_hex") == predecessor_tmp_hex
                && row_string(line, "state") == "TMP"
                && row_string(line, "code") == "REMOVED"
        }),
        "M6 predecessor cleanup omitted its converged temporary: {reclaimed:?}"
    );
    assert!(
        temporary_entries(&predecessor.sessions()).is_empty(),
        "M6 predecessor temporary was not reclaimed"
    );
    assert_eq!(payload_state(&predecessor.record(b"predecessor")), "READY");
    assert_eq!(
        fs::read(&successor_record_path).expect("read M6 converged successor record"),
        successor_record_before,
        "M6 predecessor GC rewrote or orphaned the successor record"
    );
    assert_eq!(
        snapshot(&successor_root),
        successor_root_before,
        "M6 predecessor GC changed the successor owned tree"
    );
    assert_eq!(
        snapshot(&predecessor.authority),
        predecessor_before,
        "predecessor temporary cleanup changed authority"
    );
    predecessor.cleanup();

    let mut template_predecessor = Fixture::new(true);
    assert_success(
        &template_predecessor.create("template-predecessor", "main"),
        "create template RecordTxn predecessor source",
    );
    let template_key = template_predecessor.template_key(b"template-predecessor");
    assert_success(
        &template_predecessor.remove("template-predecessor", false),
        "remove template RecordTxn predecessor source",
    );
    assert!(
        template_predecessor.records().is_empty(),
        "removed template RecordTxn predecessor source retained a session record"
    );
    let template_authority_before = snapshot(&template_predecessor.authority);
    crash_at(
        &template_predecessor,
        &binaries.instrumented,
        vec![OsString::from("gc")],
        "gc",
        "template-tombstoned-record-namespace-applied",
    );
    let template_tmp = temporary_entries(&template_predecessor.templates());
    assert_eq!(
        template_tmp.len(),
        1,
        "template RecordTxn namespace-applied did not retain one predecessor temporary"
    );
    let template_successor = template_predecessor.template_record(&template_key);
    let template_successor_before =
        fs::read(&template_successor).expect("read template RecordTxn successor receipt");
    let template_successor_value: Value = serde_json::from_slice(&template_successor_before)
        .expect("parse template RecordTxn successor receipt");
    assert_eq!(
        payload_state(&template_successor_value),
        "TOMBSTONED",
        "template RecordTxn successor was not tombstoned"
    );
    let template_root = template_predecessor.templates().join(
        template_successor_value
            .pointer("/payload/TOMBSTONED/root_name")
            .and_then(Value::as_str)
            .expect("template RecordTxn successor root name"),
    );
    let template_root_before = snapshot(&template_root);
    let reclaimed = normal_gc(&template_predecessor, &binaries.normal);
    assert_success(&reclaimed, "reclaim real template RecordTxn predecessor");
    assert!(
        maintenance_lines(&reclaimed, "reclaim real template RecordTxn predecessor")
            .iter()
            .any(|line| {
                row_string(line, "scope") == "template"
                    && row_string(line, "state") == "TMP"
                    && row_string(line, "code") == "REMOVED"
            }),
        "template RecordTxn predecessor cleanup was not reported: {reclaimed:?}"
    );
    assert!(
        temporary_entries(&template_predecessor.templates()).is_empty(),
        "template RecordTxn predecessor was not reclaimed"
    );
    assert_eq!(
        snapshot(&template_predecessor.authority),
        template_authority_before,
        "template RecordTxn predecessor cleanup changed authority"
    );
    match (template_successor.is_file(), template_root.is_dir()) {
        (true, true) => {
            assert_eq!(
                fs::read(&template_successor).expect("read retained template successor"),
                template_successor_before,
                "template RecordTxn recovery rewrote a retained successor receipt"
            );
            assert_eq!(
                snapshot(&template_root),
                template_root_before,
                "template RecordTxn recovery changed a retained successor tree"
            );
        }
        (false, false) => {}
        state => panic!("template RecordTxn recovery orphaned successor state: {state:?}"),
    }
    let template_settled = snapshot(&template_predecessor.state());
    assert_success(
        &normal_gc(&template_predecessor, &binaries.normal),
        "repeat template RecordTxn predecessor cleanup",
    );
    assert!(
        temporary_entries(&template_predecessor.templates()).is_empty(),
        "repeat template RecordTxn cleanup retained a predecessor temporary"
    );
    assert_eq!(
        snapshot(&template_predecessor.state()),
        template_settled,
        "repeat template RecordTxn predecessor cleanup was not idempotent"
    );
    template_predecessor.cleanup();

    let mut reachable_tombstoned = Fixture::new(true);
    crash_create(
        &reachable_tombstoned,
        &binaries.instrumented,
        "reachable",
        "prepared-record-parent-synced",
    );
    let reachable_record_path = reachable_tombstoned.record_path(b"reachable");
    let reachable_record =
        fs::read(&reachable_record_path).expect("read M6 reachable PREPARED receipt");
    let reachable_key = reachable_tombstoned.template_key(b"reachable");
    assert_success(
        &reachable_tombstoned.remove("reachable", true),
        "remove M6 PREPARED template reachability source",
    );
    assert!(
        reachable_tombstoned.records().is_empty(),
        "M6 PREPARED reachability source retained a record"
    );
    crash_at(
        &reachable_tombstoned,
        &binaries.instrumented,
        vec![OsString::from("gc")],
        "gc",
        "template-tombstoned-record",
    );
    let tombstoned_template = reachable_tombstoned.template_record(&reachable_key);
    let tombstoned_template_before =
        fs::read(&tombstoned_template).expect("read real M6 TOMBSTONED template receipt");
    let tombstoned_template_value: Value =
        serde_json::from_slice(&tombstoned_template_before).expect("parse M6 TOMBSTONED template");
    assert_eq!(payload_state(&tombstoned_template_value), "TOMBSTONED");
    let tombstone_root_name = tombstoned_template_value
        .pointer("/payload/TOMBSTONED/root_name")
        .and_then(Value::as_str)
        .expect("M6 TOMBSTONED template root name");
    let tombstone_root = reachable_tombstoned.templates().join(tombstone_root_name);
    assert!(
        tombstone_root.is_dir(),
        "M6 TOMBSTONED template root disappeared"
    );
    let tombstone_root_before = snapshot(&tombstone_root);
    atomic_replace(&reachable_record_path, &reachable_record);
    assert_eq!(
        payload_state(&reachable_tombstoned.record(b"reachable")),
        "PREPARED"
    );
    let retained = normal_gc(&reachable_tombstoned, &binaries.normal);
    assert_success(&retained, "retain reachable M6 TOMBSTONED template");
    assert!(
        maintenance_lines(&retained, "retain reachable M6 TOMBSTONED template")
            .iter()
            .any(|line| {
                row_string(line, "scope") == "template"
                    && row_string(line, "state") == "TOMBSTONED"
                    && row_string(line, "code") == "RETAINED"
            }),
        "reachable M6 TOMBSTONED template was not reported retained: {retained:?}"
    );
    assert_eq!(
        fs::read(&tombstoned_template).expect("read retained M6 TOMBSTONED template"),
        tombstoned_template_before,
        "reachable M6 TOMBSTONED template receipt changed"
    );
    assert_eq!(
        snapshot(&tombstone_root),
        tombstone_root_before,
        "reachable M6 TOMBSTONED template root changed"
    );
    assert_eq!(
        fs::read(&reachable_record_path).expect("read retained M6 PREPARED receipt"),
        reachable_record,
        "reachable M6 session receipt changed during template GC"
    );
    reachable_tombstoned.cleanup();

    let mut retained = Fixture::new(true);
    assert_success(
        &retained.create("retained", "main"),
        "create M6 retain matrix",
    );
    let common = retained.common(b"retained");
    let objects = common.join("objects");
    let pack = objects.join("pack");
    let packed_oid = hash_object(
        &retained.cwd,
        &common,
        b"M6 retained private packed object\n",
        true,
    );
    let packed = git_input(
        &retained.cwd,
        &[
            OsString::from("--git-dir"),
            common.as_os_str().to_os_string(),
            OsString::from("pack-objects"),
            OsString::from("--revs"),
            OsString::from("--stdout"),
        ],
        format!("{packed_oid}\n").as_bytes(),
    );
    assert_success(&packed, "pack real M6 private loose object");
    assert!(!packed.stdout.is_empty(), "real M6 pack was empty");
    assert_success(
        &git_input(
            &retained.cwd,
            &[
                OsString::from("--git-dir"),
                common.as_os_str().to_os_string(),
                OsString::from("index-pack"),
                OsString::from("--stdin"),
                OsString::from("--fix-thin"),
                OsString::from("--no-rev-index"),
            ],
            &packed.stdout,
        ),
        "index real M6 private pack",
    );
    let mut packed: Vec<_> = fs::read_dir(&pack)
        .expect("read real M6 private pack directory")
        .map(|entry| entry.expect("read real M6 private pack entry").path())
        .collect();
    packed.sort();
    assert_eq!(
        packed.len(),
        2,
        "real M6 repack did not produce one pack pair"
    );
    let pack_file = packed
        .iter()
        .find(|path| path.as_os_str().as_bytes().ends_with(b".pack"))
        .cloned()
        .expect("real M6 repack omitted pack");
    let idx_file = packed
        .iter()
        .find(|path| path.as_os_str().as_bytes().ends_with(b".idx"))
        .cloned()
        .expect("real M6 repack omitted index");

    let hard_body = b"M6 hard-linked private loose object\n";
    let hard_oid = hash_object(&retained.cwd, &common, hard_body, true);
    assert_eq!(
        hash_object(&retained.cwd, &retained.authority, hard_body, true),
        hard_oid
    );
    let hard_private = loose_object_path(&common, &hard_oid);
    let hard_link = retained.sandbox.child("hard-linked-loose");
    fs::hard_link(&hard_private, &hard_link).expect("hard-link retained M6 loose object");

    let mismatch_body = b"M6 mismatched private loose object\n";
    let mismatch_oid = hash_object(&retained.cwd, &common, mismatch_body, true);
    assert_eq!(
        hash_object(&retained.cwd, &retained.authority, mismatch_body, true),
        mismatch_oid
    );
    let mismatch_private = loose_object_path(&common, &mismatch_oid);
    let mismatch_authority = loose_object_path(&retained.authority, &mismatch_oid);
    fs::set_permissions(&mismatch_authority, fs::Permissions::from_mode(0o600))
        .expect("make M6 non-exact authority loose object writable");
    fs::write(
        &mismatch_authority,
        b"M6 deliberately non-exact authority loose object\n",
    )
    .expect("write M6 non-exact authority loose object");

    let missing_body = b"M6 authority missing private loose object\n";
    let missing_oid = hash_object(&retained.cwd, &common, missing_body, true);
    let missing_private = loose_object_path(&common, &missing_oid);
    let retained_before = snapshot(&retained.state());
    let retained_authority = snapshot(&retained.authority);
    let retain_output = retained.gc();
    assert_success(&retain_output, "retain M6 loose negative matrix");
    assert!(
        pack_file.is_file()
            && idx_file.is_file()
            && hard_private.is_file()
            && hard_link.is_file()
            && mismatch_private.is_file()
            && missing_private.is_file(),
        "M6 GC removed a retained private loose or pack entry"
    );
    assert_eq!(
        snapshot(&retained.state()),
        retained_before,
        "M6 retained loose matrix mutated state"
    );
    assert_eq!(
        snapshot(&retained.authority),
        retained_authority,
        "M6 retained loose matrix mutated authority"
    );
    retained.cleanup();

    let mut invalid_tmp = Fixture::new(true);
    assert_success(
        &invalid_tmp.create("temporary", "main"),
        "create M6 invalid temporary source",
    );
    let current = invalid_tmp.record_path(b"temporary");
    let current_bytes = fs::read(&current).expect("read M6 current record for temporary negatives");
    let final_name = current.file_name().expect("M6 current record basename");
    let pid = std::process::id();
    let non_adjacent = invalid_tmp
        .sessions()
        .join(format!(".{}-{pid}-0.tmp", final_name.to_string_lossy()));
    fs::write(&non_adjacent, &current_bytes).expect("write M6 non-adjacent temporary");
    let mut future = serde_json::from_slice::<Value>(&current_bytes).expect("parse M6 record");
    future["version"] = Value::from(99_u64);
    let future_tmp = invalid_tmp
        .sessions()
        .join(format!(".{}-{pid}-1.tmp", final_name.to_string_lossy()));
    fs::write(
        &future_tmp,
        serde_json::to_vec(&future).expect("encode M6 future temporary"),
    )
    .expect("write M6 future temporary");
    let wrong_name = invalid_tmp
        .sessions()
        .join(format!(".wrong-record-{pid}-2.tmp"));
    fs::write(&wrong_name, b"M6 wrong temporary basename\n")
        .expect("write M6 wrong temporary basename");
    let invalid_before = snapshot(&invalid_tmp.state());
    assert_error(
        &invalid_tmp.gc(),
        "GC_RECOVERY_REQUIRED",
        "invalid M6 predecessor temporaries must be retained",
    );
    assert!(
        non_adjacent.is_file() && future_tmp.is_file() && wrong_name.is_file(),
        "M6 GC removed a non-adjacent, future, or malformed temporary"
    );
    assert_eq!(
        snapshot(&invalid_tmp.state()),
        invalid_before,
        "invalid M6 temporary matrix allowed partial GC mutation"
    );
    invalid_tmp.cleanup();
    artifacts
        .cleanup()
        .expect("cleanup M6 loose binary artifacts");
}

#[test]
fn gc_tombstones_and_crash_prefix_recover_exactly_once() {
    let mut artifacts = Sandbox::new();
    let binaries = build_m6_binaries(&artifacts);
    let expected_count: usize = gc_groups().iter().map(|group| gc_stages(group).len()).sum();
    assert_eq!(expected_count, 26, "M6 GC stage ledger changed");

    let mut wrong_arm = Fixture::new(true);
    let wrong_before = snapshot(&wrong_arm.state());
    let wrong = match CheckpointController::start(
        gc_command(&wrong_arm, &binaries.instrumented),
        CheckpointTarget::new("gc", "return"),
        ArmReply::Wrong,
    ) {
        Ok(_) => panic!("M6 instrumented GC accepted a wrong controller ARM"),
        Err(output) => output,
    };
    assert!(!wrong.status.success(), "wrong M6 controller ARM succeeded");
    assert_eq!(
        snapshot(&wrong_arm.state()),
        wrong_before,
        "wrong M6 controller ARM changed state"
    );
    wrong_arm.cleanup();

    let mut eof = Fixture::new(true);
    let eof_before = snapshot(&eof.state());
    let eof_output = CheckpointController::start(
        gc_command(&eof, &binaries.instrumented),
        CheckpointTarget::new("gc", "return"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("M6 EOF controller ARM failed: {output:?}"))
    .fault_at_first(checkpoint::ProtocolFault::Eof);
    assert!(!eof_output.status.success(), "M6 preflight EOF succeeded");
    assert_eq!(
        snapshot(&eof.state()),
        eof_before,
        "M6 preflight EOF changed state"
    );
    eof.cleanup();
    let _ = [
        checkpoint::ProtocolFault::BadFrame,
        checkpoint::ProtocolFault::WrongSequence,
        checkpoint::ProtocolFault::Timeout,
    ];

    for group in gc_groups() {
        let mut fixture = prepare_gc_fixture(group, &binaries);
        let target = CheckpointTarget::new("gc", gc_stages(group)[0]);
        let run = CheckpointController::start(
            gc_command(&fixture, &binaries.instrumented),
            target,
            ArmReply::Exact,
        )
        .unwrap_or_else(|output| panic!("M6 {group} discovery ARM failed: {output:?}"))
        .run_all();
        assert_success(&run.output, &format!("M6 {group} checkpoint discovery"));
        let actual = gc_group_events(group, &run.events);
        assert_eq!(actual, gc_stages(group), "M6 {group} checkpoint ledger");
        fixture.cleanup();
    }

    for group in gc_groups() {
        for stage in gc_stages(group) {
            let mut fixture = prepare_gc_fixture(group, &binaries);
            let record_limit = fixture.record_count();
            let authority_before = snapshot(&fixture.authority);
            let cwd_before = snapshot(&fixture.cwd);
            let sibling_before = snapshot(&fixture.sibling);
            let predecessor_successor = (group == "predecessor").then(|| {
                (
                    fs::read(fixture.record_path(b"predecessor"))
                        .expect("read M6 predecessor successor receipt before crash"),
                    snapshot(&fixture.root(b"predecessor")),
                )
            });
            crash_at(
                &fixture,
                &binaries.instrumented,
                vec![OsString::from("gc")],
                "gc",
                stage,
            );
            assert!(
                fixture.record_count() <= record_limit,
                "M6 {group}/{stage} crash duplicated session records"
            );
            let recovered = normal_gc(&fixture, &binaries.normal);
            assert_success(&recovered, &format!("M6 {group}/{stage} recovery"));
            assert!(
                temporary_entries(&fixture.sessions()).is_empty()
                    && temporary_entries(&fixture.templates()).is_empty(),
                "M6 {group}/{stage} recovery retained a RecordTxn predecessor temporary"
            );
            if let Some((record_before, root_before)) = predecessor_successor {
                assert_eq!(
                    fs::read(fixture.record_path(b"predecessor"))
                        .expect("read M6 predecessor successor receipt after recovery"),
                    record_before,
                    "M6 predecessor recovery changed the successor receipt"
                );
                assert_eq!(
                    snapshot(&fixture.root(b"predecessor")),
                    root_before,
                    "M6 predecessor recovery changed the successor owned tree"
                );
            }
            assert_eq!(
                snapshot(&fixture.authority),
                authority_before,
                "M6 {group}/{stage} recovery changed authority"
            );
            assert_eq!(snapshot(&fixture.cwd), cwd_before, "M6 GC changed cwd");
            assert_eq!(
                snapshot(&fixture.sibling),
                sibling_before,
                "M6 GC changed sibling sentinel"
            );
            let settled = snapshot(&fixture.state());
            let repeated = normal_gc(&fixture, &binaries.normal);
            assert_success(&repeated, &format!("M6 {group}/{stage} repeat GC"));
            assert!(
                temporary_entries(&fixture.sessions()).is_empty()
                    && temporary_entries(&fixture.templates()).is_empty(),
                "M6 {group}/{stage} repeat GC retained a RecordTxn predecessor temporary"
            );
            assert_eq!(
                snapshot(&fixture.state()),
                settled,
                "M6 {group}/{stage} repeat GC was not idempotent"
            );
            fixture.cleanup();
        }
    }

    let mut post_durable = prepare_gc_fixture("session", &binaries);
    let authority_before = snapshot(&post_durable.authority);
    let run = eof_after_target_go(
        CheckpointController::start(
            gc_command(&post_durable, &binaries.instrumented),
            CheckpointTarget::new("gc", "session-tombstone-renamed"),
            ArmReply::Exact,
        )
        .unwrap_or_else(|output| panic!("M6 post-GO EOF ARM failed: {output:?}")),
    );
    assert!(
        !run.output.status.success(),
        "post-durable M6 GO/EOF succeeded"
    );
    assert!(
        gc_group_events("session", &run.events)
            .iter()
            .any(|stage| stage == "session-tombstone-renamed"),
        "post-durable M6 GO/EOF did not cross the durable rename"
    );
    assert_safe_gc_recovery(
        &normal_gc(&post_durable, &binaries.normal),
        "M6 post-durable GO/EOF recovery",
    );
    assert_eq!(
        snapshot(&post_durable.authority),
        authority_before,
        "post-durable M6 GO/EOF recovery changed authority"
    );
    eprintln!(
        "M6 gc evidence: session={} template={} loose+fanout={} predecessor={} global={} total={}",
        gc_stages("session").len(),
        gc_stages("template").len(),
        gc_stages("loose").len(),
        gc_stages("predecessor").len(),
        gc_stages("global").len(),
        expected_count
    );
    post_durable.cleanup();

    let mut special_tree = Fixture::new(true);
    assert_success(
        &special_tree.create("special-tree", "main"),
        "create M6 special tombstone source",
    );
    crash_remove(
        &special_tree,
        &binaries.instrumented,
        "special-tree",
        "tombstoned-record-parent-synced",
    );
    let special_record_path = special_tree.record_path(b"special-tree");
    let special_record_before =
        fs::read(&special_record_path).expect("read M6 special tombstone receipt");
    let special_record = special_tree.record(b"special-tree");
    assert_eq!(payload_state(&special_record), "TOMBSTONED");
    let special_root = special_tree.root(b"special-tree");
    let special_tombstone = special_tree.sessions().join(
        special_record
            .pointer("/payload/TOMBSTONED/tombstone_name")
            .and_then(Value::as_str)
            .expect("M6 special tombstone name"),
    );
    let fifo = mkfifo_at(&special_root, b"!m6-fifo");
    let socket = special_root.join("!m6-socket");
    let cwd_before = env::current_dir().expect("read M6 cwd before socket bind");
    let listener = bind_socket_at(&special_root, "!m6-socket");
    assert_eq!(
        env::current_dir().expect("read M6 cwd after socket bind"),
        cwd_before,
        "M6 socket fixture changed the test cwd"
    );
    assert!(
        fs::symlink_metadata(&fifo)
            .expect("stat M6 tombstone FIFO")
            .file_type()
            .is_fifo(),
        "M6 tombstone FIFO was not created"
    );
    assert!(
        fs::symlink_metadata(&socket)
            .expect("stat M6 tombstone socket")
            .file_type()
            .is_socket(),
        "M6 tombstone socket was not created"
    );
    let special_tree_before = snapshot(&special_root);
    let special_gc = normal_gc(&special_tree, &binaries.normal);
    assert_error(
        &special_gc,
        "GC_RECOVERY_REQUIRED",
        "special entries in a session tombstone must fail closed",
    );
    assert_eq!(
        fs::read(&special_record_path).expect("read retained M6 special tombstone receipt"),
        special_record_before,
        "M6 special tombstone receipt changed during recovery"
    );
    let retained_root = if special_tombstone.is_dir() {
        &special_tombstone
    } else {
        &special_root
    };
    assert!(
        retained_root.join("!m6-fifo").exists() && retained_root.join("!m6-socket").exists(),
        "M6 tombstone recovery unlinked a FIFO or socket"
    );
    assert_eq!(
        snapshot(retained_root),
        special_tree_before,
        "M6 tombstone recovery partially unlinked the owned tree"
    );
    drop(listener);
    fs::remove_file(retained_root.join("!m6-socket"))
        .expect("remove test-owned M6 tombstone socket");
    fs::remove_file(retained_root.join("!m6-fifo")).expect("remove test-owned M6 tombstone FIFO");
    assert_success(
        &normal_gc(&special_tree, &binaries.normal),
        "complete M6 tombstone after test-owned special cleanup",
    );
    assert!(
        special_tree.records().is_empty(),
        "completed M6 special tombstone retained a record"
    );
    special_tree.cleanup();
    artifacts.cleanup().expect("cleanup M6 GC binary artifacts");
}

#[test]
fn census_and_leases_fail_closed_without_mutation() {
    let mut artifacts = Sandbox::new();
    let binaries = build_m6_binaries(&artifacts);
    let mut fixture = Fixture::new(true);

    let other = fixture.sandbox.child("other-authority.git");
    git(
        &fixture.sandbox.path,
        &[
            OsString::from("init"),
            OsString::from("--bare"),
            other.as_os_str().to_os_string(),
        ],
    );
    git(
        &fixture.source,
        &[
            OsString::from("push"),
            other.as_os_str().to_os_string(),
            OsString::from("main:main"),
        ],
    );
    let mut other_dir = OsString::from("--git-dir=");
    other_dir.push(other.as_os_str());
    git(
        &fixture.sandbox.path,
        &[
            other_dir,
            OsString::from("symbolic-ref"),
            OsString::from("HEAD"),
            OsString::from("refs/heads/main"),
        ],
    );
    assert_success(
        &fixture.vws(vec![
            OsString::from("init"),
            other.as_os_str().to_os_string(),
        ]),
        "initialize second M6 authority",
    );
    assert_success(
        &fixture.create_for(&other, "other-authority", "main"),
        "create second-authority session",
    );

    crash_create(
        &fixture,
        &binaries.instrumented,
        "prepared",
        "prepared-record-parent-synced",
    );
    assert_eq!(payload_state(&fixture.record(b"prepared")), "PREPARED");
    crash_create(
        &fixture,
        &binaries.instrumented,
        "materializing",
        "materializing-record-parent-synced",
    );
    assert_eq!(
        payload_state(&fixture.record(b"materializing")),
        "MATERIALIZING"
    );
    assert_success(
        &fixture.create("tombstoned", "main"),
        "create tombstone source",
    );
    crash_remove(
        &fixture,
        &binaries.instrumented,
        "tombstoned",
        "tombstoned-record-parent-synced",
    );
    assert_eq!(payload_state(&fixture.record(b"tombstoned")), "TOMBSTONED");
    assert_success(
        &fixture.create("ready", "main"),
        "create ready census session",
    );

    let journals = [
        ("prepared-journal", "prepared-parent-synced", "PREPARED"),
        (
            "objects-journal",
            "objects-imported-parent-synced",
            "OBJECTS_IMPORTED",
        ),
        (
            "attempted-journal",
            "cas-attempted-parent-synced",
            "CAS_ATTEMPTED",
        ),
        (
            "committed-journal",
            "cas-committed-parent-synced",
            "CAS_COMMITTED",
        ),
    ];
    for (name, stage, state) in journals {
        assert_success(&fixture.create(name, "main"), &format!("create {name}"));
        commit_worktree(
            &fixture.worktree(name.as_bytes()),
            &format!("{name}.txt"),
            format!("M6 journal {state}\n").as_bytes(),
        );
        crash_publish(&fixture, &binaries.instrumented, name, stage);
        assert_eq!(journal_state(&fixture.record(name.as_bytes())), state);
    }

    let records = [
        b"prepared".as_slice(),
        b"materializing",
        b"tombstoned",
        b"ready",
        b"prepared-journal",
        b"objects-journal",
        b"attempted-journal",
        b"committed-journal",
    ];
    let keys: BTreeSet<_> = records
        .iter()
        .map(|name| fixture.template_key(name))
        .collect();
    assert!(
        keys.iter()
            .all(|key| fixture.template_record(key).is_file()),
        "legal session payload or publish journal lost its reachable template"
    );
    let rows = ndjson(
        &fixture.list(&fixture.authority),
        "list legal M6 census records",
    );
    for (name, _, state) in journals {
        let row = rows
            .iter()
            .find(|row| row_string(row, "name_hex") == hex(name.as_bytes()))
            .unwrap_or_else(|| panic!("list omitted {name}"));
        assert_eq!(row_string(row, "state"), "READY");
        assert_eq!(row_string(row, "publish_state"), state);
    }
    let all_rows = ndjson(
        &fixture.vws(vec![OsString::from("list"), OsString::from("--all")]),
        "list all M6 authorities",
    );
    assert!(
        all_rows
            .iter()
            .any(|row| row_string(row, "name_hex") == hex(b"other-authority")),
        "multi-authority census lost a registered session"
    );
    let blocked_before = snapshot(&fixture.state());
    assert_error(
        &fixture.gc(),
        "GC_RECOVERY_REQUIRED",
        "non-idle publish census must block GC",
    );
    assert_eq!(
        snapshot(&fixture.state()),
        blocked_before,
        "non-idle publish census mutated managed state"
    );
    for output in [
        fixture.create("attempted-journal", "main"),
        fixture.vws(fixture.exec_args(
            "attempted-journal",
            vec![
                real_shell().into_os_string(),
                OsString::from("-c"),
                OsString::from("exit 0"),
            ],
        )),
        fixture.remove("attempted-journal", true),
        fixture.vws(fixture.publish_args("attempted-journal")),
    ] {
        assert_error(
            &output,
            "PUBLISH_RECOVERY_REQUIRED",
            "non-idle publish did not fail closed",
        );
    }

    fs::write(fixture.sessions().join("unknown-m6-metadata"), b"unknown\n")
        .expect("write M6 unknown metadata negative fixture");
    fs::write(
        fixture.sessions().join("session-corrupt.record"),
        b"not JSON\n",
    )
    .expect("write M6 corrupt record negative fixture");
    let future = fixture.record_path(b"ready");
    let mut future_value = fixture.record(b"ready");
    future_value["version"] = Value::from(99_u64);
    atomic_replace(
        &future,
        &serde_json::to_vec(&future_value).expect("encode future M6 receipt"),
    );
    let negative_before = snapshot(&fixture.state());
    assert_error(
        &fixture.doctor(),
        "DOCTOR_RECOVERY_REQUIRED",
        "corrupt/future/unknown maintenance doctor",
    );
    assert_eq!(
        snapshot(&fixture.state()),
        negative_before,
        "doctor mutated corrupt or future evidence"
    );
    assert_error(
        &fixture.gc(),
        "GC_RECOVERY_REQUIRED",
        "corrupt/future/unknown maintenance GC",
    );
    assert_eq!(
        snapshot(&fixture.state()),
        negative_before,
        "GC mutated corrupt or future evidence"
    );
    fixture.cleanup();

    let mut counterexample = Fixture::new(true);
    assert_success(
        &counterexample.create("duplicate", "main"),
        "create duplicate loose counterexample session",
    );
    let private = counterexample.common(b"duplicate");
    let body = prefixed_object(&counterexample.cwd, &private, "00");
    let private_oid = hash_object(&counterexample.cwd, &private, &body, true);
    let authority_oid = hash_object(&counterexample.cwd, &counterexample.authority, &body, true);
    assert_eq!(private_oid, authority_oid, "M6 loose duplicate OID drifted");
    let fanout = free_fanout(&counterexample.authority.join("objects"));
    fs::write(
        counterexample.authority.join("objects").join(&fanout),
        b"ordinary authority object entry\n",
    )
    .expect("write later authority objects ordinary-file counterexample");
    let counter_before = snapshot(&counterexample.state());
    assert_error(
        &counterexample.gc(),
        "GC_RECOVERY_REQUIRED",
        "private 00 duplicate plus later authority object must fail closed",
    );
    assert_eq!(
        snapshot(&counterexample.state()),
        counter_before,
        "private 00 counterexample allowed partial GC mutation"
    );
    assert!(
        counterexample
            .common(b"duplicate")
            .join("objects")
            .join(&private_oid[..2])
            .join(&private_oid[2..])
            .is_file(),
        "private 00 duplicate was removed despite failed classification"
    );
    counterexample.cleanup();

    let mut lease = Fixture::new(true);
    assert_success(
        &lease.create("leased", "main"),
        "create shared-lease session",
    );
    let ready = lease.sandbox.child("lease-ready");
    let mutate = lease.sandbox.child("lease-mutate");
    let changed = lease.sandbox.child("lease-changed");
    let release = lease.sandbox.child("lease-release");
    let commit_graph = lease.common(b"leased").join("objects/info/commit-graph");
    let gate = "printf ready > \"$1\"\nwhile [ ! -e \"$2\" ]; do sleep 1; done\nprintf graph > \"$3\"\nprintf changed > \"$4\"\nwhile [ ! -e \"$5\" ]; do sleep 1; done";
    let child = lease
        .command_for(
            Path::new(env!("CARGO_BIN_EXE_git-vws")),
            lease.exec_args(
                "leased",
                vec![
                    real_shell().into_os_string(),
                    OsString::from("-c"),
                    OsString::from(gate),
                    OsString::from("m6-lease"),
                    ready.as_os_str().to_os_string(),
                    mutate.as_os_str().to_os_string(),
                    commit_graph.as_os_str().to_os_string(),
                    changed.as_os_str().to_os_string(),
                    release.as_os_str().to_os_string(),
                ],
            ),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shared M6 exec lease");
    wait_for(&ready, "M6 shared exec lease");
    let leased_before = snapshot(&lease.state());
    let busy = lease.gc();
    assert_success(&busy, "GC during shared M6 exec lease");
    let busy_lines = maintenance_lines(&busy, "GC during shared M6 exec lease");
    assert!(
        busy_lines
            .iter()
            .any(|line| line.get("code").and_then(Value::as_str) == Some("BUSY")),
        "GC did not report a busy shared lease: {busy:?}"
    );
    assert_eq!(
        snapshot(&lease.state()),
        leased_before,
        "GC mutated state while shared lease was held"
    );
    fs::write(&mutate, b"mutate\n").expect("release M6 shared exec write gate");
    wait_for(&changed, "M6 shared exec private metadata write");
    fs::write(&release, b"release\n").expect("release M6 shared exec lease");
    assert_success(
        &child.wait_with_output().expect("wait M6 shared exec"),
        "shared M6 exec",
    );
    let reclassified_before = snapshot(&lease.state());
    assert_error(
        &lease.gc(),
        "GC_RECOVERY_REQUIRED",
        "post-lease private metadata must be reclassified before GC",
    );
    assert_eq!(
        snapshot(&lease.state()),
        reclassified_before,
        "post-lease private metadata allowed GC mutation"
    );
    eprintln!("M6 private_objects_retained=ok");
    lease.cleanup();
    artifacts.cleanup().expect("cleanup M6 binary artifacts");
}
