#[path = "support/checkpoint.rs"]
mod checkpoint;

use checkpoint::{ArmReply, CheckpointController, CheckpointTarget};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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
        let parent_path = fs::canonicalize(env::temp_dir()).expect("canonical test parent");
        let parent = File::open(&parent_path).expect("open test parent");
        let name = CString::new(format!(
            "git-vws-m5-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("sandbox basename");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) },
            0,
            "create descriptor-owned M5 sandbox"
        );
        let root = open_directory(parent.as_raw_fd(), &name).expect("open M5 sandbox");
        assert_eq!(unsafe { libc::fchmod(root.as_raw_fd(), 0o700) }, 0);
        let node = node(&root).expect("stat M5 sandbox");
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
                "M5 retained descriptor-owned evidence: {}",
                self.path.display()
            );
            return;
        }
        self.cleanup().expect("descriptor-owned M5 sandbox cleanup");
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

struct GitTrace {
    directory: PathBuf,
    log: PathBuf,
    real_git: PathBuf,
    inherited_paths: Vec<PathBuf>,
}

impl GitTrace {
    fn new(sandbox: &Sandbox) -> Self {
        let directory = sandbox.child("git-wrapper");
        fs::create_dir(&directory).expect("create M5 Git wrapper directory");
        let log = sandbox.child("git-trace");
        fs::write(&log, b"").expect("create M5 Git trace");
        let wrapper = directory.join("git");
        fs::write(
            &wrapper,
            b"#!/bin/sh\n{\nprintf 'BEGIN\\n'\nfor argument do\nprintf '%s\\n' \"$argument\"\ndone\nprintf 'END\\n'\n} >> \"$M5_TRACE\"\nexec \"$M5_REAL_GIT\" \"$@\"\n",
        )
        .expect("write M5 Git wrapper");
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
            .expect("protect M5 Git wrapper");
        Self {
            directory,
            log,
            real_git: real_git(),
            inherited_paths: env::split_paths(&env::var_os("PATH").expect("PATH")).collect(),
        }
    }

    fn path(&self) -> OsString {
        let mut paths = vec![self.directory.clone()];
        paths.extend(self.inherited_paths.iter().cloned());
        env::join_paths(paths).expect("join trace PATH")
    }

    fn clear(&self) {
        fs::write(&self.log, b"").expect("clear M5 Git trace");
    }

    fn commands(&self) -> Vec<Vec<String>> {
        let trace = fs::read_to_string(&self.log).expect("read M5 Git trace");
        let mut commands = Vec::new();
        let mut current = None;
        for line in trace.lines() {
            match (line, current.as_mut()) {
                ("BEGIN", None) => current = Some(Vec::new()),
                ("END", Some(_)) => commands.push(current.take().expect("trace command")),
                (_, Some(arguments)) => arguments.push(line.to_owned()),
                _ => panic!("malformed M5 Git trace: {trace:?}"),
            }
        }
        assert!(current.is_none(), "unterminated M5 Git trace: {trace:?}");
        commands
    }

    fn count(&self, program: &str) -> usize {
        self.commands()
            .iter()
            .filter(|arguments| arguments.iter().any(|argument| argument == program))
            .count()
    }
}

struct Fixture {
    sandbox: Sandbox,
    home: PathBuf,
    authority: PathBuf,
    source: PathBuf,
    cwd: PathBuf,
    sibling: PathBuf,
    trace: GitTrace,
}

impl Fixture {
    fn new() -> Self {
        let sandbox = Sandbox::new();
        let (authority, source) = fixture_repo(&sandbox);
        let home = sandbox.child("home");
        fs::create_dir(&home).expect("create isolated M5 home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect M5 home");
        let cwd = sandbox.child("cwd");
        fs::create_dir(&cwd).expect("create protected M5 cwd");
        fs::write(cwd.join("cwd-sentinel"), b"M5 protected cwd\n").expect("write M5 cwd sentinel");
        let sibling = sandbox.child("sibling-sentinel");
        fs::write(&sibling, b"M5 protected sibling\n").expect("write M5 sibling sentinel");
        let trace = GitTrace::new(&sandbox);
        let fixture = Self {
            sandbox,
            home,
            authority,
            source,
            cwd,
            sibling,
            trace,
        };
        let initialized = fixture.vws(vec![
            OsString::from("init"),
            fixture.authority.as_os_str().to_os_string(),
        ]);
        assert_success(&initialized, "initialize M5 authority");
        fixture.trace.clear();
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
            .env("PATH", self.trace.path())
            .env("M5_TRACE", &self.trace.log)
            .env("M5_REAL_GIT", &self.trace.real_git)
            .current_dir(&self.cwd);
        command
    }

    fn vws_command(&self, args: Vec<OsString>) -> Command {
        self.command_for(Path::new(env!("CARGO_BIN_EXE_git-vws")), args)
    }

    fn vws(&self, args: Vec<OsString>) -> Output {
        self.vws_command(args).output().expect("run M5 git-vws")
    }

    fn repo_args(&self, mut command: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--repo"),
            self.authority.as_os_str().to_os_string(),
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

    fn create(&self, name: OsString, target: &str) -> Output {
        self.vws(self.create_args(name, target))
    }

    fn publish_args(&self, name: OsString) -> Vec<OsString> {
        self.repo_args(vec![OsString::from("publish"), name])
    }

    fn publish_hex_args(&self, name_hex: &str) -> Vec<OsString> {
        self.repo_args(vec![
            OsString::from("publish"),
            OsString::from("--name-hex"),
            OsString::from(name_hex),
        ])
    }

    fn publish(&self, name: &str) -> Output {
        self.vws(self.publish_args(OsString::from(name)))
    }

    fn publish_hex(&self, name_hex: &str) -> Output {
        self.vws(self.publish_hex_args(name_hex))
    }

    fn list(&self) -> Output {
        self.vws(self.repo_args(vec![OsString::from("list")]))
    }

    fn exec(&self, name: &str, program: Vec<OsString>) -> Output {
        let mut args = vec![
            OsString::from("exec"),
            OsString::from(name),
            OsString::from("--"),
        ];
        args.extend(program);
        self.vws(self.repo_args(args))
    }

    fn remove(&self, name: &str, force: bool) -> Output {
        let mut args = vec![OsString::from("remove"), OsString::from(name)];
        if force {
            args.push(OsString::from("--force"));
        }
        self.vws(self.repo_args(args))
    }

    fn record_path(&self, name: &[u8]) -> PathBuf {
        let expected = hex(name);
        let mut records: Vec<_> = fs::read_dir(self.sessions())
            .expect("read M5 session directory")
            .map(|entry| entry.expect("read M5 session entry").path())
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
                serde_json::from_slice::<Value>(&fs::read(path).expect("read M5 record"))
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
            .unwrap_or_else(|| panic!("missing M5 record for {}", String::from_utf8_lossy(name)))
    }

    fn record(&self, name: &[u8]) -> Value {
        serde_json::from_slice(&fs::read(self.record_path(name)).expect("read M5 record"))
            .expect("parse M5 record")
    }

    fn root(&self, name: &[u8]) -> PathBuf {
        let root_name = self
            .record(name)
            .pointer("/payload/READY/root_name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("M5 record was not READY"))
            .to_owned();
        self.sessions().join(root_name)
    }

    fn worktree(&self, name: &[u8]) -> PathBuf {
        self.root(name).join("worktree")
    }

    fn cleanup(&mut self) {
        self.sandbox.cleanup().expect("cleanup M5 fixture");
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
    git(&source, &git_args(&["config", "user.name", "M5 Test"]));
    git(
        &source,
        &git_args(&["config", "user.email", "m5@example.invalid"]),
    );
    fs::write(source.join("history"), b"base\n").expect("write M5 history");
    fs::write(source.join(".gitignore"), b"ignored/\n").expect("write M5 ignore");
    fs::create_dir(source.join("nested")).expect("create M5 nested directory");
    fs::write(source.join("nested/data"), b"M5 template data\n").expect("write M5 template data");
    git(&source, &git_args(&["add", "-A"]));
    git(&source, &git_args(&["commit", "-m", "M5 base"]));
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
    git_command(cwd, args).output().expect("run fixture Git")
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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

fn ndjson(output: &Output) -> Vec<Value> {
    assert_success(output, "M5 list");
    assert!(
        output.stdout.ends_with(b"\n") || output.stdout.is_empty(),
        "M5 NDJSON lacked final newline: {output:?}"
    );
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("parse M5 NDJSON"))
        .collect()
}

fn row_string<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing M5 {field} in {row}"))
}

fn commit_worktree(worktree: &Path, name: &str, body: &[u8]) -> String {
    git(worktree, &git_args(&["config", "user.name", "M5 Session"]));
    git(
        worktree,
        &git_args(&["config", "user.email", "session@example.invalid"]),
    );
    fs::write(worktree.join(name), body).expect("write M5 session change");
    git(worktree, &git_args(&["add", name]));
    git(
        worktree,
        &git_args(&["-c", "commit.gpgSign=false", "commit", "-m", name]),
    );
    object_id(
        &git_output(worktree, &git_args(&["rev-parse", "HEAD"])),
        "session HEAD",
    )
}

fn commit_source(fixture: &Fixture, name: &str, body: &[u8], push: bool) -> String {
    fs::write(fixture.source.join(name), body).expect("write M5 external change");
    git(&fixture.source, &git_args(&["add", name]));
    git(
        &fixture.source,
        &git_args(&["-c", "commit.gpgSign=false", "commit", "-m", name]),
    );
    let oid = object_id(
        &git_output(&fixture.source, &git_args(&["rev-parse", "HEAD"])),
        "external HEAD",
    );
    if push {
        git(&fixture.source, &git_args(&["push", "origin", "main"]));
    }
    oid
}

fn object_id(output: &Output, label: &str) -> String {
    assert_success(output, label);
    let body = output
        .stdout
        .strip_suffix(b"\n")
        .filter(|body| !body.contains(&b'\n'))
        .unwrap_or_else(|| panic!("{label} did not return one object ID: {output:?}"));
    let oid = std::str::from_utf8(body).expect("object ID UTF-8");
    assert!(
        !oid.is_empty() && oid.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} returned invalid object ID: {output:?}"
    );
    oid.to_owned()
}

fn snapshot(path: &Path) -> Vec<u8> {
    let mut output = Vec::new();
    snapshot_entry(path, path, &mut output, &|_| false, true);
    output
}

fn authority_non_publish_snapshot(authority: &Path, target: &str) -> Vec<u8> {
    let ref_path = format!("refs/heads/{target}").into_bytes();
    let reflog_path = format!("logs/refs/heads/{target}").into_bytes();
    let mut output = Vec::new();
    snapshot_entry(
        authority,
        authority,
        &mut output,
        &|relative| {
            relative == b"objects"
                || relative.starts_with(b"objects/")
                || relative == ref_path
                || relative == reflog_path
        },
        false,
    );
    output
}

fn snapshot_entry(
    root: &Path,
    path: &Path,
    output: &mut Vec<u8>,
    skip: &dyn Fn(&[u8]) -> bool,
    include_directory_nlink: bool,
) {
    let relative = path
        .strip_prefix(root)
        .expect("snapshot relative path")
        .as_os_str()
        .as_bytes();
    if !relative.is_empty() && skip(relative) {
        return;
    }
    let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
    output.extend_from_slice(relative);
    output.push(0);
    output.extend_from_slice(&metadata.mode().to_be_bytes());
    if include_directory_nlink || !metadata.is_dir() {
        output.extend_from_slice(&metadata.nlink().to_be_bytes());
    }
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
            snapshot_entry(root, &entry, output, skip, include_directory_nlink);
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

fn assert_publish_success(output: &Output, target: &str, expected: &str) {
    assert_success(output, "M5 publish");
    assert_eq!(
        output.stdout,
        format!("published {} {expected}\n", hex(target.as_bytes())).as_bytes()
    );
    assert!(
        output.stderr.is_empty(),
        "successful M5 publish emitted diagnostics: {output:?}"
    );
}

fn assert_authority_closure(authority: &Path, oid: &str) {
    let expression = format!("{oid}^{{commit}}");
    let output = git_output(authority, &git_args(&["cat-file", "-e", &expression]));
    assert_success(&output, "authority imported commit");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    let output = git_output(
        authority,
        &git_args(&[
            "fsck",
            "--connectivity-only",
            "--no-reflogs",
            "--no-dangling",
            "--no-progress",
            &expression,
        ]),
    );
    assert_success(&output, "authority imported closure");
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}

fn assert_no_publish_journal(record: &Value) {
    assert!(
        record.get("journal").is_none(),
        "IDLE M5 record serialized a journal: {record}"
    );
}

#[test]
fn publish_names_new_fast_forwards_and_private_objects_are_retained() {
    let mut fixture = Fixture::new();
    let raw_name = OsString::from_vec(b"raw-\xff-publish".to_vec());
    let raw_hex = hex(raw_name.as_bytes());
    assert_success(
        &fixture.create(raw_name.clone(), "main"),
        "create raw-name session",
    );
    let templates_before = snapshot(&fixture.templates());
    let protected_before = [snapshot(&fixture.cwd), snapshot(&fixture.sibling)];
    let raw_record = fixture.record(raw_name.as_bytes());
    assert_eq!(raw_record.get("version").and_then(Value::as_u64), Some(2));
    assert_eq!(
        raw_record
            .get("payload")
            .and_then(Value::as_object)
            .map(|payload| payload.len()),
        Some(1),
        "M5 record was not canonical READY payload"
    );
    assert_no_publish_journal(&raw_record);
    let rows = ndjson(&fixture.list());
    let raw_row = rows
        .iter()
        .find(|row| row_string(row, "name_hex") == raw_hex)
        .expect("list omitted raw M5 name");
    assert_eq!(row_string(raw_row, "state"), "READY");
    assert_eq!(row_string(raw_row, "publish_state"), "IDLE");
    let base = object_id(
        &git_output(
            &fixture.worktree(raw_name.as_bytes()),
            &git_args(&["rev-parse", "HEAD"]),
        ),
        "raw session base",
    );
    fixture.trace.clear();
    assert_publish_success(
        &fixture.vws(fixture.publish_args(raw_name.clone())),
        "main",
        &base,
    );
    assert_eq!(
        fixture.trace.count("fetch"),
        0,
        "same raw publish fetched objects"
    );
    assert_eq!(
        fixture.trace.count("update-ref"),
        0,
        "same raw publish attempted CAS"
    );
    fixture.trace.clear();
    assert_publish_success(&fixture.publish_hex(&raw_hex), "main", &base);
    assert_eq!(
        fixture.trace.count("update-ref"),
        0,
        "same --name-hex publish attempted CAS"
    );
    assert_no_publish_journal(&fixture.record(raw_name.as_bytes()));

    assert_success(
        &fixture.create(OsString::from("new-target"), "publish-new"),
        "create new-target publish session",
    );
    let new_name = b"new-target";
    let new_worktree = fixture.worktree(new_name);
    let new_oid = commit_worktree(&new_worktree, "new.txt", b"new target\n");
    let new_authority_before = authority_non_publish_snapshot(&fixture.authority, "publish-new");
    fixture.trace.clear();
    assert_publish_success(&fixture.publish("new-target"), "publish-new", &new_oid);
    assert_eq!(
        authority_non_publish_snapshot(&fixture.authority, "publish-new"),
        new_authority_before,
        "new-target publish wrote outside authority objects/ref/reflog"
    );
    assert_authority_closure(&fixture.authority, &new_oid);
    let new_record = fixture.record(new_name);
    assert_eq!(
        new_record.get("expected_old").and_then(Value::as_str),
        Some(new_oid.as_str()),
        "new target did not finalize expected_old"
    );
    assert_no_publish_journal(&new_record);

    assert_success(
        &fixture.create(OsString::from("fast"), "main"),
        "create fast-forward publish session",
    );
    let fast_name = b"fast";
    let fast_worktree = fixture.worktree(fast_name);
    let first = commit_worktree(&fast_worktree, "first.txt", b"first fast-forward\n");
    let first_before = authority_non_publish_snapshot(&fixture.authority, "main");
    fixture.trace.clear();
    assert_publish_success(&fixture.publish("fast"), "main", &first);
    assert_eq!(
        authority_non_publish_snapshot(&fixture.authority, "main"),
        first_before,
        "first fast-forward wrote outside authority objects/ref/reflog"
    );
    assert_authority_closure(&fixture.authority, &first);
    assert_eq!(
        fixture
            .record(fast_name)
            .get("expected_old")
            .and_then(Value::as_str),
        Some(first.as_str())
    );

    let second = commit_worktree(&fast_worktree, "second.txt", b"second fast-forward\n");
    let second_before = authority_non_publish_snapshot(&fixture.authority, "main");
    fixture.trace.clear();
    assert_publish_success(&fixture.publish("fast"), "main", &second);
    assert_eq!(
        authority_non_publish_snapshot(&fixture.authority, "main"),
        second_before,
        "second fast-forward wrote outside authority objects/ref/reflog"
    );
    assert_authority_closure(&fixture.authority, &second);
    let fast_record = fixture.record(fast_name);
    assert_eq!(
        fast_record.get("expected_old").and_then(Value::as_str),
        Some(second.as_str())
    );
    assert_no_publish_journal(&fast_record);

    git(
        &fast_worktree,
        &git_args(&["checkout", "-b", "private-only"]),
    );
    let private_oid = commit_worktree(&fast_worktree, "private.txt", b"retain private object\n");
    git(&fast_worktree, &git_args(&["checkout", "main"]));
    assert_success(
        &git_output(
            &fast_worktree,
            &git_args(&["cat-file", "-e", &format!("{private_oid}^{{commit}}")]),
        ),
        "private object remained reachable in session",
    );
    let authority_private = git_output(
        &fixture.authority,
        &git_args(&["cat-file", "-e", &format!("{private_oid}^{{commit}}")]),
    );
    assert!(
        !authority_private.status.success(),
        "private-only object leaked into authority: {authority_private:?}"
    );
    eprintln!("M5 private_objects_retained=ok");

    assert_eq!(snapshot(&fixture.templates()), templates_before);
    assert_eq!(snapshot(&fixture.cwd), protected_before[0]);
    assert_eq!(snapshot(&fixture.sibling), protected_before[1]);
    fixture.cleanup();
}

fn wait_for(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn list_row(fixture: &Fixture, name: &[u8]) -> Value {
    let expected = hex(name);
    ndjson(&fixture.list())
        .into_iter()
        .find(|row| row_string(row, "name_hex") == expected)
        .unwrap_or_else(|| panic!("list omitted session {}", String::from_utf8_lossy(name)))
}

#[test]
fn publish_same_non_fast_forward_and_lease_preserve_lifecycle_contract() {
    let mut fixture = Fixture::new();
    assert_success(
        &fixture.create(OsString::from("same"), "main"),
        "create same publish session",
    );
    let templates_before = snapshot(&fixture.templates());
    let protected_before = [snapshot(&fixture.cwd), snapshot(&fixture.sibling)];
    let same_oid = object_id(
        &git_output(
            &fixture.worktree(b"same"),
            &git_args(&["rev-parse", "HEAD"]),
        ),
        "same publish HEAD",
    );
    fixture.trace.clear();
    assert_publish_success(&fixture.publish("same"), "main", &same_oid);
    assert_eq!(
        fixture.trace.count("fetch"),
        0,
        "same publish fetched objects"
    );
    assert_eq!(
        fixture.trace.count("update-ref"),
        0,
        "same publish attempted an authority CAS"
    );
    assert_no_publish_journal(&fixture.record(b"same"));

    assert_success(
        &fixture.create(OsString::from("lease"), "main"),
        "create lease publish session",
    );
    let marker = fixture.sandbox.child("shared-lease-entered");
    let shell = find_executable("sh");
    let mut exec_args = vec![
        OsString::from("exec"),
        OsString::from("lease"),
        OsString::from("--"),
        shell.into_os_string(),
        OsString::from("-c"),
        OsString::from(format!(": > '{}'; sleep 2", marker.display())),
    ];
    let child = fixture
        .vws_command(fixture.repo_args(std::mem::take(&mut exec_args)))
        .spawn()
        .expect("spawn shared lease exec");
    wait_for(&marker, "shared lease program");
    assert_error(
        &fixture.publish("lease"),
        "SESSION_BUSY",
        "publish acquired an exclusive lease while exec was shared",
    );
    let status = child.wait_with_output().expect("reap shared lease exec");
    assert_success(&status, "shared lease exec");
    let lease_oid = object_id(
        &git_output(
            &fixture.worktree(b"lease"),
            &git_args(&["rev-parse", "HEAD"]),
        ),
        "lease publish HEAD",
    );
    fixture.trace.clear();
    assert_publish_success(&fixture.publish("lease"), "main", &lease_oid);
    assert_eq!(
        fixture.trace.count("update-ref"),
        0,
        "post-lease same publish attempted CAS"
    );

    assert_success(
        &fixture.create(OsString::from("nonff"), "main"),
        "create non-fast-forward session",
    );
    let local = commit_worktree(
        &fixture.worktree(b"nonff"),
        "local.txt",
        b"local non-fast-forward\n",
    );
    let external = commit_source(&fixture, "external.txt", b"external advance\n", true);
    fixture.trace.clear();
    assert_error(
        &fixture.publish("nonff"),
        "PUBLISH_NON_FAST_FORWARD",
        "non-fast-forward publish",
    );
    assert_eq!(
        fixture.trace.count("fetch"),
        0,
        "non-fast-forward publish imported objects"
    );
    assert_eq!(
        fixture.trace.count("update-ref"),
        0,
        "non-fast-forward publish attempted CAS"
    );
    assert_no_publish_journal(&fixture.record(b"nonff"));
    let row = list_row(&fixture, b"nonff");
    assert_eq!(row_string(&row, "state"), "READY");
    assert_eq!(row_string(&row, "publish_state"), "IDLE");
    let executable = fixture.exec(
        "nonff",
        vec![
            real_git().into_os_string(),
            OsString::from("status"),
            OsString::from("--porcelain=v1"),
        ],
    );
    assert_success(&executable, "non-fast-forward left lifecycle unusable");
    assert!(
        executable.stdout.starts_with(b"?? local.txt\n")
            || executable.stdout.is_empty()
            || executable.stdout.contains(&b'?'),
        "non-fast-forward exec did not reach the session worktree: {executable:?}"
    );
    assert_eq!(
        object_id(
            &git_output(
                &fixture.authority,
                &git_args(&["rev-parse", "refs/heads/main"]),
            ),
            "authority after external advance",
        ),
        external,
        "non-fast-forward publish changed authority main"
    );
    assert_ne!(local, external, "non-fast-forward fixture did not diverge");
    assert_eq!(snapshot(&fixture.templates()), templates_before);
    assert_eq!(snapshot(&fixture.cwd), protected_before[0]);
    assert_eq!(snapshot(&fixture.sibling), protected_before[1]);
    fixture.cleanup();
}

struct M5Binaries {
    instrumented: PathBuf,
    normal: PathBuf,
}

fn build_m5_binaries(sandbox: &Sandbox) -> M5Binaries {
    let instrumented_target = sandbox.child("instrumented-target");
    let normal_target = sandbox.child("normal-target");
    let instrumented = build_m5_binary(&instrumented_target, true);
    let normal = build_m5_binary(&normal_target, false);
    verify_normal_release_binary(&normal);
    M5Binaries {
        instrumented,
        normal,
    }
}

fn build_m5_binary(target_dir: &Path, instrumented: bool) -> PathBuf {
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
        target_dir.as_os_str().to_os_string(),
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
    let output = command.output().expect("build M5 test binary");
    assert_success(
        &output,
        if instrumented {
            "build instrumented M5 binary"
        } else {
            "build normal M5 binary"
        },
    );
    let binary = target_dir.join("release/git-vws");
    assert!(
        binary.is_file(),
        "M5 binary was absent: {}",
        binary.display()
    );
    binary
}

fn verify_normal_release_binary(binary: &Path) {
    let bytes = fs::read(binary).expect("read normal M5 binary");
    for marker in [
        b"M4CP/1".as_slice(),
        b"GIT_VWS_M4_CONTROL_FD",
        b"GIT_VWS_M4_NONCE",
        b"GIT_VWS_M4_TARGET",
        b"m4_checkpoint",
    ] {
        assert!(
            !bytes.windows(marker.len()).any(|window| window == marker),
            "normal M5 binary retained checkpoint bytes: {}",
            String::from_utf8_lossy(marker)
        );
    }
    for program in ["strings", "nm"] {
        let mut command = Command::new(find_executable(program));
        if program == "nm" {
            command.arg("-a");
        }
        let output = command.arg(binary).output().expect("run M5 binary scanner");
        assert_success(&output, &format!("{program} normal M5 binary"));
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
                "normal M5 {program} retained checkpoint marker: {}",
                String::from_utf8_lossy(marker)
            );
        }
    }
}

fn instrumented_publish_command(fixture: &Fixture, binary: &Path, name: &str) -> Command {
    fixture.command_for(binary, fixture.publish_args(OsString::from(name)))
}

fn journal_state(record: &Value) -> Option<&str> {
    record
        .get("journal")
        .and_then(Value::as_object)
        .and_then(|journal| {
            (journal.len() == 1).then(|| journal.keys().next().expect("one journal state").as_str())
        })
}

fn assert_event_suffix(events: &[checkpoint::Checkpoint], expected: &[&str], label: &str) {
    let actual: Vec<_> = events
        .iter()
        .filter(|event| event.operation == "publish")
        .map(|event| event.stage.as_str())
        .collect();
    assert!(
        actual.ends_with(expected),
        "{label} publish events were {actual:?}, expected suffix {expected:?}"
    );
}

fn force_authority_ref(authority: &Path, target: &str, new: &str, expected: &str) {
    git(
        authority,
        &git_args(&[
            "update-ref",
            "--no-deref",
            &format!("refs/heads/{target}"),
            new,
            expected,
        ]),
    );
}

fn authority_config_raw(fixture: &Fixture) -> Vec<u8> {
    let mut command = Command::new(real_git());
    remove_git_environment(&mut command);
    let output = command
        .current_dir(&fixture.cwd)
        .env("HOME", &fixture.home)
        .args([
            OsString::from("-C"),
            fixture.authority.as_os_str().to_os_string(),
            OsString::from("config"),
            OsString::from("--null"),
            OsString::from("--show-origin"),
            OsString::from("--show-scope"),
            OsString::from("--includes"),
            OsString::from("--list"),
        ])
        .output()
        .expect("read authority config fingerprint bytes");
    assert_success(&output, "read authority config fingerprint bytes");
    assert!(
        output.stderr.is_empty(),
        "authority config fingerprint diagnostics: {output:?}"
    );
    output.stdout
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(
        value.len() % 2 == 0
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "invalid lowercase test hex: {value}"
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => unreachable!(),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn number(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing M5 integer {pointer} in {value}"))
}

fn string<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing M5 string {pointer} in {value}"))
}

fn publish_txid(fixture: &Fixture, record: &Value, state: &str, config: &[u8]) -> String {
    let mut hasher = Sha256::new();
    let config_fingerprint = sha256_hex(config);
    let expected_old = record
        .pointer(&format!("/journal/{state}/expected_old"))
        .and_then(Value::as_str)
        .unwrap_or("-");
    let target = decode_hex(string(record, "/target"));
    let authority = fs::canonicalize(&fixture.authority).expect("canonical authority");
    for field in [
        b"git-vws/publish-id/v1".as_slice(),
        authority.as_os_str().as_bytes(),
        &number(record, "/authority_identity/dev").to_be_bytes(),
        &number(record, "/authority_identity/ino").to_be_bytes(),
        &(number(record, "/authority_identity/uid") as u32).to_be_bytes(),
        &(number(record, "/authority_identity/mode") as u32).to_be_bytes(),
        &(number(record, "/authority_identity/kind") as u32).to_be_bytes(),
        &number(record, "/authority_identity/nlink").to_be_bytes(),
        string(record, "/sid").as_bytes(),
        string(record, "/template_key").as_bytes(),
        &target,
        expected_old.as_bytes(),
        string(record, &format!("/journal/{state}/new")).as_bytes(),
        config_fingerprint.as_bytes(),
    ] {
        lp(&mut hasher, field);
    }
    hex(&hasher.finalize())
}

fn trace_command_indices(commands: &[Vec<String>], program: &str) -> Vec<usize> {
    commands
        .iter()
        .enumerate()
        .filter_map(|(index, arguments)| {
            arguments
                .iter()
                .any(|argument| argument == program)
                .then_some(index)
        })
        .collect()
}

fn atomic_replace(path: &Path, bytes: &[u8]) {
    let mut candidate = path.file_name().expect("record basename").to_os_string();
    candidate.push(".m5-tamper");
    let candidate = path.with_file_name(candidate);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&candidate)
        .expect("create controlled record tamper replacement");
    file.write_all(bytes)
        .expect("write controlled record tamper replacement");
    file.sync_all()
        .expect("sync controlled record tamper replacement");
    drop(file);
    fs::rename(&candidate, path).expect("install controlled record tamper replacement");
}

fn expected_publish_stages() -> Vec<&'static str> {
    vec![
        "prepared-temporary-synced",
        "prepared-namespace-applied",
        "prepared-exchange-old-unlinked",
        "prepared-parent-synced",
        "object-fetch-returned",
        "objects-imported-temporary-synced",
        "objects-imported-namespace-applied",
        "objects-imported-exchange-old-unlinked",
        "objects-imported-parent-synced",
        "cas-attempted-temporary-synced",
        "cas-attempted-namespace-applied",
        "cas-attempted-exchange-old-unlinked",
        "cas-attempted-parent-synced",
        "cas-child-returned-success",
        "cas-committed-temporary-synced",
        "cas-committed-namespace-applied",
        "cas-committed-exchange-old-unlinked",
        "cas-committed-parent-synced",
        "idle-finalized-temporary-synced",
        "idle-finalized-namespace-applied",
        "idle-finalized-exchange-old-unlinked",
        "idle-finalized-parent-synced",
        "return",
    ]
}

fn record_count(fixture: &Fixture) -> usize {
    fs::read_dir(fixture.sessions())
        .expect("read M5 sessions")
        .map(|entry| entry.expect("read M5 session entry").path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.as_bytes().ends_with(b".record"))
        })
        .count()
}

fn install_rejecting_reference_hook(fixture: &Fixture) -> (PathBuf, PathBuf) {
    let hooks = fixture.sandbox.child("authority-hooks");
    fs::create_dir(&hooks).expect("create authority hook directory");
    let sentinel = fixture.sandbox.child("reference-transaction-sentinel");
    let script = format!(
        "#!/bin/sh\ntarget=0\nwhile IFS=' ' read -r old new reference\ndo\n    if test \"$reference\" = refs/heads/main\n    then\n        target=1\n    fi\ndone\nif test \"$target\" -eq 1\nthen\n    printf '%s\\n' \"$1\" >> '{}'\n    if test \"$1\" = prepared\n    then\n        exit 1\n    fi\nfi\nexit 0\n",
        sentinel.display()
    );
    let hook = hooks.join("reference-transaction");
    fs::write(&hook, script).expect("write reference transaction hook");
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))
        .expect("protect reference transaction hook");
    git(
        &fixture.authority,
        &[
            OsString::from("config"),
            OsString::from("--local"),
            OsString::from("core.hooksPath"),
            hooks.as_os_str().to_os_string(),
        ],
    );
    (hooks, sentinel)
}

#[test]
fn publish_conflicts_and_compare_and_swap_fences_are_terminal() {
    let mut artifacts = Sandbox::new();
    let binaries = build_m5_binaries(&artifacts);

    let mut conflict = Fixture::new();
    assert_success(
        &conflict.create(OsString::from("conflict"), "main"),
        "create conflict session",
    );
    let conflict_worktree = conflict.worktree(b"conflict");
    commit_worktree(
        &conflict_worktree,
        "private.txt",
        b"private conflict candidate\n",
    );
    let mut controller = CheckpointController::start(
        instrumented_publish_command(&conflict, &binaries.instrumented, "conflict"),
        CheckpointTarget::new("publish", "object-fetch-returned"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("conflict controller ARM failed: {output:?}"));
    let checkpoint = controller.pause_at_target();
    let external = commit_source(
        &conflict,
        "external.txt",
        b"external conflict winner\n",
        true,
    );
    controller.release_target(&checkpoint);
    let run = controller.finish();
    assert_error(
        &run.output,
        "PUBLISH_CONFLICT",
        "external writer before CAS",
    );
    assert_event_suffix(
        &run.events,
        &[
            "conflict-aborted-temporary-synced",
            "conflict-aborted-namespace-applied",
            "conflict-aborted-exchange-old-unlinked",
            "conflict-aborted-parent-synced",
            "conflict-return",
        ],
        "pre-CAS conflict",
    );
    assert_no_publish_journal(&conflict.record(b"conflict"));
    let rebase = conflict.exec(
        "conflict",
        vec![
            real_git().into_os_string(),
            OsString::from("rebase"),
            OsString::from(&external),
        ],
    );
    assert_success(
        &rebase,
        "rebase conflicted private session through CLI exec",
    );
    let rebased = object_id(
        &git_output(&conflict_worktree, &git_args(&["rev-parse", "HEAD"])),
        "rebased conflict session",
    );
    conflict.trace.clear();
    assert_publish_success(&conflict.publish("conflict"), "main", &rebased);
    assert_authority_closure(&conflict.authority, &rebased);
    conflict.cleanup();

    let mut cas = Fixture::new();
    assert_success(
        &cas.create(OsString::from("cas"), "main"),
        "create CAS session",
    );
    commit_worktree(&cas.worktree(b"cas"), "cas.txt", b"CAS candidate\n");
    cas.trace.clear();
    let mut controller = CheckpointController::start(
        instrumented_publish_command(&cas, &binaries.instrumented, "cas"),
        CheckpointTarget::new("publish", "cas-attempted-parent-synced"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("CAS controller ARM failed: {output:?}"));
    let checkpoint = controller.pause_at_target();
    let external = commit_source(&cas, "cas-external.txt", b"CAS external winner\n", true);
    controller.release_target(&checkpoint);
    let run = controller.finish();
    assert_error(
        &run.output,
        "PUBLISH_RECOVERY_REQUIRED",
        "external writer won CAS",
    );
    assert_event_suffix(
        &run.events,
        &["cas-attempted-parent-synced", "cas-child-returned-nonzero"],
        "CAS nonzero",
    );
    assert_eq!(
        journal_state(&cas.record(b"cas")),
        Some("CAS_ATTEMPTED"),
        "CAS nonzero did not retain durable no-retry fence"
    );
    let row = list_row(&cas, b"cas");
    assert_eq!(row_string(&row, "state"), "READY");
    assert_eq!(row_string(&row, "publish_state"), "CAS_ATTEMPTED");
    assert_eq!(
        cas.trace.count("update-ref"),
        1,
        "CAS loser did not make exactly one update-ref attempt"
    );
    for (label, output) in [
        ("publish", cas.publish("cas")),
        (
            "exec",
            cas.exec(
                "cas",
                vec![real_git().into_os_string(), OsString::from("status")],
            ),
        ),
        ("remove", cas.remove("cas", false)),
        ("force remove", cas.remove("cas", true)),
        (
            "create reuse",
            cas.vws(cas.create_args(OsString::from("cas"), "main")),
        ),
    ] {
        assert_error(
            &output,
            "PUBLISH_RECOVERY_REQUIRED",
            &format!("CAS fence did not block {label}"),
        );
    }
    assert_eq!(
        object_id(
            &git_output(&cas.authority, &git_args(&["rev-parse", "refs/heads/main"]),),
            "authority after CAS conflict",
        ),
        external
    );
    cas.cleanup();

    let mut winner = Fixture::new();
    assert_success(
        &winner.create(OsString::from("winner"), "main"),
        "create VWS winner session",
    );
    let local = commit_worktree(
        &winner.worktree(b"winner"),
        "winner.txt",
        b"VWS wins first\n",
    );
    let external = commit_source(&winner, "override.txt", b"external override\n", false);
    winner.trace.clear();
    let mut controller = CheckpointController::start(
        instrumented_publish_command(&winner, &binaries.instrumented, "winner"),
        CheckpointTarget::new("publish", "cas-child-returned-success"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("winner controller ARM failed: {output:?}"));
    let checkpoint = controller.pause_at_target();
    assert_eq!(
        object_id(
            &git_output(
                &winner.authority,
                &git_args(&["rev-parse", "refs/heads/main"]),
            ),
            "authority after VWS CAS",
        ),
        local
    );
    git(
        &winner.authority,
        &[
            OsString::from("fetch"),
            OsString::from("--quiet"),
            OsString::from("--no-write-fetch-head"),
            winner.source.as_os_str().to_os_string(),
            OsString::from(&external),
        ],
    );
    force_authority_ref(&winner.authority, "main", &external, &local);
    controller.release_target(&checkpoint);
    let run = controller.finish();
    assert_publish_success(&run.output, "main", &local);
    assert_event_suffix(
        &run.events,
        &[
            "cas-child-returned-success",
            "cas-committed-temporary-synced",
            "cas-committed-namespace-applied",
            "cas-committed-exchange-old-unlinked",
            "cas-committed-parent-synced",
            "idle-finalized-temporary-synced",
            "idle-finalized-namespace-applied",
            "idle-finalized-exchange-old-unlinked",
            "idle-finalized-parent-synced",
            "return",
        ],
        "VWS CAS winner",
    );
    assert_eq!(
        winner.trace.count("update-ref"),
        1,
        "VWS winner replayed or rolled back CAS"
    );
    assert_eq!(
        object_id(
            &git_output(
                &winner.authority,
                &git_args(&["rev-parse", "refs/heads/main"]),
            ),
            "authority after external override",
        ),
        external,
        "VWS finalization rolled back external override"
    );
    assert_no_publish_journal(&winner.record(b"winner"));
    winner.cleanup();
    artifacts
        .cleanup()
        .expect("cleanup M5 instrumented artifact sandbox");
}

#[test]
fn publish_authority_audit_fixed_oid_and_crash_prefix_contract() {
    let mut artifacts = Sandbox::new();
    let binaries = build_m5_binaries(&artifacts);

    let mut wrong_arm = Fixture::new();
    assert_success(
        &wrong_arm.create(OsString::from("wrong-arm"), "main"),
        "create wrong-ARM session",
    );
    commit_worktree(
        &wrong_arm.worktree(b"wrong-arm"),
        "wrong-arm.txt",
        b"wrong ARM must fail closed\n",
    );
    wrong_arm.trace.clear();
    let wrong_arm_output = match CheckpointController::start(
        instrumented_publish_command(&wrong_arm, &binaries.instrumented, "wrong-arm"),
        CheckpointTarget::new("publish", "prepared-temporary-synced"),
        ArmReply::Wrong,
    ) {
        Ok(_) => panic!("instrumented publish accepted a wrong controller ARM"),
        Err(output) => output,
    };
    assert!(
        !wrong_arm_output.status.success(),
        "wrong controller ARM did not fail closed: {wrong_arm_output:?}"
    );
    assert_eq!(
        wrong_arm.trace.count("update-ref"),
        0,
        "wrong ARM reached CAS"
    );
    wrong_arm.cleanup();

    let mut bad_frame = Fixture::new();
    assert_success(
        &bad_frame.create(OsString::from("bad-frame"), "main"),
        "create bad-frame session",
    );
    commit_worktree(
        &bad_frame.worktree(b"bad-frame"),
        "bad-frame.txt",
        b"bad frame must fail closed\n",
    );
    bad_frame.trace.clear();
    let bad_frame_output = CheckpointController::start(
        instrumented_publish_command(&bad_frame, &binaries.instrumented, "bad-frame"),
        CheckpointTarget::new("publish", "prepared-temporary-synced"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("bad-frame controller ARM failed: {output:?}"))
    .fault_at_first(checkpoint::ProtocolFault::BadFrame);
    assert!(
        !bad_frame_output.status.success(),
        "bad controller frame did not fail closed: {bad_frame_output:?}"
    );
    assert_eq!(
        bad_frame.trace.count("update-ref"),
        0,
        "bad frame reached CAS"
    );
    assert_no_publish_journal(&bad_frame.record(b"bad-frame"));
    bad_frame.cleanup();
    let _ = [
        checkpoint::ProtocolFault::WrongSequence,
        checkpoint::ProtocolFault::Eof,
        checkpoint::ProtocolFault::Timeout,
    ];

    for (key, value) in [
        ("include.path", "authority-include"),
        ("filter.lfs.process", "false"),
        ("url.https://example.invalid/.insteadof", "m5://"),
        ("core.alternaterefscommand", "false"),
        ("remote.origin.uploadpack", "false"),
        ("remote.origin.vcs", "false"),
        ("remote.origin.promisor", "true"),
        ("remote.origin.partialclonefilter", "blob:none"),
        ("fsck.skiplist", "/dev/null"),
    ] {
        let mut hostile = Fixture::new();
        assert_success(
            &hostile.create(OsString::from("hostile"), "main"),
            "create hostile-config session",
        );
        commit_worktree(
            &hostile.worktree(b"hostile"),
            "hostile.txt",
            b"hostile authority config candidate\n",
        );
        let value = if key == "include.path" {
            let include = hostile.sandbox.child(value);
            fs::write(&include, b"").expect("write hostile include source");
            include.to_string_lossy().into_owned()
        } else {
            value.to_owned()
        };
        git(
            &hostile.authority,
            &[
                OsString::from("config"),
                OsString::from("--local"),
                OsString::from(key),
                OsString::from(value),
            ],
        );
        let authority_before = authority_non_publish_snapshot(&hostile.authority, "main");
        hostile.trace.clear();
        assert_error(
            &hostile.publish("hostile"),
            "PUBLISH_VERIFY_FAILED",
            &format!("authority config {key} was accepted"),
        );
        assert_eq!(
            hostile.trace.count("fetch"),
            0,
            "authority config {key} reached fixed-OID fetch"
        );
        assert_eq!(
            hostile.trace.count("update-ref"),
            0,
            "authority config {key} reached publish CAS"
        );
        assert_no_publish_journal(&hostile.record(b"hostile"));
        assert_eq!(
            record_count(&hostile),
            1,
            "hostile config duplicated a record"
        );
        assert_eq!(
            authority_non_publish_snapshot(&hostile.authority, "main"),
            authority_before,
            "authority config {key} wrote outside the publish whitelist"
        );
        hostile.cleanup();
    }

    let mut hook = Fixture::new();
    assert_success(
        &hook.create(OsString::from("hook"), "main"),
        "create reference-transaction hook session",
    );
    let (_, hook_sentinel) = install_rejecting_reference_hook(&hook);
    let hooks_before = authority_config_raw(&hook);
    assert!(
        hooks_before
            .windows(b"core.hookspath\n".len())
            .any(|entry| entry == b"core.hookspath\n"),
        "authority core.hooksPath was not visible to the audit"
    );
    let same = object_id(
        &git_output(&hook.worktree(b"hook"), &git_args(&["rev-parse", "HEAD"])),
        "hook same HEAD",
    );
    hook.trace.clear();
    assert_publish_success(&hook.publish("hook"), "main", &same);
    assert!(
        !hook_sentinel.exists(),
        "same publish ran reference transaction hook"
    );
    assert_eq!(hook.trace.count("fetch"), 0, "same hook publish fetched");
    assert_eq!(
        hook.trace.count("update-ref"),
        0,
        "same hook publish used CAS"
    );
    let private = commit_worktree(
        &hook.worktree(b"hook"),
        "hook.txt",
        b"reference transaction must reject\n",
    );
    let authority_before = authority_non_publish_snapshot(&hook.authority, "main");
    hook.trace.clear();
    assert_error(
        &hook.publish("hook"),
        "PUBLISH_RECOVERY_REQUIRED",
        "reference-transaction rejection",
    );
    let hook_phases = fs::read(&hook_sentinel).expect("read reference-transaction sentinel");
    assert!(
        hook_phases == b"prepared\naborted\n" || hook_phases == b"preparing\nprepared\naborted\n",
        "reference-transaction hook did not reject then abort the target transaction: {:?}",
        String::from_utf8_lossy(&hook_phases)
    );
    assert_eq!(
        journal_state(&hook.record(b"hook")),
        Some("CAS_ATTEMPTED"),
        "hook rejection did not retain the no-retry fence"
    );
    assert_eq!(
        hook.trace.count("update-ref"),
        1,
        "hook rejection skipped CAS"
    );
    assert_eq!(
        object_id(
            &git_output(
                &hook.authority,
                &git_args(&["rev-parse", "refs/heads/main"]),
            ),
            "authority after rejecting hook",
        ),
        same,
        "rejecting hook changed authority target"
    );
    assert_ne!(
        private, same,
        "hook fixture did not create a new private commit"
    );
    assert_eq!(
        authority_config_raw(&hook),
        hooks_before,
        "publish changed authority core.hooksPath"
    );
    assert_eq!(
        authority_non_publish_snapshot(&hook.authority, "main"),
        authority_before,
        "hook rejection wrote outside authority objects/ref/reflog"
    );
    hook.cleanup();

    let mut audited = Fixture::new();
    assert_success(
        &audited.create(OsString::from("audited"), "main"),
        "create authority-audit session",
    );
    let old = object_id(
        &git_output(
            &audited.authority,
            &git_args(&["rev-parse", "refs/heads/main"]),
        ),
        "authority before fixed-OID publish",
    );
    let new = commit_worktree(
        &audited.worktree(b"audited"),
        "audited.txt",
        b"fixed object publish\n",
    );
    let config_before = authority_config_raw(&audited);
    let authority_before = authority_non_publish_snapshot(&audited.authority, "main");
    let protected_before = [
        snapshot(&audited.templates()),
        snapshot(&audited.cwd),
        snapshot(&audited.sibling),
    ];
    audited.trace.clear();
    let mut controller = CheckpointController::start(
        instrumented_publish_command(&audited, &binaries.instrumented, "audited"),
        CheckpointTarget::new("publish", "cas-attempted-parent-synced"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("authority-audit controller ARM failed: {output:?}"));
    let checkpoint = controller.pause_at_target();
    let active = audited.record(b"audited");
    assert_eq!(journal_state(&active), Some("CAS_ATTEMPTED"));
    assert_eq!(
        string(&active, "/journal/CAS_ATTEMPTED/config_fingerprint"),
        sha256_hex(&config_before),
        "authority audit fingerprint did not bind raw config bytes"
    );
    let txid = publish_txid(&audited, &active, "CAS_ATTEMPTED", &config_before);
    assert_eq!(
        string(&active, "/journal/CAS_ATTEMPTED/txid"),
        txid,
        "publish txid did not independently recompute"
    );
    assert_eq!(
        checkpoint.key, txid,
        "checkpoint key was not the publish txid"
    );
    let sid = string(&active, "/sid").to_owned();
    controller.release_target(&checkpoint);
    let run = controller.run_all();
    assert_publish_success(&run.output, "main", &new);
    let events: Vec<_> = run
        .events
        .iter()
        .filter(|event| event.operation == "publish")
        .collect();
    let observed: Vec<_> = events.iter().map(|event| event.stage.as_str()).collect();
    assert_eq!(
        observed,
        expected_publish_stages(),
        "successful publish checkpoints"
    );
    assert_eq!(events.len(), 23, "successful publish checkpoint count");
    for event in &events {
        assert_eq!(event.sid, sid, "publish checkpoint sid changed");
        assert_eq!(event.key, txid, "publish checkpoint txid changed");
    }
    assert_eq!(
        audited.trace.count("update-ref"),
        1,
        "successful publish CAS count"
    );
    assert_authority_closure(&audited.authority, &new);
    assert_eq!(
        authority_non_publish_snapshot(&audited.authority, "main"),
        authority_before,
        "fixed-OID publish wrote authority config, hooks, or worktree metadata"
    );
    assert_eq!(
        authority_config_raw(&audited),
        config_before,
        "authority config changed across publish audit boundaries"
    );
    let commands = audited.trace.commands();
    let audit_arguments = vec![
        "-C".to_owned(),
        audited.authority.to_string_lossy().into_owned(),
        "config".to_owned(),
        "--null".to_owned(),
        "--show-origin".to_owned(),
        "--show-scope".to_owned(),
        "--includes".to_owned(),
        "--list".to_owned(),
    ];
    let audit_positions = trace_command_indices(&commands, "config");
    assert_eq!(audit_positions.len(), 4, "authority audit boundary count");
    for position in &audit_positions {
        assert_eq!(
            &commands[*position], &audit_arguments,
            "authority audit did not use exact raw-config argv"
        );
    }
    let fetch_arguments = vec![
        "-C".to_owned(),
        audited.authority.to_string_lossy().into_owned(),
        "fetch".to_owned(),
        "--quiet".to_owned(),
        "--no-write-fetch-head".to_owned(),
        "--no-tags".to_owned(),
        "--no-auto-maintenance".to_owned(),
        "--no-write-commit-graph".to_owned(),
        "--recurse-submodules=no".to_owned(),
        audited
            .root(b"audited")
            .join("common.git")
            .to_string_lossy()
            .into_owned(),
        new.clone(),
    ];
    let fetch_positions = trace_command_indices(&commands, "fetch");
    assert_eq!(fetch_positions.len(), 1, "fixed-OID fetch count");
    assert_eq!(
        &commands[fetch_positions[0]], &fetch_arguments,
        "fixed-OID fetch argv wrote a destination refspec or FETCH_HEAD"
    );
    let cas_arguments = vec![
        "-C".to_owned(),
        audited.authority.to_string_lossy().into_owned(),
        "update-ref".to_owned(),
        "--no-deref".to_owned(),
        "refs/heads/main".to_owned(),
        new.clone(),
        old.clone(),
    ];
    let cas_positions = trace_command_indices(&commands, "update-ref");
    assert_eq!(cas_positions.len(), 1, "successful fixed-OID CAS count");
    assert_eq!(
        &commands[cas_positions[0]], &cas_arguments,
        "publish CAS argv was not exact"
    );
    assert!(
        audit_positions[0] < audit_positions[1] && audit_positions[1] < fetch_positions[0],
        "missing frozen/pre-fetch authority audits"
    );
    assert!(
        fetch_positions[0] < audit_positions[2] && audit_positions[2] < audit_positions[3],
        "missing post-fetch/pre-CAS authority audits"
    );
    assert!(
        audit_positions[3] < cas_positions[0],
        "authority config was not audited before CAS"
    );
    assert!(
        !audited.authority.join("FETCH_HEAD").exists(),
        "fixed-OID fetch wrote authority FETCH_HEAD"
    );
    assert!(
        !audited.authority.join("refs/remotes").exists(),
        "fixed-OID fetch created remote-tracking refs"
    );
    let refs = git_output(
        &audited.authority,
        &git_args(&["for-each-ref", "--format=%(refname)"]),
    );
    assert_success(&refs, "list authority refs after fixed-OID publish");
    assert_eq!(
        refs.stdout, b"refs/heads/main\n",
        "publish created an extra authority ref"
    );
    assert_eq!(snapshot(&audited.templates()), protected_before[0]);
    assert_eq!(snapshot(&audited.cwd), protected_before[1]);
    assert_eq!(snapshot(&audited.sibling), protected_before[2]);
    assert_no_publish_journal(&audited.record(b"audited"));
    audited.cleanup();

    let mut tamper = Fixture::new();
    assert_success(
        &tamper.create(OsString::from("tamper"), "main"),
        "create txid-tamper session",
    );
    commit_worktree(
        &tamper.worktree(b"tamper"),
        "tamper.txt",
        b"txid tamper candidate\n",
    );
    tamper.trace.clear();
    let tamper_run = CheckpointController::start(
        instrumented_publish_command(&tamper, &binaries.instrumented, "tamper"),
        CheckpointTarget::new("publish", "prepared-parent-synced"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("txid-tamper controller ARM failed: {output:?}"))
    .crash_at_target();
    assert_eq!(
        tamper_run.events.last().map(|event| event.stage.as_str()),
        Some("prepared-parent-synced"),
        "txid tamper did not reach durable PREPARED"
    );
    let mut record = tamper.record(b"tamper");
    let raw = authority_config_raw(&tamper);
    assert_eq!(journal_state(&record), Some("PREPARED"));
    assert_eq!(
        string(&record, "/journal/PREPARED/txid"),
        publish_txid(&tamper, &record, "PREPARED", &raw),
        "PREPARED txid did not independently recompute"
    );
    *record
        .pointer_mut("/journal/PREPARED/txid")
        .expect("locate prepared txid") = Value::String("0".repeat(64));
    atomic_replace(
        &tamper.record_path(b"tamper"),
        &serde_json::to_vec(&record).expect("encode controlled txid tamper"),
    );
    assert_eq!(record_count(&tamper), 1, "txid tamper duplicated record");
    assert_error(
        &tamper
            .command_for(
                &binaries.normal,
                tamper.publish_args(OsString::from("tamper")),
            )
            .output()
            .expect("run normal txid tamper recovery"),
        "SESSION_CORRUPT",
        "tampered txid was accepted",
    );
    assert_eq!(
        tamper.trace.count("update-ref"),
        0,
        "tampered txid reached CAS"
    );
    tamper.cleanup();

    let mut same = Fixture::new();
    assert_success(
        &same.create(OsString::from("same-crash"), "main"),
        "create same-return crash session",
    );
    let same_oid = object_id(
        &git_output(
            &same.worktree(b"same-crash"),
            &git_args(&["rev-parse", "HEAD"]),
        ),
        "same-return crash HEAD",
    );
    same.trace.clear();
    let same_run = CheckpointController::start(
        instrumented_publish_command(&same, &binaries.instrumented, "same-crash"),
        CheckpointTarget::new("publish", "same-return"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("same-return controller ARM failed: {output:?}"))
    .crash_at_target();
    assert_eq!(
        same_run.events.last().map(|event| event.stage.as_str()),
        Some("same-return"),
        "same-return branch did not emit its checkpoint"
    );
    assert_publish_success(
        &same
            .command_for(
                &binaries.normal,
                same.publish_args(OsString::from("same-crash")),
            )
            .output()
            .expect("run normal same-return recovery"),
        "main",
        &same_oid,
    );
    assert_eq!(same.trace.count("fetch"), 0, "same-return recovery fetched");
    assert_eq!(
        same.trace.count("update-ref"),
        0,
        "same-return recovery used CAS"
    );
    same.cleanup();

    for stage in expected_publish_stages() {
        let mut recovery = Fixture::new();
        assert_success(
            &recovery.create(OsString::from("crash"), "main"),
            "create crash-prefix session",
        );
        let old = object_id(
            &git_output(
                &recovery.authority,
                &git_args(&["rev-parse", "refs/heads/main"]),
            ),
            "authority before crash-prefix publish",
        );
        let new = commit_worktree(
            &recovery.worktree(b"crash"),
            "crash.txt",
            format!("crash prefix {stage}\n").as_bytes(),
        );
        recovery.trace.clear();
        let crashed = CheckpointController::start(
            instrumented_publish_command(&recovery, &binaries.instrumented, "crash"),
            CheckpointTarget::new("publish", stage),
            ArmReply::Exact,
        )
        .unwrap_or_else(|output| {
            panic!("crash-prefix controller ARM failed at {stage}: {output:?}")
        })
        .crash_at_target();
        assert_eq!(
            crashed.events.last().map(|event| event.stage.as_str()),
            Some(stage),
            "crash-prefix target was not reached"
        );
        let durable = journal_state(&recovery.record(b"crash")).map(str::to_owned);
        let recovered = recovery
            .command_for(
                &binaries.normal,
                recovery.publish_args(OsString::from("crash")),
            )
            .output()
            .expect("run normal crash-prefix recovery");
        assert!(
            recovery.trace.count("update-ref") <= 1,
            "crash prefix {stage} replayed publish CAS"
        );
        match durable.as_deref() {
            Some("CAS_ATTEMPTED") => {
                assert_error(
                    &recovered,
                    "PUBLISH_RECOVERY_REQUIRED",
                    &format!("CAS_ATTEMPTED crash prefix {stage}"),
                );
                assert_eq!(
                    journal_state(&recovery.record(b"crash")),
                    Some("CAS_ATTEMPTED"),
                    "CAS_ATTEMPTED crash prefix {stage} lost its no-retry fence"
                );
                let current = object_id(
                    &git_output(
                        &recovery.authority,
                        &git_args(&["rev-parse", "refs/heads/main"]),
                    ),
                    "authority after CAS_ATTEMPTED crash",
                );
                assert!(
                    current == old || current == new,
                    "CAS_ATTEMPTED crash prefix {stage} changed authority unexpectedly"
                );
            }
            None | Some("PREPARED") | Some("OBJECTS_IMPORTED") | Some("CAS_COMMITTED") => {
                assert_publish_success(&recovered, "main", &new);
                assert_no_publish_journal(&recovery.record(b"crash"));
                assert_eq!(
                    object_id(
                        &git_output(
                            &recovery.authority,
                            &git_args(&["rev-parse", "refs/heads/main"]),
                        ),
                        "authority after crash-prefix recovery",
                    ),
                    new,
                    "crash prefix {stage} did not converge authority"
                );
                assert_authority_closure(&recovery.authority, &new);
            }
            Some(state) => panic!("unexpected crash-prefix journal state {state} at {stage}"),
        }
        assert_eq!(
            record_count(&recovery),
            1,
            "crash prefix {stage} duplicated record"
        );
        recovery.cleanup();
    }

    artifacts
        .cleanup()
        .expect("cleanup M5 authority/crash instrumented artifacts");
}
