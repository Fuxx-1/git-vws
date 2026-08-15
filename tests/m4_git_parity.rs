#[path = "support/checkpoint.rs"]
mod checkpoint;

use checkpoint::{
    lower_hex, ArmReply, CheckpointController, CheckpointTarget, ProtocolFault,
    M4_CONTROL_DESTINATION_FD,
};
use serde_json::Value;
use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
        let parent_path = fs::canonicalize(env::temp_dir()).expect("canonical test parent");
        let parent = File::open(&parent_path).expect("open test parent");
        let name = CString::new(format!(
            "git-vws-m4-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("sandbox basename");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) },
            0,
            "create descriptor-owned sandbox"
        );
        let root = open_directory(parent.as_raw_fd(), &name).expect("open sandbox");
        assert_eq!(unsafe { libc::fchmod(root.as_raw_fd(), 0o700) }, 0);
        let node = node(&root).expect("stat sandbox");
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
                "M4 retained descriptor-owned evidence: {}",
                self.path.display()
            );
            return;
        }
        self.cleanup().expect("descriptor-owned M4 sandbox cleanup");
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
    cwd: PathBuf,
    sibling: PathBuf,
}

impl Fixture {
    fn new(large_blob: bool) -> Self {
        let sandbox = Sandbox::new();
        let authority = fixture_repo(&sandbox, large_blob);
        let home = sandbox.child("home");
        fs::create_dir(&home).expect("create isolated home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect home");
        let cwd = sandbox.child("cwd");
        fs::create_dir(&cwd).expect("create protected cwd");
        fs::write(cwd.join("cwd-sentinel"), b"M4 protected cwd\n").expect("write cwd sentinel");
        let sibling = sandbox.child("sibling-sentinel");
        fs::write(&sibling, b"M4 protected sibling\n").expect("write sibling sentinel");
        let fixture = Self {
            sandbox,
            home,
            authority,
            cwd,
            sibling,
        };
        let initialized = fixture.vws(vec![
            OsString::from("init"),
            fixture.authority.as_os_str().to_os_string(),
        ]);
        assert_success(&initialized, "initialize M4 authority");
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

    fn vws_command(&self, args: Vec<OsString>) -> Command {
        self.command_for(Path::new(env!("CARGO_BIN_EXE_git-vws")), args)
    }

    fn vws(&self, args: Vec<OsString>) -> Output {
        self.vws_command(args).output().expect("run git-vws")
    }

    fn repo_args(&self, mut command: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--repo"),
            self.authority.as_os_str().to_os_string(),
        ];
        args.append(&mut command);
        args
    }

    fn create_args(&self, name: &str, target: &str) -> Vec<OsString> {
        self.repo_args(vec![
            OsString::from("create"),
            OsString::from(name),
            OsString::from("--target"),
            OsString::from(target),
        ])
    }

    fn create(&self, name: &str, target: &str) -> Output {
        self.vws(self.create_args(name, target))
    }

    fn remove(&self, name: &str, force: bool) -> Output {
        self.vws(self.remove_args(name, force))
    }

    fn remove_args(&self, name: &str, force: bool) -> Vec<OsString> {
        let mut args = vec![OsString::from("remove"), OsString::from(name)];
        if force {
            args.push(OsString::from("--force"));
        }
        self.repo_args(args)
    }

    fn list(&self) -> Output {
        self.vws(self.repo_args(vec![OsString::from("list")]))
    }

    fn exec_args(&self, name: &str, mut program: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("exec"),
            OsString::from(name),
            OsString::from("--"),
        ];
        args.append(&mut program);
        self.repo_args(args)
    }

    fn roots(&self) -> Vec<PathBuf> {
        children_with_suffix(&self.sessions(), ".root")
    }

    fn records(&self) -> Vec<PathBuf> {
        children_with_suffix(&self.sessions(), ".record")
    }

    fn cleanup(&mut self) {
        self.sandbox.cleanup().expect("cleanup M4 fixture");
    }
}

fn fixture_repo(sandbox: &Sandbox, large_blob: bool) -> PathBuf {
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
    git(&source, &git_args(&["config", "user.name", "M4 Test"]));
    git(
        &source,
        &git_args(&["config", "user.email", "m4@example.invalid"]),
    );
    fs::create_dir(source.join("nested")).expect("create source directory");
    fs::write(source.join("nested/data"), b"template data\n").expect("write source data");
    fs::write(source.join("history"), b"base\n").expect("write source history");
    fs::write(source.join(".gitignore"), b"ignored/\n").expect("write ignore rule");
    fs::write(source.join("run"), b"#!/bin/sh\nprintf 'M4\\n'\n").expect("write executable");
    fs::set_permissions(source.join("run"), fs::Permissions::from_mode(0o755))
        .expect("protect executable");
    std::os::unix::fs::symlink("nested/data", source.join("link")).expect("create source symlink");
    if large_blob {
        fs::write(source.join("cow.bin"), vec![0x5a; 2 * 1024 * 1024]).expect("write COW blob");
    }
    git(&source, &git_args(&["add", "-A"]));
    git(&source, &git_args(&["commit", "-m", "fixture base"]));
    fs::write(source.join("history"), b"head\n").expect("write second history");
    git(&source, &git_args(&["add", "history"]));
    git(&source, &git_args(&["commit", "-m", "fixture head"]));
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
        &[
            OsString::from("push"),
            OsString::from("origin"),
            OsString::from("HEAD:refs/heads/main"),
        ],
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

fn real_shell() -> PathBuf {
    find_executable("sh")
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

fn git_with_dates(cwd: &Path, args: &[OsString], timestamp: &str) -> Output {
    let output = git_command(cwd, args)
        .env("GIT_AUTHOR_DATE", timestamp)
        .env("GIT_COMMITTER_DATE", timestamp)
        .output()
        .expect("run dated fixture Git");
    assert_success(&output, &format!("dated fixture Git {args:?}"));
    output
}

fn git_commit(cwd: &Path, message: &str, timestamp: &str) -> Output {
    git_with_dates(cwd, &git_args(&["commit", "-m", message]), timestamp)
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

fn snapshot(path: &Path) -> Vec<u8> {
    let mut output = Vec::new();
    snapshot_entry(path, path, &mut output, false);
    output
}

fn worktree_snapshot(path: &Path) -> Vec<u8> {
    let mut output = Vec::new();
    snapshot_entry(path, path, &mut output, true);
    output
}

fn snapshot_entry(root: &Path, path: &Path, output: &mut Vec<u8>, omit_git: bool) {
    let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
    output.extend_from_slice(
        path.strip_prefix(root)
            .expect("snapshot relative path")
            .as_os_str()
            .as_bytes(),
    );
    output.push(0);
    output.extend_from_slice(&metadata.mode().to_be_bytes());
    let nlink = if omit_git && path == root {
        0
    } else {
        metadata.nlink()
    };
    output.extend_from_slice(&nlink.to_be_bytes());
    if metadata.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read snapshot directory")
            .map(|entry| entry.expect("snapshot entry").path())
            .filter(|entry| {
                !omit_git
                    || entry
                        .file_name()
                        .is_none_or(|name| name.as_bytes() != b".git")
            })
            .collect();
        entries.sort_by(|left, right| {
            left.as_os_str()
                .as_bytes()
                .cmp(right.as_os_str().as_bytes())
        });
        for entry in entries {
            snapshot_entry(root, &entry, output, omit_git);
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

fn children_with_suffix(parent: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut entries: Vec<_> = fs::read_dir(parent)
        .expect("read state children")
        .map(|entry| entry.expect("state child").path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.as_bytes().ends_with(suffix.as_bytes()))
        })
        .collect();
    entries.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    entries
}

fn root_from_create(output: &Output) -> PathBuf {
    assert_success(output, "create session");
    let text = std::str::from_utf8(&output.stdout).expect("create output UTF-8");
    PathBuf::from(
        text.strip_prefix("created session ")
            .and_then(|path| path.strip_suffix('\n'))
            .expect("canonical create output"),
    )
}

fn ndjson(output: &Output) -> Vec<Value> {
    assert!(
        output.stdout.ends_with(b"\n") || output.stdout.is_empty(),
        "NDJSON output lacked a final newline: {output:?}"
    );
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("parse NDJSON row"))
        .collect()
}

fn row_string<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing {field} string in {row}"))
}

fn wait_for(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn parity_state(native: &Path, virtual_worktree: &Path, label: &str) {
    for args in [
        git_args(&["status", "--porcelain=v1", "--untracked-files=all"]),
        git_args(&["diff", "--binary"]),
        git_args(&["diff", "--cached", "--binary"]),
        git_args(&["ls-files", "-s", "-z"]),
        git_args(&["rev-parse", "HEAD"]),
        git_args(&["rev-parse", "HEAD^{tree}"]),
        git_args(&[
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00",
            "refs/heads",
        ]),
    ] {
        let left = git_output(native, &args);
        let right = git_output(virtual_worktree, &args);
        assert_eq!(
            left.status.code(),
            right.status.code(),
            "{label}: exit mismatch for {args:?}"
        );
        assert_eq!(
            left.stdout, right.stdout,
            "{label}: stdout mismatch for {args:?}"
        );
        assert_eq!(
            left.stderr, right.stderr,
            "{label}: stderr mismatch for {args:?}"
        );
    }
    assert_eq!(
        worktree_snapshot(native),
        worktree_snapshot(virtual_worktree),
        "{label}: worktree content or modes diverged"
    );
}

fn open_path_directory(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

#[cfg(target_os = "linux")]
fn raw_name_cstring(name: &[u8]) -> CString {
    CString::new(name).expect("raw fixture name without NUL")
}

#[cfg(target_os = "linux")]
fn raw_name_read(root: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
    let directory = open_path_directory(root)?;
    let name = raw_name_cstring(name);
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    unsafe { File::from_raw_fd(raw) }.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn raw_name_create(root: &Path, name: &[u8], bytes: &[u8]) {
    let directory = open_path_directory(root).expect("open raw fixture parent descriptor");
    let name = raw_name_cstring(name);
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert!(
        raw >= 0,
        "create raw fixture name: {}",
        io::Error::last_os_error()
    );
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(bytes).expect("write raw fixture name");
    file.sync_all().expect("sync raw fixture name");
    drop(file);
    assert_eq!(
        raw_name_read(root, name.to_bytes()).expect("read raw fixture name"),
        bytes,
        "descriptor-relative raw fixture bytes changed"
    );
}

#[cfg(target_os = "linux")]
fn raw_name_remove(root: &Path, name: &[u8]) {
    let directory = open_path_directory(root).expect("open raw cleanup parent descriptor");
    let name = raw_name_cstring(name);
    assert_eq!(
        unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) },
        0,
        "remove raw fixture name: {}",
        io::Error::last_os_error()
    );
    let error =
        raw_name_read(root, name.to_bytes()).expect_err("raw fixture name survived cleanup");
    assert_eq!(
        error.kind(),
        io::ErrorKind::NotFound,
        "raw fixture cleanup error"
    );
}

#[cfg(target_os = "linux")]
fn raw_name_git_parity(native: &Path, virtual_worktree: &Path, name: &[u8], bytes: &[u8]) {
    assert_eq!(
        raw_name_read(native, name).expect("read native raw name"),
        bytes
    );
    assert_eq!(
        raw_name_read(virtual_worktree, name).expect("read VWS raw name"),
        bytes
    );
    for args in [
        git_args(&["status", "--porcelain=v1", "-z"]),
        git_args(&["diff", "--binary"]),
        git_args(&["diff", "--cached", "--binary"]),
        git_args(&["ls-files", "-s", "-z"]),
        git_args(&["ls-tree", "-rz", "HEAD"]),
        git_args(&["rev-parse", "HEAD"]),
        git_args(&["rev-parse", "HEAD^{tree}"]),
    ] {
        let native_output = git_output(native, &args);
        let virtual_output = git_output(virtual_worktree, &args);
        assert_eq!(
            native_output.status.code(),
            virtual_output.status.code(),
            "raw-name exit mismatch for {args:?}"
        );
        assert_eq!(
            native_output.stdout, virtual_output.stdout,
            "raw-name stdout mismatch for {args:?}"
        );
        assert_eq!(
            native_output.stderr, virtual_output.stderr,
            "raw-name stderr mismatch for {args:?}"
        );
        if args == git_args(&["ls-files", "-s", "-z"])
            || args == git_args(&["ls-tree", "-rz", "HEAD"])
        {
            assert!(
                native_output
                    .stdout
                    .windows(name.len())
                    .any(|window| window == name),
                "Git normalized or lost raw filename for {args:?}"
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn git_stdin(root: &Path, args: &[OsString], input: &[u8]) -> Output {
    let mut child = git_command(root, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn raw-name Git plumbing");
    let mut stdin = child.stdin.take().expect("raw-name Git stdin");
    stdin.write_all(input).expect("write raw-name Git stdin");
    drop(stdin);
    child
        .wait_with_output()
        .expect("wait raw-name Git plumbing")
}

#[cfg(target_os = "macos")]
fn git_object_id(output: &Output, label: &str) -> String {
    assert_success(output, label);
    let oid = std::str::from_utf8(&output.stdout)
        .expect("raw-name Git object id UTF-8")
        .strip_suffix('\n')
        .expect("raw-name Git object id newline");
    assert!(
        lower_hex(oid, 40) || lower_hex(oid, 64),
        "invalid raw-name Git object id: {oid:?}"
    );
    oid.to_owned()
}

#[cfg(target_os = "macos")]
fn raw_name_commit(root: &Path, raw_name: &[u8]) -> (String, String) {
    let blob = git_object_id(
        &git_stdin(
            root,
            &git_args(&["hash-object", "-w", "--stdin"]),
            b"raw name\n",
        ),
        "write raw-name blob",
    );
    let mut tree_input = format!("100644 blob {blob}\t").into_bytes();
    tree_input.extend_from_slice(raw_name);
    tree_input.push(0);
    let tree = git_object_id(
        &git_stdin(root, &git_args(&["mktree", "-z"]), &tree_input),
        "write raw-name tree",
    );
    let parent = git_object_id(
        &git_output(root, &git_args(&["rev-parse", "HEAD"])),
        "resolve raw-name parent",
    );
    let commit_args = vec![
        OsString::from("commit-tree"),
        OsString::from(&tree),
        OsString::from("-p"),
        OsString::from(parent),
        OsString::from("-m"),
        OsString::from("raw platform name"),
    ];
    let commit = git_object_id(
        &git_command(root, &commit_args)
            .env("GIT_AUTHOR_NAME", "M4 Raw")
            .env("GIT_AUTHOR_EMAIL", "raw@example.invalid")
            .env("GIT_AUTHOR_DATE", "2024-01-01T00:00:09 +0000")
            .env("GIT_COMMITTER_NAME", "M4 Raw")
            .env("GIT_COMMITTER_EMAIL", "raw@example.invalid")
            .env("GIT_COMMITTER_DATE", "2024-01-01T00:00:09 +0000")
            .output()
            .expect("commit raw-name tree"),
        "commit raw-name tree",
    );
    (tree, commit)
}

#[cfg(target_os = "macos")]
fn git_object_bytes(root: &Path, object: &str) -> Vec<u8> {
    git(
        root,
        &[
            OsString::from("cat-file"),
            OsString::from("-p"),
            OsString::from(object),
        ],
    )
    .stdout
}

#[cfg(target_os = "macos")]
fn raw_name_materialization_is_rejected(native: &Path, virtual_worktree: &Path) {
    let raw_name = b"raw-\xff-name";
    let (native_tree, native_commit) = raw_name_commit(native, raw_name);
    let (virtual_tree, virtual_commit) = raw_name_commit(virtual_worktree, raw_name);
    assert_eq!(native_tree, virtual_tree, "raw-name tree OID diverged");
    assert_eq!(
        native_commit, virtual_commit,
        "raw-name commit OID diverged"
    );
    for object in [&native_tree, &native_commit] {
        assert_eq!(
            git_object_bytes(native, object),
            git_object_bytes(virtual_worktree, object),
            "separate Git databases changed raw-name object bytes"
        );
    }
    for root in [native, virtual_worktree] {
        git(
            root,
            &[
                OsString::from("update-ref"),
                OsString::from("refs/heads/raw-platform"),
                OsString::from(&native_commit),
            ],
        );
    }
    let checkout_args = vec![OsString::from("checkout"), OsString::from(&native_commit)];
    let native_checkout = git_output(native, &checkout_args);
    let virtual_checkout = git_output(virtual_worktree, &checkout_args);
    assert_eq!(
        native_checkout.status.code(),
        virtual_checkout.status.code(),
        "raw-name checkout exit mismatch"
    );
    assert_eq!(
        native_checkout.stdout, virtual_checkout.stdout,
        "raw-name checkout stdout mismatch"
    );
    for output in [&native_checkout, &virtual_checkout] {
        assert!(
            output
                .stderr
                .windows(raw_name.len())
                .any(|window| window == raw_name),
            "macOS raw-name checkout omitted the exact failed path: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("EILSEQ") || stderr.contains("Illegal byte sequence"),
            "macOS raw-name checkout omitted EILSEQ semantics: {output:?}"
        );
    }
    eprintln!(
        "M4 macOS raw checkout exit={:?}; Git transitioned HEAD/index without materializing the path",
        native_checkout.status.code()
    );
    let expected_head = format!("{native_commit}\n").into_bytes();
    for (label, args) in [
        ("HEAD", git_args(&["rev-parse", "HEAD"])),
        ("index", git_args(&["ls-files", "-s", "-z"])),
        ("ls-files", git_args(&["ls-files", "-z"])),
        ("tree", git_args(&["ls-tree", "-rz", "HEAD"])),
        ("status", git_args(&["status", "--porcelain=v1", "-z"])),
    ] {
        let native_output = git_output(native, &args);
        let virtual_output = git_output(virtual_worktree, &args);
        assert_success(&native_output, &format!("native raw-name {label}"));
        assert_success(&virtual_output, &format!("VWS raw-name {label}"));
        assert_eq!(
            native_output.status.code(),
            virtual_output.status.code(),
            "raw-name {label} exit mismatch"
        );
        assert_eq!(
            native_output.stdout, virtual_output.stdout,
            "raw-name {label} stdout mismatch"
        );
        if label == "HEAD" {
            assert_eq!(
                native_output.stdout, expected_head,
                "raw-name checkout changed HEAD"
            );
        }
        if matches!(label, "index" | "ls-files" | "tree") {
            for output in [&native_output, &virtual_output] {
                assert!(
                    output
                        .stdout
                        .windows(raw_name.len())
                        .any(|window| window == raw_name),
                    "raw-name {label} normalized or lost raw bytes"
                );
            }
        }
    }
    for root in [native, virtual_worktree] {
        let directory = open_path_directory(root).expect("open raw-name checkout parent");
        assert!(
            !directory_names(directory.as_raw_fd())
                .expect("read raw-name checkout parent")
                .iter()
                .any(|name| name.as_slice() == raw_name),
            "macOS checkout left raw filename behind"
        );
    }
}

fn assert_protected(before: &[Vec<u8>], paths: &[&Path]) {
    let after: Vec<_> = paths.iter().map(|path| snapshot(path)).collect();
    assert_eq!(after, before, "authority/template/cwd/sibling changed");
}

struct M4Binaries {
    instrumented: PathBuf,
    normal: PathBuf,
}

fn build_m4_binaries(sandbox: &Sandbox) -> M4Binaries {
    let instrumented_target = sandbox.child("instrumented-target");
    let normal_target = sandbox.child("normal-target");
    let instrumented = build_m4_binary(&instrumented_target, true);
    let normal = build_m4_binary(&normal_target, false);
    verify_normal_release_binary(&normal);
    M4Binaries {
        instrumented,
        normal,
    }
}

fn build_m4_binary(target_dir: &Path, instrumented: bool) -> PathBuf {
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
    let output = command.output().expect("build M4 test binary");
    assert_success(
        &output,
        if instrumented {
            "build isolated instrumented M4 binary"
        } else {
            "build isolated normal release M4 binary"
        },
    );
    let binary = target_dir.join("release/git-vws");
    assert!(
        binary.is_file(),
        "isolated M4 binary was absent: {}",
        binary.display()
    );
    binary
}

fn verify_normal_release_binary(binary: &Path) {
    let bytes = fs::read(binary).expect("read normal release binary");
    for marker in [
        b"M4CP/1".as_slice(),
        b"GIT_VWS_M4_CONTROL_FD",
        b"m4_checkpoint",
    ] {
        assert!(
            !bytes.windows(marker.len()).any(|window| window == marker),
            "normal release binary retained checkpoint bytes: {}",
            String::from_utf8_lossy(marker)
        );
    }
    let strings = Command::new(find_executable("strings"))
        .arg(binary)
        .output()
        .expect("run strings negative scan");
    assert_success(&strings, "strings normal release binary");
    let nm = Command::new(find_executable("nm"))
        .arg("-a")
        .arg(binary)
        .output()
        .expect("run nm negative scan");
    assert_success(&nm, "nm normal release binary");
    for marker in [
        b"M4CP/1".as_slice(),
        b"GIT_VWS_M4_CONTROL_FD",
        b"m4_checkpoint",
    ] {
        assert!(
            !strings
                .stdout
                .windows(marker.len())
                .any(|window| window == marker)
                && !nm
                    .stdout
                    .windows(marker.len())
                    .any(|window| window == marker),
            "normal release strings/nm retained checkpoint marker: {}",
            String::from_utf8_lossy(marker)
        );
    }
}

fn only_child(parent: &Path, suffix: &str) -> PathBuf {
    let children = children_with_suffix(parent, suffix);
    assert_eq!(
        children.len(),
        1,
        "expected one {suffix} child: {children:?}"
    );
    children.into_iter().next().expect("one state child")
}

fn instrumented_create_command(
    fixture: &Fixture,
    binary: &Path,
    name: &str,
    target: &str,
) -> Command {
    fixture.command_for(binary, fixture.create_args(name, target))
}

fn instrumented_remove_command(fixture: &Fixture, binary: &Path, name: &str) -> Command {
    fixture.command_for(binary, fixture.remove_args(name, false))
}

fn discover_checkpoints(binaries: &M4Binaries, operation: &str) -> Vec<CheckpointTarget> {
    let mut fixture = Fixture::new(false);
    let command = if operation == "remove" {
        root_from_create(&fixture.create("crash", "crash-main"));
        instrumented_remove_command(&fixture, &binaries.instrumented, "crash")
    } else {
        instrumented_create_command(&fixture, &binaries.instrumented, "crash", "crash-main")
    };
    let target = CheckpointTarget::new(operation, "ready-return");
    let run = CheckpointController::start(command, target, ArmReply::Exact)
        .unwrap_or_else(|output| panic!("instrumented discovery ARM failed: {output:?}"))
        .run_all();
    assert_success(&run.output, "instrumented checkpoint discovery");
    let mut targets = Vec::new();
    for event in run.events {
        if event.operation != operation {
            continue;
        }
        let candidate = CheckpointTarget::new(&event.operation, &event.stage);
        if !targets.contains(&candidate) {
            targets.push(candidate);
        }
    }
    assert!(!targets.is_empty(), "no reachable {operation} checkpoints");
    eprintln!("M4 {operation} crash checkpoints={}", targets.len());
    fixture.cleanup();
    targets
}

fn assert_recovery_output(output: &Output, context: &str) {
    if output.status.success() {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("INCOMPLETE") || stderr.contains("RECOVERY_REQUIRED"),
        "{context} was neither complete nor an allowed retained recovery result: {output:?}"
    );
    assert!(
        !stderr.contains("M4_CHECKPOINT_FAILED"),
        "{context} used an instrumented recovery binary: {output:?}"
    );
}

fn assert_crash_state_boundaries(fixture: &Fixture) {
    assert!(
        fixture.records().len() <= 1,
        "crash left duplicate session records"
    );
    assert!(
        fixture.roots().len() <= 1,
        "crash left duplicate session roots"
    );
    assert!(
        children_with_suffix(&fixture.sessions(), ".tombstone").len() <= 1,
        "crash left duplicate tombstones"
    );
    assert!(
        children_with_suffix(&fixture.templates(), ".record").len() <= 1,
        "crash left duplicate template records"
    );
    assert!(
        children_with_suffix(&fixture.templates(), ".root").len() <= 1,
        "crash left duplicate template roots"
    );
}

fn crash_and_recover_once(binaries: &M4Binaries, checkpoint: &CheckpointTarget) {
    let mut fixture = Fixture::new(false);
    let external = fixture.sandbox.child("external-sentinel");
    fs::write(&external, b"M4 crash boundary sentinel\n").expect("write external sentinel");
    let authority_before = snapshot(&fixture.authority);
    let protected_paths = [
        fixture.cwd.as_path(),
        fixture.sibling.as_path(),
        external.as_path(),
    ];
    let protected_before: Vec<_> = protected_paths.iter().map(|path| snapshot(path)).collect();
    let (command, recovery_args, remove) = if checkpoint.operation == "remove" {
        root_from_create(&fixture.create("crash", "crash-main"));
        let template_before = snapshot(&fixture.templates());
        let command = instrumented_remove_command(&fixture, &binaries.instrumented, "crash");
        let recovery = fixture.remove_args("crash", false);
        (command, recovery, Some(template_before))
    } else {
        let command =
            instrumented_create_command(&fixture, &binaries.instrumented, "crash", "crash-main");
        let recovery = fixture.create_args("crash", "crash-main");
        (command, recovery, None)
    };
    let run = CheckpointController::start(command, checkpoint.clone(), ArmReply::Exact)
        .unwrap_or_else(|output| {
            panic!("instrumented crash ARM failed at {checkpoint:?}: {output:?}")
        })
        .crash_at_target();
    assert!(
        run.events
            .iter()
            .any(|event| event.operation == checkpoint.operation && event.stage == checkpoint.stage),
        "controller did not observe target {checkpoint:?}"
    );
    assert_crash_state_boundaries(&fixture);
    assert_eq!(
        snapshot(&fixture.authority),
        authority_before,
        "crash wrote authority"
    );
    assert_protected(&protected_before, &protected_paths);
    if let Some(template_before) = remove {
        assert_eq!(
            snapshot(&fixture.templates()),
            template_before,
            "remove crash wrote template"
        );
    }

    let recovery = fixture
        .command_for(&binaries.normal, recovery_args)
        .output()
        .expect("run normal release recovery");
    assert_recovery_output(&recovery, &format!("normal recovery at {checkpoint:?}"));
    assert_crash_state_boundaries(&fixture);
    assert_eq!(
        snapshot(&fixture.authority),
        authority_before,
        "normal recovery wrote authority"
    );
    assert_protected(&protected_before, &protected_paths);
    if checkpoint.operation == "remove" && recovery.status.success() {
        assert!(
            fixture.records().is_empty(),
            "completed remove retained a record"
        );
        assert!(
            fixture.roots().is_empty(),
            "completed remove retained a root"
        );
    }
    if checkpoint.operation != "remove" && recovery.status.success() {
        let listed = fixture
            .command_for(
                &binaries.normal,
                fixture.repo_args(vec![OsString::from("list")]),
            )
            .output()
            .expect("list normal recovery result");
        assert_success(&listed, "list completed crash recovery");
        let rows = ndjson(&listed);
        assert_eq!(
            rows.len(),
            1,
            "completed recovery did not leave one session"
        );
        assert_eq!(row_string(&rows[0], "state"), "READY");
    }
    fixture.cleanup();
}

fn assert_protocol_failure(output: &Output, label: &str) {
    assert_error(output, "M4_CHECKPOINT_FAILED", label);
}

fn protocol_fault_once(binaries: &M4Binaries, fault: ProtocolFault, label: &str) {
    let mut fixture = Fixture::new(false);
    let target = CheckpointTarget::new("create", "prepared-record-temporary-synced");
    let command =
        instrumented_create_command(&fixture, &binaries.instrumented, "fault", "fault-main");
    let output = CheckpointController::start(command, target, ArmReply::Exact)
        .unwrap_or_else(|output| panic!("protocol fault ARM failed: {output:?}"))
        .fault_at_first(fault);
    assert_protocol_failure(&output, label);
    fixture.cleanup();
}

fn assert_bad_arm_rejected(binaries: &M4Binaries) {
    let mut fixture = Fixture::new(false);
    let target = CheckpointTarget::new("create", "prepared-record-temporary-synced");
    let command = instrumented_create_command(&fixture, &binaries.instrumented, "arm", "arm-main");
    let output = match CheckpointController::start(command, target, ArmReply::Wrong) {
        Ok(controller) => {
            drop(controller);
            panic!("instrumented binary accepted a mismatched ARM");
        }
        Err(output) => output,
    };
    assert_protocol_failure(&output, "mismatched ARM");
    fixture.cleanup();
}

fn assert_control_fd_is_hidden_from_git_child(binaries: &M4Binaries) {
    let mut fixture = Fixture::new(false);
    root_from_create(&fixture.create("fd", "fd-main"));
    let alias = format!(
        "alias.m4fd=!sh -c 'test ! -e /dev/fd/{M4_CONTROL_DESTINATION_FD} && test -z \"${{GIT_VWS_M4_CONTROL_FD+x}}\" && test -z \"${{GIT_VWS_M4_NONCE+x}}\" && test -z \"${{GIT_VWS_M4_TARGET+x}}\" && printf \"clean\\n\"'"
    );
    let command = fixture.command_for(
        &binaries.instrumented,
        fixture.exec_args(
            "fd",
            vec![
                real_git().into_os_string(),
                OsString::from("-c"),
                OsString::from(&alias),
                OsString::from("m4fd"),
            ],
        ),
    );
    let run = CheckpointController::start(
        command,
        CheckpointTarget::new("create", "prepared-record-temporary-synced"),
        ArmReply::Exact,
    )
    .unwrap_or_else(|output| panic!("FD oracle ARM failed: {output:?}"))
    .run_all();
    assert_success(&run.output, "Git child FD/CLOEXEC oracle");
    assert_eq!(run.output.stdout, b"clean\n");
    assert!(
        run.output.stderr.is_empty(),
        "FD oracle diagnostics: {:?}",
        run.output
    );
    fixture.cleanup();
}

fn filesystem_identity(path: &Path) -> (u64, String) {
    let file = File::open(path).expect("open filesystem identity path");
    let metadata = file.metadata().expect("stat filesystem identity path");
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) },
        0,
        "fstatfs test filesystem"
    );
    #[cfg(target_os = "macos")]
    let kind = unsafe { CStr::from_ptr(stat.f_fstypename.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    #[cfg(target_os = "linux")]
    let kind = format!("0x{:x}", stat.f_type as u64);
    (metadata.dev(), kind)
}

#[cfg(target_os = "linux")]
fn fiemap_shares_extents(source: &Path, destination: &Path) -> bool {
    #[repr(C)]
    struct Fiemap {
        start: u64,
        length: u64,
        flags: u32,
        mapped: u32,
        extent_count: u32,
        reserved: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Extent {
        logical: u64,
        physical: u64,
        length: u64,
        reserved64: [u64; 2],
        flags: u32,
        reserved: [u32; 3],
    }
    #[repr(C)]
    struct Buffer {
        map: Fiemap,
        extents: [Extent; 32],
    }
    const REQUEST: libc::Ioctl = 0xc020_660bu32 as libc::Ioctl;
    const SYNC: u32 = 0x0000_0001;
    const SHARED: u32 = 0x0000_2000;
    let source_file = File::open(source).expect("open FIEMAP source");
    let destination_file = File::open(destination).expect("open FIEMAP destination");
    let length = source_file.metadata().expect("stat FIEMAP source").len();
    if length == 0
        || destination_file
            .metadata()
            .expect("stat FIEMAP destination")
            .len()
            != length
    {
        return false;
    }
    let mut source_map: Buffer = unsafe { std::mem::zeroed() };
    let mut destination_map: Buffer = unsafe { std::mem::zeroed() };
    for map in [&mut source_map, &mut destination_map] {
        map.map.length = length;
        map.map.flags = SYNC;
        map.map.extent_count = map.extents.len() as u32;
    }
    if unsafe { libc::ioctl(source_file.as_raw_fd(), REQUEST, &mut source_map) } != 0
        || unsafe { libc::ioctl(destination_file.as_raw_fd(), REQUEST, &mut destination_map) } != 0
        || source_map.map.mapped == 0
        || source_map.map.mapped != destination_map.map.mapped
        || source_map.map.mapped as usize > source_map.extents.len()
    {
        return false;
    }
    source_map.extents[..source_map.map.mapped as usize]
        .iter()
        .zip(destination_map.extents[..destination_map.map.mapped as usize].iter())
        .all(|(left, right)| {
            left.logical == right.logical
                && left.physical == right.physical
                && left.length == right.length
                && left.flags & SHARED != 0
                && right.flags & SHARED != 0
        })
}

#[test]
fn native_cow_evidence_uses_the_host_storage_oracle() {
    let mut fixture = Fixture::new(false);
    let (device, filesystem) = filesystem_identity(&fixture.sandbox.path);
    #[cfg(target_os = "linux")]
    if filesystem != "0x58465342" {
        eprintln!("M4 COW NOT_EXECUTED: Linux filesystem={filesystem}, requires XFS FIEMAP row");
        fixture.cleanup();
        return;
    }
    #[cfg(target_os = "macos")]
    assert_eq!(
        filesystem, "apfs",
        "M4 macOS COW requires APFS: {filesystem}"
    );
    let root = root_from_create(&fixture.create("cow", "cow-main"));
    let template_root = only_child(&fixture.templates(), ".root");
    let source = template_root.join("nested/data");
    let destination = root.join("worktree/nested/data");
    let source_metadata = fs::metadata(&source).expect("stat COW source");
    let destination_metadata = fs::metadata(&destination).expect("stat COW destination");
    assert_eq!(
        source_metadata.dev(),
        device,
        "template filesystem identity changed"
    );
    assert_eq!(
        destination_metadata.dev(),
        device,
        "worktree filesystem identity changed"
    );
    assert_ne!(
        source_metadata.ino(),
        destination_metadata.ino(),
        "COW reused template inode"
    );
    assert_eq!(
        source_metadata.len(),
        destination_metadata.len(),
        "COW changed content length"
    );
    assert!(
        source_metadata.blocks() > 0 && destination_metadata.blocks() > 0,
        "COW allocation evidence absent"
    );
    #[cfg(target_os = "macos")]
    eprintln!(
        "M4 APFS COW dev={device} source_inode={} destination_inode={} source_blocks={} destination_blocks={}",
        source_metadata.ino(),
        destination_metadata.ino(),
        source_metadata.blocks(),
        destination_metadata.blocks()
    );
    #[cfg(target_os = "linux")]
    {
        assert!(
            fiemap_shares_extents(&source, &destination),
            "XFS FICLONE did not retain FIEMAP shared-extent evidence"
        );
        eprintln!(
            "M4 XFS COW dev={device} source_inode={} destination_inode={} source_blocks={} destination_blocks={}",
            source_metadata.ino(),
            destination_metadata.ino(),
            source_metadata.blocks(),
            destination_metadata.blocks()
        );
    }
    let mut destination_file = fs::OpenOptions::new()
        .write(true)
        .open(&destination)
        .expect("open cloned destination for COW mutation");
    destination_file
        .write_all(&[0xa5])
        .expect("mutate COW destination");
    destination_file
        .sync_all()
        .expect("sync COW destination mutation");
    let mut source_first = [0_u8; 1];
    File::open(&source)
        .expect("open COW source after destination mutation")
        .read_exact(&mut source_first)
        .expect("read COW source after destination mutation");
    assert_eq!(
        source_first,
        [b't'],
        "COW destination mutation changed sealed template"
    );
    fixture.cleanup();
}

#[test]
fn checkpoint_protocol_and_all_reachable_crash_prefixes_are_safe() {
    let mut artifacts = Sandbox::new();
    let binaries = build_m4_binaries(&artifacts);
    assert_bad_arm_rejected(&binaries);
    protocol_fault_once(&binaries, ProtocolFault::BadFrame, "malformed GO frame");
    protocol_fault_once(&binaries, ProtocolFault::WrongSequence, "wrong GO sequence");
    protocol_fault_once(&binaries, ProtocolFault::Eof, "controller EOF");
    protocol_fault_once(&binaries, ProtocolFault::Timeout, "controller timeout");
    assert_control_fd_is_hidden_from_git_child(&binaries);
    let mut targets = discover_checkpoints(&binaries, "template");
    targets.extend(discover_checkpoints(&binaries, "create"));
    targets.extend(discover_checkpoints(&binaries, "remove"));
    for target in &targets {
        crash_and_recover_once(&binaries, target);
    }
    eprintln!("M4 crash-prefix targets exercised={}", targets.len());
    artifacts
        .cleanup()
        .expect("cleanup M4 instrumented artifact sandbox");
}

#[test]
fn ordinary_worktree_and_vws_have_git_parity_for_history_conflicts_and_paths() {
    let mut fixture = Fixture::new(false);
    let native = fixture.sandbox.child("native");
    git(
        &fixture.sandbox.path,
        &[
            OsString::from("clone"),
            OsString::from("--no-hardlinks"),
            fixture.authority.as_os_str().to_os_string(),
            native.as_os_str().to_os_string(),
        ],
    );
    git(&native, &git_args(&["config", "user.name", "M4 Parity"]));
    git(
        &native,
        &git_args(&["config", "user.email", "parity@example.invalid"]),
    );
    git(&native, &git_args(&["checkout", "-b", "parity-main"]));
    git(&native, &git_args(&["branch", "-D", "main"]));

    let virtual_root = root_from_create(&fixture.create("parity", "parity-main"));
    let authority_before = snapshot(&fixture.authority);
    let virtual_worktree = virtual_root.join("worktree");
    git(
        &virtual_worktree,
        &git_args(&["config", "user.name", "M4 Parity"]),
    );
    git(
        &virtual_worktree,
        &git_args(&["config", "user.email", "parity@example.invalid"]),
    );
    let templates_before = snapshot(&fixture.templates());
    let protected_paths = [fixture.cwd.as_path(), fixture.sibling.as_path()];
    let protected_before: Vec<_> = protected_paths.iter().map(|path| snapshot(path)).collect();

    parity_state(&native, &virtual_worktree, "initial status and diff");
    for root in [&native, &virtual_worktree] {
        fs::write(root.join("parity.txt"), b"staged parity\n").expect("write staged parity file");
        git(root, &git_args(&["add", "parity.txt"]));
    }
    parity_state(&native, &virtual_worktree, "add and index");
    git_commit(&native, "parity staged", "2024-01-01T00:00:01 +0000");
    git_commit(
        &virtual_worktree,
        "parity staged",
        "2024-01-01T00:00:01 +0000",
    );
    parity_state(&native, &virtual_worktree, "commit");

    for root in [&native, &virtual_worktree] {
        git(root, &git_args(&["checkout", "-b", "merge-side"]));
        fs::write(root.join("merge-side"), b"merge side\n").expect("write merge-side file");
        git(root, &git_args(&["add", "merge-side"]));
        git_commit(root, "merge side", "2024-01-01T00:00:02 +0000");
        git(root, &git_args(&["checkout", "parity-main"]));
        fs::write(root.join("main-side"), b"main side\n").expect("write main-side file");
        git(root, &git_args(&["add", "main-side"]));
        git_commit(root, "main side", "2024-01-01T00:00:03 +0000");
    }
    let merge_args = git_args(&["merge", "--no-edit", "merge-side"]);
    for root in [&native, &virtual_worktree] {
        git_with_dates(root, &merge_args, "2024-01-01T00:00:03 +0000");
    }
    parity_state(&native, &virtual_worktree, "merge");

    for root in [&native, &virtual_worktree] {
        git(root, &git_args(&["checkout", "-b", "rebase-side"]));
        fs::write(root.join("rebase-side"), b"rebase side\n").expect("write rebase-side file");
        git(root, &git_args(&["add", "rebase-side"]));
        git_commit(root, "rebase side", "2024-01-01T00:00:04 +0000");
        git(root, &git_args(&["checkout", "parity-main"]));
        fs::write(root.join("rebase-main"), b"rebase main\n").expect("write rebase-main file");
        git(root, &git_args(&["add", "rebase-main"]));
        git_commit(root, "rebase main", "2024-01-01T00:00:05 +0000");
        git(root, &git_args(&["checkout", "rebase-side"]));
    }
    let rebase_args = git_args(&["rebase", "parity-main"]);
    for root in [&native, &virtual_worktree] {
        git_with_dates(root, &rebase_args, "2024-01-01T00:00:05 +0000");
    }
    parity_state(&native, &virtual_worktree, "rebase");
    for root in [&native, &virtual_worktree] {
        git(root, &git_args(&["reset", "--mixed", "HEAD~1"]));
    }
    parity_state(&native, &virtual_worktree, "rebase mixed reset");
    for root in [&native, &virtual_worktree] {
        git(root, &git_args(&["reset", "--hard", "HEAD"]));
    }
    parity_state(&native, &virtual_worktree, "rebase hard reset");
    for root in [&native, &virtual_worktree] {
        fs::create_dir(root.join("ignored")).expect("create ignored directory");
        fs::write(root.join("ignored/file"), b"ignored\n").expect("write ignored file");
        fs::write(root.join("untracked"), b"untracked\n").expect("write untracked file");
        git(root, &git_args(&["clean", "-fdx"]));
    }
    parity_state(&native, &virtual_worktree, "rebase clean");

    for root in [&native, &virtual_worktree] {
        git(root, &git_args(&["checkout", "parity-main"]));
        git(root, &git_args(&["checkout", "-b", "conflict-side"]));
        fs::write(root.join("history"), b"conflict side\n").expect("write conflict side");
        git(root, &git_args(&["add", "history"]));
        git_commit(root, "conflict side", "2024-01-01T00:00:06 +0000");
        git(root, &git_args(&["checkout", "parity-main"]));
        fs::write(root.join("history"), b"conflict main\n").expect("write conflict main");
        git(root, &git_args(&["add", "history"]));
        git_commit(root, "conflict main", "2024-01-01T00:00:07 +0000");
    }
    let native_conflict = git_output(&native, &git_args(&["merge", "conflict-side"]));
    let virtual_conflict = git_output(&virtual_worktree, &git_args(&["merge", "conflict-side"]));
    assert_eq!(
        native_conflict.status.code(),
        virtual_conflict.status.code(),
        "conflict exit mismatch"
    );
    assert!(
        !native_conflict.status.success(),
        "native conflict unexpectedly merged"
    );
    parity_state(&native, &virtual_worktree, "conflict index and status");
    git(&native, &git_args(&["merge", "--abort"]));
    git(&virtual_worktree, &git_args(&["merge", "--abort"]));

    let case_sensitive = {
        let lower = native.join("case-probe");
        let upper = native.join("CASE-PROBE");
        fs::write(&lower, b"lower\n").expect("write lower case probe");
        fs::write(&upper, b"upper\n").expect("write upper case probe");
        let distinct = fs::symlink_metadata(&lower)
            .expect("stat lower case probe")
            .ino()
            != fs::symlink_metadata(&upper)
                .expect("stat upper case probe")
                .ino();
        fs::remove_file(&lower).expect("remove lower case probe");
        if upper.exists() {
            fs::remove_file(&upper).expect("remove upper case probe");
        }
        distinct
    };
    eprintln!("M4 host case-sensitive={case_sensitive}");
    for root in [&native, &virtual_worktree] {
        fs::write(root.join("mode-file"), b"mode\n").expect("write mode fixture");
        fs::set_permissions(root.join("mode-file"), fs::Permissions::from_mode(0o755))
            .expect("set mode fixture executable");
        fs::remove_file(root.join("link")).expect("replace fixture symlink");
        std::os::unix::fs::symlink("history", root.join("link")).expect("replace parity symlink");
        fs::write(root.join("case-name"), b"case\n").expect("write case fixture");
        if case_sensitive {
            fs::write(root.join("CASE-NAME"), b"upper case\n").expect("write upper case fixture");
        }
        git(root, &git_args(&["add", "-A"]));
        git_commit(root, "mode symlink case", "2024-01-01T00:00:08 +0000");
    }
    parity_state(
        &native,
        &virtual_worktree,
        "mode symlink and host case behavior",
    );
    #[cfg(target_os = "linux")]
    {
        let raw_name = b"raw-\xff-name";
        for root in [&native, &virtual_worktree] {
            raw_name_create(root, raw_name, b"raw name\n");
            git(root, &git_args(&["add", "-A"]));
            git_commit(root, "raw filename", "2024-01-01T00:00:09 +0000");
        }
        raw_name_git_parity(&native, &virtual_worktree, raw_name, b"raw name\n");
        for root in [&native, &virtual_worktree] {
            raw_name_remove(root, raw_name);
        }
    }
    #[cfg(target_os = "macos")]
    raw_name_materialization_is_rejected(&native, &virtual_worktree);
    assert_eq!(
        snapshot(&fixture.authority),
        authority_before,
        "parity wrote authority"
    );
    assert_eq!(
        snapshot(&fixture.templates()),
        templates_before,
        "runtime wrote template"
    );
    assert_protected(&protected_before, &protected_paths);
    fixture.cleanup();
}

#[test]
fn exec_preserves_direct_contract_and_n3_sessions_are_isolated_and_leased() {
    let mut fixture = Fixture::new(false);
    let authority_before = snapshot(&fixture.authority);
    let alpha = root_from_create(&fixture.create("alpha", "alpha-main"));
    let bravo = root_from_create(&fixture.create("bravo", "bravo-main"));
    let charlie = root_from_create(&fixture.create("charlie", "charlie-main"));
    let alpha_worktree = alpha.join("worktree");
    let bravo_worktree = bravo.join("worktree");
    let charlie_worktree = charlie.join("worktree");
    for worktree in [&alpha_worktree, &bravo_worktree, &charlie_worktree] {
        git(worktree, &git_args(&["config", "user.name", "M4 Session"]));
        git(
            worktree,
            &git_args(&["config", "user.email", "session@example.invalid"]),
        );
    }
    let templates_before = snapshot(&fixture.templates());
    let protected_paths = [fixture.cwd.as_path(), fixture.sibling.as_path()];
    let protected_before: Vec<_> = protected_paths.iter().map(|path| snapshot(path)).collect();

    fs::write(alpha_worktree.join("alpha-only"), b"alpha commit\n").expect("write alpha commit");
    git(&alpha_worktree, &git_args(&["add", "alpha-only"]));
    git_commit(
        &alpha_worktree,
        "alpha private",
        "2024-01-01T00:01:01 +0000",
    );
    fs::write(bravo_worktree.join("history"), b"bravo dirty\n").expect("write bravo dirty");
    assert_eq!(
        git(&bravo_worktree, &git_args(&["status", "--porcelain=v1"])).stdout,
        b" M history\n"
    );
    let alpha_before_charlie = snapshot(&alpha);
    let bravo_before_charlie = snapshot(&bravo);

    git(
        &charlie_worktree,
        &git_args(&["checkout", "-b", "charlie-side"]),
    );
    fs::write(charlie_worktree.join("history"), b"charlie side\n").expect("write charlie side");
    git(&charlie_worktree, &git_args(&["add", "history"]));
    git_commit(
        &charlie_worktree,
        "charlie side",
        "2024-01-01T00:01:02 +0000",
    );
    git(&charlie_worktree, &git_args(&["checkout", "charlie-main"]));
    fs::write(charlie_worktree.join("history"), b"charlie main\n").expect("write charlie main");
    git(&charlie_worktree, &git_args(&["add", "history"]));
    git_commit(
        &charlie_worktree,
        "charlie main",
        "2024-01-01T00:01:03 +0000",
    );
    let conflict = git_output(&charlie_worktree, &git_args(&["merge", "charlie-side"]));
    assert!(
        !conflict.status.success(),
        "charlie conflict unexpectedly merged"
    );
    git(&charlie_worktree, &git_args(&["merge", "--abort"]));
    git(
        &charlie_worktree,
        &git_args(&["checkout", "-b", "charlie-reset"]),
    );
    fs::write(charlie_worktree.join("charlie-reset"), b"reset\n").expect("write charlie reset");
    git(&charlie_worktree, &git_args(&["add", "charlie-reset"]));
    git_commit(
        &charlie_worktree,
        "charlie reset",
        "2024-01-01T00:01:04 +0000",
    );
    git(
        &charlie_worktree,
        &git_args(&["reset", "--mixed", "HEAD~1"]),
    );
    git(&charlie_worktree, &git_args(&["reset", "--hard", "HEAD"]));
    assert_eq!(
        snapshot(&alpha),
        alpha_before_charlie,
        "charlie changed alpha"
    );
    assert_eq!(
        snapshot(&bravo),
        bravo_before_charlie,
        "charlie changed bravo"
    );
    assert_eq!(
        snapshot(&fixture.templates()),
        templates_before,
        "session runtime changed template"
    );
    assert_eq!(
        snapshot(&fixture.authority),
        authority_before,
        "session runtime changed authority"
    );

    let rows = ndjson(&fixture.list());
    assert_eq!(rows.len(), 3, "N=3 list lost a session");
    assert!(rows.iter().all(|row| row_string(row, "state") == "READY"));
    let root_before_busy = snapshot(&alpha);
    let records_before_busy: Vec<_> = fixture
        .records()
        .iter()
        .map(|path| fs::read(path).expect("read session record"))
        .collect();
    let release = fixture.sandbox.child("release-leases");
    let ready_one = fixture.sandbox.child("ready-one");
    let ready_two = fixture.sandbox.child("ready-two");
    let gate = "printf ready > \"$1\"\nwhile [ ! -e \"$2\" ]; do sleep 1; done";
    let spawn_gate = |ready: &Path| {
        fixture
            .vws_command(fixture.exec_args(
                "alpha",
                vec![
                    real_shell().into_os_string(),
                    OsString::from("-c"),
                    OsString::from(gate),
                    OsString::from("lease-gate"),
                    ready.as_os_str().to_os_string(),
                    release.as_os_str().to_os_string(),
                ],
            ))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shared leased exec")
    };
    let first = spawn_gate(&ready_one);
    let second = spawn_gate(&ready_two);
    wait_for(&ready_one, "first shared exec");
    wait_for(&ready_two, "second shared exec");
    let busy = fixture.remove("alpha", true);
    assert_error(
        &busy,
        "SESSION_BUSY",
        "exclusive remove during shared leases",
    );
    assert_eq!(
        snapshot(&alpha),
        root_before_busy,
        "busy remove changed root"
    );
    let records_after_busy: Vec<_> = fixture
        .records()
        .iter()
        .map(|path| fs::read(path).expect("read session record"))
        .collect();
    assert_eq!(
        records_after_busy, records_before_busy,
        "busy remove changed records"
    );
    fs::write(&release, b"release\n").expect("release shared leases");
    assert_success(
        &first.wait_with_output().expect("wait first shared exec"),
        "first shared exec",
    );
    assert_success(
        &second.wait_with_output().expect("wait second shared exec"),
        "second shared exec",
    );
    let removed = fixture.remove("alpha", true);
    assert_success(&removed, "remove alpha after shared leases");
    assert!(
        ndjson(&removed)
            .iter()
            .any(|row| row_string(row, "event") == "REMOVED"),
        "post-lease remove did not report REMOVED"
    );

    let mut direct = fixture
        .vws_command(fixture.exec_args(
            "bravo",
            vec![
                real_shell().into_os_string(),
                OsString::from("-c"),
                OsString::from("printf 'cwd=%s arg1=%s arg2=%s\\n' \"$PWD\" \"$1\" \"$2\"; cat; printf 'stderr\\n' >&2; exit 37"),
                OsString::from("direct-argv"),
                OsString::from("one"),
                OsString::from("two"),
            ],
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn direct exec");
    let mut direct_stdin = direct.stdin.take().expect("direct stdin");
    direct_stdin
        .write_all(b"stdin exact\n")
        .expect("write direct stdin");
    drop(direct_stdin);
    let direct = direct.wait_with_output().expect("wait direct exec");
    assert_eq!(direct.status.code(), Some(37), "direct exit code changed");
    assert_eq!(
        direct.stdout,
        format!(
            "cwd={} arg1=one arg2=two\nstdin exact\n",
            bravo_worktree.display()
        )
        .as_bytes()
    );
    assert_eq!(direct.stderr, b"stderr\n", "direct exec added VWS noise");

    let foreign = fixture.sandbox.child("foreign.git");
    git(
        &fixture.sandbox.path,
        &[
            OsString::from("init"),
            OsString::from("--bare"),
            foreign.as_os_str().to_os_string(),
        ],
    );
    let foreign_worktree = fixture.sandbox.child("foreign-worktree");
    fs::create_dir(&foreign_worktree).expect("create foreign worktree");
    let foreign_index = fixture.sandbox.child("foreign-index");
    fs::write(&foreign_index, b"foreign index\n").expect("write foreign index");
    let foreign_before = snapshot(&foreign);
    let routed = fixture
        .vws_command(fixture.exec_args(
            "bravo",
            vec![
                real_git().into_os_string(),
                OsString::from("rev-parse"),
                OsString::from("--show-toplevel"),
            ],
        ))
        .env("GIT_DIR", &foreign)
        .env("GIT_WORK_TREE", &foreign_worktree)
        .env("GIT_COMMON_DIR", &foreign)
        .env("GIT_INDEX_FILE", &foreign_index)
        .output()
        .expect("run routed exec");
    assert_success(&routed, "exec clears inherited Git routing");
    assert_eq!(
        routed.stdout,
        format!("{}\n", bravo_worktree.display()).as_bytes()
    );
    assert!(
        routed.stderr.is_empty(),
        "routed exec added VWS noise: {routed:?}"
    );
    assert_eq!(
        snapshot(&foreign),
        foreign_before,
        "exec touched foreign Git state"
    );
    assert_eq!(
        snapshot(&fixture.templates()),
        templates_before,
        "exec/remove changed template"
    );
    assert_eq!(
        snapshot(&fixture.authority),
        authority_before,
        "exec/remove changed authority"
    );
    assert_protected(&protected_before, &protected_paths);
    fixture.cleanup();
}
