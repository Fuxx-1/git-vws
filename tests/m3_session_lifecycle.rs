use serde_json::Value;
use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};
use std::thread;
use std::time::{Duration, Instant};

static NEXT_SANDBOX: AtomicUsize = AtomicUsize::new(0);
static NATIVE_COW_PROBE: OnceLock<(bool, String)> = OnceLock::new();

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
            "git-vws-m3-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("sandbox basename");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) },
            0,
            "create sandbox"
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
        if self.root.is_some() && !thread::panicking() {
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
    let mut entries = Vec::new();
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
            entries.push(name.to_vec());
        }
    }
    if unsafe { libc::closedir(directory) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(entries)
}

fn clear_owned(parent: RawFd, device: u64) -> io::Result<()> {
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
    fn new() -> Self {
        let sandbox = Sandbox::new();
        let authority = fixture_repo(&sandbox, "authority.git");
        let home = sandbox.child("home");
        fs::create_dir(&home).expect("create test home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect test home");
        let cwd = sandbox.child("cwd");
        fs::create_dir(&cwd).expect("create protected cwd");
        fs::write(cwd.join("cwd-sentinel"), b"protected cwd\n").expect("write cwd sentinel");
        let sibling = sandbox.child("sibling-sentinel");
        fs::write(&sibling, b"protected sibling\n").expect("write sibling sentinel");
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
        assert_success(&initialized, "initialize fixture authority");
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

    fn vws_command(&self, args: Vec<OsString>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-vws"));
        remove_git_environment(&mut command);
        command
            .args(args)
            .env("HOME", &self.home)
            .current_dir(&self.cwd);
        command
    }

    fn vws(&self, args: Vec<OsString>) -> Output {
        self.vws_command(args).output().expect("run git-vws")
    }

    fn for_repository(&self, authority: &Path, mut command: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--repo"),
            authority.as_os_str().to_os_string(),
        ];
        args.append(&mut command);
        args
    }

    fn create(&self, name: OsString) -> Output {
        self.create_at(&self.authority, name)
    }

    fn create_at(&self, authority: &Path, name: OsString) -> Output {
        self.vws(self.for_repository(authority, vec![OsString::from("create"), name]))
    }

    fn create_at_with_target(&self, authority: &Path, name: OsString, target: &str) -> Output {
        self.vws(self.for_repository(
            authority,
            vec![
                OsString::from("create"),
                name,
                OsString::from("--target"),
                OsString::from(target),
            ],
        ))
    }

    fn list(&self) -> Output {
        self.list_at(&self.authority)
    }

    fn list_at(&self, authority: &Path) -> Output {
        self.vws(self.for_repository(authority, vec![OsString::from("list")]))
    }

    fn list_all(&self) -> Output {
        self.vws(vec![OsString::from("list"), OsString::from("--all")])
    }

    fn exec_args(
        &self,
        authority: &Path,
        name: OsString,
        mut program: Vec<OsString>,
    ) -> Vec<OsString> {
        let mut command = vec![OsString::from("exec"), name, OsString::from("--")];
        command.append(&mut program);
        self.for_repository(authority, command)
    }

    fn exec_hex_args(
        &self,
        authority: &Path,
        name_hex: &str,
        mut program: Vec<OsString>,
    ) -> Vec<OsString> {
        let mut command = vec![
            OsString::from("exec"),
            OsString::from("--name-hex"),
            OsString::from(name_hex),
            OsString::from("--"),
        ];
        command.append(&mut program);
        self.for_repository(authority, command)
    }

    fn remove(&self, name: &str, force: bool) -> Output {
        self.remove_at(&self.authority, name, force)
    }

    fn remove_at(&self, authority: &Path, name: &str, force: bool) -> Output {
        let mut command = vec![OsString::from("remove"), OsString::from(name)];
        if force {
            command.push(OsString::from("--force"));
        }
        self.vws(self.for_repository(authority, command))
    }

    fn session_root(&self) -> PathBuf {
        only_child(&self.sessions(), ".root")
    }

    fn session_record(&self) -> PathBuf {
        only_child(&self.sessions(), ".record")
    }

    fn make_authority(&self, name: &str) -> PathBuf {
        let authority = fixture_repo(&self.sandbox, name);
        let initialized = self.vws(vec![
            OsString::from("init"),
            authority.as_os_str().to_os_string(),
        ]);
        assert_success(&initialized, "initialize secondary authority");
        authority
    }

    fn cleanup(&mut self) {
        self.sandbox.cleanup().expect("cleanup M3 fixture");
    }
}

fn fixture_repo(sandbox: &Sandbox, name: &str) -> PathBuf {
    let bare = sandbox.child(name);
    git(
        &sandbox.path,
        &[
            OsString::from("init"),
            OsString::from("--bare"),
            bare.as_os_str().to_os_string(),
        ],
    );
    let source = sandbox.child(&format!("{name}-source"));
    git(
        &sandbox.path,
        &[OsString::from("init"), source.as_os_str().to_os_string()],
    );
    git(&source, &git_args(&["config", "user.name", "M3 Test"]));
    git(
        &source,
        &git_args(&["config", "user.email", "m3@example.invalid"]),
    );
    fs::create_dir(source.join("nested")).expect("create source nested directory");
    fs::write(source.join("nested/data"), b"template content\n").expect("write source file");
    fs::write(source.join("history"), b"first\n").expect("write first history");
    fs::write(source.join(".gitignore"), b"ignored/\n").expect("write ignore rule");
    fs::write(source.join("run"), b"#!/bin/sh\nprintf 'ok\\n'\n").expect("write executable");
    fs::set_permissions(source.join("run"), fs::Permissions::from_mode(0o755))
        .expect("protect executable");
    std::os::unix::fs::symlink("nested/data", source.join("link")).expect("create source symlink");
    git(&source, &git_args(&["add", "-A"]));
    git(&source, &git_args(&["commit", "-m", "fixture base"]));
    fs::write(source.join("history"), b"second\n").expect("write second history");
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

fn real_git() -> &'static Path {
    static REAL_GIT: OnceLock<PathBuf> = OnceLock::new();
    REAL_GIT.get_or_init(|| find_executable("git")).as_path()
}

fn real_shell() -> &'static Path {
    static REAL_SHELL: OnceLock<PathBuf> = OnceLock::new();
    REAL_SHELL.get_or_init(|| find_executable("sh")).as_path()
}

fn remove_git_environment(command: &mut Command) {
    for (name, _) in env::vars_os() {
        if name.as_bytes().starts_with(b"GIT_") {
            command.env_remove(name);
        }
    }
}

fn git(cwd: &Path, args: &[OsString]) -> Output {
    let mut command = Command::new(real_git());
    remove_git_environment(&mut command);
    let output = command
        .current_dir(cwd)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("run fixture git");
    assert_success(&output, &format!("fixture git {args:?}"));
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
            .as_bytes(),
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
                .as_bytes(),
        );
    }
}

fn protected_snapshot(paths: &[&Path]) -> Vec<Vec<u8>> {
    paths.iter().map(|path| snapshot(path)).collect()
}

fn assert_protected(before: &[Vec<u8>], paths: &[&Path]) {
    assert_eq!(
        protected_snapshot(paths),
        before,
        "authority, template, cwd, or sibling sentinel changed"
    );
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
                .is_some_and(|name| name.as_bytes().ends_with(suffix.as_bytes()))
        })
        .collect();
    entries.sort();
    entries
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
    assert!(
        output.stdout.ends_with(b"\n") || output.stdout.is_empty(),
        "NDJSON output lacked a final newline: {output:?}"
    );
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("parse NDJSON record"))
        .collect()
}

fn row_string<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {field}: {row}"))
}

fn row_number(row: &Value, field: &str) -> u64 {
    row.get(field)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing numeric field {field}: {row}"))
}

fn list_key(row: &Value) -> (String, u64, u64, u64, u64, u64, u64, String) {
    let identity = row
        .get("authority_identity")
        .unwrap_or_else(|| panic!("missing authority identity: {row}"));
    (
        row_string(row, "authority_path_hex").to_owned(),
        row_number(identity, "dev"),
        row_number(identity, "ino"),
        row_number(identity, "uid"),
        row_number(identity, "mode"),
        row_number(identity, "kind"),
        row_number(identity, "nlink"),
        row_string(row, "name_hex").to_owned(),
    )
}

fn assert_sorted_rows(rows: &[Value]) {
    let actual: Vec<_> = rows.iter().map(list_key).collect();
    let mut expected = actual.clone();
    expected.sort();
    assert_eq!(
        actual, expected,
        "list rows were not in stable authority/name order"
    );
}

fn metadata_directory(root: &Path) -> PathBuf {
    let pointer = fs::read(root.join("worktree/.git")).expect("read worktree .git pointer");
    let path = pointer
        .strip_prefix(b"gitdir: ")
        .and_then(|value| value.strip_suffix(b"\n"))
        .expect("canonical worktree gitdir pointer");
    PathBuf::from(OsString::from_vec(path.to_vec()))
}

fn replace_file(path: &Path, replacement: &[u8]) -> PathBuf {
    let file_name = path.file_name().expect("replacement basename");
    let mut backup_name = file_name.to_os_string();
    backup_name.push(".m3-original");
    let backup = path.with_file_name(backup_name);
    fs::rename(path, &backup).expect("move protected file aside");
    let mut candidate_name = file_name.to_os_string();
    candidate_name.push(".m3-replacement");
    let candidate = path.with_file_name(candidate_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&candidate)
        .expect("create foreign replacement");
    file.write_all(replacement)
        .expect("write foreign replacement");
    file.sync_all().expect("sync foreign replacement");
    drop(file);
    fs::rename(&candidate, path).expect("install foreign replacement");
    backup
}

fn restore_file(path: &Path, backup: &Path) {
    fs::remove_file(path).expect("remove exact foreign replacement");
    fs::rename(backup, path).expect("restore protected file");
}

fn replace_same_bytes(path: &Path) {
    let bytes = fs::read(path).expect("read record before replacement");
    let mut candidate_name = path.file_name().expect("record basename").to_os_string();
    candidate_name.push(".m3-replacement");
    let candidate = path.with_file_name(candidate_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&candidate)
        .expect("create replacement record");
    file.write_all(&bytes).expect("write replacement record");
    file.sync_all().expect("sync replacement record");
    drop(file);
    fs::rename(candidate, path).expect("replace record with new inode");
}

fn wait_for(path: &Path, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn lock_exclusive(file: &File) {
    assert_eq!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) },
        0,
        "acquire exclusive lease"
    );
}

fn unlock(file: &File) {
    assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
}

fn require_native_cow() {
    let (available, detail) = NATIVE_COW_PROBE.get_or_init(|| {
        let mut sandbox = Sandbox::new();
        let authority = fixture_repo(&sandbox, "probe-authority.git");
        let home = sandbox.child("probe-home");
        fs::create_dir(&home).expect("create probe home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect probe home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-vws"));
        remove_git_environment(&mut command);
        let initialized = command
            .args([OsString::from("init"), authority.as_os_str().to_os_string()])
            .env("HOME", &home)
            .output()
            .expect("run native COW probe init");
        assert_success(&initialized, "native COW probe init");
        let mut create = Command::new(env!("CARGO_BIN_EXE_git-vws"));
        remove_git_environment(&mut create);
        let output = create
            .args([
                OsString::from("--repo"),
                authority.as_os_str().to_os_string(),
                OsString::from("create"),
                OsString::from("native-cow-probe"),
            ])
            .env("HOME", &home)
            .output()
            .expect("run native COW probe create");
        let available = output.status.success();
        let detail = format!("{output:?}");
        sandbox.cleanup().expect("cleanup native COW probe");
        (available, detail)
    });
    assert!(*available, "NOT_EXECUTED: native COW unavailable: {detail}");
}

#[test]
fn list_is_empty_by_default_orders_raw_names_and_isolates_corruption() {
    require_native_cow();
    let mut fixture = Fixture::new();
    let state_before = snapshot(&fixture.state());
    let empty = fixture.list();
    assert_success(&empty, "list empty registered state");
    assert!(
        empty.stdout.is_empty(),
        "empty list emitted rows: {empty:?}"
    );
    assert!(
        empty.stderr.is_empty(),
        "empty list emitted diagnostics: {empty:?}"
    );
    assert_eq!(
        snapshot(&fixture.state()),
        state_before,
        "list created state entries"
    );

    let secondary = fixture.make_authority("secondary.git");
    assert_success(&fixture.create(OsString::from("zeta")), "create zeta");
    assert_success(&fixture.create(OsString::from("alpha")), "create alpha");
    let raw_name = OsString::from_vec(b"raw-\xff".to_vec());
    let raw_name_hex = hex(raw_name.as_bytes());
    assert_success(
        &fixture.create_at_with_target(&secondary, raw_name.clone(), "raw-name-target"),
        "create non-UTF-8 session",
    );
    let templates = fixture.templates();
    let protected_paths = [
        fixture.authority.as_path(),
        secondary.as_path(),
        templates.as_path(),
        fixture.cwd.as_path(),
        fixture.sibling.as_path(),
    ];
    let protected = protected_snapshot(&protected_paths);

    let default_rows = ndjson(&fixture.list());
    assert_eq!(default_rows.len(), 2, "default list crossed authorities");
    assert_eq!(row_string(&default_rows[0], "name_hex"), hex(b"alpha"));
    assert_eq!(row_string(&default_rows[1], "name_hex"), hex(b"zeta"));
    assert!(default_rows
        .iter()
        .all(|row| row_string(row, "state") == "READY"));

    let mut raw_exec = fixture.vws_command(fixture.exec_hex_args(
        &secondary,
        &raw_name_hex,
        vec![
            real_shell().as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from("printf 'raw-name\\n'"),
            OsString::from("raw-name"),
        ],
    ));
    let raw_exec = raw_exec.output().expect("exec non-UTF-8 name by hex");
    assert_success(&raw_exec, "exec non-UTF-8 name by hex");
    assert_eq!(raw_exec.stdout, b"raw-name\n");
    assert!(
        raw_exec.stderr.is_empty(),
        "exec added diagnostics: {raw_exec:?}"
    );

    let all = fixture.list_all();
    assert_success(&all, "list all authorities");
    let all_rows = ndjson(&all);
    assert_eq!(all_rows.len(), 3, "all list missed a healthy record");
    assert_sorted_rows(&all_rows);
    assert!(
        all_rows
            .iter()
            .any(|row| row_string(row, "name_hex") == raw_name_hex),
        "list lost non-UTF-8 raw name: {all_rows:?}"
    );

    let usage = fixture.vws(vec![
        OsString::from("--repo"),
        fixture.authority.as_os_str().to_os_string(),
        OsString::from("list"),
        OsString::from("--all"),
    ]);
    assert!(
        !usage.status.success() && !usage.stderr.is_empty(),
        "--repo plus --all was accepted: {usage:?}"
    );

    let malformed = fixture.sessions().join("session-malformed.record");
    fs::write(&malformed, b"not canonical session JSON\n").expect("write malformed record");
    fs::set_permissions(&malformed, fs::Permissions::from_mode(0o600))
        .expect("protect malformed record");
    let corrupt = fixture.list_all();
    assert_error(
        &corrupt,
        "SESSION_CORRUPT",
        "list malformed record isolation",
    );
    let corrupt_rows = ndjson(&corrupt);
    let healthy: Vec<_> = corrupt_rows
        .iter()
        .filter(|row| row_string(row, "state") != "CORRUPT")
        .collect();
    let corrupt_rows: Vec<_> = corrupt_rows
        .iter()
        .filter(|row| row_string(row, "state") == "CORRUPT")
        .collect();
    assert_eq!(healthy.len(), 3, "corruption hid healthy list rows");
    assert_eq!(
        corrupt_rows.len(),
        1,
        "malformed record did not isolate to one row"
    );
    assert_eq!(row_string(corrupt_rows[0], "code"), "SESSION_CORRUPT");
    assert_eq!(
        row_string(corrupt_rows[0], "record_name_hex"),
        hex(b"session-malformed.record")
    );
    assert_protected(&protected, &protected_paths);
    fixture.cleanup();
}

#[test]
fn native_git_runtime_survives_repeated_create_and_lists_ready() {
    require_native_cow();
    let mut fixture = Fixture::new();
    assert_success(&fixture.create(OsString::from("alpha")), "create alpha");
    let root = fixture.session_root();
    let worktree = root.join("worktree");
    let templates = fixture.templates();
    let protected_paths = [
        fixture.authority.as_path(),
        templates.as_path(),
        fixture.cwd.as_path(),
        fixture.sibling.as_path(),
    ];
    let protected = protected_snapshot(&protected_paths);

    git(
        &worktree,
        &git_args(&["config", "user.name", "Runtime Test"]),
    );
    git(
        &worktree,
        &git_args(&["config", "user.email", "runtime@example.invalid"]),
    );
    fs::write(worktree.join("nested/data"), b"committed runtime change\n")
        .expect("write committed runtime change");
    git(&worktree, &git_args(&["add", "nested/data"]));
    git(&worktree, &git_args(&["commit", "-m", "runtime commit"]));
    git(&worktree, &git_args(&["checkout", "-b", "runtime-branch"]));
    fs::write(worktree.join("nested/data"), b"dirty runtime change\n")
        .expect("write dirty runtime change");
    git(&worktree, &git_args(&["add", "nested/data"]));
    git(&worktree, &git_args(&["reset", "--mixed", "HEAD"]));
    let before_head = git(&worktree, &git_args(&["rev-parse", "HEAD"])).stdout;
    let before_status = git(&worktree, &git_args(&["status", "--porcelain=v1"])).stdout;
    assert_eq!(before_status, b" M nested/data\n");

    let repeated = fixture.create(OsString::from("alpha"));
    assert_success(&repeated, "repeated create after native Git mutations");
    assert_eq!(
        git(&worktree, &git_args(&["rev-parse", "HEAD"])).stdout,
        before_head,
        "repeated create reset native HEAD"
    );
    assert_eq!(
        git(&worktree, &git_args(&["rev-parse", "--abbrev-ref", "HEAD"])).stdout,
        b"runtime-branch\n",
        "repeated create reset native branch"
    );
    assert_eq!(
        fs::read(worktree.join("nested/data")).expect("read dirty native change"),
        b"dirty runtime change\n",
        "repeated create reset dirty native content"
    );
    assert_eq!(
        git(&worktree, &git_args(&["status", "--porcelain=v1"])).stdout,
        before_status,
        "repeated create changed native index state"
    );
    let rows = ndjson(&fixture.list());
    assert_eq!(rows.len(), 1);
    assert_eq!(row_string(&rows[0], "state"), "READY");
    assert_protected(&protected, &protected_paths);
    fixture.cleanup();
}

#[test]
fn authority_commit_graph_and_pack_advertisement_survive_session_maintenance() {
    require_native_cow();
    let mut fixture = Fixture::new();
    let authority = fixture_repo(&fixture.sandbox, "maintenance.git");
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(authority.as_os_str());
    git(
        &fixture.sandbox.path,
        &[
            git_dir.clone(),
            OsString::from("commit-graph"),
            OsString::from("write"),
            OsString::from("--reachable"),
        ],
    );
    git(
        &fixture.sandbox.path,
        &[git_dir, OsString::from("update-server-info")],
    );
    assert!(
        authority.join("objects/info/commit-graph").is_file()
            && authority.join("objects/info/packs").is_file(),
        "fixture Git maintenance did not create standard object info files"
    );
    assert_success(
        &fixture.vws(vec![
            OsString::from("init"),
            authority.as_os_str().to_os_string(),
        ]),
        "initialize authority with Git maintenance metadata",
    );
    assert_success(
        &fixture.create_at(&authority, OsString::from("maintained")),
        "create session from authority with Git maintenance metadata",
    );
    assert_success(
        &fixture.vws(vec![OsString::from("doctor")]),
        "doctor accepts Git maintenance metadata",
    );
    assert_success(
        &fixture.remove_at(&authority, "maintained", false),
        "remove clean session with Git maintenance metadata",
    );
    assert_success(
        &fixture.vws(vec![OsString::from("gc")]),
        "GC accepts Git maintenance metadata",
    );
    fixture.cleanup();
}

#[test]
fn exec_preserves_direct_process_contract_and_clears_git_routing() {
    require_native_cow();
    let mut fixture = Fixture::new();
    assert_success(&fixture.create(OsString::from("alpha")), "create alpha");
    let root = fixture.session_root();
    let worktree = root.join("worktree");
    let templates = fixture.templates();
    let protected_paths = [
        fixture.authority.as_path(),
        templates.as_path(),
        fixture.cwd.as_path(),
        fixture.sibling.as_path(),
    ];
    let protected = protected_snapshot(&protected_paths);

    let script = "printf 'argv0=<%s>\\narg1=<%s>\\n' \"$0\" \"$1\"\nprintf 'cwd=<%s>\\n' \"$(pwd -P)\"\nIFS= read -r line\nprintf 'stdin=<%s>\\n' \"$line\"\nprintf 'stderr=<%s>\\n' \"$2\" >&2\nexit 37";
    let mut child = fixture
        .vws_command(fixture.exec_args(
            &fixture.authority,
            OsString::from("alpha"),
            vec![
                real_shell().as_os_str().to_os_string(),
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("argv zero"),
                OsString::from("argument one"),
                OsString::from("error token"),
            ],
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn direct exec");
    child
        .stdin
        .take()
        .expect("direct exec stdin")
        .write_all(b"input exact\n")
        .expect("write direct exec stdin");
    let direct = child.wait_with_output().expect("wait direct exec");
    assert_eq!(
        direct.status.code(),
        Some(37),
        "direct exit changed: {direct:?}"
    );
    assert_eq!(
        direct.stdout,
        format!(
            "argv0=<argv zero>\narg1=<argument one>\ncwd=<{}>\nstdin=<input exact>\n",
            worktree.display()
        )
        .as_bytes(),
        "direct argv/cwd/stdin/stdout changed"
    );
    assert_eq!(
        direct.stderr, b"stderr=<error token>\n",
        "direct stderr changed"
    );

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
            &fixture.authority,
            OsString::from("alpha"),
            vec![
                real_git().as_os_str().to_os_string(),
                OsString::from("rev-parse"),
                OsString::from("--show-toplevel"),
            ],
        ))
        .env("GIT_DIR", &foreign)
        .env("GIT_WORK_TREE", &foreign_worktree)
        .env("GIT_COMMON_DIR", &foreign)
        .env("GIT_INDEX_FILE", &foreign_index)
        .output()
        .expect("exec with inherited Git routing variables");
    assert_success(&routed, "direct exec clears inherited Git routing");
    assert_eq!(
        routed.stdout,
        format!("{}\n", worktree.display()).as_bytes(),
        "direct Git command escaped the managed worktree"
    );
    assert!(
        routed.stderr.is_empty(),
        "direct Git exec added VWS noise: {routed:?}"
    );
    assert_eq!(
        snapshot(&foreign),
        foreign_before,
        "direct exec touched foreign Git state"
    );
    assert_protected(&protected, &protected_paths);
    fixture.cleanup();
}

#[test]
fn shared_exec_leases_block_remove_then_allow_clean_removal() {
    require_native_cow();
    let mut fixture = Fixture::new();
    assert_success(&fixture.create(OsString::from("alpha")), "create alpha");
    let root = fixture.session_root();
    let record = fixture.session_record();
    let templates = fixture.templates();
    let protected_paths = [
        fixture.authority.as_path(),
        templates.as_path(),
        fixture.cwd.as_path(),
        fixture.sibling.as_path(),
    ];
    let protected = protected_snapshot(&protected_paths);
    let root_before = snapshot(&root);
    let record_before = fs::read(&record).expect("read record before busy remove");
    let release = fixture.sandbox.child("release-exec-leases");
    let ready_one = fixture.sandbox.child("ready-exec-one");
    let ready_two = fixture.sandbox.child("ready-exec-two");
    let gate = "printf ready > \"$1\"\nwhile [ ! -e \"$2\" ]; do sleep 1; done";
    let spawn_gate = |ready: &Path| {
        fixture
            .vws_command(fixture.exec_args(
                &fixture.authority,
                OsString::from("alpha"),
                vec![
                    real_shell().as_os_str().to_os_string(),
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
            .expect("spawn leased direct exec")
    };
    let first = spawn_gate(&ready_one);
    let second = spawn_gate(&ready_two);
    wait_for(&ready_one, "first shared exec lease");
    wait_for(&ready_two, "second shared exec lease");
    let busy = fixture.remove("alpha", true);
    assert_error(&busy, "SESSION_BUSY", "remove during shared exec leases");
    assert_eq!(
        snapshot(&root),
        root_before,
        "busy remove changed session root"
    );
    assert_eq!(
        fs::read(&record).expect("read record after busy remove"),
        record_before
    );
    assert_protected(&protected, &protected_paths);

    fs::write(&release, b"release\n").expect("release shared exec leases");
    let first = first.wait_with_output().expect("wait first leased exec");
    let second = second.wait_with_output().expect("wait second leased exec");
    assert_success(&first, "first shared exec completion");
    assert_success(&second, "second shared exec completion");
    let removed = fixture.remove("alpha", false);
    assert_remove_event(&removed, b"alpha", "remove after shared exec leases");
    assert!(!root.exists(), "clean remove retained session root");
    assert!(!record.exists(), "clean remove retained session record");
    assert_protected(&protected, &protected_paths);
    fixture.cleanup();
}

#[test]
fn remove_rejects_discard_risk_and_force_only_skips_user_data_risk() {
    require_native_cow();

    let mut dirty = Fixture::new();
    assert_success(
        &dirty.create(OsString::from("dirty")),
        "create dirty session",
    );
    let dirty_root = dirty.session_root();
    let dirty_record = dirty.session_record();
    let dirty_worktree = dirty_root.join("worktree");
    fs::write(dirty_worktree.join("nested/data"), b"dirty tracked data\n")
        .expect("write tracked dirty data");
    fs::create_dir_all(dirty_worktree.join("ignored")).expect("create ignored worktree path");
    fs::write(dirty_worktree.join("ignored/evidence"), b"ignored data\n")
        .expect("write ignored dirty data");
    let dirty_templates = dirty.templates();
    let dirty_paths = [
        dirty.authority.as_path(),
        dirty_templates.as_path(),
        dirty.cwd.as_path(),
        dirty.sibling.as_path(),
    ];
    let dirty_protected = protected_snapshot(&dirty_paths);
    let rejected = dirty.remove("dirty", false);
    assert_error(
        &rejected,
        "SESSION_DISCARD_RISK",
        "remove dirty and ignored worktree",
    );
    assert!(
        dirty_root.exists() && dirty_record.exists(),
        "risk rejection removed session state"
    );
    assert_protected(&dirty_protected, &dirty_paths);
    let forced = dirty.remove("dirty", true);
    assert_remove_event(&forced, b"dirty", "force remove dirty session");
    assert!(!dirty_root.exists() && !dirty_record.exists());
    assert_protected(&dirty_protected, &dirty_paths);
    dirty.cleanup();

    let mut private_ref = Fixture::new();
    assert_success(
        &private_ref.create(OsString::from("private-ref")),
        "create private ref session",
    );
    let private_root = private_ref.session_root();
    let private_record = private_ref.session_record();
    let worktree = private_root.join("worktree");
    git(
        &worktree,
        &git_args(&["config", "user.name", "Private Ref"]),
    );
    git(
        &worktree,
        &git_args(&["config", "user.email", "private-ref@example.invalid"]),
    );
    fs::write(worktree.join("nested/data"), b"private ref commit\n").expect("write private ref");
    git(&worktree, &git_args(&["add", "nested/data"]));
    git(&worktree, &git_args(&["commit", "-m", "private ref"]));
    assert!(
        git(&worktree, &git_args(&["status", "--porcelain=v1"]))
            .stdout
            .is_empty(),
        "private ref fixture was not clean"
    );
    let private_templates = private_ref.templates();
    let private_paths = [
        private_ref.authority.as_path(),
        private_templates.as_path(),
        private_ref.cwd.as_path(),
        private_ref.sibling.as_path(),
    ];
    let private_protected = protected_snapshot(&private_paths);
    let rejected = private_ref.remove("private-ref", false);
    assert_error(
        &rejected,
        "SESSION_DISCARD_RISK",
        "remove clean private ref",
    );
    assert!(
        private_root.exists() && private_record.exists(),
        "private ref risk removed session state"
    );
    assert_protected(&private_protected, &private_paths);
    let forced = private_ref.remove("private-ref", true);
    assert_remove_event(&forced, b"private-ref", "force remove private ref");
    assert_protected(&private_protected, &private_paths);
    private_ref.cleanup();

    let mut reflog = Fixture::new();
    assert_success(
        &reflog.create(OsString::from("reflog")),
        "create reflog session",
    );
    let reflog_root = reflog.session_root();
    let reflog_record = reflog.session_record();
    let worktree = reflog_root.join("worktree");
    git(
        &worktree,
        &git_args(&["config", "user.name", "Reflog Test"]),
    );
    git(
        &worktree,
        &git_args(&["config", "user.email", "reflog@example.invalid"]),
    );
    let initial_head = git(&worktree, &git_args(&["rev-parse", "HEAD"])).stdout;
    fs::write(worktree.join("nested/data"), b"reflog-only commit\n").expect("write reflog data");
    git(&worktree, &git_args(&["add", "nested/data"]));
    git(&worktree, &git_args(&["commit", "-m", "reflog only"]));
    let reflog_commit = git(&worktree, &git_args(&["rev-parse", "HEAD"])).stdout;
    let initial_head = String::from_utf8(initial_head).expect("initial head UTF-8");
    git(
        &worktree,
        &[
            OsString::from("reset"),
            OsString::from("--hard"),
            OsString::from(initial_head.trim()),
        ],
    );
    assert!(
        git(&worktree, &git_args(&["status", "--porcelain=v1"]))
            .stdout
            .is_empty(),
        "reflog fixture worktree was not clean"
    );
    assert!(
        git(&worktree, &git_args(&["reflog", "--format=%H"]))
            .stdout
            .windows(reflog_commit.len())
            .any(|entry| entry == reflog_commit.as_slice()),
        "fixture did not retain the private commit in its reflog"
    );
    let reflog_templates = reflog.templates();
    let reflog_paths = [
        reflog.authority.as_path(),
        reflog_templates.as_path(),
        reflog.cwd.as_path(),
        reflog.sibling.as_path(),
    ];
    let reflog_protected = protected_snapshot(&reflog_paths);
    let rejected = reflog.remove("reflog", false);
    assert_error(
        &rejected,
        "SESSION_DISCARD_RISK",
        "remove clean private reflog",
    );
    assert!(
        reflog_root.exists() && reflog_record.exists(),
        "reflog risk removed session state"
    );
    assert_protected(&reflog_protected, &reflog_paths);
    let forced = reflog.remove("reflog", true);
    assert_remove_event(&forced, b"reflog", "force remove reflog session");
    assert_protected(&reflog_protected, &reflog_paths);
    reflog.cleanup();
}

#[test]
fn tombstone_recovery_resumes_and_already_absent_remove_is_idempotent() {
    require_native_cow();
    let mut fixture = Fixture::new();
    assert_success(&fixture.create(OsString::from("alpha")), "create alpha");
    let root = fixture.session_root();
    let record = fixture.session_record();
    let external = fixture.sandbox.child("recovery-external");
    fs::write(&external, b"keep external evidence\n").expect("write recovery external file");
    fs::hard_link(&external, root.join("worktree/recovery-hardlink"))
        .expect("create hardlink recovery barrier");
    let templates = fixture.templates();
    let protected_paths = [
        fixture.authority.as_path(),
        templates.as_path(),
        fixture.cwd.as_path(),
        fixture.sibling.as_path(),
    ];
    let protected = protected_snapshot(&protected_paths);

    let interrupted = fixture.remove("alpha", true);
    assert_error(
        &interrupted,
        "RECOVERY_REQUIRED",
        "force remove hardlink-tampered session",
    );
    assert!(
        record.exists(),
        "interrupted remove discarded tombstone record"
    );
    let tombstone = only_child(&fixture.sessions(), ".tombstone");
    let retained_link = tombstone.join("worktree/recovery-hardlink");
    assert!(
        retained_link.exists(),
        "interrupted remove lost evidence leaf"
    );
    assert_eq!(
        fs::read(&external).expect("read external after interrupted remove"),
        b"keep external evidence\n",
        "interrupted remove touched foreign hardlink target"
    );
    assert_protected(&protected, &protected_paths);

    fs::remove_file(&retained_link).expect("remove exact recovery barrier");
    assert_eq!(
        fs::read(&external).expect("read external after barrier removal"),
        b"keep external evidence\n",
        "recovery barrier cleanup removed foreign target"
    );
    let resumed = fixture.remove("alpha", false);
    assert_remove_event(&resumed, b"alpha", "resume tombstoned remove");
    assert!(
        children_with_suffix(&fixture.sessions(), ".root").is_empty()
            && children_with_suffix(&fixture.sessions(), ".tombstone").is_empty()
            && children_with_suffix(&fixture.sessions(), ".record").is_empty(),
        "tombstone recovery left a managed artifact"
    );
    let idempotent = fixture.remove("alpha", false);
    assert_remove_event(&idempotent, b"alpha", "idempotent remove after recovery");
    assert_protected(&protected, &protected_paths);
    fixture.cleanup();
}

#[test]
fn record_same_bytes_new_inode_is_rejected_across_exec_capability_boundary() {
    require_native_cow();
    let mut fixture = Fixture::new();
    assert_success(&fixture.create(OsString::from("alpha")), "create alpha");
    let root = fixture.session_root();
    let record = fixture.session_record();
    let original = fs::read(&record).expect("read original session record");
    let templates = fixture.templates();
    let protected_paths = [
        fixture.authority.as_path(),
        templates.as_path(),
        fixture.cwd.as_path(),
        fixture.sibling.as_path(),
    ];
    let protected = protected_snapshot(&protected_paths);
    let lease = File::open(&root).expect("open root lease descriptor");
    lock_exclusive(&lease);
    let marker = fixture.sandbox.child("record-replacement-program-ran");
    let mut child = fixture
        .vws_command(fixture.exec_args(
            &fixture.authority,
            OsString::from("alpha"),
            vec![
                real_shell().as_os_str().to_os_string(),
                OsString::from("-c"),
                OsString::from("printf ran > \"$1\""),
                OsString::from("replacement-check"),
                marker.as_os_str().to_os_string(),
            ],
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn exec behind exclusive lease");
    thread::sleep(Duration::from_millis(250));
    assert!(
        child.try_wait().expect("observe blocked exec").is_none(),
        "exec ended before its lease capability could be replaced"
    );
    replace_same_bytes(&record);
    unlock(&lease);
    let output = child.wait_with_output().expect("wait replaced-record exec");
    assert_error(
        &output,
        "SESSION_RECOVERY_REQUIRED",
        "same-byte record replacement across exec boundary",
    );
    assert!(
        !marker.exists(),
        "direct program ran after record replacement"
    );
    assert_eq!(
        fs::read(&record).expect("read retained replacement record"),
        original,
        "record replacement changed its bytes"
    );
    assert!(root.exists(), "record replacement caused root cleanup");
    assert_protected(&protected, &protected_paths);
    fixture.cleanup();
}

#[test]
fn force_rejects_root_and_runtime_topology_replacements_without_cleanup() {
    require_native_cow();

    let mut root_fixture = Fixture::new();
    assert_success(
        &root_fixture.create(OsString::from("root-replacement")),
        "create root replacement session",
    );
    let root = root_fixture.session_root();
    let record = root_fixture.session_record();
    let saved = root.with_file_name("saved-root");
    fs::rename(&root, &saved).expect("move managed root aside");
    fs::create_dir(&root).expect("create foreign root replacement");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("protect foreign root replacement");
    let foreign_root_file = root.join("foreign-root-sentinel");
    fs::write(&foreign_root_file, b"foreign root\n").expect("write foreign root sentinel");
    let templates = root_fixture.templates();
    let root_paths = [
        root_fixture.authority.as_path(),
        templates.as_path(),
        root_fixture.cwd.as_path(),
        root_fixture.sibling.as_path(),
    ];
    let root_protected = protected_snapshot(&root_paths);
    let rejected = root_fixture.remove("root-replacement", true);
    assert!(
        !rejected.status.success()
            && (String::from_utf8_lossy(&rejected.stderr).contains("SESSION_CORRUPT")
                || String::from_utf8_lossy(&rejected.stderr).contains("RECOVERY_REQUIRED")),
        "force remove replaced root: {rejected:?}"
    );
    assert!(record.exists(), "replaced root removed the record");
    assert_eq!(
        fs::read(&foreign_root_file).expect("read foreign root sentinel"),
        b"foreign root\n",
        "force remove deleted foreign root contents"
    );
    assert_protected(&root_protected, &root_paths);
    fs::remove_file(&foreign_root_file).expect("remove exact foreign root sentinel");
    fs::remove_dir(&root).expect("remove exact foreign root directory");
    fs::rename(&saved, &root).expect("restore managed root");
    root_fixture.cleanup();

    for label in ["dot-git", "gitdir", "commondir", "alternates"] {
        let mut fixture = Fixture::new();
        assert_success(
            &fixture.create(OsString::from("topology")),
            &format!("create {label} replacement session"),
        );
        let root = fixture.session_root();
        let metadata = metadata_directory(&root);
        let target = match label {
            "dot-git" => root.join("worktree/.git"),
            "gitdir" => metadata.join("gitdir"),
            "commondir" => metadata.join("commondir"),
            "alternates" => root.join("common.git/objects/info/alternates"),
            _ => unreachable!("known topology target"),
        };
        let backup = replace_file(&target, b"foreign topology\n");
        let record = fixture.session_record();
        let templates = fixture.templates();
        let protected_paths = [
            fixture.authority.as_path(),
            templates.as_path(),
            fixture.cwd.as_path(),
            fixture.sibling.as_path(),
        ];
        let protected = protected_snapshot(&protected_paths);
        let rejected = fixture.remove("topology", true);
        assert!(
            !rejected.status.success()
                && (String::from_utf8_lossy(&rejected.stderr).contains("SESSION_CORRUPT")
                    || String::from_utf8_lossy(&rejected.stderr).contains("RECOVERY_REQUIRED")),
            "force remove accepted replaced {label}: {rejected:?}"
        );
        assert!(
            record.exists() && root.exists(),
            "force remove removed {label} state"
        );
        assert_eq!(
            fs::read(&target).expect("read foreign topology replacement"),
            b"foreign topology\n",
            "force remove deleted foreign {label} replacement"
        );
        assert_protected(&protected, &protected_paths);
        restore_file(&target, &backup);
        fixture.cleanup();
    }
}

fn assert_remove_event(output: &Output, name: &[u8], context: &str) {
    assert_success(output, context);
    assert!(
        output.stderr.is_empty(),
        "{context} added diagnostics: {output:?}"
    );
    let rows = ndjson(output);
    assert_eq!(rows.len(), 1, "{context} did not emit one event: {rows:?}");
    assert_eq!(row_string(&rows[0], "event"), "REMOVED");
    assert_eq!(row_string(&rows[0], "name_hex"), hex(name));
}
