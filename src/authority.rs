use std::env;
use std::ffi::{CStr, CString, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::git;

const STATE_ROOT: &[u8] = b".git-vws";
const MAX_GIT_OUTPUT: usize = 1024;
const MAX_RECORD_BYTES: usize = 4096;
const GIT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
type ExchangeMutator = fn(RawFd, &CStr);
#[cfg(test)]
static EXCHANGE_MUTATOR: Mutex<Option<ExchangeMutator>> = Mutex::new(None);

#[cfg(test)]
use crate::git::{lose_probe_ownership, sigchld_allows_waiting};
#[cfg(test)]
use std::sync::Mutex;

#[derive(Debug)]
pub(crate) struct Error {
    pub(crate) code: &'static str,
    pub(crate) detail: String,
}

impl Error {
    pub(crate) fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub(crate) fn io(code: &'static str, context: &str, error: io::Error) -> Self {
        Self::new(code, format!("{context}: {error}"))
    }

    fn probe_failed(detail: impl Into<String>) -> Self {
        Self::new("GIT_PROBE_FAILED", detail)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub(crate) struct Authority {
    pub(crate) canonical: PathBuf,
    pub(crate) identity: Identity,
    pub(crate) object_format: String,
    pub(crate) ref_format: String,
}

impl Authority {
    fn matches(&self, other: &Self) -> bool {
        self.canonical == other.canonical
            && self.identity.same_node(other.identity)
            && self.object_format == other.object_format
            && self.ref_format == other.ref_format
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Identity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) uid: u32,
    pub(crate) mode: u32,
    pub(crate) kind: u32,
    pub(crate) nlink: u64,
}

impl Identity {
    pub(crate) fn from_stat(stat: &libc::stat) -> Self {
        Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino,
            uid: stat.st_uid,
            mode: stat.st_mode as u32 & 0o7777,
            kind: stat.st_mode as u32 & libc::S_IFMT as u32,
            nlink: stat.st_nlink as u64,
        }
    }

    pub(crate) fn from_file(file: &File) -> Result<Self, Error> {
        let mut stat = zeroed_stat();
        for _ in 0..3 {
            if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } == 0 {
                return Ok(Self::from_stat(&stat));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot stat descriptor",
                    error,
                ));
            }
        }
        Err(Error::new(
            "STATE_UNAVAILABLE",
            "cannot stat descriptor after retries",
        ))
    }

    pub(crate) fn directory(&self) -> bool {
        self.kind == libc::S_IFDIR as u32
    }

    pub(crate) fn regular(&self) -> bool {
        self.kind == libc::S_IFREG as u32
    }

    pub(crate) fn same_node(&self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.uid == other.uid
            && self.mode == other.mode
            && self.kind == other.kind
    }
}

#[derive(Debug)]
struct Record {
    canonical: PathBuf,
    identity: Identity,
    object_format: String,
    ref_format: String,
}

impl From<&Authority> for Record {
    fn from(authority: &Authority) -> Self {
        Self {
            canonical: authority.canonical.clone(),
            identity: authority.identity,
            object_format: authority.object_format.clone(),
            ref_format: authority.ref_format.clone(),
        }
    }
}

impl Record {
    fn exactly_matches(&self, authority: &Authority) -> bool {
        self.canonical == authority.canonical
            && self.identity.dev == authority.identity.dev
            && self.identity.ino == authority.identity.ino
            && self.identity.uid == authority.identity.uid
            && self.identity.mode == authority.identity.mode
            && self.identity.kind == authority.identity.kind
            && self.object_format == authority.object_format
            && self.ref_format == authority.ref_format
    }

    fn encode(&self) -> Vec<u8> {
        format!(
            "version=1\npath={}\ndev={}\nino={}\nuid={}\nmode={}\nobject={}\nref={}\n",
            hex(self.canonical.as_os_str().as_bytes()),
            self.identity.dev,
            self.identity.ino,
            self.identity.uid,
            self.identity.mode,
            self.object_format,
            self.ref_format
        )
        .into_bytes()
    }
}

pub(crate) fn init(input: &Path) -> Result<String, Error> {
    let first = inspect_authority(input)?;
    let second = inspect_authority(&first.canonical)?;
    if !first.matches(&second) {
        return Err(Error::new(
            "AUTHORITY_IDENTITY_DRIFT",
            "authority changed during preflight",
        ));
    }

    let mut state = StateRoot::open()?;
    match transaction(&mut state, &second) {
        Ok(()) => Ok(format!(
            "initialized bare authority {}",
            second.canonical.display()
        )),
        Err(error) if state.committed() || state.preserve_root() => Err(error),
        Err(error) => match state.abort_new_root() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(cleanup_error),
        },
    }
}

pub(crate) fn inspect(input: &Path) -> Result<Authority, Error> {
    let first = inspect_authority(input)?;
    let second = inspect_authority(&first.canonical)?;
    if !first.matches(&second) {
        return Err(Error::new(
            "AUTHORITY_IDENTITY_DRIFT",
            "authority changed during preflight",
        ));
    }
    Ok(second)
}

pub(crate) fn open_state() -> Result<StateRoot, Error> {
    StateRoot::open()
}

pub(crate) fn authority_record_present(
    state: &StateRoot,
    authority: &Authority,
) -> Result<bool, Error> {
    let name = record_name(&authority.canonical);
    match read_record_at(state.root_fd(), name.as_bytes()) {
        Ok(record) => Ok(record.exactly_matches(authority)),
        Err(error) if error.code == "STATE_UNAVAILABLE" => Ok(false),
        Err(error) => Err(error),
    }
}

fn transaction(state: &mut StateRoot, authority: &Authority) -> Result<(), Error> {
    state.lock()?;
    let locked_probe = inspect_authority(&authority.canonical)?;
    if !authority.matches(&locked_probe) {
        return Err(Error::new(
            "AUTHORITY_IDENTITY_DRIFT",
            "authority changed before state transaction",
        ));
    }
    scan_records(state, authority)?;

    let record = Record::from(authority);
    let final_name = record_name(&record.canonical);
    let mut pending = RecordTxn::begin(
        state.root_file(),
        final_name.to_bytes(),
        &record.encode(),
        None,
    )?;
    let final_probe = match inspect_authority(&authority.canonical) {
        Ok(probe) => probe,
        Err(error) => return Err(pending.abort(error)),
    };
    if !authority.matches(&final_probe) {
        return Err(pending.abort(Error::new(
            "AUTHORITY_IDENTITY_DRIFT",
            "authority changed before state commit",
        )));
    }
    if let Err(error) = pending.commit() {
        let error = if error.code == "STATE_RECORD_EXISTS" {
            final_collision_error(state.root_fd(), &final_name, authority)
        } else {
            error
        };
        if matches!(
            error.code,
            "AUTHORITY_DUPLICATE"
                | "STATE_CORRUPT"
                | "STATE_COMMITTED_RECOVERY_REQUIRED"
                | "STATE_COMMITTED_UNSYNCED"
        ) {
            state.preserve_root = true;
        }
        return Err(error);
    }
    if !read_record_at(state.root_fd(), final_name.as_bytes())?.exactly_matches(authority) {
        state.preserve_root = true;
        return Err(Error::new(
            "STATE_COMMITTED_RECOVERY_REQUIRED",
            "state record binding changed after its final rename",
        ));
    }
    if let Err(error) = state.commit_record() {
        if error.code == "STATE_COMMITTED_UNSYNCED" {
            state.preserve_root = true;
        }
        return Err(error);
    }
    if !read_record_at(state.root_fd(), final_name.as_bytes())?.exactly_matches(authority) {
        state.preserve_root = true;
        return Err(Error::new(
            "STATE_COMMITTED_RECOVERY_REQUIRED",
            "state record binding changed after parent sync",
        ));
    }
    Ok(())
}

fn inspect_authority(input: &Path) -> Result<Authority, Error> {
    let canonical = fs::canonicalize(input)
        .map_err(|error| Error::io("AUTHORITY_INVALID", "cannot canonicalize authority", error))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| Error::io("AUTHORITY_INVALID", "cannot stat authority", error))?;
    let identity = identity_from_metadata(&metadata);
    if !identity.directory() {
        return Err(Error::new(
            "AUTHORITY_INVALID",
            "authority is not a directory",
        ));
    }

    let probe = git_probe(&canonical)?;
    if probe[0] != "true" {
        return Err(Error::new(
            "AUTHORITY_NOT_BARE",
            "Git did not report a bare repository",
        ));
    }
    let git_dir = canonical_git_path(&probe[1], "git-dir")?;
    let common_dir = canonical_git_path(&probe[2], "git-common-dir")?;
    let git_identity = identity_for_path(&git_dir, "git-dir")?;
    let common_identity = identity_for_path(&common_dir, "git-common-dir")?;
    if canonical != git_dir
        || git_dir != common_dir
        || !identity.same_node(git_identity)
        || !identity.same_node(common_identity)
    {
        return Err(Error::new(
            "AUTHORITY_NOT_SOLE",
            "authority, git-dir, and common-dir differ",
        ));
    }

    let object_format = supported_format(&probe[3], &["sha1", "sha256"], "object")?;
    let ref_format = supported_format(&probe[4], &["files", "reftable"], "ref")?;
    verify_storage(&common_dir, &ref_format)?;
    Ok(Authority {
        canonical,
        identity,
        object_format,
        ref_format,
    })
}

fn git_probe(path: &Path) -> Result<Vec<String>, Error> {
    let args: Vec<OsString> = [
        OsString::from("-C"),
        path.as_os_str().to_os_string(),
        OsString::from("rev-parse"),
        OsString::from("--is-bare-repository"),
        OsString::from("--path-format=absolute"),
        OsString::from("--git-dir"),
        OsString::from("--git-common-dir"),
        OsString::from("--show-object-format=storage"),
        OsString::from("--show-ref-format"),
    ]
    .into_iter()
    .collect();
    let output = git::GitChild::spawn_for(&args, None, GIT_PROBE_TIMEOUT)
        .map_err(from_git_error)?
        .capture(MAX_GIT_OUTPUT)
        .map_err(from_git_error)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(Error::probe_failed("Git probe did not complete cleanly"));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| Error::new("GIT_PROBE_FAILED", "Git probe output was not UTF-8"))?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| Error::new("GIT_PROBE_FAILED", "Git probe lacked a final newline"))?;
    let fields: Vec<String> = body.split('\n').map(ToOwned::to_owned).collect();
    if fields.len() != 5
        || fields
            .iter()
            .any(|field| field.is_empty() || field.contains('\r'))
    {
        return Err(Error::probe_failed("Git probe output was ambiguous"));
    }
    Ok(fields)
}

fn from_git_error(error: git::Error) -> Error {
    Error::new(error.code, error.detail)
}

fn canonical_git_path(value: &str, label: &str) -> Result<PathBuf, Error> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(Error::new(
            "GIT_PROBE_FAILED",
            format!("{label} was not absolute"),
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        Error::io(
            "GIT_PROBE_FAILED",
            &format!("cannot canonicalize {label}"),
            error,
        )
    })
}

fn verify_storage(common: &Path, ref_format: &str) -> Result<(), Error> {
    ensure_directory(&common.join("objects"), "objects")?;
    if ref_format == "files" {
        ensure_directory(&common.join("refs"), "refs")?;
    } else {
        ensure_directory(&common.join("reftable"), "reftable")?;
    }
    reject_if_present(&common.join("worktrees"), "linked-worktree registry")?;
    reject_if_present(&common.join("objects/info/alternates"), "object alternates")?;
    Ok(())
}

fn ensure_directory(path: &Path, label: &str) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Error::io("AUTHORITY_INVALID", &format!("cannot stat {label}"), error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::new(
            "AUTHORITY_STORAGE_INVALID",
            format!("{label} is not a real directory"),
        ));
    }
    Ok(())
}

fn reject_if_present(path: &Path, label: &str) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Error::new(
            "AUTHORITY_STORAGE_INVALID",
            format!("{label} is present"),
        )),
        Err(error) => Err(Error::io(
            "AUTHORITY_INVALID",
            &format!("cannot inspect {label}"),
            error,
        )),
    }
}

fn supported_format(value: &str, supported: &[&str], kind: &str) -> Result<String, Error> {
    if supported.contains(&value) {
        Ok(value.to_owned())
    } else {
        Err(Error::new(
            "FORMAT_UNSUPPORTED",
            format!("unsupported {kind} format {value:?}"),
        ))
    }
}

pub(crate) struct StateRoot {
    home: File,
    root_path: PathBuf,
    root: Option<File>,
    root_name: CString,
    created: bool,
    identity: Identity,
    home_locked: bool,
    root_locked: bool,
    committed: bool,
    preserve_root: bool,
}

impl StateRoot {
    fn open() -> Result<Self, Error> {
        let root_path = state_root_path()?;
        let home = open_home()?;
        let home_identity = Identity::from_file(&home)?;
        if !home_identity.directory() || home_identity.uid != current_uid() {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                "HOME is not an owned directory",
            ));
        }
        lock_descriptor(&home, "HOME")?;

        let root_name = cstring(STATE_ROOT, "state root")?;
        let created = match unsafe { libc::mkdirat(home.as_raw_fd(), root_name.as_ptr(), 0o700) } {
            0 => true,
            _ if io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists => false,
            _ => {
                return Err(Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot create state root",
                    io::Error::last_os_error(),
                ));
            }
        };
        let root = match open_directory_at(home.as_raw_fd(), &root_name, "state root") {
            Ok(root) => root,
            Err(error) if created => {
                return Err(Error::new(
                    "STATE_CLEANUP_FAILED",
                    format!("cannot arm newly created state root: {error}"),
                ));
            }
            Err(error) => return Err(error),
        };
        if created {
            let mut armed = ArmedNewRoot::new(&home, root, &root_name);
            if let Err(error) = armed.refresh_identity() {
                return Err(armed.abort(error));
            }
            if unsafe { libc::fchmod(armed.root_fd(), 0o700) } != 0 {
                return Err(armed.abort(Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot protect new state root",
                    io::Error::last_os_error(),
                )));
            }
            let identity = match armed.refresh_identity() {
                Ok(identity) => identity,
                Err(error) => return Err(armed.abort(error)),
            };
            if !valid_state_root(identity) {
                return Err(armed.abort(Error::new(
                    "STATE_UNAVAILABLE",
                    "state root is not owner-only",
                )));
            }
            let root = armed.disarm();
            let mut state = Self {
                home,
                root_path,
                root: Some(root),
                root_name,
                created,
                identity,
                home_locked: true,
                root_locked: false,
                committed: false,
                preserve_root: false,
            };
            if let Err(error) = state.revalidate_root() {
                return match state.abort_new_root() {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(cleanup_error),
                };
            }
            return Ok(state);
        }

        let identity = Identity::from_file(&root)?;
        if !valid_state_root(identity) {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                "state root is not owner-only",
            ));
        }
        let state = Self {
            home,
            root_path,
            root: Some(root),
            root_name,
            created,
            identity,
            home_locked: true,
            root_locked: false,
            committed: false,
            preserve_root: false,
        };
        state.revalidate_root()?;
        Ok(state)
    }

    pub(crate) fn root_fd(&self) -> RawFd {
        self.root.as_ref().expect("state root open").as_raw_fd()
    }

    fn root_file(&self) -> &File {
        self.root.as_ref().expect("state root open")
    }

    pub(crate) fn container_path(&self, name: &str) -> Result<PathBuf, Error> {
        if name != "templates" && name != "sessions" {
            return Err(Error::new("STATE_CORRUPT", "unknown state container"));
        }
        Ok(self.root_path.join(name))
    }

    pub(crate) fn ensure_containers(&self) -> Result<(), Error> {
        for name in [b"templates".as_slice(), b"sessions".as_slice()] {
            let name = cstring(name, "state container")?;
            let result = unsafe { libc::mkdirat(self.root_fd(), name.as_ptr(), 0o700) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(Error::io(
                        "STATE_UNAVAILABLE",
                        "cannot create state container",
                        error,
                    ));
                }
            }
            let directory = open_directory_at(self.root_fd(), &name, "state container")?;
            let identity = Identity::from_file(&directory)?;
            if identity.dev != self.identity.dev || !valid_state_container(identity) {
                return Err(Error::new(
                    "STATE_CORRUPT",
                    "state container is not an owner-only directory on the state volume",
                ));
            }
        }
        self.root
            .as_ref()
            .expect("state root open")
            .sync_all()
            .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot sync state containers", error))
    }

    pub(crate) fn open_container(&self, name: &[u8]) -> Result<File, Error> {
        let name = cstring(name, "state container")?;
        let file = open_directory_at(self.root_fd(), &name, "state container")?;
        let identity = Identity::from_file(&file)?;
        if identity.dev != self.identity.dev || !valid_state_container(identity) {
            return Err(Error::new(
                "STATE_CORRUPT",
                "state container binding is invalid",
            ));
        }
        Ok(file)
    }

    fn lock(&mut self) -> Result<(), Error> {
        lock_descriptor(self.root.as_ref().expect("state root open"), "state root")?;
        self.root_locked = true;
        self.revalidate_root()
    }

    fn revalidate_root(&self) -> Result<(), Error> {
        let entry = Identity::from_stat(&stat_at(
            self.home.as_raw_fd(),
            &self.root_name,
            libc::AT_SYMLINK_NOFOLLOW,
        )?);
        let descriptor = Identity::from_file(self.root.as_ref().expect("state root open"))?;
        if !entry.same_node(self.identity)
            || !descriptor.same_node(self.identity)
            || !valid_state_root(entry)
            || !valid_state_root(descriptor)
        {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                "state root no longer matches its descriptor capability",
            ));
        }
        Ok(())
    }

    fn abort_new_root(&mut self) -> Result<(), Error> {
        if !self.created || self.committed {
            return Ok(());
        }
        let root = self.root.as_ref().ok_or_else(|| {
            Error::new("STATE_CLEANUP_FAILED", "new state root descriptor vanished")
        })?;
        cleanup_new_root(&self.home, root, &self.root_name, self.identity)?;
        self.root.take();
        self.root_locked = false;
        Ok(())
    }

    fn commit_record(&mut self) -> Result<(), Error> {
        self.committed = true;
        if self.created {
            self.home.sync_all().map_err(|error| {
                Error::io(
                    "STATE_COMMITTED_UNSYNCED",
                    "cannot sync HOME after new state root commit",
                    error,
                )
            })?;
        }
        self.revalidate_root().map_err(|_| {
            Error::new(
                "STATE_COMMITTED_RECOVERY_REQUIRED",
                "state root binding changed after record commit",
            )
        })
    }

    fn committed(&self) -> bool {
        self.committed
    }

    fn preserve_root(&self) -> bool {
        self.preserve_root
    }

    fn unlock_root(&mut self) {
        if self.root_locked {
            if let Some(root) = self.root.as_ref() {
                let _ = unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_UN) };
            }
            self.root_locked = false;
        }
    }

    fn unlock_home(&mut self) {
        if self.home_locked {
            let _ = unsafe { libc::flock(self.home.as_raw_fd(), libc::LOCK_UN) };
            self.home_locked = false;
        }
    }
}

struct ArmedNewRoot<'a> {
    home: &'a File,
    root: Option<File>,
    name: &'a CStr,
    identity: Option<Identity>,
    armed: bool,
}

impl<'a> ArmedNewRoot<'a> {
    fn new(home: &'a File, root: File, name: &'a CStr) -> Self {
        Self {
            home,
            root: Some(root),
            name,
            identity: None,
            armed: true,
        }
    }

    fn root_fd(&self) -> RawFd {
        self.root
            .as_ref()
            .expect("armed state root open")
            .as_raw_fd()
    }

    fn refresh_identity(&mut self) -> Result<Identity, Error> {
        let identity = Identity::from_file(self.root.as_ref().expect("armed state root open"))?;
        self.identity = Some(identity);
        if !safe_new_root(identity) {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                "new state root is not owner-only",
            ));
        }
        Ok(identity)
    }

    fn abort(mut self, error: Error) -> Error {
        match self.cleanup() {
            Ok(()) => error,
            Err(cleanup_error) => cleanup_error,
        }
    }

    fn cleanup(&mut self) -> Result<(), Error> {
        self.armed = false;
        let identity = self.identity.ok_or_else(|| {
            Error::new(
                "STATE_CLEANUP_FAILED",
                "new state root identity was not established",
            )
        })?;
        cleanup_new_root(
            self.home,
            self.root.as_ref().expect("armed state root open"),
            self.name,
            identity,
        )
    }

    fn disarm(mut self) -> File {
        self.armed = false;
        self.root.take().expect("armed state root open")
    }
}

impl Drop for ArmedNewRoot<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cleanup();
        }
    }
}

impl Drop for StateRoot {
    fn drop(&mut self) {
        self.unlock_root();
        self.unlock_home();
    }
}

pub(crate) struct RecordTxn {
    parent: File,
    final_name: CString,
    temporary_name: CString,
    temporary: Option<File>,
    temporary_identity: Option<Identity>,
    expected_old: Option<RecordBinding>,
    bytes: Vec<u8>,
    armed: bool,
}

impl RecordTxn {
    pub(crate) fn begin(
        parent: &File,
        basename: &[u8],
        bytes: &[u8],
        expected_old: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let final_name = cstring(basename, "record")?;
        let expected_old = expected_old
            .map(|expected| {
                let binding = read_file_binding(
                    parent.as_raw_fd(),
                    basename,
                    expected.len().max(bytes.len()),
                )?;
                if binding.bytes != expected {
                    return Err(Error::new(
                        "STATE_CORRUPT",
                        "state record bytes changed before its atomic replacement",
                    ));
                }
                Ok(binding)
            })
            .transpose()?;
        let temporary_name = cstring(
            format!(
                ".{}-{}-{}.tmp",
                String::from_utf8_lossy(basename),
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
            "temporary record",
        )?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(Error::io(
                "STATE_UNAVAILABLE",
                "cannot create temporary state record",
                io::Error::last_os_error(),
            ));
        }
        let mut transaction = Self {
            parent: parent.try_clone().map_err(|error| {
                Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot retain state record parent capability",
                    error,
                )
            })?,
            final_name,
            temporary_name,
            temporary: Some(unsafe { File::from_raw_fd(raw) }),
            temporary_identity: None,
            expected_old,
            bytes: bytes.to_vec(),
            armed: true,
        };
        if let Err(error) = transaction.initialize() {
            return Err(transaction.abort(error));
        }
        Ok(transaction)
    }

    fn initialize(&mut self) -> Result<(), Error> {
        let file = self
            .temporary
            .as_ref()
            .expect("armed temporary record descriptor");
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(Error::io(
                "STATE_UNAVAILABLE",
                "cannot protect temporary state record",
                io::Error::last_os_error(),
            ));
        }
        let identity = Identity::from_file(file)?;
        if !valid_record(identity) {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                "temporary state record is not owner-only",
            ));
        }
        self.temporary_identity = Some(identity);
        let file = self
            .temporary
            .as_mut()
            .expect("armed temporary record descriptor");
        file.write_all(&self.bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| {
                Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot write temporary state record",
                    error,
                )
            })?;
        if Identity::from_file(file)? != identity {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                "temporary state record descriptor changed before commit",
            ));
        }
        self.temporary.take();
        Ok(())
    }

    pub(crate) fn commit(&mut self) -> Result<RecordBinding, Error> {
        let temporary_identity = self.temporary_identity.ok_or_else(|| {
            Error::new(
                "STATE_CLEANUP_FAILED",
                "temporary state record identity was not established",
            )
        })?;
        if Identity::from_stat(&stat_at(
            self.parent.as_raw_fd(),
            &self.temporary_name,
            libc::AT_SYMLINK_NOFOLLOW,
        )?) != temporary_identity
        {
            return Err(self.abort(Error::new(
                "STATE_CLEANUP_FAILED",
                "temporary state record binding changed before commit",
            )));
        }
        match self.expected_old.clone() {
            None => self.commit_new(temporary_identity),
            Some(expected_old) => self.commit_exchange(temporary_identity, expected_old),
        }
    }

    fn commit_new(&mut self, temporary_identity: Identity) -> Result<RecordBinding, Error> {
        match rename_no_replace(
            self.parent.as_raw_fd(),
            &self.temporary_name,
            &self.final_name,
        ) {
            Ok(()) => {
                self.armed = false;
                let binding = self.verify_new_binding(temporary_identity)?;
                sync_record_parent(&self.parent)?;
                self.verify_new_binding(temporary_identity).map(|_| binding)
            }
            Err(error) if rename_result_is_unknown(&error) => {
                self.armed = false;
                Err(Error::io(
                    "STATE_COMMITTED_RECOVERY_REQUIRED",
                    "state record rename has an unknown result",
                    error,
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(self.abort(
                Error::new("STATE_RECORD_EXISTS", "state record already exists"),
            )),
            Err(error) => Err(self.abort(Error::io(
                "STATE_UNAVAILABLE",
                "cannot publish temporary state record",
                error,
            ))),
        }
    }

    fn commit_exchange(
        &mut self,
        temporary_identity: Identity,
        expected_old: RecordBinding,
    ) -> Result<RecordBinding, Error> {
        let current = match read_file_binding(
            self.parent.as_raw_fd(),
            self.final_name.to_bytes(),
            expected_old.bytes.len().max(self.bytes.len()),
        ) {
            Ok(binding) => binding,
            Err(error) => return Err(self.abort(error)),
        };
        if current != expected_old {
            return Err(self.abort(Error::new(
                "STATE_CORRUPT",
                "state record bytes or identity changed before its atomic replacement",
            )));
        }
        if let Err(error) = rename_exchange(
            self.parent.as_raw_fd(),
            &self.temporary_name,
            &self.final_name,
        ) {
            if rename_result_is_unknown(&error) {
                self.armed = false;
                return Err(Error::io(
                    "STATE_COMMITTED_RECOVERY_REQUIRED",
                    "state record exchange has an unknown result",
                    error,
                ));
            }
            return Err(self.abort(Error::io(
                "STATE_UNAVAILABLE",
                "cannot exchange state records",
                error,
            )));
        }
        #[cfg(test)]
        exchange_after_rename(self.parent.as_raw_fd(), &self.final_name);
        self.armed = false;
        let expected_new = RecordBinding {
            bytes: self.bytes.clone(),
            identity: temporary_identity,
        };
        let published = read_file_binding(
            self.parent.as_raw_fd(),
            self.final_name.to_bytes(),
            self.bytes.len(),
        );
        let displaced = read_file_binding(
            self.parent.as_raw_fd(),
            self.temporary_name.to_bytes(),
            expected_old.bytes.len(),
        );
        if published.as_ref().ok() != Some(&expected_new)
            || displaced.as_ref().ok() != Some(&expected_old)
        {
            return Err(self.rollback_exchange_if_owned(
                temporary_identity,
                &expected_old,
                Error::new(
                    "STATE_COMMITTED_RECOVERY_REQUIRED",
                    "state record exchange bindings drifted before cleanup",
                ),
            ));
        }
        if let Err(error) = unlink_capability(
            self.parent.as_raw_fd(),
            &self.temporary_name,
            expected_old.identity,
        ) {
            return Err(Error::new(
                "STATE_COMMITTED_RECOVERY_REQUIRED",
                format!("cannot remove exchanged expected-old record: {error}"),
            ));
        }
        sync_record_parent(&self.parent)?;
        self.verify_new_binding(temporary_identity)
    }

    fn verify_new_binding(&self, temporary_identity: Identity) -> Result<RecordBinding, Error> {
        let binding = read_file_binding(
            self.parent.as_raw_fd(),
            self.final_name.to_bytes(),
            self.bytes.len(),
        )?;
        if binding.identity != temporary_identity || binding.bytes != self.bytes {
            return Err(Error::new(
                "STATE_COMMITTED_RECOVERY_REQUIRED",
                "state record binding changed after its final rename",
            ));
        }
        Ok(binding)
    }

    fn rollback_exchange_if_owned(
        &mut self,
        temporary_identity: Identity,
        expected_old: &RecordBinding,
        primary: Error,
    ) -> Error {
        let expected_new = RecordBinding {
            bytes: self.bytes.clone(),
            identity: temporary_identity,
        };
        let final_binding = read_file_binding(
            self.parent.as_raw_fd(),
            self.final_name.to_bytes(),
            self.bytes.len(),
        );
        let temporary_binding = read_file_binding(
            self.parent.as_raw_fd(),
            self.temporary_name.to_bytes(),
            expected_old.bytes.len(),
        );
        if final_binding.as_ref().ok() != Some(&expected_new)
            || temporary_binding.as_ref().ok() != Some(expected_old)
        {
            return Error::new(
                "STATE_COMMITTED_RECOVERY_REQUIRED",
                "state record exchange drifted; rollback would move an external binding",
            );
        }
        if let Err(error) = rename_exchange(
            self.parent.as_raw_fd(),
            &self.temporary_name,
            &self.final_name,
        ) {
            return Error::io(
                "STATE_COMMITTED_RECOVERY_REQUIRED",
                "cannot roll back a verified state record exchange",
                error,
            );
        }
        let restored = read_file_binding(
            self.parent.as_raw_fd(),
            self.final_name.to_bytes(),
            expected_old.bytes.len(),
        );
        let new_temporary = read_file_binding(
            self.parent.as_raw_fd(),
            self.temporary_name.to_bytes(),
            self.bytes.len(),
        );
        if restored.as_ref().ok() != Some(expected_old)
            || new_temporary.as_ref().ok() != Some(&expected_new)
        {
            return Error::new(
                "STATE_COMMITTED_RECOVERY_REQUIRED",
                "state record rollback did not restore both verified bindings",
            );
        }
        cleanup_unpublished_record(
            &self.parent,
            &self.temporary_name,
            temporary_identity,
            primary,
        )
    }

    pub(crate) fn abort(&mut self, primary: Error) -> Error {
        if !self.armed {
            return primary;
        }
        self.armed = false;
        let identity = match self.temporary_identity {
            Some(identity) => identity,
            None => match self
                .temporary
                .as_ref()
                .ok_or_else(|| {
                    Error::new(
                        "STATE_CLEANUP_FAILED",
                        "temporary state record descriptor vanished before cleanup",
                    )
                })
                .and_then(Identity::from_file)
            {
                Ok(identity) if valid_private_record(identity) => identity,
                Ok(_) => {
                    return Error::new(
                        "STATE_CLEANUP_FAILED",
                        "temporary state record was unsafe before cleanup",
                    )
                }
                Err(error) => return error,
            },
        };
        self.temporary.take();
        cleanup_unpublished_record(&self.parent, &self.temporary_name, identity, primary)
    }
}

#[cfg(test)]
fn exchange_after_rename(parent: RawFd, final_name: &CStr) {
    if let Some(mutator) = *EXCHANGE_MUTATOR.lock().expect("exchange test lock") {
        mutator(parent, final_name);
    }
}

impl Drop for RecordTxn {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.abort(Error::new(
                "STATE_CLEANUP_FAILED",
                "temporary state record was dropped before commit",
            ));
        }
    }
}

fn open_home() -> Result<File, Error> {
    let home =
        env::var_os("HOME").ok_or_else(|| Error::new("STATE_UNAVAILABLE", "HOME is not set"))?;
    let bytes = home.as_bytes();
    if !bytes.starts_with(b"/") {
        return Err(Error::new("STATE_UNAVAILABLE", "HOME is not absolute"));
    }
    let mut current = File::open("/")
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot open filesystem root", error))?;
    for component in bytes[1..].split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                "HOME contains an unsafe path component",
            ));
        }
        let name = cstring(component, "HOME component")?;
        current = open_directory_at(current.as_raw_fd(), &name, "HOME component")?;
    }
    Ok(current)
}

fn state_root_path() -> Result<PathBuf, Error> {
    let home =
        env::var_os("HOME").ok_or_else(|| Error::new("STATE_UNAVAILABLE", "HOME is not set"))?;
    let bytes = home.as_bytes();
    if !bytes.starts_with(b"/")
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(Error::new(
            "STATE_UNAVAILABLE",
            "HOME is not a safe absolute path",
        ));
    }
    Ok(PathBuf::from(home).join(".git-vws"))
}

fn lock_descriptor(file: &File, label: &str) -> Result<(), Error> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(Error::io(
            "STATE_BUSY",
            &format!("cannot lock {label}"),
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn cleanup_new_root(
    home: &File,
    root: &File,
    name: &CStr,
    expected: Identity,
) -> Result<(), Error> {
    if !safe_new_root(expected) {
        return Err(Error::new(
            "STATE_CLEANUP_FAILED",
            "new state root was not owner-only",
        ));
    }
    let descriptor = Identity::from_file(root).map_err(|_| {
        Error::new(
            "STATE_CLEANUP_FAILED",
            "cannot revalidate new state root descriptor",
        )
    })?;
    if !descriptor.same_node(expected) || !safe_new_root(descriptor) {
        return Err(Error::new(
            "STATE_CLEANUP_FAILED",
            "new state root descriptor changed before cleanup",
        ));
    }
    let entry = Identity::from_stat(
        &stat_at(home.as_raw_fd(), name, libc::AT_SYMLINK_NOFOLLOW).map_err(|_| {
            Error::new(
                "STATE_CLEANUP_FAILED",
                "cannot revalidate new state root parent entry",
            )
        })?,
    );
    if !entry.same_node(expected) || !safe_new_root(entry) {
        return Err(Error::new(
            "STATE_CLEANUP_FAILED",
            "new state root identity changed before cleanup",
        ));
    }
    let names = directory_names(root.as_raw_fd()).map_err(|_| {
        Error::new(
            "STATE_CLEANUP_FAILED",
            "cannot enumerate new state root for cleanup",
        )
    })?;
    if !names.is_empty() {
        return Err(Error::new(
            "STATE_CLEANUP_FAILED",
            "new state root contains entries not owned by this transaction",
        ));
    }
    unlink_directory_at(home.as_raw_fd(), name).map_err(|error| {
        Error::io(
            "STATE_CLEANUP_FAILED",
            "cannot remove new state root",
            error,
        )
    })
}

fn scan_records(state: &StateRoot, authority: &Authority) -> Result<(), Error> {
    let mut names = directory_names(state.root_fd())?;
    if names.is_empty() && !state.created {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state root exists without an authority record",
        ));
    }
    names.sort();
    for name in names {
        if name == b"templates" || name == b"sessions" {
            let container = cstring(&name, "state container")?;
            let identity = Identity::from_stat(&stat_at(
                state.root_fd(),
                &container,
                libc::AT_SYMLINK_NOFOLLOW,
            )?);
            if !valid_state_container(identity) || identity.dev != state.identity.dev {
                return Err(Error::new(
                    "STATE_CORRUPT",
                    "state container is not an exact owned directory",
                ));
            }
            continue;
        }
        if !name.ends_with(b".record") || name.starts_with(b".") {
            return Err(Error::new(
                "STATE_CORRUPT",
                "state root contains an unexpected entry",
            ));
        }
        let record = read_record_at(state.root_fd(), &name)?;
        if name != record_name(&record.canonical).as_bytes() {
            return Err(Error::new(
                "STATE_CORRUPT",
                "state record filename does not match its canonical path",
            ));
        }
        if record.canonical == authority.canonical {
            return if record.exactly_matches(authority) {
                Err(Error::new(
                    "AUTHORITY_DUPLICATE",
                    "authority already initialized",
                ))
            } else {
                Err(Error::new(
                    "AUTHORITY_IDENTITY_DRIFT",
                    "canonical authority path identifies different data",
                ))
            };
        }
        if record.identity.dev == authority.identity.dev
            && record.identity.ino == authority.identity.ino
        {
            return Err(Error::new(
                "STATE_CORRUPT",
                "foreign state record claims the authority identity",
            ));
        }
    }
    Ok(())
}

fn final_collision_error(root_fd: RawFd, final_name: &CStr, authority: &Authority) -> Error {
    match read_record_at(root_fd, final_name.to_bytes()) {
        Ok(record) if record.exactly_matches(authority) => {
            Error::new("AUTHORITY_DUPLICATE", "authority already initialized")
        }
        Ok(_) | Err(_) => Error::new(
            "STATE_CORRUPT",
            "state record collision does not exactly match the authority",
        ),
    }
}

fn read_record_at(root_fd: RawFd, name: &[u8]) -> Result<Record, Error> {
    let name = cstring(name, "record")?;
    let before = Identity::from_stat(&stat_at(root_fd, &name, libc::AT_SYMLINK_NOFOLLOW)?);
    if !valid_record(before) {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state record is not an owner-only regular file",
        ));
    }
    let mut file = open_file_at(root_fd, &name, "state record")?;
    let opened = Identity::from_file(&file)
        .map_err(|_| Error::new("STATE_CORRUPT", "cannot stat opened state record"))?;
    if opened != before || !valid_record(opened) {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state record changed while opening",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::io("STATE_CORRUPT", "cannot read state record", error))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state record exceeds the limit",
        ));
    }
    let record = parse_record(&bytes)?;
    if record.encode() != bytes {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state record is not canonically encoded",
        ));
    }
    let descriptor = Identity::from_file(&file)
        .map_err(|_| Error::new("STATE_CORRUPT", "cannot restat opened state record"))?;
    let final_entry = Identity::from_stat(
        &stat_at(root_fd, &name, libc::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| Error::new("STATE_CORRUPT", "cannot restat state record basename"))?,
    );
    if !record_binding_matches(opened, descriptor, final_entry) {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state record binding changed while reading",
        ));
    }
    Ok(record)
}

fn record_binding_matches(opened: Identity, descriptor: Identity, final_entry: Identity) -> bool {
    opened == descriptor && descriptor == final_entry
}

fn parse_record(bytes: &[u8]) -> Result<Record, Error> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::new("STATE_CORRUPT", "state record is not UTF-8"))?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| Error::new("STATE_CORRUPT", "state record lacks a final newline"))?;
    let fields: Vec<&str> = body.split('\n').collect();
    if fields.len() != 8 {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state record has the wrong field count",
        ));
    }
    let values = [
        field(fields[0], "version")?,
        field(fields[1], "path")?,
        field(fields[2], "dev")?,
        field(fields[3], "ino")?,
        field(fields[4], "uid")?,
        field(fields[5], "mode")?,
        field(fields[6], "object")?,
        field(fields[7], "ref")?,
    ];
    if values[0] != "1" {
        return Err(Error::new("STATE_CORRUPT", "unknown state record version"));
    }
    let object_format = supported_format(values[6], &["sha1", "sha256"], "object")
        .map_err(|_| Error::new("STATE_CORRUPT", "invalid state object format"))?;
    let ref_format = supported_format(values[7], &["files", "reftable"], "ref")
        .map_err(|_| Error::new("STATE_CORRUPT", "invalid state ref format"))?;
    Ok(Record {
        canonical: decode_path(values[1])?,
        identity: Identity {
            dev: parse_number(values[2], "dev")?,
            ino: parse_number(values[3], "ino")?,
            uid: parse_number(values[4], "uid")?,
            mode: parse_number(values[5], "mode")?,
            kind: libc::S_IFDIR as u32,
            nlink: 0,
        },
        object_format,
        ref_format,
    })
}

fn field<'a>(line: &'a str, key: &str) -> Result<&'a str, Error> {
    line.strip_prefix(&format!("{key}="))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::new("STATE_CORRUPT", format!("invalid {key} field")))
}

fn parse_number<T>(value: &str, key: &str) -> Result<T, Error>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| Error::new("STATE_CORRUPT", format!("invalid {key} number")))
}

fn record_name(path: &Path) -> CString {
    CString::new(format!("authority-{:016x}.record", path_hash(path)))
        .expect("fixed record basename")
}

fn valid_state_root(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode == 0o700
        && identity.nlink >= 2
}

fn valid_state_container(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode == 0o700
        && identity.nlink >= 2
}

fn safe_new_root(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode & 0o077 == 0
        && identity.nlink >= 2
}

fn valid_record(identity: Identity) -> bool {
    identity.regular()
        && identity.uid == current_uid()
        && identity.mode == 0o600
        && identity.nlink == 1
}

fn valid_private_record(identity: Identity) -> bool {
    identity.regular()
        && identity.uid == current_uid()
        && identity.mode & 0o077 == 0
        && identity.nlink == 1
}

fn identity_for_path(path: &Path, label: &str) -> Result<Identity, Error> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Error::io("AUTHORITY_INVALID", &format!("cannot stat {label}"), error))?;
    Ok(identity_from_metadata(&metadata))
}

fn identity_from_metadata(metadata: &fs::Metadata) -> Identity {
    Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        kind: metadata.mode() & libc::S_IFMT as u32,
        nlink: metadata.nlink(),
    }
}

fn cstring(bytes: &[u8], label: &str) -> Result<CString, Error> {
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(Error::new(
            "STATE_CORRUPT",
            format!("invalid {label} basename"),
        ));
    }
    CString::new(bytes).map_err(|_| Error::new("STATE_CORRUPT", format!("invalid {label} bytes")))
}

fn open_directory_at(parent: RawFd, name: &CStr, label: &str) -> Result<File, Error> {
    let raw = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(Error::io(
            "STATE_UNAVAILABLE",
            &format!("cannot open {label}"),
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn open_file_at(parent: RawFd, name: &CStr, label: &str) -> Result<File, Error> {
    let raw = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(Error::io(
            "STATE_CORRUPT",
            &format!("cannot open {label}"),
            io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}

fn directory_names(fd: RawFd) -> Result<Vec<Vec<u8>>, Error> {
    let dot = c".";
    let directory_fd = unsafe {
        libc::openat(
            fd,
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory_fd < 0 {
        return Err(Error::io(
            "STATE_UNAVAILABLE",
            "cannot open an independent directory stream",
            io::Error::last_os_error(),
        ));
    }
    let directory = unsafe { libc::fdopendir(directory_fd) };
    if directory.is_null() {
        unsafe { libc::close(directory_fd) };
        return Err(Error::io(
            "STATE_UNAVAILABLE",
            "cannot enumerate state root",
            io::Error::last_os_error(),
        ));
    }
    let mut names = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error().unwrap_or(0) != 0 {
                unsafe { libc::closedir(directory) };
                return Err(Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot enumerate state root",
                    error,
                ));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    if unsafe { libc::closedir(directory) } != 0 {
        return Err(Error::io(
            "STATE_UNAVAILABLE",
            "cannot close state directory",
            io::Error::last_os_error(),
        ));
    }
    Ok(names)
}

fn stat_at(parent: RawFd, name: &CStr, flags: libc::c_int) -> Result<libc::stat, Error> {
    let mut stat = zeroed_stat();
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, flags) } != 0 {
        return Err(Error::io(
            "STATE_UNAVAILABLE",
            "cannot revalidate descriptor-relative path",
            io::Error::last_os_error(),
        ));
    }
    Ok(stat)
}

fn unlink_capability(parent: RawFd, name: &CStr, expected: Identity) -> Result<(), Error> {
    let current = Identity::from_stat(&stat_at(parent, name, libc::AT_SYMLINK_NOFOLLOW)?);
    if current != expected || !valid_private_record(current) {
        return Err(Error::new(
            "STATE_CLEANUP_FAILED",
            "temporary record identity changed before cleanup",
        ));
    }
    unlink_file_at(parent, name).map_err(|error| {
        Error::io(
            "STATE_CLEANUP_FAILED",
            "cannot remove temporary record",
            error,
        )
    })
}

fn unlink_file_at(parent: RawFd, name: &CStr) -> io::Result<()> {
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn unlink_directory_at(parent: RawFd, name: &CStr) -> io::Result<()> {
    if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn rename_no_replace(parent: RawFd, old: &CStr, new: &CStr) -> io::Result<()> {
    if unsafe {
        libc::renameatx_np(
            parent,
            old.as_ptr(),
            parent,
            new.as_ptr(),
            libc::RENAME_EXCL,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn rename_no_replace(parent: RawFd, old: &CStr, new: &CStr) -> io::Result<()> {
    if unsafe {
        libc::renameat2(
            parent,
            old.as_ptr(),
            parent,
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
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

fn zeroed_stat() -> libc::stat {
    unsafe { std::mem::zeroed() }
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_path(value: &str) -> Result<PathBuf, Error> {
    if value.len() % 2 != 0 {
        return Err(Error::new("STATE_CORRUPT", "path encoding has odd length"));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high =
            hex_digit(pair[0]).ok_or_else(|| Error::new("STATE_CORRUPT", "path is not hex"))?;
        let low =
            hex_digit(pair[1]).ok_or_else(|| Error::new("STATE_CORRUPT", "path is not hex"))?;
        bytes.push((high << 4) | low);
    }
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
        return Err(Error::new("STATE_CORRUPT", "recorded path is not absolute"));
    }
    Ok(path)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn path_hash(path: &Path) -> u64 {
    path.as_os_str()
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecordBinding {
    pub(crate) bytes: Vec<u8>,
    pub(crate) identity: Identity,
}

pub(crate) fn remove_record(parent: &File, basename: &[u8], expected: &[u8]) -> Result<(), Error> {
    let binding = read_file_binding(parent.as_raw_fd(), basename, expected.len())?;
    if binding.bytes != expected {
        return Err(Error::new(
            "STATE_CORRUPT",
            "state record bytes changed before removal",
        ));
    }
    let name = cstring(basename, "record")?;
    unlink_capability(parent.as_raw_fd(), &name, binding.identity)?;
    sync_record_parent(parent)
}

fn cleanup_unpublished_record(
    parent: &File,
    name: &CStr,
    identity: Identity,
    primary: Error,
) -> Error {
    if let Err(error) = unlink_capability(parent.as_raw_fd(), name, identity) {
        return error;
    }
    match parent.sync_all() {
        Ok(()) => primary,
        Err(error) => Error::io(
            "STATE_COMMITTED_RECOVERY_REQUIRED",
            "cannot sync state record parent after cleanup",
            error,
        ),
    }
}

fn sync_record_parent(parent: &File) -> Result<(), Error> {
    parent.sync_all().map_err(|error| {
        Error::io(
            "STATE_COMMITTED_UNSYNCED",
            "cannot sync state record parent directory",
            error,
        )
    })
}

fn rename_result_is_unknown(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Interrupted
}

fn rename_exchange(parent: RawFd, left: &CStr, right: &CStr) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            parent,
            left.as_ptr(),
            parent,
            right.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            parent,
            left.as_ptr(),
            parent,
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn read_file_binding(
    parent: RawFd,
    basename: &[u8],
    limit: usize,
) -> Result<RecordBinding, Error> {
    let name = cstring(basename, "record")?;
    let before = Identity::from_stat(&stat_at(parent, &name, libc::AT_SYMLINK_NOFOLLOW)?);
    if !valid_record(before) && !valid_private_record(before) {
        return Err(Error::new(
            "STATE_CORRUPT",
            "record is not an owner-only regular file",
        ));
    }
    let mut file = open_file_at(parent, &name, "record")?;
    let opened = Identity::from_file(&file)?;
    if opened != before {
        return Err(Error::new("STATE_CORRUPT", "record changed while opening"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((limit.saturating_add(1)) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::io("STATE_CORRUPT", "cannot read record", error))?;
    if bytes.len() > limit {
        return Err(Error::new("STATE_CORRUPT", "record exceeds the limit"));
    }
    let descriptor = Identity::from_file(&file)?;
    let final_entry = Identity::from_stat(&stat_at(parent, &name, libc::AT_SYMLINK_NOFOLLOW)?);
    if !record_binding_matches(opened, descriptor, final_entry) {
        return Err(Error::new(
            "STATE_CORRUPT",
            "record binding changed while reading",
        ));
    }
    Ok(RecordBinding {
        bytes,
        identity: final_entry,
    })
}

pub(crate) fn read_file_if_present(
    parent: RawFd,
    basename: &[u8],
    limit: usize,
) -> Result<Option<Vec<u8>>, Error> {
    let name = cstring(basename, "record")?;
    let mut stat = zeroed_stat();
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(Error::io(
            "STATE_UNAVAILABLE",
            "cannot inspect record",
            error,
        ));
    }
    read_file_binding(parent, basename, limit).map(|binding| Some(binding.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replace_exchange_final(parent: RawFd, name: &CStr) {
        let raw = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(
            raw >= 0,
            "open external record: {}",
            io::Error::last_os_error()
        );
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(b"external\n")
            .expect("write external record");
        file.sync_all().expect("sync external record");
    }

    #[test]
    fn exchange_drift_does_not_move_an_external_binding() {
        let path = env::temp_dir().join(format!(
            "git-vws-record-txn-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create record transaction directory");
        let parent = File::open(&path).expect("open record transaction directory");
        let name = b"session.record";
        RecordTxn::begin(&parent, name, b"old\n", None)
            .expect("create old record")
            .commit()
            .expect("commit old record");
        let mut transaction =
            RecordTxn::begin(&parent, name, b"new\n", Some(b"old\n")).expect("begin exchange");
        *EXCHANGE_MUTATOR.lock().expect("exchange test lock") = Some(replace_exchange_final);
        let error = transaction.commit().expect_err("exchange drift must fail");
        *EXCHANGE_MUTATOR.lock().expect("exchange test lock") = None;
        assert_eq!(error.code, "STATE_COMMITTED_RECOVERY_REQUIRED");
        assert_eq!(
            fs::read(path.join("session.record")).expect("read external record"),
            b"external\n"
        );
        drop(transaction);
        drop(parent);
        fs::remove_dir_all(&path).expect("clean record transaction directory");
    }

    #[test]
    fn record_binding_rejects_opened_or_final_mismatch() {
        let opened = Identity::from_stat(&zeroed_stat());
        let mismatched = Identity { ino: 2, ..opened };
        assert!(record_binding_matches(opened, opened, opened));
        assert!(!record_binding_matches(opened, mismatched, opened));
        assert!(!record_binding_matches(opened, opened, mismatched));
        for (handler, flags, expected) in [
            (libc::SIG_DFL, 0, true),
            (libc::SIG_IGN, 0, false),
            (libc::SIG_DFL, libc::SA_NOCLDWAIT as libc::c_ulong, false),
            (2, 0, false),
        ] {
            assert_eq!(sigchld_allows_waiting(handler, flags), expected);
        }
        let mut capability = Some(7);
        let lost = lose_probe_ownership(&mut capability);
        assert_eq!(lost.code, "GIT_PROBE_CLEANUP_FAILED");
        assert_eq!(capability, None);
    }
}
