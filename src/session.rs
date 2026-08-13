use crate::authority::{self, Authority, Error, Identity, StateRoot};
use crate::git::{self, AuditConfig, Output};
use crate::storage::{self, CowPlan};
use crate::template;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_RECORD: usize = 16 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
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

pub(crate) struct CreateRequest {
    pub(crate) name: OsString,
    pub(crate) from: Option<OsString>,
    pub(crate) target: Option<OsString>,
    pub(crate) path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SessionPayload {
    Prepared {
        root_name: String,
    },
    Materializing {
        root_name: String,
        root_identity: Identity,
    },
    Ready {
        root_name: String,
        root_identity: Identity,
        common_identity: Identity,
        worktree: Box<storage::CowReceipt>,
        git: GitMetadataReceipt,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct GitMetadataReceipt {
    dot_git: String,
    head: String,
    target_ref: String,
    index: String,
    worktrees: String,
    alternates: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SessionRecord {
    version: u8,
    sid: String,
    authority_path: String,
    authority_identity: Identity,
    name: String,
    base: String,
    target: String,
    expected_old: Option<String>,
    template_key: String,
    template: storage::SealedTreeReceipt,
    container_identity: Identity,
    volume: String,
    payload: SessionPayload,
}

pub(crate) fn create(repository: &Path, request: CreateRequest) -> Result<PathBuf, Error> {
    let authority = authority::inspect(repository)?;
    let state = registered(&authority)?;
    let target = request.target.unwrap_or_else(|| request.name.clone());
    validate_branch(&authority, &target)?;
    let target_old = resolve_target(&authority, &target)?;
    let base = match request.from.as_deref() {
        Some(from) => resolve_commit(&authority, from)?,
        None => match target_old.as_deref() {
            Some(existing) => existing.to_owned(),
            None => resolve_commit(&authority, OsStr::new("HEAD"))?,
        },
    };
    let tree = resolve_tree(&authority, &base)?;
    let template = template::acquire(&state, &authority, &tree)?;
    state.ensure_containers()?;
    let sessions = state.open_container(b"sessions")?;
    let container_identity = Identity::from_file(&sessions)?;
    let volume = storage::volume_id(&sessions)?;
    if template.sealed.volume != volume {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "template and session containers are not on the same COW volume",
        ));
    }
    let sessions_path = state.container_path("sessions")?;
    bind_path(&sessions_path, &sessions, "session container")?;
    let sid = session_id(&authority, request.name.as_os_str());
    let root_name = root_name(&sid);
    let root_path = sessions_path.join(&root_name);
    if let Some(path) = request.path {
        if path != root_path {
            return Err(Error::new(
                "SESSION_UNSUPPORTED",
                "--path must be the exact managed session root",
            ));
        }
    }
    let record_name = record_name(&sid);
    let prepared = SessionRecord {
        version: 2,
        sid: sid.clone(),
        authority_path: authority::hex(authority.canonical.as_os_str().as_bytes()),
        authority_identity: authority.identity,
        name: authority::hex(request.name.as_os_str().as_bytes()),
        base: base.clone(),
        target: authority::hex(target.as_os_str().as_bytes()),
        expected_old: target_old.clone(),
        template_key: template.key.clone(),
        template: template.sealed.clone(),
        container_identity,
        volume,
        payload: SessionPayload::Prepared {
            root_name: root_name.clone(),
        },
    };
    if let Some(existing) = read_record(&sessions, &record_name)? {
        if existing == prepared {
            return Err(Error::new(
                "SESSION_INCOMPLETE",
                "session record is prepared but has no stable root",
            ));
        }
        if matches_existing(&existing, &prepared) {
            return match &existing.payload {
                SessionPayload::Ready { .. } => ready_session(&sessions, &root_path, existing),
                SessionPayload::Prepared { .. } | SessionPayload::Materializing { .. } => {
                    Err(Error::new(
                        "SESSION_INCOMPLETE",
                        "session creation is incomplete and was retained for diagnosis",
                    ))
                }
            };
        }
        return Err(Error::new(
            "SESSION_EXISTS",
            "session name is already bound to different create inputs",
        ));
    }
    let prepared_bytes = encode_record(&prepared)?;
    authority::RecordTxn::begin(&sessions, &record_name, &prepared_bytes, None)?.commit()?;

    let root = create_directory(&sessions, &root_name, 0o700, "session root")?;
    let root_identity = Identity::from_file(&root)?;
    let mut transaction = CreateTxn::new(
        &sessions,
        record_name,
        prepared_bytes,
        root,
        root_name.clone(),
        root_identity,
    );
    let result = materialize_session(
        &mut transaction,
        &state,
        &authority,
        &template,
        &root_path,
        &target,
        &base,
    );
    match result {
        Ok(path) => {
            transaction.disarm();
            Ok(path)
        }
        Err(error) => Err(transaction.abort(error)),
    }
}

fn materialize_session(
    transaction: &mut CreateTxn<'_>,
    state: &StateRoot,
    authority: &Authority,
    template: &template::Template,
    root_path: &Path,
    target: &OsStr,
    base: &str,
) -> Result<PathBuf, Error> {
    let root_name = transaction.root_name.clone();
    let root_identity = transaction.root_identity;
    let mut materializing: SessionRecord =
        serde_json::from_slice(transaction.record()).map_err(|_| {
            Error::new(
                "SESSION_CORRUPT",
                "creating transaction lost its canonical prepared record",
            )
        })?;
    materializing.payload = SessionPayload::Materializing {
        root_name: root_name.clone(),
        root_identity,
    };
    let materializing_bytes = encode_record(&materializing)?;
    authority::RecordTxn::begin(
        transaction.sessions,
        &transaction.record_name,
        &materializing_bytes,
        Some(transaction.record()),
    )?
    .commit()?;
    transaction.replace_record(materializing_bytes);
    bind_path(root_path, transaction.root(), "session root")?;

    let empty_template = create_directory(
        transaction.root(),
        ".git-vws-empty-template",
        0o700,
        "empty Git template",
    )?;
    let empty_template_identity = Identity::from_file(&empty_template)?;
    let empty_template_path = root_path.join(".git-vws-empty-template");
    bind_path(&empty_template_path, &empty_template, "empty Git template")?;
    let common_path = root_path.join("common.git");
    bind_path(root_path, transaction.root(), "session root")?;
    init_private_common(authority, &common_path, &empty_template_path)?;
    let common = storage::open_directory_at(transaction.root().as_raw_fd(), c"common.git")?;
    if unsafe { libc::fchmod(common.as_raw_fd(), 0o700) } != 0 {
        return Err(Error::io(
            "SESSION_IO_FAILED",
            "cannot protect private common-dir",
            io::Error::last_os_error(),
        ));
    }
    let common_identity = Identity::from_file(&common)
        .map_err(|_| Error::new("SESSION_IO_FAILED", "cannot inspect private common-dir"))?;
    if !storage::private_directory(common_identity) {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            "private common-dir has invalid identity",
        ));
    }
    bind_path(&common_path, &common, "private common-dir")?;
    remove_empty_directory(
        transaction.root(),
        ".git-vws-empty-template",
        empty_template_identity,
        "empty Git template",
    )?;
    write_alternate(
        &common,
        authority.canonical.join("objects").as_os_str().as_bytes(),
    )?;
    configure_private_common(&common_path)?;

    let worktree_path = root_path.join("worktree");
    bind_path(root_path, transaction.root(), "session root")?;
    add_linked_worktree(&common_path, &worktree_path, target, base)?;
    let worktree = storage::open_directory_at(transaction.root().as_raw_fd(), c"worktree")?;
    let worktree_identity = Identity::from_file(&worktree)?;
    if !owned_directory(worktree_identity) {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            "linked worktree is not an owned directory",
        ));
    }
    let templates = state.open_container(b"templates")?;
    let template_name = format!("template-{}.root", template.key);
    let template_name = cstring(template_name.as_bytes(), "sealed template root")?;
    let template_root = storage::open_directory_at(templates.as_raw_fd(), &template_name)?;
    if Identity::from_file(&template_root)? != template.sealed.root {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template root binding changed before native clone",
        ));
    }
    let clone_parent_identity = Identity::from_file(transaction.root())?;
    if !storage::private_directory(clone_parent_identity) {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            "session root changed before native clone",
        ));
    }
    let receipt = storage::cow_clone(CowPlan {
        source: &template_root,
        destination_parent: transaction.root(),
        destination_parent_identity: clone_parent_identity,
        destination_name: c"worktree",
        source_receipt: &template.sealed,
        destination_identity: worktree_identity,
    })?;
    if receipt.source != template.sealed
        || receipt.destination != Identity::from_file(&worktree)?
        || !owned_directory(receipt.destination)
    {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            "native COW receipt did not match the template record",
        ));
    }
    read_tree(&worktree_path)?;
    status_clean(&worktree_path)?;
    sync_tree(&common)?;
    sync_tree(&worktree)?;
    transaction
        .root()
        .sync_all()
        .map_err(|error| Error::io("SESSION_IO_FAILED", "cannot sync session root", error))?;
    transaction.sessions.sync_all().map_err(|error| {
        Error::io(
            "SESSION_IO_FAILED",
            "cannot sync session container before READY",
            error,
        )
    })?;

    let current = authority::read_file_binding(
        transaction.sessions.as_raw_fd(),
        &transaction.record_name,
        MAX_RECORD,
    )?;
    if current.bytes != transaction.record() {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "CREATING session record changed before READY commit",
        ));
    }
    let final_root_identity = Identity::from_file(transaction.root())?;
    if !storage::private_directory(final_root_identity) {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            "session root changed before READY commit",
        ));
    }
    bind_path(root_path, transaction.root(), "session root")?;
    materializing.payload = SessionPayload::Ready {
        root_name: root_name.clone(),
        root_identity: final_root_identity,
        common_identity: Identity::from_file(&common)?,
        worktree: Box::new(receipt),
        git: git_metadata(&common, &common_path, &worktree_path, &worktree, target)?,
    };
    let ready_bytes = encode_record(&materializing)?;
    authority::RecordTxn::begin(
        transaction.sessions,
        &transaction.record_name,
        &ready_bytes,
        Some(transaction.record()),
    )?
    .commit()?;
    transaction.replace_record(ready_bytes);
    Ok(root_path.to_path_buf())
}

fn registered(authority: &Authority) -> Result<StateRoot, Error> {
    let state = authority::open_state()?;
    if !authority::authority_record_present(&state, authority)? {
        return Err(Error::new(
            "AUTHORITY_UNREGISTERED",
            "create requires an existing exact authority record",
        ));
    }
    Ok(state)
}

struct CreateTxn<'a> {
    sessions: &'a File,
    record_name: Vec<u8>,
    record: Vec<u8>,
    root: Option<File>,
    root_name: String,
    root_identity: Identity,
    armed: bool,
}

impl<'a> CreateTxn<'a> {
    fn new(
        sessions: &'a File,
        record_name: Vec<u8>,
        record: Vec<u8>,
        root: File,
        root_name: String,
        root_identity: Identity,
    ) -> Self {
        Self {
            sessions,
            record_name,
            record,
            root: Some(root),
            root_name,
            root_identity,
            armed: true,
        }
    }

    fn root(&self) -> &File {
        self.root
            .as_ref()
            .expect("creating session root descriptor")
    }

    fn record(&self) -> &[u8] {
        &self.record
    }

    fn replace_record(&mut self, record: Vec<u8>) {
        self.record = record;
    }

    fn disarm(mut self) {
        self.armed = false;
    }

    fn abort(&mut self, primary: Error) -> Error {
        if !self.armed || retain_creating(&primary) {
            self.armed = false;
            return primary;
        }
        self.armed = false;
        let name = match cstring(self.root_name.as_bytes(), "session root") {
            Ok(name) => name,
            Err(error) => return error,
        };
        self.root.take();
        if let Err(error) = storage::remove_owned_tree(self.sessions, &name, self.root_identity) {
            return error;
        }
        match authority::remove_record(self.sessions, &self.record_name, &self.record) {
            Ok(()) => primary,
            Err(error) => error,
        }
    }
}

impl Drop for CreateTxn<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.abort(Error::new(
                "SESSION_RECOVERY_REQUIRED",
                "session create transaction was dropped before READY",
            ));
        }
    }
}

fn retain_creating(error: &Error) -> bool {
    error.code.starts_with("GIT_")
        || error.code.contains("RECOVERY")
        || error.code.contains("UNSYNCED")
        || error.code.contains("_IO_")
        || error.code == "STATE_UNAVAILABLE"
        || error.detail.contains("rename")
        || error.detail.contains("sync")
}

fn matches_existing(existing: &SessionRecord, prepared: &SessionRecord) -> bool {
    existing.version == 2
        && existing.sid == prepared.sid
        && existing.authority_path == prepared.authority_path
        && existing.authority_identity == prepared.authority_identity
        && existing.name == prepared.name
        && existing.base == prepared.base
        && existing.target == prepared.target
        && existing.expected_old == prepared.expected_old
        && existing.template_key == prepared.template_key
        && existing.template == prepared.template
        && existing
            .container_identity
            .same_node(prepared.container_identity)
        && existing.volume == prepared.volume
}

fn ready_session(
    sessions: &File,
    root_path: &Path,
    record: SessionRecord,
) -> Result<PathBuf, Error> {
    let SessionPayload::Ready {
        root_name: record_root,
        root_identity,
        common_identity,
        worktree: worktree_receipt,
        git,
    } = record.payload
    else {
        return Err(Error::new("SESSION_CORRUPT", "session record is not READY"));
    };
    if record_root != root_name(&record.sid) || worktree_receipt.source != record.template {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session record has an invalid root or template receipt",
        ));
    }
    let name = cstring(record_root.as_bytes(), "session root")?;
    let root = storage::open_directory_at(sessions.as_raw_fd(), &name)?;
    if Identity::from_file(&root)? != root_identity
        || storage::identity_at(sessions.as_raw_fd(), &name)? != root_identity
        || !storage::private_directory(root_identity)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session root binding changed",
        ));
    }
    bind_path(root_path, &root, "session root")?;
    let worktree_path = root_path.join("worktree");
    let common_path = root_path.join("common.git");
    let worktree = storage::open_directory_at(root.as_raw_fd(), c"worktree")?;
    let common = storage::open_directory_at(root.as_raw_fd(), c"common.git")?;
    if !Identity::from_file(sessions)?.same_node(record.container_identity)
        || storage::volume_id(sessions)? != record.volume
        || common_identity != Identity::from_file(&common)?
        || worktree_receipt.destination != Identity::from_file(&worktree)?
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session receipts no longer match their stable bindings",
        ));
    }
    bind_path(&worktree_path, &worktree, "linked worktree")?;
    bind_path(&common_path, &common, "private common-dir")?;
    storage::verify_worktree(&worktree, &worktree_receipt)?;
    let target = OsString::from_vec(decode_hex(&record.target)?);
    if git_metadata(&common, &common_path, &worktree_path, &worktree, &target)? != git {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session Git metadata receipt changed",
        ));
    }
    status_clean(&worktree_path)?;
    Ok(root_path.to_path_buf())
}

fn resolve_target(authority: &Authority, target: &OsStr) -> Result<Option<String>, Error> {
    let mut reference = OsString::from("refs/heads/");
    reference.push(target);
    let args = [
        OsString::from("rev-parse"),
        OsString::from("--verify"),
        OsString::from("--quiet"),
        reference,
    ];
    let output = git::capture(
        &args,
        Some(&authority.canonical),
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(git_error)?;
    if output.status.success() {
        return parse_oid_output(&output.stdout, &authority.object_format).map(Some);
    }
    if output.stdout.is_empty() && output.stderr.is_empty() {
        return Ok(None);
    }
    Err(Error::new(
        "GIT_PROBE_FAILED",
        "cannot resolve the target branch",
    ))
}

fn resolve_commit(authority: &Authority, revision: &OsStr) -> Result<String, Error> {
    let mut expression = revision.to_os_string();
    expression.push("^{commit}");
    let args = [
        OsString::from("rev-parse"),
        OsString::from("--verify"),
        expression,
    ];
    let output = git::capture(
        &args,
        Some(&authority.canonical),
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(git_error)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(Error::new(
            "BASE_INVALID",
            "base revision does not resolve to a commit",
        ));
    }
    parse_oid_output(&output.stdout, &authority.object_format)
}

fn resolve_tree(authority: &Authority, base: &str) -> Result<String, Error> {
    let mut expression = OsString::from(base);
    expression.push("^{tree}");
    let args = [
        OsString::from("rev-parse"),
        OsString::from("--verify"),
        expression,
    ];
    let output = git::capture(
        &args,
        Some(&authority.canonical),
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(git_error)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(Error::new(
            "BASE_INVALID",
            "base commit does not resolve to a tree",
        ));
    }
    parse_oid_output(&output.stdout, &authority.object_format)
}

fn validate_branch(authority: &Authority, target: &OsStr) -> Result<(), Error> {
    if target.as_bytes().is_empty() || target.as_bytes().starts_with(b"-") {
        return Err(Error::new(
            "TARGET_INVALID",
            "target branch name is invalid",
        ));
    }
    let args = [
        OsString::from("check-ref-format"),
        OsString::from("--branch"),
        target.to_os_string(),
    ];
    let output = git::capture(
        &args,
        Some(&authority.canonical),
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(git_error)?;
    if output.status.success() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            "TARGET_INVALID",
            "target branch name is invalid",
        ))
    }
}

fn init_private_common(
    authority: &Authority,
    common: &Path,
    empty_template: &Path,
) -> Result<(), Error> {
    let mut template = OsString::from("--template=");
    template.push(empty_template.as_os_str());
    let mut object_format = OsString::from("--object-format=");
    object_format.push(&authority.object_format);
    let mut ref_format = OsString::from("--ref-format=");
    ref_format.push(&authority.ref_format);
    let args = [
        OsString::from("init"),
        OsString::from("--bare"),
        OsString::from("--quiet"),
        object_format,
        ref_format,
        template,
        common.as_os_str().to_os_string(),
    ];
    require_clean(
        git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Isolated).map_err(git_error)?,
        "initialize private common-dir",
    )
}

fn write_alternate(common: &File, authority_objects: &[u8]) -> Result<(), Error> {
    if authority_objects.contains(&b'\n') || authority_objects.contains(&b'\r') {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            "authority object path cannot be encoded as one alternate entry",
        ));
    }
    let objects = storage::open_directory_at(common.as_raw_fd(), c"objects")?;
    let info = storage::open_directory_at(objects.as_raw_fd(), c"info")?;
    let name = c"alternates";
    let raw = unsafe {
        libc::openat(
            info.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(Error::io(
            "SESSION_IO_FAILED",
            "cannot create private object alternate",
            io::Error::last_os_error(),
        ));
    }
    let mut alternate = unsafe { File::from_raw_fd(raw) };
    alternate
        .write_all(authority_objects)
        .and_then(|_| alternate.write_all(b"\n"))
        .and_then(|_| alternate.sync_data())
        .map_err(|error| {
            Error::io(
                "SESSION_IO_FAILED",
                "cannot persist private object alternate",
                error,
            )
        })?;
    info.sync_all()
        .map_err(|error| Error::io("SESSION_IO_FAILED", "cannot sync alternate parent", error))
}

fn configure_private_common(common: &Path) -> Result<(), Error> {
    for (key, expected) in [("core.filemode", "true"), ("core.symlinks", "true")] {
        let mut git_dir = OsString::from("--git-dir=");
        git_dir.push(common.as_os_str());
        let args = [
            git_dir,
            OsString::from("config"),
            OsString::from(key),
            OsString::from(expected),
        ];
        require_clean(
            git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Isolated).map_err(git_error)?,
            "configure private common-dir",
        )?;
        let mut git_dir = OsString::from("--git-dir=");
        git_dir.push(common.as_os_str());
        let args = [
            git_dir,
            OsString::from("config"),
            OsString::from("--get"),
            OsString::from(key),
        ];
        let output =
            git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Isolated).map_err(git_error)?;
        if !output.status.success()
            || output.stderr != b""
            || output.stdout != format!("{expected}\n").as_bytes()
        {
            return Err(Error::new(
                "SESSION_IO_FAILED",
                "private common-dir did not retain required Git configuration",
            ));
        }
    }
    Ok(())
}

fn add_linked_worktree(
    common: &Path,
    worktree: &Path,
    target: &OsStr,
    base: &str,
) -> Result<(), Error> {
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(common.as_os_str());
    let args = [
        git_dir,
        OsString::from("worktree"),
        OsString::from("add"),
        OsString::from("--quiet"),
        OsString::from("--no-checkout"),
        OsString::from("-b"),
        target.to_os_string(),
        worktree.as_os_str().to_os_string(),
        OsString::from(base),
    ];
    require_clean(
        git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Isolated).map_err(git_error)?,
        "create private linked worktree",
    )
}

fn read_tree(worktree: &Path) -> Result<(), Error> {
    let args = [
        OsString::from("read-tree"),
        OsString::from("--reset"),
        OsString::from("HEAD"),
    ];
    require_clean(
        git::capture(&args, Some(worktree), GIT_TIMEOUT, AuditConfig::Isolated)
            .map_err(git_error)?,
        "build linked-worktree index",
    )
}

fn status_clean(worktree: &Path) -> Result<(), Error> {
    let args = [
        OsString::from("status"),
        OsString::from("--porcelain=v1"),
        OsString::from("--untracked-files=all"),
    ];
    let output = git::capture(&args, Some(worktree), GIT_TIMEOUT, AuditConfig::Isolated)
        .map_err(git_error)?;
    if output.status.success() && output.stderr.is_empty() && output.stdout.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            "SESSION_DIRTY",
            "new linked worktree did not have a clean Git status",
        ))
    }
}

fn git_metadata(
    common: &File,
    common_path: &Path,
    worktree_path: &Path,
    worktree: &File,
    target: &OsStr,
) -> Result<GitMetadataReceipt, Error> {
    let dot_git = hash_bytes(&read_regular_at(
        worktree,
        c".git",
        "linked-worktree metadata",
    )?);
    let head = hash_bytes(&clean_git_output(
        git::capture(
            &[
                OsString::from("-C"),
                worktree_path.as_os_str().to_os_string(),
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                OsString::from("HEAD"),
            ],
            None,
            GIT_TIMEOUT,
            AuditConfig::Isolated,
        )
        .map_err(git_error)?,
        "read linked-worktree HEAD",
    )?);
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(common_path.as_os_str());
    let mut reference = OsString::from("refs/heads/");
    reference.push(target);
    let target_ref = hash_bytes(&clean_git_output(
        git::capture(
            &[
                git_dir.clone(),
                OsString::from("rev-parse"),
                OsString::from("--verify"),
                reference,
            ],
            None,
            GIT_TIMEOUT,
            AuditConfig::Isolated,
        )
        .map_err(git_error)?,
        "read private target ref",
    )?);
    let index = hash_bytes(&clean_git_output(
        git::capture(
            &[
                OsString::from("-C"),
                worktree_path.as_os_str().to_os_string(),
                OsString::from("ls-files"),
                OsString::from("--stage"),
                OsString::from("-z"),
            ],
            None,
            GIT_TIMEOUT,
            AuditConfig::Isolated,
        )
        .map_err(git_error)?,
        "read linked-worktree index",
    )?);
    let worktrees = hash_bytes(&clean_git_output(
        git::capture(
            &[
                git_dir,
                OsString::from("worktree"),
                OsString::from("list"),
                OsString::from("--porcelain"),
            ],
            None,
            GIT_TIMEOUT,
            AuditConfig::Isolated,
        )
        .map_err(git_error)?,
        "read private worktree registry",
    )?);
    let objects = storage::open_directory_at(common.as_raw_fd(), c"objects")?;
    let info = storage::open_directory_at(objects.as_raw_fd(), c"info")?;
    let alternates = hash_bytes(&read_regular_at(&info, c"alternates", "private alternate")?);
    Ok(GitMetadataReceipt {
        dot_git,
        head,
        target_ref,
        index,
        worktrees,
        alternates,
    })
}

fn clean_git_output(output: Output, label: &str) -> Result<Vec<u8>, Error> {
    if output.status.success() && output.stderr.is_empty() {
        Ok(output.stdout)
    } else {
        Err(Error::new(
            "SESSION_IO_FAILED",
            format!("Git could not {label}"),
        ))
    }
}

fn read_regular_at(parent: &File, name: &CStr, label: &str) -> Result<Vec<u8>, Error> {
    let before = storage::identity_at(parent.as_raw_fd(), name)?;
    if !before.regular() || before.uid != current_uid() || before.nlink != 1 {
        return Err(Error::new(
            "SESSION_CORRUPT",
            format!("{label} is not an owned regular file"),
        ));
    }
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(Error::io(
            "SESSION_IO_FAILED",
            &format!("cannot open {label}"),
            io::Error::last_os_error(),
        ));
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    if Identity::from_file(&file)? != before {
        return Err(Error::new(
            "SESSION_CORRUPT",
            format!("{label} changed while opening"),
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_RECORD + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::io("SESSION_IO_FAILED", &format!("cannot read {label}"), error))?;
    if bytes.len() > MAX_RECORD {
        return Err(Error::new(
            "SESSION_CORRUPT",
            format!("{label} exceeds its receipt limit"),
        ));
    }
    if Identity::from_file(&file)? != before
        || storage::identity_at(parent.as_raw_fd(), name)? != before
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            format!("{label} changed while reading"),
        ));
    }
    Ok(bytes)
}

fn hash_bytes(bytes: &[u8]) -> String {
    authority::hex(&Sha256::digest(bytes))
}

fn require_clean(output: Output, label: &str) -> Result<(), Error> {
    if output.status.success() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            "SESSION_IO_FAILED",
            format!("Git could not {label}"),
        ))
    }
}

fn parse_oid_output(output: &[u8], object_format: &str) -> Result<String, Error> {
    let body = output
        .strip_suffix(b"\n")
        .filter(|body| !body.contains(&b'\n'))
        .ok_or_else(|| Error::new("GIT_PROBE_FAILED", "Git object ID output was ambiguous"))?;
    let oid = std::str::from_utf8(body)
        .map_err(|_| Error::new("GIT_PROBE_FAILED", "Git object ID was not ASCII"))?;
    let expected = if object_format == "sha1" { 40 } else { 64 };
    if oid.len() != expected || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::new("GIT_PROBE_FAILED", "Git object ID was invalid"));
    }
    Ok(oid.to_owned())
}

fn read_record(sessions: &File, name: &[u8]) -> Result<Option<SessionRecord>, Error> {
    let Some(bytes) = authority::read_file_if_present(sessions.as_raw_fd(), name, MAX_RECORD)?
    else {
        return Ok(None);
    };
    let record: SessionRecord = serde_json::from_slice(&bytes)
        .map_err(|_| Error::new("SESSION_CORRUPT", "session record is not valid JSON"))?;
    if encode_record(&record)? != bytes {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record is not canonically encoded",
        ));
    }
    validate_record(&record)?;
    Ok(Some(record))
}

fn encode_record(record: &SessionRecord) -> Result<Vec<u8>, Error> {
    validate_record(record)?;
    let bytes = serde_json::to_vec(record).map_err(|error| {
        Error::new(
            "SESSION_IO_FAILED",
            format!("cannot encode session record: {error}"),
        )
    })?;
    if bytes.len() > MAX_RECORD {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record exceeds its receipt limit",
        ));
    }
    Ok(bytes)
}

fn validate_record(record: &SessionRecord) -> Result<(), Error> {
    if record.version != 2
        || !valid_hash(&record.sid)
        || !valid_hash(&record.template_key)
        || !valid_hash(&record.template.manifest.digest)
        || !valid_hash(&record.template.content_digest)
        || !valid_hex(&record.authority_path)
        || !valid_hex(&record.name)
        || !valid_hex(&record.target)
        || !valid_oid(&record.base)
        || !storage::private_directory(record.container_identity)
        || record.volume.is_empty()
        || record.template.volume != record.volume
        || record
            .expected_old
            .as_deref()
            .is_some_and(|oid| !valid_oid(oid))
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record contains invalid fields",
        ));
    }
    let valid = match &record.payload {
        SessionPayload::Prepared {
            root_name: prepared_root,
        } => prepared_root == &root_name(&record.sid),
        SessionPayload::Materializing {
            root_name: materializing_root,
            root_identity,
        } => {
            materializing_root == &root_name(&record.sid)
                && storage::private_directory(*root_identity)
        }
        SessionPayload::Ready {
            root_name: ready_root,
            root_identity,
            common_identity,
            worktree,
            git,
        } => {
            ready_root == &root_name(&record.sid)
                && storage::private_directory(*root_identity)
                && storage::private_directory(*common_identity)
                && worktree.source == record.template
                && owned_directory(worktree.destination)
                && valid_hash(&git.dot_git)
                && valid_hash(&git.head)
                && valid_hash(&git.target_ref)
                && valid_hash(&git.index)
                && valid_hash(&git.worktrees)
                && valid_hash(&git.alternates)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(Error::new(
            "SESSION_CORRUPT",
            "session stage bindings are invalid",
        ))
    }
}

fn sync_tree(directory: &File) -> Result<(), Error> {
    for bytes in storage::directory_names(directory.as_raw_fd())? {
        let name = cstring(&bytes, "private Git metadata")?;
        let entry = storage::identity_at(directory.as_raw_fd(), &name)?;
        match entry.kind {
            kind if kind == DIRECTORY_TYPE => {
                let child = storage::open_directory_at(directory.as_raw_fd(), &name)?;
                if Identity::from_file(&child)? != entry {
                    return Err(Error::new(
                        "SESSION_IO_FAILED",
                        "private directory binding changed",
                    ));
                }
                sync_tree(&child)?;
            }
            kind if kind == REGULAR_TYPE => {
                let raw = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw < 0 {
                    return Err(Error::io(
                        "SESSION_IO_FAILED",
                        "cannot open private Git metadata",
                        io::Error::last_os_error(),
                    ));
                }
                let file = unsafe { File::from_raw_fd(raw) };
                if Identity::from_file(&file)? != entry {
                    return Err(Error::new(
                        "SESSION_IO_FAILED",
                        "private metadata binding changed",
                    ));
                }
                file.sync_all().map_err(|error| {
                    Error::io(
                        "SESSION_IO_FAILED",
                        "cannot sync private Git metadata",
                        error,
                    )
                })?;
            }
            kind if kind == SYMLINK_TYPE => {}
            _ => {
                return Err(Error::new(
                    "SESSION_IO_FAILED",
                    "private Git metadata is special",
                ))
            }
        }
    }
    directory.sync_all().map_err(|error| {
        Error::io(
            "SESSION_IO_FAILED",
            "cannot sync private Git directory",
            error,
        )
    })
}

fn create_directory(parent: &File, name: &str, mode: u32, label: &str) -> Result<File, Error> {
    let name = cstring(name.as_bytes(), label)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(Error::io(
            "SESSION_IO_FAILED",
            &format!("cannot create {label}"),
            io::Error::last_os_error(),
        ));
    }
    let directory = storage::open_directory_at(parent.as_raw_fd(), &name)?;
    if unsafe { libc::fchmod(directory.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(Error::io(
            "SESSION_IO_FAILED",
            &format!("cannot protect {label}"),
            io::Error::last_os_error(),
        ));
    }
    if !storage::private_directory(Identity::from_file(&directory)?) {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            format!("{label} has an invalid identity"),
        ));
    }
    Ok(directory)
}

fn remove_empty_directory(
    parent: &File,
    name: &str,
    expected: Identity,
    label: &str,
) -> Result<(), Error> {
    let name = cstring(name.as_bytes(), label)?;
    let entry = storage::identity_at(parent.as_raw_fd(), &name)?;
    if entry != expected || !storage::private_directory(entry) {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            format!("{label} identity changed before cleanup"),
        ));
    }
    let directory = storage::open_directory_at(parent.as_raw_fd(), &name)?;
    if Identity::from_file(&directory)? != expected
        || !storage::directory_names(directory.as_raw_fd())?.is_empty()
    {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            format!("{label} is no longer an owned empty directory"),
        ));
    }
    drop(directory);
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(Error::io(
            "SESSION_IO_FAILED",
            &format!("cannot clean up {label}"),
            io::Error::last_os_error(),
        ));
    }
    parent.sync_all().map_err(|error| {
        Error::io(
            "SESSION_IO_FAILED",
            "cannot sync session root cleanup",
            error,
        )
    })
}

fn bind_path(path: &Path, descriptor: &File, label: &str) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| Error::io("SESSION_IO_FAILED", &format!("cannot stat {label}"), error))?;
    let entry = Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        kind: metadata.mode() & FILE_TYPE_MASK,
        nlink: metadata.nlink(),
    };
    if entry != Identity::from_file(descriptor)? {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            format!("{label} path does not match its descriptor"),
        ));
    }
    Ok(())
}

fn session_id(authority: &Authority, name: &OsStr) -> String {
    let mut hasher = Sha256::new();
    for field in [
        b"git-vws/session-id/v1".as_slice(),
        authority.canonical.as_os_str().as_bytes(),
        &authority.identity.dev.to_be_bytes(),
        &authority.identity.ino.to_be_bytes(),
        &authority.identity.uid.to_be_bytes(),
        name.as_bytes(),
    ] {
        lp(&mut hasher, field);
    }
    authority::hex(&hasher.finalize())
}

fn lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn root_name(sid: &str) -> String {
    format!("session-{sid}.root")
}

fn record_name(sid: &str) -> Vec<u8> {
    format!("session-{sid}.record").into_bytes()
}

fn owned_directory(identity: Identity) -> bool {
    identity.directory() && identity.uid == current_uid() && identity.nlink >= 2
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_hex(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if !valid_hex(value) {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "stored session bytes are not hexadecimal",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| match (hex_digit(pair[0]), hex_digit(pair[1])) {
            (Some(left), Some(right)) => Ok((left << 4) | right),
            _ => Err(Error::new(
                "SESSION_CORRUPT",
                "stored session bytes are not hexadecimal",
            )),
        })
        .collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn cstring(bytes: &[u8], label: &str) -> Result<CString, Error> {
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(Error::new(
            "SESSION_CORRUPT",
            format!("invalid {label} basename"),
        ));
    }
    CString::new(bytes).map_err(|_| Error::new("SESSION_CORRUPT", format!("invalid {label} bytes")))
}

fn git_error(error: git::Error) -> Error {
    Error::new(error.code, error.detail)
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_record() -> SessionRecord {
        let directory = Identity {
            dev: 1,
            ino: 1,
            uid: current_uid(),
            mode: 0o700,
            kind: DIRECTORY_TYPE,
            nlink: 2,
        };
        let sid = "a".repeat(64);
        SessionRecord {
            version: 2,
            sid: sid.clone(),
            authority_path: "00".to_owned(),
            authority_identity: directory,
            name: "00".to_owned(),
            base: "b".repeat(40),
            target: "00".to_owned(),
            expected_old: None,
            template_key: sid.clone(),
            template: storage::SealedTreeReceipt {
                root: Identity {
                    mode: 0o555,
                    ..directory
                },
                volume: "volume".to_owned(),
                manifest: storage::ManifestReceipt {
                    digest: sid.clone(),
                    entries: 0,
                },
                content_digest: sid.clone(),
            },
            container_identity: directory,
            volume: "volume".to_owned(),
            payload: SessionPayload::Prepared {
                root_name: root_name(&sid),
            },
        }
    }

    #[test]
    fn session_record_outbound_gate_rejects_invalid_records_in_memory() {
        let record = valid_record();
        let mut empty = record.clone();
        empty.name.clear();
        assert_eq!(
            encode_record(&empty).expect_err("empty name accepted").code,
            "SESSION_CORRUPT"
        );
        let mut oversized = record;
        oversized.name = "6e".repeat(9 * 1024);
        let error = encode_record(&oversized).expect_err("oversized name accepted");
        assert_eq!(error.code, "SESSION_CORRUPT");
        assert!(error.detail.contains("receipt limit"));
    }

    #[test]
    fn session_record_outbound_gate_distinguishes_ready_common_mode_in_memory() {
        let record = valid_record();
        assert!(encode_record(&record).is_ok(), "Prepared pass");

        let directory = record.container_identity;
        let mut materializing = record.clone();
        materializing.payload = SessionPayload::Materializing {
            root_name: root_name(&record.sid),
            root_identity: directory,
        };
        assert!(
            encode_record(&materializing).is_ok(),
            "Materializing root 0700 pass"
        );

        let mut ready = materializing;
        ready.payload = SessionPayload::Ready {
            root_name: root_name(&record.sid),
            root_identity: directory,
            common_identity: directory,
            worktree: Box::new(storage::CowReceipt {
                source: record.template.clone(),
                destination: directory,
            }),
            git: GitMetadataReceipt {
                dot_git: record.sid.clone(),
                head: record.sid.clone(),
                target_ref: record.sid.clone(),
                index: record.sid.clone(),
                worktrees: record.sid.clone(),
                alternates: record.sid.clone(),
            },
        };
        assert!(encode_record(&ready).is_ok(), "Ready common 0700 pass");

        let SessionPayload::Ready {
            common_identity, ..
        } = &mut ready.payload
        else {
            panic!("Ready common mode 0755 setup");
        };
        common_identity.mode = 0o755;
        assert_eq!(
            encode_record(&ready)
                .expect_err("Ready common mode 0755 accepted")
                .code,
            "SESSION_CORRUPT",
            "Ready common mode 0755 rejects"
        );
    }
}
