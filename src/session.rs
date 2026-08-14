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
use std::process::ExitStatus;
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
    Tombstoned {
        root_name: String,
        tombstone_name: String,
        root_identity: Identity,
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

#[derive(Clone)]
struct RecordCapability {
    basename: Vec<u8>,
    record: SessionRecord,
    binding: authority::RecordBinding,
}

#[derive(Serialize)]
struct ListRecord {
    version: u8,
    authority_path_hex: String,
    authority_identity: Identity,
    name_hex: String,
    state: &'static str,
    base: String,
    target_hex: String,
    managed_path_hex: String,
}

#[derive(Serialize)]
struct CorruptRecord {
    version: u8,
    state: &'static str,
    record_name_hex: String,
    code: &'static str,
}

#[derive(Serialize)]
struct RemoveEvent {
    version: u8,
    event: &'static str,
    authority_path_hex: String,
    authority_identity: Identity,
    name_hex: String,
}

struct SessionContext {
    authority: Authority,
    sessions: File,
    sessions_path: PathBuf,
}

pub(crate) fn list(repository: Option<&Path>, all: bool) -> Result<(), Error> {
    if all && repository.is_some() {
        return Err(Error::new(
            "SESSION_USAGE",
            "--all cannot be combined with --repo",
        ));
    }
    let (sessions, sessions_path, selected_authority) = if let Some(repository) = repository {
        let (authority, sessions) = optional_session_context(repository)?;
        let Some((sessions, sessions_path)) = sessions else {
            return Ok(());
        };
        (sessions, sessions_path, Some(authority))
    } else {
        let Some((sessions, sessions_path)) = sessions_for_read()? else {
            return Ok(());
        };
        (sessions, sessions_path, None)
    };
    let mut healthy = Vec::new();
    let mut corrupt = Vec::new();
    for name in storage::directory_names(sessions.as_raw_fd())? {
        if !name.starts_with(b"session-") || !name.ends_with(b".record") {
            continue;
        }
        let capability = match read_record_capability(&sessions, &name) {
            Ok(capability) => capability,
            Err(_) => {
                corrupt.push((
                    name,
                    CorruptRecord {
                        version: 1,
                        state: "CORRUPT",
                        record_name_hex: String::new(),
                        code: "SESSION_CORRUPT",
                    },
                ));
                continue;
            }
        };
        let runtime_authority = if let Some(authority) = selected_authority.as_ref() {
            let record_path = match authority_path_from_record(&capability.record) {
                Ok(path) => path,
                Err(_) => {
                    corrupt.push((
                        name,
                        CorruptRecord {
                            version: 1,
                            state: "CORRUPT",
                            record_name_hex: String::new(),
                            code: "SESSION_CORRUPT",
                        },
                    ));
                    continue;
                }
            };
            if record_path != authority.canonical {
                continue;
            }
            if !record_authority_matches(&capability.record, authority) {
                corrupt.push((
                    name,
                    CorruptRecord {
                        version: 1,
                        state: "CORRUPT",
                        record_name_hex: String::new(),
                        code: "SESSION_CORRUPT",
                    },
                ));
                continue;
            }
            authority.clone()
        } else {
            match authority_from_record(&capability.record) {
                Ok(authority) => authority,
                Err(_) => {
                    corrupt.push((
                        name,
                        CorruptRecord {
                            version: 1,
                            state: "CORRUPT",
                            record_name_hex: String::new(),
                            code: "SESSION_CORRUPT",
                        },
                    ));
                    continue;
                }
            }
        };
        if diagnose_list_record(&sessions, &sessions_path, &runtime_authority, &capability).is_err()
        {
            corrupt.push((
                name,
                CorruptRecord {
                    version: 1,
                    state: "CORRUPT",
                    record_name_hex: String::new(),
                    code: "SESSION_CORRUPT",
                },
            ));
            continue;
        }
        healthy.push(list_record(&capability.record, &sessions_path));
    }
    healthy.sort_by(|left, right| {
        left.authority_path_hex
            .cmp(&right.authority_path_hex)
            .then_with(|| {
                left.authority_identity
                    .dev
                    .cmp(&right.authority_identity.dev)
            })
            .then_with(|| {
                left.authority_identity
                    .ino
                    .cmp(&right.authority_identity.ino)
            })
            .then_with(|| {
                left.authority_identity
                    .uid
                    .cmp(&right.authority_identity.uid)
            })
            .then_with(|| {
                left.authority_identity
                    .mode
                    .cmp(&right.authority_identity.mode)
            })
            .then_with(|| {
                left.authority_identity
                    .kind
                    .cmp(&right.authority_identity.kind)
            })
            .then_with(|| {
                left.authority_identity
                    .nlink
                    .cmp(&right.authority_identity.nlink)
            })
            .then_with(|| left.name_hex.cmp(&right.name_hex))
    });
    corrupt.sort_by(|left, right| left.0.cmp(&right.0));
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    for record in healthy {
        serde_json::to_writer(&mut output, &record).map_err(|error| {
            Error::new(
                "SESSION_IO_FAILED",
                format!("cannot encode session listing: {error}"),
            )
        })?;
        output.write_all(b"\n").map_err(|error| {
            Error::io("SESSION_IO_FAILED", "cannot write session listing", error)
        })?;
    }
    let had_corrupt = !corrupt.is_empty();
    for (name, mut record) in corrupt {
        record.record_name_hex = authority::hex(&name);
        serde_json::to_writer(&mut output, &record).map_err(|error| {
            Error::new(
                "SESSION_IO_FAILED",
                format!("cannot encode corrupt listing: {error}"),
            )
        })?;
        output.write_all(b"\n").map_err(|error| {
            Error::io("SESSION_IO_FAILED", "cannot write corrupt listing", error)
        })?;
    }
    output
        .flush()
        .map_err(|error| Error::io("SESSION_IO_FAILED", "cannot flush session listing", error))?;
    if !had_corrupt {
        Ok(())
    } else {
        Err(Error::new(
            "SESSION_CORRUPT",
            "one or more session records could not be trusted",
        ))
    }
}

pub(crate) fn exec(
    repository: &Path,
    raw_name: Option<OsString>,
    name_hex: Option<String>,
    program: Vec<OsString>,
) -> Result<ExitStatus, Error> {
    let name = selected_name(raw_name, name_hex)?;
    let program = program
        .split_first()
        .ok_or_else(|| Error::new("SESSION_USAGE", "exec requires a program after --"))?;
    let context = session_context(repository)?;
    let sid = session_id(&context.authority, &name);
    let record_name = record_name(&sid);
    let capability = required_record(&context.sessions, &record_name, &context.authority)?;
    let ready = load_ready_capability(
        &context.sessions,
        &context.sessions_path,
        &context.authority,
        &capability,
    )?;
    acquire_lease(&ready.root, false)?;
    revalidate_ready_lease(&context, &capability, &ready)?;
    git::GitChild::spawn_direct(
        program.0.as_os_str(),
        program.1,
        &ready.worktree_path,
        ready.root.as_raw_fd(),
    )
    .map_err(git_error)?
    .wait_direct()
    .map_err(git_error)
}

pub(crate) fn remove(
    repository: &Path,
    raw_name: Option<OsString>,
    name_hex: Option<String>,
    force: bool,
) -> Result<String, Error> {
    let name = selected_name(raw_name, name_hex)?;
    let (authority, sessions) = optional_session_context(repository)?;
    let Some((sessions, sessions_path)) = sessions else {
        return remove_event(&authority, &name);
    };
    let context = SessionContext {
        authority,
        sessions,
        sessions_path,
    };
    let sid = session_id(&context.authority, &name);
    let record_name = record_name(&sid);
    let capability = match optional_record(&context.sessions, &record_name, &context.authority)? {
        Some(capability) => capability,
        None => {
            if root_or_tombstone_present(&context.sessions, &sid)? {
                return Err(Error::new(
                    "SESSION_RECOVERY_REQUIRED",
                    "session record is absent while a managed root remains",
                ));
            }
            return remove_event(&context.authority, &name);
        }
    };
    let tombstoned = match &capability.record.payload {
        SessionPayload::Tombstoned { .. } => capability,
        SessionPayload::Ready { .. } => {
            let ready = load_ready_capability(
                &context.sessions,
                &context.sessions_path,
                &context.authority,
                &capability,
            )?;
            acquire_lease(&ready.root, true)?;
            let capability = revalidate_ready_lease(&context, &capability, &ready)?;
            if !force {
                ensure_discard_safe(&ready, &capability.record)?;
            }
            transition_tombstone(&context.sessions, &capability)?
        }
        SessionPayload::Materializing { .. } => {
            if !force {
                return Err(Error::new(
                    "SESSION_DISCARD_RISK",
                    "incomplete session removal requires --force",
                ));
            }
            let root = open_payload_root(&context.sessions, &capability.record)?;
            acquire_lease(&root, true)?;
            let capability = revalidate_record(&context.sessions, &capability)?;
            transition_tombstone(&context.sessions, &capability)?
        }
        SessionPayload::Prepared { .. } => {
            if !force {
                return Err(Error::new(
                    "SESSION_DISCARD_RISK",
                    "prepared session removal requires --force",
                ));
            }
            if root_or_tombstone_present(&context.sessions, &sid)? {
                return Err(Error::new(
                    "SESSION_RECOVERY_REQUIRED",
                    "prepared session has a root despite lacking its descriptor receipt",
                ));
            }
            ensure_record_container(&context.sessions, &capability.record)?;
            remove_record_capability(&context.sessions, &capability, "remove")?;
            #[cfg(git_vws_m4_checkpoint)]
            session_checkpoint("remove", &capability.record, "return")?;
            return remove_event(&context.authority, &name);
        }
    };
    complete_tombstone(&context, &tombstoned)?;
    #[cfg(git_vws_m4_checkpoint)]
    session_checkpoint("remove", &tombstoned.record, "return")?;
    remove_event(&context.authority, &name)
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
    if let Some(existing) = optional_record(&sessions, &record_name, &authority)? {
        if existing.record == prepared {
            return Err(Error::new(
                "SESSION_INCOMPLETE",
                "session record is prepared but has no stable root",
            ));
        }
        if matches_existing(&existing.record, &prepared) {
            return match &existing.record.payload {
                SessionPayload::Ready { .. } => {
                    Ok(
                        load_ready_capability(&sessions, &sessions_path, &authority, &existing)?
                            .root_path,
                    )
                }
                SessionPayload::Prepared { .. } | SessionPayload::Materializing { .. } => {
                    Err(Error::new(
                        "SESSION_INCOMPLETE",
                        "session creation is incomplete and was retained for diagnosis",
                    ))
                }
                SessionPayload::Tombstoned { .. } => Err(Error::new(
                    "SESSION_RECOVERY_REQUIRED",
                    "session removal is incomplete and was retained for diagnosis",
                )),
            };
        }
        return Err(Error::new(
            "SESSION_EXISTS",
            "session name is already bound to different create inputs",
        ));
    }
    let prepared_bytes = encode_record(&prepared)?;
    let capability = create_record_capability(&sessions, record_name, &prepared_bytes, &prepared)?;

    let root = create_directory(&sessions, &root_name, 0o700, "session root")?;
    #[cfg(git_vws_m4_checkpoint)]
    session_checkpoint("create", &prepared, "session-root-created")?;
    let root_identity = Identity::from_file(&root)?;
    let mut transaction = CreateTxn::new(
        &sessions,
        capability,
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
    #[cfg(git_vws_m4_checkpoint)]
    let m4_sid = transaction.capability().record.sid.clone();
    #[cfg(git_vws_m4_checkpoint)]
    let m4_key = transaction.capability().record.template_key.clone();
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| crate::m4_checkpoint::checkpoint("create", &m4_sid, &m4_key, stage);
    let mut materializing = transaction.capability().record.clone();
    materializing.payload = SessionPayload::Materializing {
        root_name: root_name.clone(),
        root_identity,
    };
    let materializing_bytes = encode_record(&materializing)?;
    let capability = replace_record_capability(
        transaction.sessions,
        transaction.capability(),
        &materializing_bytes,
        "create",
        "materializing-record",
    )?;
    transaction.replace_capability(capability);
    bind_path(root_path, transaction.root(), "session root")?;

    let empty_template = create_directory(
        transaction.root(),
        ".git-vws-empty-template",
        0o700,
        "empty Git template",
    )?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("empty-template-created")?;
    let empty_template_identity = Identity::from_file(&empty_template)?;
    let empty_template_path = root_path.join(".git-vws-empty-template");
    bind_path(&empty_template_path, &empty_template, "empty Git template")?;
    let common_path = root_path.join("common.git");
    bind_path(root_path, transaction.root(), "session root")?;
    init_private_common(authority, &common_path, &empty_template_path)?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("private-git-initialized")?;
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
        &transaction.capability().record,
    )?;
    write_alternate(
        &common,
        authority.canonical.join("objects").as_os_str().as_bytes(),
        &transaction.capability().record,
    )?;
    configure_private_common(&common_path, &transaction.capability().record)?;

    let worktree_path = root_path.join("worktree");
    bind_path(root_path, transaction.root(), "session root")?;
    add_linked_worktree(
        &common_path,
        &worktree_path,
        target,
        base,
        &transaction.capability().record,
    )?;
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
    #[cfg(git_vws_m4_checkpoint)]
    m4("cow-complete")?;
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
    #[cfg(git_vws_m4_checkpoint)]
    m4("read-tree-complete")?;
    status_clean(&worktree_path)?;
    sync_tree(&common)?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("common-tree-synced")?;
    sync_tree(&worktree)?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("worktree-tree-synced")?;
    transaction
        .root()
        .sync_all()
        .map_err(|error| Error::io("SESSION_IO_FAILED", "cannot sync session root", error))?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("session-tree-synced")?;
    transaction.sessions.sync_all().map_err(|error| {
        Error::io(
            "SESSION_IO_FAILED",
            "cannot sync session container before READY",
            error,
        )
    })?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("sessions-container-synced")?;

    let capability = revalidate_record(transaction.sessions, transaction.capability())?;
    transaction.replace_capability(capability);
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
    let capability = replace_record_capability(
        transaction.sessions,
        transaction.capability(),
        &ready_bytes,
        "create",
        "ready-record",
    )?;
    transaction.replace_capability(capability);
    #[cfg(git_vws_m4_checkpoint)]
    m4("ready-return")?;
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

fn sessions_for_read() -> Result<Option<(File, PathBuf)>, Error> {
    let state = authority::open_existing_state()?;
    let path = state.container_path("sessions")?;
    let sessions = state.open_container_if_present(b"sessions")?;
    drop(state);
    Ok(sessions.map(|sessions| (sessions, path)))
}

fn session_context(repository: &Path) -> Result<SessionContext, Error> {
    let (authority, sessions) = optional_session_context(repository)?;
    let (sessions, sessions_path) = sessions.ok_or_else(|| {
        Error::new(
            "SESSION_ABSENT",
            "authority has no managed session container",
        )
    })?;
    Ok(SessionContext {
        authority,
        sessions,
        sessions_path,
    })
}

fn optional_session_context(
    repository: &Path,
) -> Result<(Authority, Option<(File, PathBuf)>), Error> {
    let authority = authority::inspect(repository)?;
    let state = authority::open_existing_state()?;
    if !authority::authority_record_present(&state, &authority)? {
        return Err(Error::new(
            "AUTHORITY_UNREGISTERED",
            "session lifecycle requires an existing exact authority record",
        ));
    }
    let sessions_path = state.container_path("sessions")?;
    let sessions = state.open_container_if_present(b"sessions")?;
    drop(state);
    Ok((
        authority,
        sessions.map(|sessions| (sessions, sessions_path)),
    ))
}

fn list_record(record: &SessionRecord, sessions_path: &Path) -> ListRecord {
    let (state, root) = match &record.payload {
        SessionPayload::Prepared { root_name }
        | SessionPayload::Materializing { root_name, .. } => ("CREATING", root_name),
        SessionPayload::Ready { root_name, .. } => ("READY", root_name),
        SessionPayload::Tombstoned { tombstone_name, .. } => ("TOMBSTONED", tombstone_name),
    };
    ListRecord {
        version: 1,
        authority_path_hex: record.authority_path.clone(),
        authority_identity: record.authority_identity,
        name_hex: record.name.clone(),
        state,
        base: record.base.clone(),
        target_hex: record.target.clone(),
        managed_path_hex: authority::hex(sessions_path.join(root).as_os_str().as_bytes()),
    }
}

fn selected_name(raw_name: Option<OsString>, name_hex: Option<String>) -> Result<OsString, Error> {
    match (raw_name, name_hex) {
        (Some(name), None) if valid_session_name(name.as_os_str().as_bytes()) => Ok(name),
        (None, Some(encoded)) if valid_lower_hex(&encoded) => {
            let bytes = decode_hex(&encoded)?;
            if valid_session_name(&bytes) {
                Ok(OsString::from_vec(bytes))
            } else {
                Err(Error::new(
                    "SESSION_USAGE",
                    "--name-hex decodes to an invalid name",
                ))
            }
        }
        (Some(_), None) => Err(Error::new("SESSION_USAGE", "session name is invalid")),
        (None, Some(_)) => Err(Error::new(
            "SESSION_USAGE",
            "--name-hex must be lowercase non-empty even-length hexadecimal",
        )),
        _ => Err(Error::new(
            "SESSION_USAGE",
            "select exactly one of NAME or --name-hex",
        )),
    }
}

fn valid_session_name(bytes: &[u8]) -> bool {
    !bytes.is_empty() && !bytes.contains(&0)
}

fn valid_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn required_record(
    sessions: &File,
    name: &[u8],
    authority: &Authority,
) -> Result<RecordCapability, Error> {
    optional_record(sessions, name, authority)?
        .ok_or_else(|| Error::new("SESSION_ABSENT", "managed session record does not exist"))
}

fn optional_record(
    sessions: &File,
    name: &[u8],
    authority: &Authority,
) -> Result<Option<RecordCapability>, Error> {
    let name = cstring(name, "session record")?;
    if entry_identity_if_present(sessions.as_raw_fd(), &name)?.is_none() {
        return Ok(None);
    }
    let capability = read_record_capability(sessions, name.to_bytes())?;
    if !record_authority_matches(&capability.record, authority) {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record is bound to a different authority",
        ));
    }
    Ok(Some(capability))
}

fn read_record_capability(sessions: &File, basename: &[u8]) -> Result<RecordCapability, Error> {
    let binding = authority::read_file_binding(sessions.as_raw_fd(), basename, MAX_RECORD)
        .map_err(|error| record_binding_recovery(error, "cannot read session record capability"))?;
    record_capability_from_binding(basename.to_vec(), binding)
}

fn record_capability_from_binding(
    basename: Vec<u8>,
    binding: authority::RecordBinding,
) -> Result<RecordCapability, Error> {
    let record = parse_record(&binding.bytes)?;
    if basename != record_name(&record.sid) {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record basename does not match its session ID",
        ));
    }
    let name = decode_hex(&record.name)?;
    let authority_path = authority_path_from_record(&record)?;
    if !valid_session_name(&name)
        || !record.authority_identity.directory()
        || record.sid != session_id_for_binding(&authority_path, record.authority_identity, &name)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record does not prove its authority and name binding",
        ));
    }
    Ok(RecordCapability {
        basename,
        record,
        binding,
    })
}

fn parse_record(bytes: &[u8]) -> Result<SessionRecord, Error> {
    let record: SessionRecord = serde_json::from_slice(bytes)
        .map_err(|_| Error::new("SESSION_CORRUPT", "session record is not valid JSON"))?;
    if encode_record(&record)? != bytes {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record is not canonically encoded",
        ));
    }
    Ok(record)
}

fn authority_path_from_record(record: &SessionRecord) -> Result<PathBuf, Error> {
    let bytes = decode_hex(&record.authority_path)?;
    let path = PathBuf::from(OsString::from_vec(bytes));
    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record authority path is not absolute",
        ));
    }
    Ok(path)
}

fn authority_from_record(record: &SessionRecord) -> Result<Authority, Error> {
    Ok(Authority {
        canonical: authority_path_from_record(record)?,
        identity: record.authority_identity,
        object_format: String::new(),
        ref_format: String::new(),
    })
}

fn record_binding_recovery(error: Error, boundary: &str) -> Error {
    Error::new(
        "SESSION_RECOVERY_REQUIRED",
        format!("{boundary}: {}", error.detail),
    )
}

fn bound_record_error(error: Error, boundary: &str) -> Error {
    record_binding_recovery(error, boundary)
}

fn replace_record_capability(
    sessions: &File,
    expected: &RecordCapability,
    bytes: &[u8],
    _operation: &'static str,
    _stage: &'static str,
) -> Result<RecordCapability, Error> {
    #[cfg(not(git_vws_m4_checkpoint))]
    let transaction =
        authority::RecordTxn::begin_bound(sessions, &expected.basename, bytes, &expected.binding)
            .map_err(|error| bound_record_error(error, "cannot begin record replacement"))?;
    #[cfg(git_vws_m4_checkpoint)]
    let transaction = authority::RecordTxn::begin_bound_checkpointed(
        sessions,
        &expected.basename,
        bytes,
        &expected.binding,
        (
            _operation,
            &expected.record.sid,
            &expected.record.template_key,
            _stage,
        ),
    )
    .map_err(|error| bound_record_error(error, "cannot begin record replacement"))?;
    let mut transaction = transaction;
    let binding = transaction
        .commit()
        .map_err(|error| bound_record_error(error, "cannot commit record replacement"))?;
    record_capability_from_binding(expected.basename.clone(), binding)
}

fn create_record_capability(
    sessions: &File,
    basename: Vec<u8>,
    bytes: &[u8],
    _record: &SessionRecord,
) -> Result<RecordCapability, Error> {
    #[cfg(not(git_vws_m4_checkpoint))]
    let transaction = authority::RecordTxn::begin(sessions, &basename, bytes, None)?;
    #[cfg(git_vws_m4_checkpoint)]
    let transaction = authority::RecordTxn::begin_checkpointed(
        sessions,
        &basename,
        bytes,
        None,
        (
            "create",
            &_record.sid,
            &_record.template_key,
            "prepared-record",
        ),
    )?;
    let mut transaction = transaction;
    let binding = transaction.commit()?;
    record_capability_from_binding(basename, binding)
}

fn remove_record_capability(
    sessions: &File,
    expected: &RecordCapability,
    _operation: &'static str,
) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    return authority::remove_record_bound(
        sessions,
        &expected.basename,
        &expected.binding,
        _operation,
        &expected.record.sid,
        &expected.record.template_key,
    )
    .map_err(|error| bound_record_error(error, "cannot remove bound session record"));
    #[cfg(not(git_vws_m4_checkpoint))]
    authority::remove_record_bound(sessions, &expected.basename, &expected.binding)
        .map_err(|error| bound_record_error(error, "cannot remove bound session record"))
}

fn acquire_lease(root: &File, exclusive: bool) -> Result<(), Error> {
    let operation = if exclusive {
        libc::LOCK_EX | libc::LOCK_NB
    } else {
        libc::LOCK_SH
    };
    loop {
        if unsafe { libc::flock(root.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted && !exclusive {
            continue;
        }
        if exclusive && error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(Error::new(
                "SESSION_BUSY",
                "session root is leased by an active command",
            ));
        }
        return Err(Error::io(
            "SESSION_BUSY",
            "cannot acquire session lease",
            error,
        ));
    }
}

fn revalidate_record(
    sessions: &File,
    expected: &RecordCapability,
) -> Result<RecordCapability, Error> {
    let current = read_record_capability(sessions, &expected.basename)?;
    if current.binding != expected.binding {
        return Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "session record bytes or identity changed across a capability boundary",
        ));
    }
    Ok(current)
}

fn revalidate_ready_lease(
    context: &SessionContext,
    expected: &RecordCapability,
    ready: &ReadySession,
) -> Result<RecordCapability, Error> {
    let current = revalidate_record(&context.sessions, expected)?;
    let checked = load_ready_session(
        &context.sessions,
        &context.sessions_path,
        &context.authority,
        &current.record,
    )?;
    let current = revalidate_record(&context.sessions, &current)?;
    if !Identity::from_file(&ready.root)?.same_node(ready.root_identity)
        || !storage::identity_at(context.sessions.as_raw_fd(), &ready.root_name)?
            .same_node(ready.root_identity)
        || !Identity::from_file(&checked.root)?.same_node(ready.root_identity)
        || checked.worktree_path != ready.worktree_path
    {
        return Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "session root binding changed while its lease was held",
        ));
    }
    Ok(current)
}

fn root_or_tombstone_present(sessions: &File, sid: &str) -> Result<bool, Error> {
    Ok(entry_identity_if_present(
        sessions.as_raw_fd(),
        &cstring(root_name(sid).as_bytes(), "session root")?,
    )?
    .is_some()
        || entry_identity_if_present(
            sessions.as_raw_fd(),
            &cstring(tombstone_name(sid).as_bytes(), "session tombstone")?,
        )?
        .is_some())
}

fn entry_identity_if_present(parent: i32, name: &CStr) -> Result<Option<Identity>, Error> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        return Ok(Some(Identity::from_stat(&stat)));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(Error::io(
            "SESSION_RECOVERY_REQUIRED",
            "cannot inspect managed session root",
            error,
        ))
    }
}

fn open_payload_root(sessions: &File, record: &SessionRecord) -> Result<File, Error> {
    match &record.payload {
        SessionPayload::Materializing {
            root_name,
            root_identity,
        } => open_authorized_root(sessions, record, root_name, *root_identity),
        SessionPayload::Tombstoned {
            tombstone_name,
            root_identity,
            ..
        } => open_authorized_root(sessions, record, tombstone_name, *root_identity),
        _ => Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "session record has no removable descriptor-bound root",
        )),
    }
}

fn open_authorized_root(
    sessions: &File,
    record: &SessionRecord,
    name: &str,
    expected: Identity,
) -> Result<File, Error> {
    ensure_record_container(sessions, record)?;
    let name = cstring(name.as_bytes(), "managed session root")?;
    let root = storage::open_directory_at(sessions.as_raw_fd(), &name)?;
    if !storage::identity_at(sessions.as_raw_fd(), &name)?.same_node(expected)
        || !Identity::from_file(&root)?.same_node(expected)
        || !storage::private_directory(expected)
        || storage::volume_id(&root)? != record.volume
    {
        return Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "managed session root no longer matches the record binding",
        ));
    }
    Ok(root)
}

fn ensure_record_container(sessions: &File, record: &SessionRecord) -> Result<(), Error> {
    let container = Identity::from_file(sessions)?;
    if !container.same_node(record.container_identity)
        || !storage::private_directory(container)
        || storage::volume_id(sessions)? != record.volume
    {
        return Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "session container no longer matches the record binding",
        ));
    }
    Ok(())
}

fn transition_tombstone(
    sessions: &File,
    expected: &RecordCapability,
) -> Result<RecordCapability, Error> {
    let (root_name, root_identity) = match &expected.record.payload {
        SessionPayload::Ready {
            root_name,
            root_identity,
            ..
        }
        | SessionPayload::Materializing {
            root_name,
            root_identity,
        } => (root_name.clone(), *root_identity),
        _ => {
            return Err(Error::new(
                "SESSION_RECOVERY_REQUIRED",
                "session record cannot transition to a tombstone",
            ));
        }
    };
    let mut tombstoned = expected.record.clone();
    tombstoned.payload = SessionPayload::Tombstoned {
        root_name,
        tombstone_name: tombstone_name(&expected.record.sid),
        root_identity,
    };
    let bytes = encode_record(&tombstoned)?;
    replace_record_capability(sessions, expected, &bytes, "remove", "tombstoned-record")
}

fn complete_tombstone(context: &SessionContext, expected: &RecordCapability) -> Result<(), Error> {
    let SessionPayload::Tombstoned {
        root_name,
        tombstone_name,
        root_identity,
    } = &expected.record.payload
    else {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record is not TOMBSTONED",
        ));
    };
    let root = cstring(root_name.as_bytes(), "session root")?;
    let tombstone = cstring(tombstone_name.as_bytes(), "session tombstone")?;
    ensure_record_container(&context.sessions, &expected.record)?;
    let root_entry = entry_identity_if_present(context.sessions.as_raw_fd(), &root)?;
    let tombstone_entry = entry_identity_if_present(context.sessions.as_raw_fd(), &tombstone)?;
    let leased = match (root_entry, tombstone_entry) {
        (Some(root_entry), None) if root_entry.same_node(*root_identity) => open_authorized_root(
            &context.sessions,
            &expected.record,
            root_name,
            *root_identity,
        )?,
        (None, Some(tombstone_entry)) if tombstone_entry.same_node(*root_identity) => {
            open_authorized_root(
                &context.sessions,
                &expected.record,
                tombstone_name,
                *root_identity,
            )?
        }
        (None, None) => {
            let current = revalidate_record(&context.sessions, expected)?;
            return remove_record_capability(&context.sessions, &current, "remove");
        }
        _ => {
            return Err(Error::new(
                "SESSION_RECOVERY_REQUIRED",
                "tombstone root bindings are ambiguous or changed",
            ));
        }
    };
    acquire_lease(&leased, true)?;
    let current = revalidate_record(&context.sessions, expected)?;
    if current.record != expected.record {
        return Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "tombstone record changed while its lease was held",
        ));
    }
    promote_tombstone(
        &context.sessions,
        &root,
        &tombstone,
        *root_identity,
        &expected.record,
    )?;
    let current = revalidate_record(&context.sessions, &current)?;
    storage::remove_owned_tree(&context.sessions, &tombstone, *root_identity)?;
    #[cfg(git_vws_m4_checkpoint)]
    session_checkpoint("remove", &current.record, "owned-tree-removed")?;
    remove_record_capability(&context.sessions, &current, "remove")
}

fn promote_tombstone(
    sessions: &File,
    root: &CStr,
    tombstone: &CStr,
    expected: Identity,
    _record: &SessionRecord,
) -> Result<(), Error> {
    match (
        entry_identity_if_present(sessions.as_raw_fd(), root)?,
        entry_identity_if_present(sessions.as_raw_fd(), tombstone)?,
    ) {
        (Some(root_identity), None) if root_identity.same_node(expected) => {
            match authority::rename_no_replace(sessions.as_raw_fd(), root, tombstone) {
                Ok(()) => {
                    #[cfg(git_vws_m4_checkpoint)]
                    session_checkpoint("remove", _record, "tombstone-renamed")?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    return Err(Error::io(
                        "SESSION_RECOVERY_REQUIRED",
                        "session tombstone rename has an unknown result",
                        error,
                    ));
                }
                Err(error) => {
                    return Err(Error::io(
                        "SESSION_RECOVERY_REQUIRED",
                        "cannot rename session root into its tombstone namespace",
                        error,
                    ));
                }
            }
            sessions.sync_all().map_err(|error| {
                Error::io(
                    "SESSION_RECOVERY_REQUIRED",
                    "cannot sync session container after tombstone rename",
                    error,
                )
            })?;
            #[cfg(git_vws_m4_checkpoint)]
            session_checkpoint("remove", _record, "tombstone-parent-synced")?;
            if !entry_identity_if_present(sessions.as_raw_fd(), tombstone)?
                .is_some_and(|identity| identity.same_node(expected))
            {
                return Err(Error::new(
                    "SESSION_RECOVERY_REQUIRED",
                    "session tombstone binding changed after rename",
                ));
            }
            Ok(())
        }
        (None, Some(tombstone_identity)) if tombstone_identity.same_node(expected) => Ok(()),
        _ => Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "session root and tombstone names are not safely recoverable",
        )),
    }
}

#[cfg(git_vws_m4_checkpoint)]
fn session_checkpoint(operation: &str, record: &SessionRecord, stage: &str) -> Result<(), Error> {
    crate::m4_checkpoint::checkpoint(operation, &record.sid, &record.template_key, stage)
}

fn ensure_discard_safe(ready: &ReadySession, record: &SessionRecord) -> Result<(), Error> {
    let output = git::capture(
        &[
            OsString::from("status"),
            OsString::from("--porcelain=v1"),
            OsString::from("--untracked-files=all"),
            OsString::from("--ignored=matching"),
        ],
        Some(&ready.worktree_path),
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(|_| discard_risk("cannot inspect worktree changes"))?;
    if !output.status.success() || !output.stderr.is_empty() || !output.stdout.is_empty() {
        return Err(discard_risk(
            "worktree has tracked, untracked, or ignored changes",
        ));
    }
    let common = storage::open_directory_at(ready.root.as_raw_fd(), c"common.git")?;
    ensure_private_refs_safe(&common, &ready.root_path, record)?;
    ensure_private_object_store_empty(&common)?;
    ensure_no_unreachable_private_closure(&common, &ready.root_path, record)?;
    Ok(())
}

fn discard_risk(detail: impl Into<String>) -> Error {
    Error::new("SESSION_DISCARD_RISK", detail)
}

fn ensure_private_refs_safe(
    common: &File,
    root_path: &Path,
    record: &SessionRecord,
) -> Result<(), Error> {
    let common_path = root_path.join("common.git");
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(common_path.as_os_str());
    let output = git::capture(
        &[
            git_dir,
            OsString::from("for-each-ref"),
            OsString::from("--format=%(refname) %(objectname)"),
        ],
        None,
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(|_| discard_risk("cannot inspect private refs"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(discard_risk("cannot inspect private refs"));
    }
    let target = decode_hex(&record.target)?;
    let mut expected_ref = b"refs/heads/".to_vec();
    expected_ref.extend_from_slice(&target);
    let mut ref_count = 0_usize;
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Some(separator) = line.iter().rposition(|byte| *byte == b' ') else {
            return Err(discard_risk("private ref listing was malformed"));
        };
        if line[..separator] != expected_ref[..] || &line[separator + 1..] != record.base.as_bytes()
        {
            return Err(discard_risk(
                "private refs differ from the initial session target",
            ));
        }
        ref_count += 1;
    }
    if ref_count != 1 {
        return Err(discard_risk(
            "private ref baseline is not exactly the initial session target",
        ));
    }
    let objects = storage::open_directory_at(common.as_raw_fd(), c"objects")?;
    if Identity::from_file(&objects)?.dev != Identity::from_file(common)?.dev {
        return Err(discard_risk(
            "private object directory left the session volume",
        ));
    }
    Ok(())
}

fn ensure_private_object_store_empty(common: &File) -> Result<(), Error> {
    let objects = storage::open_directory_at(common.as_raw_fd(), c"objects")?;
    for name in storage::directory_names(objects.as_raw_fd())? {
        let name = cstring(&name, "private object entry")?;
        match name.to_bytes() {
            b"info" => {
                let info = storage::open_directory_at(objects.as_raw_fd(), &name)?;
                for child in storage::directory_names(info.as_raw_fd())? {
                    if child != b"alternates" {
                        return Err(discard_risk(
                            "private object metadata contains additional entries",
                        ));
                    }
                }
            }
            b"pack" => {
                let pack = storage::open_directory_at(objects.as_raw_fd(), &name)?;
                if !storage::directory_names(pack.as_raw_fd())?.is_empty() {
                    return Err(discard_risk("private object store contains packed objects"));
                }
            }
            _ => return Err(discard_risk("private object store contains loose objects")),
        }
    }
    Ok(())
}

fn ensure_no_unreachable_private_closure(
    common: &File,
    root_path: &Path,
    record: &SessionRecord,
) -> Result<(), Error> {
    let mut git_dir = OsString::from("--git-dir=");
    git_dir.push(root_path.join("common.git").as_os_str());
    let output = git::capture(
        &[
            git_dir,
            OsString::from("fsck"),
            OsString::from("--no-reflogs"),
            OsString::from("--unreachable"),
            OsString::from("--no-progress"),
        ],
        None,
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(|_| discard_risk("cannot prove the private object closure is disposable"))?;
    if !output.status.success() || !output.stdout.is_empty() {
        return Err(discard_risk(
            "private refs, reflogs, or objects are not proven disposable",
        ));
    }
    if output.stderr.is_empty() {
        return Ok(());
    }
    let target = decode_hex(&record.target)
        .map_err(|_| discard_risk("private refs, reflogs, or objects are not proven disposable"))?;
    let head_bytes = read_regular_at(common, c"HEAD", "private common HEAD")
        .map_err(|_| discard_risk("private refs, reflogs, or objects are not proven disposable"))?;
    let head = unborn_head(&head_bytes, &target).ok_or_else(|| {
        discard_risk("private refs, reflogs, or objects are not proven disposable")
    })?;
    let mut expected_stderr = b"notice: HEAD points to an unborn branch (".to_vec();
    expected_stderr.extend_from_slice(head);
    expected_stderr.extend_from_slice(b")\n");
    if output.stderr != expected_stderr
        || read_regular_at(common, c"HEAD", "private common HEAD").map_err(|_| {
            discard_risk("private refs, reflogs, or objects are not proven disposable")
        })? != head_bytes
    {
        return Err(discard_risk(
            "private refs, reflogs, or objects are not proven disposable",
        ));
    }
    Ok(())
}

fn unborn_head<'a>(bytes: &'a [u8], target: &[u8]) -> Option<&'a [u8]> {
    let head = bytes
        .strip_prefix(b"ref: refs/heads/")?
        .strip_suffix(b"\n")?;
    if head.contains(&b'\n') || head.contains(&b'\r') || !git_safe_unborn_head(head, target) {
        None
    } else {
        Some(head)
    }
}

fn git_safe_unborn_head(head: &[u8], target: &[u8]) -> bool {
    !head.is_empty()
        && head != target
        && !head.starts_with(b"/")
        && !head.starts_with(b"-")
        && !head.ends_with(b"/")
        && !head.windows(2).any(|pair| pair == b".." || pair == b"//")
        && head
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        && head.split(|byte| *byte == b'/').all(|component| {
            !component.is_empty()
                && !component.starts_with(b".")
                && !component.ends_with(b".")
                && !component.ends_with(b".lock")
        })
}

fn remove_event(authority: &Authority, name: &OsStr) -> Result<String, Error> {
    serde_json::to_string(&RemoveEvent {
        version: 1,
        event: "REMOVED",
        authority_path_hex: authority::hex(authority.canonical.as_os_str().as_bytes()),
        authority_identity: authority.identity,
        name_hex: authority::hex(name.as_bytes()),
    })
    .map_err(|error| {
        Error::new(
            "SESSION_IO_FAILED",
            format!("cannot encode remove event: {error}"),
        )
    })
}

struct CreateTxn<'a> {
    sessions: &'a File,
    capability: RecordCapability,
    root: Option<File>,
    root_name: String,
    root_identity: Identity,
    armed: bool,
}

impl<'a> CreateTxn<'a> {
    fn new(
        sessions: &'a File,
        capability: RecordCapability,
        root: File,
        root_name: String,
        root_identity: Identity,
    ) -> Self {
        Self {
            sessions,
            capability,
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

    fn capability(&self) -> &RecordCapability {
        &self.capability
    }

    fn replace_capability(&mut self, capability: RecordCapability) {
        self.capability = capability;
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
        let capability = match revalidate_record(self.sessions, &self.capability) {
            Ok(capability) => capability,
            Err(error) => return error,
        };
        self.root.take();
        if let Err(error) = storage::remove_owned_tree(self.sessions, &name, self.root_identity) {
            return error;
        }
        match remove_record_capability(self.sessions, &capability, "create") {
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

struct ReadySession {
    root: File,
    root_name: CString,
    root_identity: Identity,
    root_path: PathBuf,
    worktree_path: PathBuf,
}

fn load_ready_capability(
    sessions: &File,
    sessions_path: &Path,
    authority: &Authority,
    capability: &RecordCapability,
) -> Result<ReadySession, Error> {
    let ready = load_ready_session(sessions, sessions_path, authority, &capability.record)?;
    revalidate_record(sessions, capability)?;
    Ok(ready)
}

fn diagnose_list_record(
    sessions: &File,
    sessions_path: &Path,
    authority: &Authority,
    capability: &RecordCapability,
) -> Result<(), Error> {
    bind_path(sessions_path, sessions, "session container")?;
    match &capability.record.payload {
        SessionPayload::Ready { .. } => {
            let _ = load_ready_capability(sessions, sessions_path, authority, capability)?;
        }
        SessionPayload::Prepared { .. } => {
            ensure_record_container(sessions, &capability.record)?;
            revalidate_record(sessions, capability)?;
        }
        SessionPayload::Materializing {
            root_name,
            root_identity,
        } => {
            let _ = open_authorized_root(sessions, &capability.record, root_name, *root_identity)?;
            let tombstone = cstring(
                tombstone_name(&capability.record.sid).as_bytes(),
                "session tombstone",
            )?;
            if entry_identity_if_present(sessions.as_raw_fd(), &tombstone)?.is_some() {
                return Err(Error::new(
                    "SESSION_RECOVERY_REQUIRED",
                    "materializing session has an unexpected tombstone",
                ));
            }
            revalidate_record(sessions, capability)?;
        }
        SessionPayload::Tombstoned {
            root_name,
            tombstone_name,
            root_identity,
        } => {
            ensure_record_container(sessions, &capability.record)?;
            let root = cstring(root_name.as_bytes(), "session root")?;
            let tombstone = cstring(tombstone_name.as_bytes(), "session tombstone")?;
            let root_entry = entry_identity_if_present(sessions.as_raw_fd(), &root)?;
            let tombstone_entry = entry_identity_if_present(sessions.as_raw_fd(), &tombstone)?;
            let authorized = match (root_entry, tombstone_entry) {
                (Some(root), None) if root.same_node(*root_identity) => {
                    let _ = open_authorized_root(
                        sessions,
                        &capability.record,
                        root_name,
                        *root_identity,
                    )?;
                    true
                }
                (None, Some(tombstone)) if tombstone.same_node(*root_identity) => {
                    let _ = open_authorized_root(
                        sessions,
                        &capability.record,
                        tombstone_name,
                        *root_identity,
                    )?;
                    true
                }
                (None, None) => true,
                _ => false,
            };
            if !authorized {
                return Err(Error::new(
                    "SESSION_RECOVERY_REQUIRED",
                    "tombstoned session roots are not record-authorized",
                ));
            }
            revalidate_record(sessions, capability)?;
        }
    }
    Ok(())
}

fn load_ready_session(
    sessions: &File,
    sessions_path: &Path,
    authority: &Authority,
    record: &SessionRecord,
) -> Result<ReadySession, Error> {
    let SessionPayload::Ready {
        root_name: record_root,
        root_identity,
        common_identity,
        worktree: worktree_receipt,
        ..
    } = &record.payload
    else {
        return Err(Error::new("SESSION_CORRUPT", "session record is not READY"));
    };
    if !record_authority_matches(record, authority)
        || record_root != &root_name(&record.sid)
        || worktree_receipt.source != record.template
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session record has invalid authority or receipt bindings",
        ));
    }
    let name = cstring(record_root.as_bytes(), "session root")?;
    let root = storage::open_directory_at(sessions.as_raw_fd(), &name)?;
    if !Identity::from_file(&root)?.same_node(*root_identity)
        || !storage::identity_at(sessions.as_raw_fd(), &name)?.same_node(*root_identity)
        || !storage::private_directory(*root_identity)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session root binding changed",
        ));
    }
    let root_path = sessions_path.join(record_root);
    bind_path(&root_path, &root, "session root")?;
    let worktree_path = root_path.join("worktree");
    let common_path = root_path.join("common.git");
    let worktree = storage::open_directory_at(root.as_raw_fd(), c"worktree")?;
    let common = storage::open_directory_at(root.as_raw_fd(), c"common.git")?;
    let container_identity = Identity::from_file(sessions)?;
    let worktree_identity = Identity::from_file(&worktree)?;
    if !container_identity.same_node(record.container_identity)
        || !storage::private_directory(container_identity)
        || storage::volume_id(sessions)? != record.volume
        || storage::volume_id(&root)? != record.volume
        || storage::volume_id(&common)? != record.volume
        || storage::volume_id(&worktree)? != record.volume
        || !common_identity.same_node(Identity::from_file(&common)?)
        || !storage::private_directory(*common_identity)
        || !worktree_receipt.destination.same_node(worktree_identity)
        || !owned_worktree(worktree_identity)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session receipts no longer match their stable bindings",
        ));
    }
    bind_path(&worktree_path, &worktree, "linked worktree")?;
    bind_path(&common_path, &common, "private common-dir")?;
    verify_runtime_topology(&common, &common_path, &worktree, &worktree_path, authority)?;
    if !Identity::from_file(&root)?.same_node(*root_identity)
        || !storage::identity_at(sessions.as_raw_fd(), &name)?.same_node(*root_identity)
        || !Identity::from_file(&common)?.same_node(*common_identity)
        || !storage::identity_at(root.as_raw_fd(), c"common.git")?.same_node(*common_identity)
        || !Identity::from_file(&worktree)?.same_node(worktree_identity)
        || !storage::identity_at(root.as_raw_fd(), c"worktree")?.same_node(worktree_identity)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "READY session topology changed while validating descriptor bindings",
        ));
    }
    Ok(ReadySession {
        root,
        root_name: name,
        root_identity: *root_identity,
        root_path,
        worktree_path,
    })
}

fn record_authority_matches(record: &SessionRecord, authority: &Authority) -> bool {
    record.authority_path == authority::hex(authority.canonical.as_os_str().as_bytes())
        && record.authority_identity.same_node(authority.identity)
}

fn owned_worktree(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode == 0o755
        && identity.nlink >= 2
}

fn verify_runtime_topology(
    common: &File,
    common_path: &Path,
    worktree: &File,
    worktree_path: &Path,
    authority: &Authority,
) -> Result<(), Error> {
    let dot_git = read_regular_at(worktree, c".git", "linked-worktree metadata")?;
    let gitdir = dot_git
        .strip_prefix(b"gitdir: ")
        .and_then(|value| value.strip_suffix(b"\n"))
        .filter(|value| !value.is_empty() && !value.contains(&b'\n') && !value.contains(&b'\r'))
        .ok_or_else(|| Error::new("SESSION_CORRUPT", "linked .git pointer is invalid"))?;
    let mut worktrees_prefix = common_path
        .join("worktrees")
        .as_os_str()
        .as_bytes()
        .to_vec();
    worktrees_prefix.push(b'/');
    let metadata_name = gitdir
        .strip_prefix(worktrees_prefix.as_slice())
        .filter(|name| !name.is_empty() && !name.contains(&b'/'))
        .ok_or_else(|| {
            Error::new(
                "SESSION_CORRUPT",
                "linked .git pointer leaves private common-dir",
            )
        })?;
    let common_identity = Identity::from_file(common)?;
    let common_volume = storage::volume_id(common)?;
    let worktrees = storage::open_directory_at(common.as_raw_fd(), c"worktrees")?;
    let worktrees_identity = Identity::from_file(&worktrees)?;
    if !private_git_metadata_directory(worktrees_identity)
        || worktrees_identity.dev != common_identity.dev
        || storage::volume_id(&worktrees)? != common_volume
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "private Git worktree registry is not an owned same-volume directory",
        ));
    }
    let metadata_name = cstring(metadata_name, "private worktree metadata")?;
    let metadata = storage::open_directory_at(worktrees.as_raw_fd(), &metadata_name)?;
    let metadata_identity = Identity::from_file(&metadata)?;
    if !private_git_metadata_directory(metadata_identity)
        || metadata_identity.dev != worktrees_identity.dev
        || storage::volume_id(&metadata)? != common_volume
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "private Git worktree metadata is not an owned same-volume directory",
        ));
    }
    let expected_gitdir = worktree_path.join(".git");
    let mut expected_gitdir_bytes = expected_gitdir.as_os_str().as_bytes().to_vec();
    expected_gitdir_bytes.push(b'\n');
    if read_regular_at(&metadata, c"gitdir", "private worktree gitdir")? != expected_gitdir_bytes {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "private Git worktree metadata does not point to the managed worktree",
        ));
    }
    if read_regular_at(&metadata, c"commondir", "private worktree commondir")? != b"../..\n" {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "private Git worktree commondir is not the canonical relative binding",
        ));
    }
    let metadata_parent = storage::open_directory_at(metadata.as_raw_fd(), c"..")?;
    let common_from_metadata = storage::open_directory_at(metadata_parent.as_raw_fd(), c"..")?;
    if !Identity::from_file(&metadata_parent)?.same_node(worktrees_identity)
        || !Identity::from_file(&common_from_metadata)?.same_node(common_identity)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "private Git worktree commondir does not resolve to the verified common-dir",
        ));
    }
    let objects = storage::open_directory_at(common.as_raw_fd(), c"objects")?;
    let info = storage::open_directory_at(objects.as_raw_fd(), c"info")?;
    let mut expected_alternate = authority
        .canonical
        .join("objects")
        .as_os_str()
        .as_bytes()
        .to_vec();
    expected_alternate.push(b'\n');
    if read_regular_at(&info, c"alternates", "private alternate")? != expected_alternate {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "private object alternate no longer matches the authority",
        ));
    }
    if !storage::identity_at(common.as_raw_fd(), c"worktrees")?.same_node(worktrees_identity)
        || !Identity::from_file(&worktrees)?.same_node(worktrees_identity)
        || !storage::identity_at(worktrees.as_raw_fd(), &metadata_name)?
            .same_node(metadata_identity)
        || !Identity::from_file(&metadata)?.same_node(metadata_identity)
        || !private_git_metadata_directory(worktrees_identity)
        || !private_git_metadata_directory(metadata_identity)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "private Git worktree topology changed while validating runtime metadata",
        ));
    }
    Ok(())
}

fn private_git_metadata_directory(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode & 0o022 == 0
        && identity.nlink >= 2
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
    let mut args = vec![
        OsString::from("init"),
        OsString::from("--bare"),
        OsString::from("--quiet"),
        object_format,
        template,
        common.as_os_str().to_os_string(),
    ];
    if authority.ref_format != "files" {
        let mut ref_format = OsString::from("--ref-format=");
        ref_format.push(&authority.ref_format);
        args.insert(4, ref_format);
    }
    require_clean(
        git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Isolated).map_err(git_error)?,
        "initialize private common-dir",
    )
}

fn write_alternate(
    common: &File,
    authority_objects: &[u8],
    _record: &SessionRecord,
) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| session_checkpoint("create", _record, stage);
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
    #[cfg(git_vws_m4_checkpoint)]
    m4("alternate-file-synced")?;
    info.sync_all()
        .map_err(|error| Error::io("SESSION_IO_FAILED", "cannot sync alternate parent", error))?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("alternate-parent-synced")?;
    Ok(())
}

fn configure_private_common(common: &Path, _record: &SessionRecord) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| session_checkpoint("create", _record, stage);
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
        #[cfg(git_vws_m4_checkpoint)]
        m4(if key == "core.filemode" {
            "filemode-configured"
        } else {
            "symlinks-configured"
        })?;
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
    _record: &SessionRecord,
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
    )?;
    #[cfg(git_vws_m4_checkpoint)]
    session_checkpoint("create", _record, "worktree-added")?;
    Ok(())
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
    let name = decode_hex(&record.name)?;
    let authority_path = authority_path_from_record(record)?;
    if !valid_session_name(&name)
        || !record.authority_identity.directory()
        || record.sid != session_id_for_binding(&authority_path, record.authority_identity, &name)
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record does not prove its authority and name binding",
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
        SessionPayload::Tombstoned {
            root_name: tombstoned_root,
            tombstone_name: tombstone_basename,
            root_identity,
        } => {
            tombstoned_root == &root_name(&record.sid)
                && tombstone_basename == &tombstone_name(&record.sid)
                && storage::private_directory(*root_identity)
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
    _record: &SessionRecord,
) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| session_checkpoint("create", _record, stage);
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
    #[cfg(git_vws_m4_checkpoint)]
    m4("empty-template-unlinked")?;
    parent.sync_all().map_err(|error| {
        Error::io(
            "SESSION_IO_FAILED",
            "cannot sync session root cleanup",
            error,
        )
    })?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("empty-template-parent-synced")?;
    Ok(())
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
    session_id_for_binding(&authority.canonical, authority.identity, name.as_bytes())
}

fn session_id_for_binding(
    authority_path: &Path,
    authority_identity: Identity,
    name: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        b"git-vws/session-id/v1".as_slice(),
        authority_path.as_os_str().as_bytes(),
        &authority_identity.dev.to_be_bytes(),
        &authority_identity.ino.to_be_bytes(),
        &authority_identity.uid.to_be_bytes(),
        name,
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

fn tombstone_name(sid: &str) -> String {
    format!("session-{sid}.tombstone")
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
    valid_lower_hex(value)
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
        let authority_path = PathBuf::from("/git-vws-test-authority");
        let raw_name = b"fixture";
        let sid = session_id_for_binding(&authority_path, directory, raw_name);
        SessionRecord {
            version: 2,
            sid: sid.clone(),
            authority_path: authority::hex(authority_path.as_os_str().as_bytes()),
            authority_identity: directory,
            name: authority::hex(raw_name),
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
        let raw_name = vec![b'n'; 9 * 1024];
        oversized.name = authority::hex(&raw_name);
        let authority_path =
            authority_path_from_record(&oversized).expect("fixture authority path");
        oversized.sid =
            session_id_for_binding(&authority_path, oversized.authority_identity, &raw_name);
        oversized.payload = SessionPayload::Prepared {
            root_name: root_name(&oversized.sid),
        };
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
