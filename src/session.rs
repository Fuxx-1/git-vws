use crate::authority::{self, Authority, Error, Identity, StateRoot};
use crate::git::{self, AuditConfig, Output};
use crate::storage::{self, CowPlan};
use crate::template::{self, MaintenanceReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PublishJournal {
    Idle,
    Prepared {
        txid: String,
        new: String,
        expected_old: Option<String>,
        config_fingerprint: String,
    },
    ObjectsImported {
        txid: String,
        new: String,
        expected_old: Option<String>,
        config_fingerprint: String,
    },
    CasAttempted {
        txid: String,
        new: String,
        expected_old: Option<String>,
        config_fingerprint: String,
    },
    CasCommitted {
        txid: String,
        new: String,
        expected_old: Option<String>,
        config_fingerprint: String,
    },
}

impl Default for PublishJournal {
    fn default() -> Self {
        Self::Idle
    }
}

impl PublishJournal {
    fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    fn state(&self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Prepared { .. } => "PREPARED",
            Self::ObjectsImported { .. } => "OBJECTS_IMPORTED",
            Self::CasAttempted { .. } => "CAS_ATTEMPTED",
            Self::CasCommitted { .. } => "CAS_COMMITTED",
        }
    }

    fn fields(&self) -> Option<(&str, &str, Option<&str>, &str)> {
        match self {
            Self::Idle => None,
            Self::Prepared {
                txid,
                new,
                expected_old,
                config_fingerprint,
            }
            | Self::ObjectsImported {
                txid,
                new,
                expected_old,
                config_fingerprint,
            }
            | Self::CasAttempted {
                txid,
                new,
                expected_old,
                config_fingerprint,
            }
            | Self::CasCommitted {
                txid,
                new,
                expected_old,
                config_fingerprint,
            } => Some((txid, new, expected_old.as_deref(), config_fingerprint)),
        }
    }
}

fn publish_journal_is_idle(journal: &PublishJournal) -> bool {
    journal.is_idle()
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
    #[serde(default, skip_serializing_if = "publish_journal_is_idle")]
    journal: PublishJournal,
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
    publish_state: &'static str,
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

struct SessionCensus {
    reachable_templates: BTreeSet<String>,
    capabilities: Vec<CensusCapability>,
    temporaries: Vec<Vec<u8>>,
    report: MaintenanceReport,
}

struct CensusCapability {
    capability: RecordCapability,
    private_objects: Option<PrivateObjectPlan>,
}

#[derive(Eq, PartialEq)]
struct PrivateObjectPlan {
    objects_identity: Identity,
    authority_objects: AuthorityObjectsPlan,
    pack_present: bool,
    fanouts: Vec<PrivateFanoutPlan>,
}

#[derive(Eq, PartialEq)]
struct AuthorityObjectsPlan {
    identity: Identity,
    volume: String,
    entries: Vec<AuthorityObjectPlan>,
}

#[derive(Eq, PartialEq)]
struct AuthorityObjectPlan {
    name: Vec<u8>,
    identity: Identity,
    children: Vec<(Vec<u8>, Identity)>,
}

#[derive(Eq, PartialEq)]
struct PrivateFanoutPlan {
    name: Vec<u8>,
    identity: Identity,
    authority_identity: Option<Identity>,
    loose: Vec<PrivateLoosePlan>,
}

#[derive(Eq, PartialEq)]
struct PrivateLoosePlan {
    name: Vec<u8>,
    identity: Identity,
    action: LooseAction,
}

#[derive(Eq, PartialEq)]
enum LooseAction {
    Remove { authority_identity: Identity },
    Retain,
}

#[derive(Serialize)]
struct MaintenanceLine {
    version: u8,
    kind: &'static str,
    scope: &'static str,
    record_name_hex: String,
    path_hex: String,
    state: &'static str,
    code: &'static str,
}

#[derive(Serialize)]
struct MaintenanceSummary {
    version: u8,
    kind: &'static str,
    items: usize,
    findings: usize,
    recovery_required: bool,
}

struct SessionContext {
    authority: Authority,
    sessions: File,
    sessions_path: PathBuf,
}

fn maintenance_context(
    sessions: &File,
    sessions_path: &Path,
    record: &SessionRecord,
) -> Result<SessionContext, Error> {
    Ok(SessionContext {
        authority: authority_from_record(record)?,
        sessions: sessions.try_clone().map_err(|error| {
            Error::io(
                "SESSION_RECOVERY_REQUIRED",
                "cannot retain session container for maintenance",
                error,
            )
        })?,
        sessions_path: sessions_path.to_path_buf(),
    })
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

pub(crate) fn doctor() -> Result<(), Error> {
    maintain(false)
}

pub(crate) fn gc() -> Result<(), Error> {
    maintain(true)
}

fn maintain(cleanup: bool) -> Result<(), Error> {
    let mut report = MaintenanceReport::default();
    let state = match authority::open_existing_state() {
        Ok(state) => state,
        Err(error)
            if error.code == "STATE_UNAVAILABLE" && error.detail == "state root does not exist" =>
        {
            return finish_maintenance(report, cleanup);
        }
        Err(_) => {
            report.recovery("state", b"", b"", "CORRUPT");
            return finish_maintenance(report, cleanup);
        }
    };
    if !scan_state_root(&state, &mut report) {
        return finish_maintenance(report, cleanup);
    }
    let templates = maintenance_container(&state, b"templates", &mut report);
    let sessions = maintenance_container(&state, b"sessions", &mut report);
    let (Some(templates), Some(sessions)) = (templates.as_ref(), sessions.as_ref()) else {
        if templates.is_none() && sessions.is_none() {
            return finish_maintenance(report, cleanup);
        }
        if templates.is_none() {
            report.recovery("state", b"", b"templates", "ABSENT");
        }
        if sessions.is_none() {
            report.recovery("state", b"", b"sessions", "ABSENT");
        }
        return finish_maintenance(report, cleanup);
    };
    let sessions_path = match state.container_path("sessions") {
        Ok(path) => path,
        Err(_) => {
            report.recovery("state", b"", b"sessions", "CORRUPT");
            return finish_maintenance(report, cleanup);
        }
    };
    let mut census = match session_census(templates, sessions, &sessions_path, !cleanup) {
        Ok(census) => census,
        Err(_) => {
            report.recovery("session", b"", b"", "CORRUPT");
            return finish_maintenance(report, cleanup);
        }
    };
    let session_safe = !census.report.recovery_required;
    if !cleanup || !session_safe {
        merge_maintenance(&mut report, &mut census.report);
    }
    let mut template_report = match template::doctor(templates) {
        Ok(template_report) => template_report,
        Err(_) => {
            report.recovery("template", b"", b"", "CORRUPT");
            return finish_maintenance(report, cleanup);
        }
    };
    let template_safe = !template_report.recovery_required;
    if !cleanup || !template_safe {
        merge_maintenance(&mut report, &mut template_report);
    }
    if !cleanup || !session_safe || !template_safe || report.recovery_required {
        return finish_maintenance(report, cleanup);
    }
    let mut template_report = match template::gc(templates, || {
        let census = session_census(templates, sessions, &sessions_path, false)?;
        if !census.report.recovery_required {
            Ok(census.reachable_templates)
        } else {
            Err(Error::new(
                "GC_RECOVERY_REQUIRED",
                "session census cannot prove template reachability",
            ))
        }
    }) {
        Ok(template_report) => template_report,
        Err(_) => {
            report.recovery("template", b"", b"", "CORRUPT");
            return finish_maintenance(report, cleanup);
        }
    };
    merge_maintenance(&mut report, &mut template_report);
    if report.recovery_required {
        return finish_maintenance(report, cleanup);
    }
    let mut session_report = gc_sessions(sessions, &sessions_path, &census);
    merge_maintenance(&mut report, &mut session_report);
    finish_maintenance(report, cleanup)
}

fn maintenance_container(
    state: &StateRoot,
    name: &[u8],
    report: &mut MaintenanceReport,
) -> Option<File> {
    match state.open_container_if_present(name) {
        Ok(container) => container,
        Err(_) => {
            report.recovery("state", b"", name, "CORRUPT");
            None
        }
    }
}

fn scan_state_root(state: &StateRoot, report: &mut MaintenanceReport) -> bool {
    let names = match storage::directory_names(state.root_fd()) {
        Ok(names) => names,
        Err(_) => {
            report.recovery("state", b"", b"", "CORRUPT");
            return false;
        }
    };
    let mut safe = true;
    let mut authority_records = 0_usize;
    for name in names {
        if name == b"templates" || name == b"sessions" {
            continue;
        }
        match authority::is_ignorable_system_metadata(state.root_fd(), &name) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(_) => {
                report.recovery("state", &name, &name, "CORRUPT");
                safe = false;
                continue;
            }
        }
        if !name.starts_with(b".") && name.ends_with(b".record") {
            match authority::validate_authority_record(state, &name) {
                Ok(()) => authority_records += 1,
                Err(_) => {
                    report.recovery("state", &name, &name, "CORRUPT");
                    safe = false;
                }
            }
            continue;
        }
        report.recovery("state", &name, &name, "UNKNOWN");
        safe = false;
    }
    if authority_records == 0 {
        report.recovery("state", b"", b"", "AUTHORITY");
        safe = false;
    }
    safe
}

fn merge_maintenance(report: &mut MaintenanceReport, other: &mut MaintenanceReport) {
    report.recovery_required |= other.recovery_required;
    report.entries.append(&mut other.entries);
}

fn finish_maintenance(mut report: MaintenanceReport, cleanup: bool) -> Result<(), Error> {
    if cleanup && !report.recovery_required {
        #[cfg(git_vws_m4_checkpoint)]
        if crate::m4_checkpoint::checkpoint("gc", "-", "-", "return").is_err() {
            report.recovery("gc", b"", b"", "RETURN");
        }
    }
    write_maintenance(&mut report)?;
    if report.recovery_required {
        Err(Error::new(
            if cleanup {
                "GC_RECOVERY_REQUIRED"
            } else {
                "DOCTOR_RECOVERY_REQUIRED"
            },
            "maintenance found state that cannot be safely reclaimed",
        ))
    } else {
        Ok(())
    }
}

fn write_maintenance(report: &mut MaintenanceReport) -> Result<(), Error> {
    report.entries.sort_by(|left, right| {
        left.scope
            .cmp(right.scope)
            .then_with(|| left.record_name.cmp(&right.record_name))
            .then_with(|| left.path_name.cmp(&right.path_name))
            .then_with(|| left.state.cmp(right.state))
            .then_with(|| left.code.cmp(right.code))
    });
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    let mut items = 0_usize;
    let mut findings = 0_usize;
    for entry in &report.entries {
        let item = entry.code != "RECOVERY_REQUIRED";
        if item {
            items += 1;
        } else {
            findings += 1;
        }
        serde_json::to_writer(
            &mut output,
            &MaintenanceLine {
                version: 1,
                kind: if item { "item" } else { "finding" },
                scope: entry.scope,
                record_name_hex: authority::hex(&entry.record_name),
                path_hex: authority::hex(&entry.path_name),
                state: entry.state,
                code: entry.code,
            },
        )
        .map_err(|error| {
            Error::new(
                "SESSION_IO_FAILED",
                format!("cannot encode maintenance record: {error}"),
            )
        })?;
        output.write_all(b"\n").map_err(|error| {
            Error::io(
                "SESSION_IO_FAILED",
                "cannot write maintenance record",
                error,
            )
        })?;
    }
    serde_json::to_writer(
        &mut output,
        &MaintenanceSummary {
            version: 1,
            kind: "summary",
            items,
            findings,
            recovery_required: report.recovery_required,
        },
    )
    .map_err(|error| {
        Error::new(
            "SESSION_IO_FAILED",
            format!("cannot encode maintenance summary: {error}"),
        )
    })?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|error| {
            Error::io(
                "SESSION_IO_FAILED",
                "cannot flush maintenance output",
                error,
            )
        })
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
    ensure_publish_idle(&capability.record)?;
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

pub(crate) fn publish(
    repository: &Path,
    raw_name: Option<OsString>,
    name_hex: Option<String>,
) -> Result<String, Error> {
    let name = selected_name(raw_name, name_hex)?;
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
    acquire_lease(&ready.root, true)?;
    let capability = revalidate_ready_lease(&context, &capability, &ready)?;
    let target = publish_target(&capability.record)?;
    match &capability.record.journal {
        PublishJournal::CasAttempted { .. } => {
            let _ = frozen_publish_fields(&context.authority, &capability.record, &target)?;
            return Err(Error::new(
                "PUBLISH_RECOVERY_REQUIRED",
                "a publish compare-and-swap was attempted and cannot be replayed",
            ));
        }
        PublishJournal::CasCommitted { .. } => {
            return finalize_committed_publish(&context, capability, &target);
        }
        PublishJournal::Idle
        | PublishJournal::Prepared { .. }
        | PublishJournal::ObjectsImported { .. } => {}
    }
    let common_path = ready.root_path.join("common.git");
    match capability.record.journal.clone() {
        PublishJournal::Idle => {
            let config_fingerprint = audit_authority_config(&context.authority)?;
            validate_publish_target(&context.authority, &target)?;
            let expected_old = authority_target_commit(&context.authority, &target)?;
            let new =
                private_target_commit(&common_path, &target, &context.authority.object_format)?;
            ensure_publish_relation(&common_path, expected_old.as_deref(), &new)?;
            let txid = publish_txid(
                &context.authority,
                &capability.record,
                &target,
                expected_old.as_deref(),
                &new,
                &config_fingerprint,
            );
            if expected_old.as_deref() == Some(new.as_str()) {
                verify_authority_closure(&context.authority, &new)?;
                let current_config = audit_authority_config(&context.authority)?;
                ensure_authority_config(&current_config, &config_fingerprint)?;
                validate_publish_target(&context.authority, &target)?;
                ensure_private_target(
                    &common_path,
                    &target,
                    &context.authority.object_format,
                    &new,
                )?;
                ensure_authority_expected_old(&context.authority, &target, Some(&new))?;
                #[cfg(git_vws_m4_checkpoint)]
                publish_checkpoint(&capability.record.sid, &txid, "same-return")
                    .map_err(publish_recovery)?;
                return Ok(publish_success(&capability.record, &new));
            }
            ensure_publish_target_unchecked_out(&context.authority, &target)?;
            ensure_authority_expected_old(&context.authority, &target, expected_old.as_deref())?;
            let prepared = replace_publish_journal(
                &context.sessions,
                &capability,
                PublishJournal::Prepared {
                    txid: txid.clone(),
                    new,
                    expected_old,
                    config_fingerprint,
                },
                &txid,
                "prepared",
            )
            .map_err(publish_recovery)?;
            publish_prepared(&context, &ready, prepared, &target, &common_path)
        }
        PublishJournal::Prepared { .. } => {
            publish_prepared(&context, &ready, capability, &target, &common_path)
        }
        PublishJournal::ObjectsImported { .. } => {
            publish_objects_imported(&context, &ready, capability, &target, &common_path)
        }
        PublishJournal::CasAttempted { .. } | PublishJournal::CasCommitted { .. } => {
            unreachable!("publish journal state was handled before target access")
        }
    }
}

fn publish_prepared(
    context: &SessionContext,
    ready: &ReadySession,
    capability: RecordCapability,
    target: &OsStr,
    common_path: &Path,
) -> Result<String, Error> {
    let (txid, new, expected_old, config_fingerprint) =
        frozen_publish_fields(&context.authority, &capability.record, target)?;
    let current_config = audit_authority_config(&context.authority)?;
    ensure_authority_config(&current_config, &config_fingerprint)?;
    validate_publish_target(&context.authority, target)?;
    ensure_publish_target_unchecked_out(&context.authority, target)?;
    ensure_private_target(common_path, target, &context.authority.object_format, &new)?;
    ensure_publish_relation(common_path, expected_old.as_deref(), &new)?;
    if authority_target_commit(&context.authority, target)?.as_deref() != expected_old.as_deref() {
        return abort_publish_conflict(&context.sessions, &capability, &txid);
    }
    import_publish_objects(&context.authority, common_path, &new)?;
    #[cfg(git_vws_m4_checkpoint)]
    publish_checkpoint(&capability.record.sid, &txid, "object-fetch-returned")
        .map_err(publish_recovery)?;
    let current_config = audit_authority_config(&context.authority)?;
    ensure_authority_config(&current_config, &config_fingerprint)?;
    ensure_private_target(common_path, target, &context.authority.object_format, &new)?;
    verify_authority_closure(&context.authority, &new)?;
    let objects_imported = replace_publish_journal(
        &context.sessions,
        &capability,
        PublishJournal::ObjectsImported {
            txid: txid.clone(),
            new,
            expected_old,
            config_fingerprint,
        },
        &txid,
        "objects-imported",
    )
    .map_err(publish_recovery)?;
    publish_objects_imported(context, ready, objects_imported, target, common_path)
}

fn publish_objects_imported(
    context: &SessionContext,
    _ready: &ReadySession,
    capability: RecordCapability,
    target: &OsStr,
    common_path: &Path,
) -> Result<String, Error> {
    let (txid, new, expected_old, config_fingerprint) =
        frozen_publish_fields(&context.authority, &capability.record, target)?;
    let current_config = audit_authority_config(&context.authority)?;
    ensure_authority_config(&current_config, &config_fingerprint)?;
    validate_publish_target(&context.authority, target)?;
    ensure_private_target(common_path, target, &context.authority.object_format, &new)?;
    ensure_publish_relation(common_path, expected_old.as_deref(), &new)?;
    verify_authority_closure(&context.authority, &new)?;
    if authority_target_commit(&context.authority, target)?.as_deref() != expected_old.as_deref() {
        return abort_publish_conflict(&context.sessions, &capability, &txid);
    }
    ensure_publish_target_unchecked_out(&context.authority, target)?;
    let attempted = replace_publish_journal(
        &context.sessions,
        &capability,
        PublishJournal::CasAttempted {
            txid: txid.clone(),
            new: new.clone(),
            expected_old: expected_old.clone(),
            config_fingerprint: config_fingerprint.clone(),
        },
        &txid,
        "cas-attempted",
    )
    .map_err(publish_recovery)?;
    let update = update_publish_ref(&context.authority, target, &new, expected_old.as_deref())
        .map_err(publish_recovery)?;
    if update.status.success() {
        #[cfg(git_vws_m4_checkpoint)]
        publish_checkpoint(&attempted.record.sid, &txid, "cas-child-returned-success")
            .map_err(publish_recovery)?;
        let committed = replace_publish_journal(
            &context.sessions,
            &attempted,
            PublishJournal::CasCommitted {
                txid: txid.clone(),
                new: new.clone(),
                expected_old,
                config_fingerprint,
            },
            &txid,
            "cas-committed",
        )
        .map_err(publish_committed_recovery)?;
        return finalize_committed_publish(context, committed, target);
    }
    #[cfg(git_vws_m4_checkpoint)]
    publish_checkpoint(&attempted.record.sid, &txid, "cas-child-returned-nonzero")
        .map_err(publish_recovery)?;
    Err(Error::new(
        "PUBLISH_RECOVERY_REQUIRED",
        "authority rejected the publish compare-and-swap and it cannot be replayed",
    ))
}

fn finalize_committed_publish(
    context: &SessionContext,
    capability: RecordCapability,
    target: &OsStr,
) -> Result<String, Error> {
    let (txid, new, _, _) = frozen_publish_fields(&context.authority, &capability.record, target)?;
    let record = finish_publish_journal(&context.sessions, &capability, &txid, Some(new.clone()))
        .map_err(publish_committed_recovery)?;
    #[cfg(git_vws_m4_checkpoint)]
    publish_checkpoint(&record.record.sid, &txid, "return").map_err(publish_committed_recovery)?;
    Ok(publish_success(&record.record, &new))
}

fn publish_success(record: &SessionRecord, new: &str) -> String {
    format!("published {} {new}", record.target)
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
    ensure_publish_idle(&capability.record)?;
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
    complete_tombstone(&context, &tombstoned, "remove")?;
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
        journal: PublishJournal::Idle,
    };
    if let Some(existing) = optional_record(&sessions, &record_name, &authority)? {
        ensure_publish_idle(&existing.record)?;
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
    authority: &Authority,
    template: &template::Template,
    root_path: &Path,
    target: &OsStr,
    base: &str,
) -> Result<PathBuf, Error> {
    let tree_timeout = template::tree_operation_timeout(template.sealed.manifest.entries);
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
        &transaction.capability().record.template_key,
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
    init_private_common(authority, &common_path, &empty_template_path, tree_timeout)?;
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
    configure_private_common(&common_path, &transaction.capability().record, tree_timeout)?;

    let worktree_path = root_path.join("worktree");
    bind_path(root_path, transaction.root(), "session root")?;
    add_linked_worktree(
        &common_path,
        &worktree_path,
        target,
        base,
        &transaction.capability().record,
        tree_timeout,
    )?;
    let worktree = storage::open_directory_at(transaction.root().as_raw_fd(), c"worktree")?;
    let worktree_identity = Identity::from_file(&worktree)?;
    if !owned_directory(worktree_identity) {
        return Err(Error::new(
            "SESSION_IO_FAILED",
            "linked worktree is not an owned directory",
        ));
    }
    if Identity::from_file(&template.root)? != template.sealed.root {
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
        source: &template.root,
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
    read_tree(&worktree_path, tree_timeout)?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("read-tree-complete")?;
    status_clean(&worktree_path, tree_timeout)?;
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
        git: git_metadata(
            &common,
            &common_path,
            &worktree_path,
            &worktree,
            target,
            tree_timeout,
        )?,
    };
    let ready_bytes = encode_record(&materializing)?;
    let capability = replace_record_capability(
        transaction.sessions,
        transaction.capability(),
        &ready_bytes,
        "create",
        &transaction.capability().record.template_key,
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
        publish_state: record.journal.state(),
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

fn ensure_publish_idle(record: &SessionRecord) -> Result<(), Error> {
    if record.journal.is_idle() {
        return Ok(());
    }
    let code = match &record.journal {
        PublishJournal::CasCommitted { .. } => "PUBLISH_COMMITTED_RECOVERY_REQUIRED",
        _ => "PUBLISH_RECOVERY_REQUIRED",
    };
    Err(Error::new(
        code,
        "session publish journal must be recovered before another lifecycle operation",
    ))
}

fn frozen_publish_fields(
    authority: &Authority,
    record: &SessionRecord,
    target: &OsStr,
) -> Result<(String, String, Option<String>, String), Error> {
    let (txid, new, expected_old, config_fingerprint) =
        record.journal.fields().ok_or_else(|| {
            Error::new(
                "SESSION_CORRUPT",
                "session record has no frozen publish journal fields",
            )
        })?;
    if txid
        != publish_txid(
            authority,
            record,
            target,
            expected_old,
            new,
            config_fingerprint,
        )
    {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "publish journal transaction does not match its record binding",
        ));
    }
    Ok((
        txid.to_owned(),
        new.to_owned(),
        expected_old.map(str::to_owned),
        config_fingerprint.to_owned(),
    ))
}

fn publish_target(record: &SessionRecord) -> Result<OsString, Error> {
    let target = decode_hex(&record.target)?;
    if target.is_empty() || target.contains(&0) {
        return Err(Error::new(
            "SESSION_CORRUPT",
            "session record target is not a usable Git reference name",
        ));
    }
    Ok(OsString::from_vec(target))
}

fn publish_txid(
    authority: &Authority,
    record: &SessionRecord,
    target: &OsStr,
    expected_old: Option<&str>,
    new: &str,
    config_fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    let expected_old = expected_old.unwrap_or("-");
    for field in [
        b"git-vws/publish-id/v1".as_slice(),
        authority.canonical.as_os_str().as_bytes(),
        &authority.identity.dev.to_be_bytes(),
        &authority.identity.ino.to_be_bytes(),
        &authority.identity.uid.to_be_bytes(),
        &authority.identity.mode.to_be_bytes(),
        &authority.identity.kind.to_be_bytes(),
        &authority.identity.nlink.to_be_bytes(),
        record.sid.as_bytes(),
        record.template_key.as_bytes(),
        target.as_bytes(),
        expected_old.as_bytes(),
        new.as_bytes(),
        config_fingerprint.as_bytes(),
    ] {
        lp(&mut hasher, field);
    }
    authority::hex(&hasher.finalize())
}

fn replace_publish_journal(
    sessions: &File,
    expected: &RecordCapability,
    journal: PublishJournal,
    txid: &str,
    stage: &'static str,
) -> Result<RecordCapability, Error> {
    let mut record = expected.record.clone();
    record.journal = journal;
    let bytes = encode_record(&record)?;
    replace_record_capability(sessions, expected, &bytes, "publish", txid, stage)
}

fn abort_publish_conflict<T>(
    sessions: &File,
    expected: &RecordCapability,
    txid: &str,
) -> Result<T, Error> {
    #[cfg(git_vws_m4_checkpoint)]
    let sid = expected.record.sid.clone();
    replace_publish_journal(
        sessions,
        expected,
        PublishJournal::Idle,
        txid,
        "conflict-aborted",
    )
    .map_err(publish_recovery)?;
    #[cfg(git_vws_m4_checkpoint)]
    publish_checkpoint(&sid, txid, "conflict-return").map_err(publish_recovery)?;
    Err(Error::new(
        "PUBLISH_CONFLICT",
        "authority target changed before the publish compare-and-swap",
    ))
}

fn finish_publish_journal(
    sessions: &File,
    expected: &RecordCapability,
    txid: &str,
    expected_old: Option<String>,
) -> Result<RecordCapability, Error> {
    let mut record = expected.record.clone();
    record.expected_old = expected_old;
    record.journal = PublishJournal::Idle;
    let bytes = encode_record(&record)?;
    replace_record_capability(
        sessions,
        expected,
        &bytes,
        "publish",
        txid,
        "idle-finalized",
    )
}

fn publish_recovery(error: Error) -> Error {
    Error::new(
        "PUBLISH_RECOVERY_REQUIRED",
        format!(
            "publish journal outcome requires recovery: {}",
            error.detail
        ),
    )
}

fn publish_committed_recovery(error: Error) -> Error {
    Error::new(
        "PUBLISH_COMMITTED_RECOVERY_REQUIRED",
        format!("publish commit outcome requires recovery: {}", error.detail),
    )
}

#[cfg(git_vws_m4_checkpoint)]
fn publish_checkpoint(sid: &str, txid: &str, stage: &str) -> Result<(), Error> {
    crate::m4_checkpoint::checkpoint("publish", sid, txid, stage)
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

fn session_recovery(detail: &'static str) -> Error {
    Error::new("SESSION_RECOVERY_REQUIRED", detail)
}

fn bound_record_error(error: Error, boundary: &str) -> Error {
    record_binding_recovery(error, boundary)
}

fn replace_record_capability(
    sessions: &File,
    expected: &RecordCapability,
    bytes: &[u8],
    _operation: &'static str,
    _checkpoint_key: &str,
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
        (_operation, &expected.record.sid, _checkpoint_key, _stage),
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
        || !Identity::from_file(&ready.common)?.same_node(ready.common_identity)
        || !Identity::from_file(&checked.common)?.same_node(ready.common_identity)
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
    replace_record_capability(
        sessions,
        expected,
        &bytes,
        "remove",
        &expected.record.template_key,
        "tombstoned-record",
    )
}

fn complete_tombstone(
    context: &SessionContext,
    expected: &RecordCapability,
    operation: &'static str,
) -> Result<(), Error> {
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
            return remove_record_capability(&context.sessions, &current, operation);
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
        operation,
    )?;
    let current = revalidate_record(&context.sessions, &current)?;
    if operation == "gc" {
        storage::remove_owned_tree_gc(&context.sessions, &tombstone, *root_identity)?;
    } else {
        storage::remove_owned_tree(&context.sessions, &tombstone, *root_identity)?;
    }
    #[cfg(git_vws_m4_checkpoint)]
    session_checkpoint(
        operation,
        &current.record,
        tombstone_stage(operation, "owned-tree-removed"),
    )?;
    remove_record_capability(&context.sessions, &current, operation)
}

fn promote_tombstone(
    sessions: &File,
    root: &CStr,
    tombstone: &CStr,
    expected: Identity,
    _record: &SessionRecord,
    _operation: &'static str,
) -> Result<(), Error> {
    match (
        entry_identity_if_present(sessions.as_raw_fd(), root)?,
        entry_identity_if_present(sessions.as_raw_fd(), tombstone)?,
    ) {
        (Some(root_identity), None) if root_identity.same_node(expected) => {
            match authority::rename_no_replace(sessions.as_raw_fd(), root, tombstone) {
                Ok(()) => {
                    #[cfg(git_vws_m4_checkpoint)]
                    session_checkpoint(
                        _operation,
                        _record,
                        tombstone_stage(_operation, "tombstone-renamed"),
                    )?;
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
            session_checkpoint(
                _operation,
                _record,
                tombstone_stage(_operation, "tombstone-parent-synced"),
            )?;
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
fn tombstone_stage(operation: &str, stage: &'static str) -> &'static str {
    if operation != "gc" {
        return stage;
    }
    match stage {
        "tombstone-renamed" => "session-tombstone-renamed",
        "tombstone-parent-synced" => "session-tombstone-parent-synced",
        "owned-tree-removed" => "session-owned-tree-removed",
        _ => stage,
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
    ensure_private_refs_safe(&ready.common, &ready.root_path, record)?;
    ensure_private_object_store_empty(&ready.common)?;
    ensure_no_unreachable_private_closure(&ready.common, &ready.root_path, record)?;
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
    common: File,
    common_identity: Identity,
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

fn session_census(
    templates: &File,
    sessions: &File,
    sessions_path: &Path,
    report_temporary: bool,
) -> Result<SessionCensus, Error> {
    let names = storage::directory_names(sessions.as_raw_fd())?;
    let mut census = SessionCensus {
        reachable_templates: BTreeSet::new(),
        capabilities: Vec::new(),
        temporaries: Vec::new(),
        report: MaintenanceReport::default(),
    };
    let mut authorized = BTreeSet::new();
    for name in &names {
        if !session_record_name(name) {
            continue;
        }
        authorized.insert(name.clone());
        match read_record_capability(sessions, name) {
            Ok(capability) => {
                match &capability.record.payload {
                    SessionPayload::Prepared { .. } => {}
                    SessionPayload::Materializing { root_name, .. }
                    | SessionPayload::Ready { root_name, .. } => {
                        authorized.insert(root_name.as_bytes().to_vec());
                    }
                    SessionPayload::Tombstoned {
                        root_name,
                        tombstone_name,
                        ..
                    } => {
                        authorized.insert(root_name.as_bytes().to_vec());
                        authorized.insert(tombstone_name.as_bytes().to_vec());
                    }
                }
                let state = match capability.record.payload {
                    SessionPayload::Prepared { .. } | SessionPayload::Materializing { .. } => {
                        "CREATING"
                    }
                    SessionPayload::Ready { .. } => "READY",
                    SessionPayload::Tombstoned { .. } => "TOMBSTONED",
                };
                let private_objects: Result<Option<PrivateObjectPlan>, Error> = (|| {
                    template::validate_session_template(
                        templates,
                        &capability.record.template_key,
                        &capability.record.template,
                    )?;
                    let authority = authority_from_record(&capability.record)?;
                    if !matches!(capability.record.payload, SessionPayload::Ready { .. }) {
                        diagnose_list_record(sessions, sessions_path, &authority, &capability)?;
                        return Ok(None);
                    }
                    let ready =
                        load_ready_capability(sessions, sessions_path, &authority, &capability)?;
                    let plan =
                        classify_private_objects(&ready.common, &authority, &capability.record)?;
                    revalidate_record(sessions, &capability)?;
                    Ok(Some(plan))
                })(
                );
                if private_objects.is_ok() {
                    census
                        .reachable_templates
                        .insert(capability.record.template_key.clone());
                }
                if private_objects.is_err() {
                    census.report.recovery("session", name, name, state);
                } else if !capability.record.journal.is_idle() {
                    census.report.recovery("session", name, name, "PUBLISH");
                } else {
                    census.report.entry(
                        "session",
                        name,
                        name,
                        state,
                        if matches!(capability.record.payload, SessionPayload::Tombstoned { .. }) {
                            "PENDING"
                        } else {
                            "RETAINED"
                        },
                    );
                }
                census.capabilities.push(CensusCapability {
                    capability,
                    private_objects: private_objects.ok().flatten(),
                });
            }
            Err(_) => {
                census.report.recovery("session", name, name, "CORRUPT");
            }
        }
    }
    for name in names {
        if authorized.contains(&name) {
            continue;
        }
        if authority::is_ignorable_system_metadata(sessions.as_raw_fd(), &name)? {
            continue;
        }
        if name.starts_with(b".") && name.ends_with(b".tmp") {
            match session_predecessor_temporary(sessions, &name) {
                Ok(_) => {
                    census.temporaries.push(name.clone());
                    if report_temporary {
                        census
                            .report
                            .entry("session", &name, &name, "TMP", "RETAINED");
                    }
                }
                Err(_) => {
                    census.report.recovery("session", &name, &name, "TMP");
                }
            }
        } else {
            census.report.recovery("session", &name, &name, "UNKNOWN");
        }
    }
    Ok(census)
}

fn session_record_name(name: &[u8]) -> bool {
    name.starts_with(b"session-") && name.ends_with(b".record")
}

fn session_predecessor_temporary(
    sessions: &File,
    name: &[u8],
) -> Result<(RecordCapability, authority::RecordTxnTemporary), Error> {
    let temporary =
        authority::record_txn_temporary(sessions, name, MAX_RECORD)?.ok_or_else(|| {
            Error::new(
                "SESSION_RECOVERY_REQUIRED",
                "temporary session record basename is not a RecordTxn predecessor",
            )
        })?;
    if !session_record_name(&temporary.final_name) {
        return Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "temporary record does not name a session record",
        ));
    }
    let previous =
        record_capability_from_binding(temporary.final_name.clone(), temporary.binding.clone())?;
    let current = read_record_capability(sessions, &temporary.final_name)?;
    if session_precedes(&previous.record, &current.record) {
        Ok((current, temporary))
    } else {
        Err(Error::new(
            "SESSION_RECOVERY_REQUIRED",
            "temporary session record is not the direct predecessor of its current record",
        ))
    }
}

fn session_precedes(previous: &SessionRecord, current: &SessionRecord) -> bool {
    if !matches_existing(previous, current)
        || !previous.journal.is_idle()
        || !current.journal.is_idle()
    {
        return false;
    }
    match (&previous.payload, &current.payload) {
        (
            SessionPayload::Prepared { root_name: left },
            SessionPayload::Materializing {
                root_name: right, ..
            },
        ) => left == right,
        (
            SessionPayload::Materializing {
                root_name: left,
                root_identity: left_identity,
            },
            SessionPayload::Ready {
                root_name: right,
                root_identity: right_identity,
                ..
            },
        ) => left == right && left_identity.same_node(*right_identity),
        (
            SessionPayload::Ready {
                root_name: left,
                root_identity: left_identity,
                ..
            },
            SessionPayload::Tombstoned {
                root_name: right,
                root_identity: right_identity,
                ..
            },
        ) => left == right && left_identity.same_node(*right_identity),
        _ => false,
    }
}

fn gc_sessions(sessions: &File, sessions_path: &Path, census: &SessionCensus) -> MaintenanceReport {
    let mut report = MaintenanceReport::default();
    for name in &census.temporaries {
        match gc_session_predecessor_temporary(sessions, name) {
            Ok(_) => report.entry("session", name, name, "TMP", "REMOVED"),
            Err(_) => {
                report.recovery("session", name, name, "TMP");
                return report;
            }
        }
    }
    for census_capability in &census.capabilities {
        let capability = &census_capability.capability;
        match &capability.record.payload {
            SessionPayload::Tombstoned { tombstone_name, .. } => {
                let result = maintenance_context(sessions, sessions_path, &capability.record)
                    .and_then(|context| {
                        complete_tombstone(&context, capability, "gc")?;
                        #[cfg(git_vws_m4_checkpoint)]
                        session_checkpoint("gc", &capability.record, "session-return")?;
                        Ok(())
                    });
                if result.is_ok() {
                    report.entry(
                        "session",
                        &capability.basename,
                        tombstone_name.as_bytes(),
                        "TOMBSTONED",
                        "REMOVED",
                    );
                } else {
                    report.recovery(
                        "session",
                        &capability.basename,
                        tombstone_name.as_bytes(),
                        "TOMBSTONED",
                    );
                    return report;
                }
            }
            SessionPayload::Ready { .. } if capability.record.journal.is_idle() => {
                let result = census_capability
                    .private_objects
                    .as_ref()
                    .ok_or_else(|| {
                        session_recovery("READY session was not fully classified before cleanup")
                    })
                    .and_then(|plan| {
                        gc_private_loose(sessions, sessions_path, capability, plan, &mut report)
                    });
                match result {
                    Ok(()) => {}
                    Err(error) if error.code == "SESSION_BUSY" => report.entry(
                        "session",
                        &capability.basename,
                        &capability.basename,
                        "READY",
                        "BUSY",
                    ),
                    Err(_) => {
                        report.recovery(
                            "session",
                            &capability.basename,
                            &capability.basename,
                            "READY",
                        );
                        return report;
                    }
                }
            }
            _ => {}
        }
    }
    report
}

fn gc_session_predecessor_temporary(
    sessions: &File,
    name: &[u8],
) -> Result<RecordCapability, Error> {
    let (current, temporary) = session_predecessor_temporary(sessions, name)?;
    #[cfg(git_vws_m4_checkpoint)]
    authority::remove_record_txn_temporary_bound(
        sessions,
        name,
        &temporary.binding,
        "gc",
        &current.record.sid,
        &current.record.template_key,
    )?;
    #[cfg(not(git_vws_m4_checkpoint))]
    authority::remove_record_txn_temporary_bound(sessions, name, &temporary.binding)?;
    #[cfg(git_vws_m4_checkpoint)]
    session_checkpoint("gc", &current.record, "predecessor-tmp-removed")?;
    Ok(current)
}

fn gc_private_loose(
    sessions: &File,
    sessions_path: &Path,
    capability: &RecordCapability,
    plan: &PrivateObjectPlan,
    report: &mut MaintenanceReport,
) -> Result<(), Error> {
    let context = maintenance_context(sessions, sessions_path, &capability.record)?;
    let ready = load_ready_capability(
        &context.sessions,
        &context.sessions_path,
        &context.authority,
        capability,
    )?;
    acquire_lease(&ready.root, true)?;
    let current = revalidate_ready_lease(&context, capability, &ready)?;
    ensure_publish_idle(&current.record)?;
    let lease_plan = classify_private_objects(&ready.common, &context.authority, &current.record)?;
    require_session(
        lease_plan == *plan,
        "private object classifier binding changed while its lease was held",
    )?;
    let (authority_objects, mut authority_objects_plan) =
        open_record_authority_objects(&current.record)?;
    classify_authority_objects(
        &authority_objects,
        &mut authority_objects_plan,
        current.record.base.len(),
    )?;
    require_session(
        authority_objects_plan == plan.authority_objects,
        "authority object classifier binding changed before cleanup",
    )?;
    let (private_objects, objects_identity) = open_private_objects(&ready.common, &current.record)?;
    require_session(
        objects_identity == plan.objects_identity
            && private_objects_matches_plan(&private_objects, plan)?,
        "private object classifier binding changed before cleanup",
    )?;
    if plan.pack_present {
        report.entry(
            "loose",
            &current.basename,
            &loose_path_name(&current.record, b"pack", None),
            "PACK",
            "RETAINED",
        );
    }
    let mut removed = false;
    for fanout_plan in &plan.fanouts {
        let fanout_name = &fanout_plan.name;
        let fanout = cstring(fanout_name, "private loose object fanout")?;
        let (private_fanout, fanout_identity) = open_git_metadata_directory(
            &private_objects,
            &fanout,
            objects_identity,
            &current.record.volume,
            "private object metadata is not an owned same-volume directory",
        )?;
        require_session(
            fanout_identity == fanout_plan.identity
                && private_fanout_matches_plan(&private_fanout, fanout_plan)?,
            "private loose object fanout changed after classification",
        )?;
        let authority_fanout = match fanout_plan.authority_identity {
            Some(expected) if fanout_plan.loose.iter().any(loose_plan_removes) => {
                match open_authority_fanout(&authority_objects, &authority_objects_plan, &fanout)? {
                    Some((fanout, identity)) if identity == expected => Some(fanout),
                    _ => {
                        return Err(session_recovery(
                            "authority loose object fanout changed after classification",
                        ))
                    }
                }
            }
            _ => None,
        };
        let fanout_removed = gc_loose_fanout(
            &private_fanout,
            authority_fanout.as_ref(),
            fanout_name,
            &fanout_plan.loose,
            &current,
            report,
        )?;
        let empty = storage::directory_names(private_fanout.as_raw_fd())?.is_empty();
        drop(authority_fanout);
        drop(private_fanout);
        if empty {
            storage::unlink_empty_owned_directory(
                &private_objects,
                &fanout,
                fanout_identity,
                &current.record.volume,
            )?;
            #[cfg(git_vws_m4_checkpoint)]
            session_checkpoint("gc", &current.record, "loose-fanout-unlinked")?;
            private_objects.sync_all().map_err(|error| {
                Error::io(
                    "SESSION_RECOVERY_REQUIRED",
                    "cannot sync private object directory after fanout cleanup",
                    error,
                )
            })?;
            #[cfg(git_vws_m4_checkpoint)]
            session_checkpoint("gc", &current.record, "loose-fanout-parent-synced")?;
            report.entry(
                "loose",
                &current.basename,
                &loose_path_name(&current.record, fanout_name, None),
                "FANOUT",
                "REMOVED",
            );
            removed = true;
        }
        removed |= fanout_removed;
    }
    if removed {
        #[cfg(git_vws_m4_checkpoint)]
        session_checkpoint("gc", &current.record, "loose-return")?;
    }
    Ok(())
}

fn gc_loose_fanout(
    private_fanout: &File,
    authority_fanout: Option<&File>,
    fanout_name: &[u8],
    loose: &[PrivateLoosePlan],
    current: &RecordCapability,
    report: &mut MaintenanceReport,
) -> Result<bool, Error> {
    let mut removed = false;
    for loose_plan in loose {
        let name = cstring(&loose_plan.name, "private loose object")?;
        if storage::identity_at(private_fanout.as_raw_fd(), &name)? != loose_plan.identity {
            return Err(session_recovery(
                "private loose object changed after classification",
            ));
        }
        let path = loose_path_name(&current.record, fanout_name, Some(&loose_plan.name));
        match &loose_plan.action {
            LooseAction::Retain => retain_loose(report, current, &path),
            LooseAction::Remove { authority_identity } => {
                let authority_fanout = authority_fanout.ok_or_else(|| {
                    session_recovery("authority loose object plan lost its fanout binding")
                })?;
                storage::unlink_identical_owned_regular(
                    private_fanout,
                    &name,
                    loose_plan.identity,
                    authority_fanout,
                    &name,
                    *authority_identity,
                )?;
                #[cfg(git_vws_m4_checkpoint)]
                session_checkpoint("gc", &current.record, "loose-object-unlinked")?;
                private_fanout.sync_all().map_err(|error| {
                    Error::io(
                        "SESSION_RECOVERY_REQUIRED",
                        "cannot sync private loose object fanout",
                        error,
                    )
                })?;
                #[cfg(git_vws_m4_checkpoint)]
                session_checkpoint("gc", &current.record, "loose-object-parent-synced")?;
                report.entry("loose", &current.basename, &path, "LOOSE", "REMOVED");
                removed = true;
            }
        }
    }
    Ok(removed)
}

fn private_objects_matches_plan(objects: &File, plan: &PrivateObjectPlan) -> Result<bool, Error> {
    let mut expected = vec![b"info".to_vec()];
    if plan.pack_present {
        expected.push(b"pack".to_vec());
    }
    expected.extend(plan.fanouts.iter().map(|fanout| fanout.name.clone()));
    expected.sort();
    Ok(storage::directory_names(objects.as_raw_fd())? == expected)
}

fn private_fanout_matches_plan(fanout: &File, plan: &PrivateFanoutPlan) -> Result<bool, Error> {
    Ok(storage::directory_names(fanout.as_raw_fd())?
        == plan
            .loose
            .iter()
            .map(|loose| loose.name.clone())
            .collect::<Vec<_>>())
}

fn loose_plan_removes(plan: &PrivateLoosePlan) -> bool {
    matches!(&plan.action, LooseAction::Remove { .. })
}

fn retain_loose(report: &mut MaintenanceReport, current: &RecordCapability, path: &[u8]) {
    report.entry("loose", &current.basename, path, "LOOSE", "RETAINED");
}

fn open_record_authority_objects(
    record: &SessionRecord,
) -> Result<(File, AuthorityObjectsPlan), Error> {
    let path = authority_path_from_record(record)?;
    let root = File::open(&path).map_err(|error| {
        Error::io(
            "SESSION_RECOVERY_REQUIRED",
            "cannot open authority for loose object comparison",
            error,
        )
    })?;
    require_session(
        Identity::from_file(&root)?.same_node(record.authority_identity)
            && record.authority_identity.directory(),
        "authority identity changed before loose object comparison",
    )?;
    bind_path(&path, &root, "authority")?;
    let root_identity = Identity::from_file(&root)?;
    let root_volume = storage::volume_id(&root)?;
    let (objects, identity) = open_git_metadata_directory(
        &root,
        c"objects",
        root_identity,
        &root_volume,
        "authority object metadata is not an owned same-volume directory",
    )?;
    Ok((
        objects,
        AuthorityObjectsPlan {
            identity,
            volume: root_volume,
            entries: Vec::new(),
        },
    ))
}

fn open_git_metadata_directory(
    parent: &File,
    name: &CStr,
    parent_identity: Identity,
    volume: &str,
    detail: &'static str,
) -> Result<(File, Identity), Error> {
    let identity = storage::identity_at(parent.as_raw_fd(), name)?;
    let directory = storage::open_directory_at(parent.as_raw_fd(), name)?;
    require_session(
        Identity::from_file(&directory)? == identity
            && private_git_metadata_directory(identity)
            && identity.dev == parent_identity.dev
            && storage::volume_id(&directory)? == volume,
        detail,
    )?;
    Ok((directory, identity))
}

fn open_private_objects(common: &File, record: &SessionRecord) -> Result<(File, Identity), Error> {
    open_git_metadata_directory(
        common,
        c"objects",
        Identity::from_file(common)?,
        &record.volume,
        "private object metadata is not an owned same-volume directory",
    )
}

fn classify_private_objects(
    common: &File,
    authority: &Authority,
    record: &SessionRecord,
) -> Result<PrivateObjectPlan, Error> {
    let (authority_objects, mut authority_objects_plan) = open_record_authority_objects(record)?;
    classify_authority_objects(
        &authority_objects,
        &mut authority_objects_plan,
        record.base.len(),
    )?;
    let (objects, objects_identity) = open_private_objects(common, record)?;
    let oid_length = record.base.len();
    let tail_length = oid_length - 2;
    let mut plan = PrivateObjectPlan {
        objects_identity,
        authority_objects: authority_objects_plan,
        pack_present: false,
        fanouts: Vec::new(),
    };
    let mut info_present = false;
    for entry in storage::directory_names(objects.as_raw_fd())? {
        match entry.as_slice() {
            b"info" => {
                classify_private_info(&objects, objects_identity, authority, record)?;
                info_present = true;
            }
            b"pack" => {
                classify_private_pack(&objects, objects_identity, &record.volume, oid_length)?;
                plan.pack_present = true;
            }
            _ if loose_fanout_name(&entry) => plan.fanouts.push(classify_private_fanout(
                &objects,
                objects_identity,
                &record.volume,
                &authority_objects,
                &plan.authority_objects,
                &entry,
                tail_length,
            )?),
            _ => {
                return Err(session_recovery(
                    "private object store contains an unrecognized entry",
                ))
            }
        }
    }
    require_session(
        info_present
            && Identity::from_file(&objects)? == objects_identity
            && storage::identity_at(common.as_raw_fd(), c"objects")? == objects_identity
            && Identity::from_file(&authority_objects)? == plan.authority_objects.identity
            && storage::volume_id(&authority_objects)? == plan.authority_objects.volume,
        "private object store changed during classification",
    )?;
    Ok(plan)
}

fn classify_authority_objects(
    objects: &File,
    plan: &mut AuthorityObjectsPlan,
    oid_length: usize,
) -> Result<(), Error> {
    plan.entries.clear();
    for entry in storage::directory_names(objects.as_raw_fd())? {
        require_session(
            matches!(entry.as_slice(), b"info" | b"pack") || loose_fanout_name(&entry),
            "authority object store contains an unrecognized entry",
        )?;
        let name = cstring(&entry, "authority object metadata")?;
        let (directory, identity) = open_git_metadata_directory(
            objects,
            &name,
            plan.identity,
            &plan.volume,
            "authority object metadata is not an owned same-volume directory",
        )?;
        let children = match entry.as_slice() {
            b"info" => classify_authority_info(&directory, identity, &plan.volume)?,
            b"pack" => classify_pack_entries(
                &directory,
                identity,
                &plan.volume,
                oid_length,
                "authority packed object",
            )?,
            _ => classify_authority_fanout(&directory, identity, &plan.volume, oid_length - 2)?,
        };
        plan.entries.push(AuthorityObjectPlan {
            name: entry,
            identity,
            children,
        });
    }
    Ok(())
}

fn classify_authority_fanout(
    fanout: &File,
    fanout_identity: Identity,
    volume: &str,
    tail_length: usize,
) -> Result<Vec<(Vec<u8>, Identity)>, Error> {
    let mut children = Vec::new();
    for tail in storage::directory_names(fanout.as_raw_fd())? {
        let name = cstring(&tail, "authority loose object")?;
        let identity = storage::identity_at(fanout.as_raw_fd(), &name)?;
        require_session(
            tail.len() == tail_length && lower_hex(&tail),
            "authority loose object has an unrecognized name or type",
        )?;
        validate_authority_regular(
            fanout,
            &name,
            identity,
            fanout_identity,
            volume,
            "authority loose object has an unsafe identity",
        )?;
        children.push((tail, identity));
    }
    require_session(
        Identity::from_file(fanout)? == fanout_identity,
        "authority loose object fanout changed during classification",
    )?;
    Ok(children)
}

fn classify_authority_info(
    info: &File,
    info_identity: Identity,
    volume: &str,
) -> Result<Vec<(Vec<u8>, Identity)>, Error> {
    let mut children = Vec::new();
    for entry in storage::directory_names(info.as_raw_fd())? {
        let name = cstring(&entry, "authority object info")?;
        let identity = storage::identity_at(info.as_raw_fd(), &name)?;
        require_session(
            matches!(entry.as_slice(), b"commit-graph" | b"packs"),
            "authority object info contains an unrecognized entry",
        )?;
        validate_authority_regular(
            info,
            &name,
            identity,
            info_identity,
            volume,
            "authority object info has an unsafe identity",
        )?;
        children.push((entry, identity));
    }
    require_session(
        Identity::from_file(info)? == info_identity,
        "authority object info changed during classification",
    )?;
    Ok(children)
}

fn validate_authority_regular(
    parent: &File,
    name: &CStr,
    expected: Identity,
    parent_identity: Identity,
    volume: &str,
    detail: &'static str,
) -> Result<(), Error> {
    require_session(
        expected.regular()
            && expected.uid == current_uid()
            && expected.nlink == 1
            && expected.mode & 0o022 == 0
            && expected.dev == parent_identity.dev,
        detail,
    )?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(Error::io(
            "SESSION_RECOVERY_REQUIRED",
            detail,
            io::Error::last_os_error(),
        ));
    }
    let file = unsafe { File::from_raw_fd(raw) };
    require_session(
        Identity::from_file(&file)? == expected && storage::same_volume(&file, volume)?,
        detail,
    )
}

fn classify_private_info(
    objects: &File,
    objects_identity: Identity,
    authority: &Authority,
    record: &SessionRecord,
) -> Result<(), Error> {
    let (info, identity) = open_git_metadata_directory(
        objects,
        c"info",
        objects_identity,
        &record.volume,
        "private object metadata is not an owned same-volume directory",
    )?;
    let names = storage::directory_names(info.as_raw_fd())?;
    require_session(
        names.len() == 1 && names[0] == b"alternates",
        "private object info directory contains an unrecognized entry",
    )?;
    let mut expected = authority
        .canonical
        .join("objects")
        .into_os_string()
        .into_vec();
    expected.push(b'\n');
    require_session(
        read_regular_at(&info, c"alternates", "private alternate")? == expected
            && Identity::from_file(&info)? == identity
            && storage::identity_at(objects.as_raw_fd(), c"info")? == identity,
        "private object alternate changed during classification",
    )?;
    Ok(())
}

fn classify_private_pack(
    objects: &File,
    objects_identity: Identity,
    volume: &str,
    oid_length: usize,
) -> Result<(), Error> {
    let (pack, identity) = open_git_metadata_directory(
        objects,
        c"pack",
        objects_identity,
        volume,
        "private object metadata is not an owned same-volume directory",
    )?;
    classify_pack_entries(&pack, identity, volume, oid_length, "private packed object")?;
    require_session(
        Identity::from_file(&pack)? == identity
            && storage::identity_at(objects.as_raw_fd(), c"pack")? == identity,
        "private packed object directory changed during classification",
    )?;
    Ok(())
}

fn classify_pack_entries(
    pack: &File,
    pack_identity: Identity,
    volume: &str,
    oid_length: usize,
    label: &'static str,
) -> Result<Vec<(Vec<u8>, Identity)>, Error> {
    let entries = storage::directory_names(pack.as_raw_fd())?;
    let mut children = Vec::new();
    for entry in &entries {
        let name = cstring(entry, label)?;
        let entry_identity = storage::identity_at(pack.as_raw_fd(), &name)?;
        require_session(
            pack_entry_name(entry, oid_length),
            "packed object has an unrecognized name or type",
        )?;
        validate_authority_regular(
            pack,
            &name,
            entry_identity,
            pack_identity,
            volume,
            "packed object has an unsafe identity",
        )?;
        let pair = pack_entry_pair(entry)
            .ok_or_else(|| session_recovery("packed object has an unrecognized name or type"))?;
        require_session(
            entries.iter().any(|candidate| candidate == &pair),
            "packed object is missing its pair",
        )?;
        children.push((entry.clone(), entry_identity));
    }
    Ok(children)
}

fn classify_private_fanout(
    objects: &File,
    objects_identity: Identity,
    volume: &str,
    authority_objects: &File,
    authority_plan: &AuthorityObjectsPlan,
    name: &[u8],
    tail_length: usize,
) -> Result<PrivateFanoutPlan, Error> {
    let name = cstring(name, "private loose object fanout")?;
    let (fanout, identity) = open_git_metadata_directory(
        objects,
        &name,
        objects_identity,
        volume,
        "private object metadata is not an owned same-volume directory",
    )?;
    let authority_fanout = open_authority_fanout(authority_objects, authority_plan, &name)?;
    let authority_identity = authority_fanout.as_ref().map(|(_, identity)| *identity);
    let mut loose = Vec::new();
    for tail in storage::directory_names(fanout.as_raw_fd())? {
        let tail_name = cstring(&tail, "private loose object")?;
        let tail_identity = storage::identity_at(fanout.as_raw_fd(), &tail_name)?;
        require_session(
            tail.len() == tail_length && lower_hex(&tail) && loose_regular_owner(tail_identity),
            "private loose object has an unrecognized name or type",
        )?;
        let action = classify_private_loose(
            &fanout,
            &tail_name,
            tail_identity,
            authority_fanout.as_ref().map(|(fanout, _)| fanout),
            authority_identity,
        )?;
        loose.push(PrivateLoosePlan {
            name: tail,
            identity: tail_identity,
            action,
        });
    }
    if let Some((authority_fanout, expected)) = authority_fanout.as_ref() {
        require_session(
            Identity::from_file(authority_fanout)? == *expected
                && storage::identity_at(authority_objects.as_raw_fd(), &name)? == *expected,
            "authority loose object fanout changed during classification",
        )?;
    }
    require_session(
        Identity::from_file(&fanout)? == identity
            && storage::identity_at(objects.as_raw_fd(), &name)? == identity,
        "private loose object fanout changed during classification",
    )?;
    Ok(PrivateFanoutPlan {
        name: name.into_bytes(),
        identity,
        authority_identity,
        loose,
    })
}

fn open_authority_fanout(
    authority_objects: &File,
    authority_plan: &AuthorityObjectsPlan,
    name: &CStr,
) -> Result<Option<(File, Identity)>, Error> {
    let Some(expected) = entry_identity_if_present(authority_objects.as_raw_fd(), name)? else {
        return Ok(None);
    };
    require_session(
        private_git_metadata_directory(expected) && expected.dev == authority_plan.identity.dev,
        "authority loose object fanout has an unsafe identity",
    )?;
    let (fanout, identity) = open_git_metadata_directory(
        authority_objects,
        name,
        authority_plan.identity,
        &authority_plan.volume,
        "authority object metadata is not an owned same-volume directory",
    )?;
    require_session(
        identity == expected,
        "authority loose object fanout changed while opening",
    )?;
    Ok(Some((fanout, identity)))
}

fn classify_private_loose(
    private_fanout: &File,
    name: &CStr,
    private_identity: Identity,
    authority_fanout: Option<&File>,
    authority_fanout_identity: Option<Identity>,
) -> Result<LooseAction, Error> {
    let Some(authority_fanout) = authority_fanout else {
        return Ok(LooseAction::Retain);
    };
    let Some(authority_identity) = entry_identity_if_present(authority_fanout.as_raw_fd(), name)?
    else {
        return Ok(LooseAction::Retain);
    };
    let authority_fanout_identity = authority_fanout_identity
        .ok_or_else(|| session_recovery("authority loose object plan lost its fanout identity"))?;
    require_session(
        loose_regular_owner(authority_identity)
            && authority_identity.dev == authority_fanout_identity.dev,
        "authority loose object has an unsafe identity",
    )?;
    match storage::verify_identical_owned_regular(
        private_fanout,
        name,
        private_identity,
        authority_fanout,
        name,
        authority_identity,
    ) {
        Ok(()) if private_identity.nlink == 1 && authority_identity.nlink == 1 => {
            Ok(LooseAction::Remove { authority_identity })
        }
        Ok(()) => Ok(LooseAction::Retain),
        Err(error)
            if error.code == "STORAGE_UNSUPPORTED"
                && error.detail == "private loose object is not an exact authority duplicate" =>
        {
            Ok(LooseAction::Retain)
        }
        Err(error) => Err(error),
    }
}

fn pack_entry_name(name: &[u8], oid_length: usize) -> bool {
    for suffix in [b".pack".as_slice(), b".idx".as_slice(), b".rev".as_slice()] {
        if let Some(oid) = name
            .strip_prefix(b"pack-")
            .and_then(|value| value.strip_suffix(suffix))
        {
            return oid.len() == oid_length && lower_hex(oid);
        }
    }
    false
}

fn pack_entry_pair(name: &[u8]) -> Option<Vec<u8>> {
    let (stem, suffix) = if let Some(stem) = name.strip_suffix(b".pack") {
        (stem, b".idx".as_slice())
    } else if let Some(stem) = name.strip_suffix(b".idx") {
        (stem, b".pack".as_slice())
    } else if let Some(stem) = name.strip_suffix(b".rev") {
        (stem, b".pack".as_slice())
    } else {
        return None;
    };
    let mut pair = stem.to_vec();
    pair.extend_from_slice(suffix);
    Some(pair)
}

fn loose_regular_owner(identity: Identity) -> bool {
    identity.regular() && identity.uid == current_uid()
}

fn loose_fanout_name(name: &[u8]) -> bool {
    name.len() == 2 && lower_hex(name)
}

fn lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn require_session(condition: bool, detail: &'static str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(session_recovery(detail))
    }
}

fn loose_path_name(record: &SessionRecord, fanout: &[u8], tail: Option<&[u8]>) -> Vec<u8> {
    let mut path = root_name(&record.sid).into_bytes();
    path.extend_from_slice(b"/common.git/objects/");
    path.extend_from_slice(fanout);
    if let Some(tail) = tail {
        path.push(b'/');
        path.extend_from_slice(tail);
    }
    path
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
        common,
        common_identity: *common_identity,
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

fn validate_publish_target(authority: &Authority, target: &OsStr) -> Result<(), Error> {
    let args = [
        OsString::from("-C"),
        authority.canonical.as_os_str().to_os_string(),
        OsString::from("check-ref-format"),
        OsString::from("--branch"),
        target.to_os_string(),
    ];
    let output = git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Authority)
        .map_err(|_| Error::new("PUBLISH_VERIFY_FAILED", "cannot validate publish target"))?;
    if output.status.success() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "session target is not a valid direct branch name",
        ))
    }
}

fn ensure_publish_target_unchecked_out(authority: &Authority, target: &OsStr) -> Result<(), Error> {
    let args = [
        OsString::from("-C"),
        authority.canonical.as_os_str().to_os_string(),
        OsString::from("worktree"),
        OsString::from("list"),
        OsString::from("--porcelain"),
    ];
    let output = git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Authority).map_err(|_| {
        Error::new(
            "PUBLISH_VERIFY_FAILED",
            "cannot inspect authority worktrees",
        )
    })?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "cannot inspect authority worktrees",
        ));
    }
    let mut expected = b"branch refs/heads/".to_vec();
    expected.extend_from_slice(target.as_bytes());
    if output
        .stdout
        .split(|byte| *byte == b'\n')
        .any(|line| line == expected)
    {
        return Err(Error::new(
            "PUBLISH_TARGET_CHECKED_OUT",
            "publish target is checked out by an authority worktree",
        ));
    }
    Ok(())
}

fn audit_authority_config(authority: &Authority) -> Result<String, Error> {
    let args = [
        OsString::from("-C"),
        authority.canonical.as_os_str().to_os_string(),
        OsString::from("config"),
        OsString::from("--null"),
        OsString::from("--show-origin"),
        OsString::from("--show-scope"),
        OsString::from("--includes"),
        OsString::from("--list"),
    ];
    let output = git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Authority)
        .map_err(|_| Error::new("PUBLISH_VERIFY_FAILED", "cannot audit authority config"))?;
    if !output.status.success()
        || !output.stderr.is_empty()
        || !authority_config_is_safe(&output.stdout)
    {
        return Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "authority config is not safe for fixed-object publish",
        ));
    }
    Ok(hash_bytes(&output.stdout))
}

fn ensure_authority_config(current: &str, expected: &str) -> Result<(), Error> {
    if current == expected {
        Ok(())
    } else {
        Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "authority config changed during the publish transaction",
        ))
    }
}

fn authority_config_is_safe(raw: &[u8]) -> bool {
    if raw.is_empty() {
        return true;
    }
    let Some(raw) = raw.strip_suffix(b"\0") else {
        return false;
    };
    let mut fields = raw.split(|byte| *byte == 0);
    loop {
        let Some(scope) = fields.next() else {
            return true;
        };
        let (Some(origin), Some(entry)) = (fields.next(), fields.next()) else {
            return false;
        };
        if !authority_config_entry_is_safe(scope, origin, entry) {
            return false;
        }
    }
}

fn authority_config_entry_is_safe(scope: &[u8], origin: &[u8], entry: &[u8]) -> bool {
    if !matches!(scope, b"system" | b"global" | b"local" | b"worktree")
        || !origin.starts_with(b"file:")
    {
        return false;
    }
    let Some(separator) = entry.iter().position(|byte| *byte == b'\n') else {
        return false;
    };
    let key = entry[..separator]
        .iter()
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    !key.starts_with(b"include.")
        && !key.starts_with(b"includeif.")
        && !key.starts_with(b"filter.")
        && !key.starts_with(b"fsck.")
        && !key.starts_with(b"url.")
        && !bytes_include(&key, b"alternaterefscommand")
        && !(key.starts_with(b"remote.")
            && (key.ends_with(b".uploadpack") || key.ends_with(b".vcs")))
        && !bytes_include(&key, b"promisor")
        && !bytes_include(&key, b"partialclone")
}

fn bytes_include(bytes: &[u8], needle: &[u8]) -> bool {
    bytes
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn private_target_commit(
    common_path: &Path,
    target: &OsStr,
    object_format: &str,
) -> Result<String, Error> {
    target_commit(
        common_path,
        target,
        object_format,
        AuditConfig::Isolated,
        false,
    )?
    .ok_or_else(|| {
        Error::new(
            "PUBLISH_VERIFY_FAILED",
            "private target is absent or not a direct commit",
        )
    })
}

fn authority_target_commit(authority: &Authority, target: &OsStr) -> Result<Option<String>, Error> {
    target_commit(
        &authority.canonical,
        target,
        &authority.object_format,
        AuditConfig::Authority,
        true,
    )
}

fn target_commit(
    repository: &Path,
    target: &OsStr,
    object_format: &str,
    audit: AuditConfig,
    authority_command: bool,
) -> Result<Option<String>, Error> {
    let mut reference = OsString::from("refs/heads/");
    reference.push(target);
    let mut args = Vec::new();
    if authority_command {
        args.push(OsString::from("-C"));
        args.push(repository.as_os_str().to_os_string());
    }
    args.extend([
        OsString::from("for-each-ref"),
        OsString::from("--format=%(refname) %(objectname) %(objecttype) %(symref)"),
        reference.clone(),
    ]);
    let cwd = (!authority_command).then_some(repository);
    let output = git::capture(&args, cwd, GIT_TIMEOUT, audit)
        .map_err(|_| Error::new("PUBLISH_VERIFY_FAILED", "cannot read publish target"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "cannot read publish target",
        ));
    }
    parse_target_commit_output(
        &output.stdout,
        reference.as_os_str().as_bytes(),
        object_format,
    )
}

fn parse_target_commit_output(
    output: &[u8],
    expected_ref: &[u8],
    object_format: &str,
) -> Result<Option<String>, Error> {
    if output.is_empty() {
        return Ok(None);
    }
    let body = output
        .strip_suffix(b"\n")
        .filter(|body| !body.contains(&b'\n'))
        .ok_or_else(|| {
            Error::new(
                "PUBLISH_VERIFY_FAILED",
                "publish target output was ambiguous",
            )
        })?;
    let mut fields = body.splitn(4, |byte| *byte == b' ');
    let (Some(reference), Some(oid), Some(kind), Some(symref)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "publish target output was malformed",
        ));
    };
    if reference != expected_ref || kind != b"commit" || !symref.is_empty() {
        return Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "publish target is not one direct commit reference",
        ));
    }
    parse_publish_oid(oid, object_format).map(Some)
}

fn parse_publish_oid(output: &[u8], object_format: &str) -> Result<String, Error> {
    let oid = std::str::from_utf8(output).map_err(|_| {
        Error::new(
            "PUBLISH_VERIFY_FAILED",
            "publish target object ID was not ASCII",
        )
    })?;
    if oid_matches_format(oid, object_format) {
        Ok(oid.to_owned())
    } else {
        Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "publish target object ID did not match the authority format",
        ))
    }
}

fn oid_matches_format(oid: &str, object_format: &str) -> bool {
    let width = match object_format {
        "sha1" => 40,
        "sha256" => 64,
        _ => return false,
    };
    oid.len() == width
        && oid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn ensure_private_target(
    common_path: &Path,
    target: &OsStr,
    object_format: &str,
    expected: &str,
) -> Result<(), Error> {
    if private_target_commit(common_path, target, object_format)? == expected {
        Ok(())
    } else {
        Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "private target changed after the publish journal was prepared",
        ))
    }
}

fn ensure_publish_relation(
    common_path: &Path,
    expected_old: Option<&str>,
    new: &str,
) -> Result<(), Error> {
    let Some(expected_old) = expected_old else {
        return Ok(());
    };
    if expected_old == new {
        return Ok(());
    }
    let args = [
        OsString::from("merge-base"),
        OsString::from("--is-ancestor"),
        OsString::from(expected_old),
        OsString::from(new),
    ];
    let output = git::capture(&args, Some(common_path), GIT_TIMEOUT, AuditConfig::Isolated)
        .map_err(|_| Error::new("PUBLISH_VERIFY_FAILED", "cannot verify publish ancestry"))?;
    if output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
        return Ok(());
    }
    if output.status.code() == Some(1) && output.stdout.is_empty() && output.stderr.is_empty() {
        return Err(Error::new(
            "PUBLISH_NON_FAST_FORWARD",
            "private target is not a fast-forward of the frozen authority target",
        ));
    }
    Err(Error::new(
        "PUBLISH_VERIFY_FAILED",
        "cannot prove the publish ancestry relation",
    ))
}

fn ensure_authority_expected_old(
    authority: &Authority,
    target: &OsStr,
    expected_old: Option<&str>,
) -> Result<(), Error> {
    if authority_target_commit(authority, target)?.as_deref() == expected_old {
        Ok(())
    } else {
        Err(Error::new(
            "PUBLISH_CONFLICT",
            "authority target no longer matches the frozen expected-old",
        ))
    }
}

fn import_publish_objects(
    authority: &Authority,
    common_path: &Path,
    new: &str,
) -> Result<(), Error> {
    let args = [
        OsString::from("-C"),
        authority.canonical.as_os_str().to_os_string(),
        OsString::from("fetch"),
        OsString::from("--quiet"),
        OsString::from("--no-write-fetch-head"),
        OsString::from("--no-tags"),
        OsString::from("--no-auto-maintenance"),
        OsString::from("--no-write-commit-graph"),
        OsString::from("--recurse-submodules=no"),
        common_path.as_os_str().to_os_string(),
        OsString::from(new),
    ];
    let output = git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Authority)
        .map_err(|_| Error::new("PUBLISH_IMPORT_FAILED", "cannot import private objects"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::new(
            "PUBLISH_IMPORT_FAILED",
            "Git rejected the fixed-object import",
        ))
    }
}

fn verify_authority_closure(authority: &Authority, new: &str) -> Result<(), Error> {
    let expression = OsString::from(format!("{new}^{{commit}}"));
    let cat_file = [
        OsString::from("-C"),
        authority.canonical.as_os_str().to_os_string(),
        OsString::from("cat-file"),
        OsString::from("-e"),
        expression.clone(),
    ];
    let output = git::capture(&cat_file, None, GIT_TIMEOUT, AuditConfig::Authority)
        .map_err(|_| Error::new("PUBLISH_VERIFY_FAILED", "cannot verify imported commit"))?;
    if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "authority does not contain the imported commit",
        ));
    }
    let fsck = [
        OsString::from("-C"),
        authority.canonical.as_os_str().to_os_string(),
        OsString::from("fsck"),
        OsString::from("--connectivity-only"),
        OsString::from("--no-reflogs"),
        OsString::from("--no-dangling"),
        OsString::from("--no-progress"),
        expression,
    ];
    let output = git::capture(&fsck, None, GIT_TIMEOUT, AuditConfig::Authority)
        .map_err(|_| Error::new("PUBLISH_VERIFY_FAILED", "cannot verify imported closure"))?;
    if output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            "PUBLISH_VERIFY_FAILED",
            "authority does not prove the imported commit closure",
        ))
    }
}

fn update_publish_ref(
    authority: &Authority,
    target: &OsStr,
    new: &str,
    expected_old: Option<&str>,
) -> Result<Output, Error> {
    let mut reference = OsString::from("refs/heads/");
    reference.push(target);
    let old = expected_old.map(str::to_owned).unwrap_or_else(|| {
        "0".repeat(if authority.object_format == "sha1" {
            40
        } else {
            64
        })
    });
    let args = [
        OsString::from("-C"),
        authority.canonical.as_os_str().to_os_string(),
        OsString::from("update-ref"),
        OsString::from("--no-deref"),
        reference,
        OsString::from(new),
        OsString::from(old),
    ];
    git::capture(&args, None, GIT_TIMEOUT, AuditConfig::Authority)
        .map_err(|_| Error::new("PUBLISH_RECOVERY_REQUIRED", "publish CAS result is unknown"))
}

fn init_private_common(
    authority: &Authority,
    common: &Path,
    empty_template: &Path,
    timeout: Duration,
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
        git::capture(&args, None, timeout, AuditConfig::Isolated).map_err(git_error)?,
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

fn configure_private_common(
    common: &Path,
    _record: &SessionRecord,
    timeout: Duration,
) -> Result<(), Error> {
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
            git::capture(&args, None, timeout, AuditConfig::Isolated).map_err(git_error)?,
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
            git::capture(&args, None, timeout, AuditConfig::Isolated).map_err(git_error)?;
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
    timeout: Duration,
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
        git::capture(&args, None, timeout, AuditConfig::Isolated).map_err(git_error)?,
        "create private linked worktree",
    )?;
    #[cfg(git_vws_m4_checkpoint)]
    session_checkpoint("create", _record, "worktree-added")?;
    Ok(())
}

fn read_tree(worktree: &Path, timeout: Duration) -> Result<(), Error> {
    let args = [
        OsString::from("read-tree"),
        OsString::from("--reset"),
        OsString::from("HEAD"),
    ];
    require_clean(
        git::capture(&args, Some(worktree), timeout, AuditConfig::Isolated).map_err(git_error)?,
        "build linked-worktree index",
    )
}

fn status_clean(worktree: &Path, timeout: Duration) -> Result<(), Error> {
    let args = [
        OsString::from("status"),
        OsString::from("--porcelain=v1"),
        OsString::from("--untracked-files=all"),
    ];
    let output =
        git::capture(&args, Some(worktree), timeout, AuditConfig::Isolated).map_err(git_error)?;
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
    timeout: Duration,
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
            timeout,
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
            timeout,
            AuditConfig::Isolated,
        )
        .map_err(git_error)?,
        "read private target ref",
    )?);
    const INDEX_RECEIPT_LIMIT: usize = 4 * 1024 * 1024;
    let index = hash_bytes(&clean_git_output(
        git::capture_with_limit(
            &[
                OsString::from("-C"),
                worktree_path.as_os_str().to_os_string(),
                OsString::from("ls-files"),
                OsString::from("--stage"),
                OsString::from("-z"),
            ],
            None,
            timeout,
            AuditConfig::Isolated,
            INDEX_RECEIPT_LIMIT,
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
            timeout,
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
        || !valid_publish_journal(record)
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

fn valid_publish_journal(record: &SessionRecord) -> bool {
    let Some((txid, new, expected_old, config_fingerprint)) = record.journal.fields() else {
        return true;
    };
    matches!(&record.payload, SessionPayload::Ready { .. })
        && valid_lower_hash(txid)
        && valid_lower_oid(new)
        && expected_old.is_none_or(valid_lower_oid)
        && valid_lower_hash(config_fingerprint)
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

fn valid_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

fn valid_lower_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
            journal: PublishJournal::Idle,
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

    #[test]
    fn pack_reverse_indexes_are_validated_as_pack_metadata() {
        let oid = "0123456789abcdef0123456789abcdef01234567";
        let rev = format!("pack-{oid}.rev");
        assert!(pack_entry_name(rev.as_bytes(), oid.len()));
        assert_eq!(
            pack_entry_pair(rev.as_bytes()),
            Some(format!("pack-{oid}.pack").into_bytes())
        );
        assert!(!pack_entry_name(b"pack-0123456789abcdef.rev", oid.len()));
    }
}
