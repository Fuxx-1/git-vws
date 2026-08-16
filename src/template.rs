use crate::authority::{self, Authority, Error, Identity, StateRoot};
use crate::git::{self, AuditConfig, GitChild};
use crate::storage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

const MAX_RECORD: usize = 16 * 1024;
const MAX_LS_TREE_RECORD: usize = 1024 * 1024;
const MAX_SYMLINK: usize = 4096;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const POLICY_VERSION: &[u8] = b"git-vws/checkout-policy/v1";
#[cfg(target_os = "linux")]
const SYMLINK_TYPE: u32 = libc::S_IFLNK;
#[cfg(target_os = "macos")]
const SYMLINK_TYPE: u32 = libc::S_IFLNK as u32;
static NEXT_BUILD: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Template {
    pub(crate) key: String,
    pub(crate) sealed: storage::SealedTreeReceipt,
    pub(crate) root: File,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TemplatePayload {
    Prepared {
        building_name: String,
    },
    Materializing {
        building_name: String,
        root_identity: Identity,
    },
    Publishing {
        building_name: String,
        ready_name: String,
        sealed: storage::SealedTreeReceipt,
    },
    Ready {
        root_name: String,
        sealed: storage::SealedTreeReceipt,
    },
    Tombstoned {
        root_name: String,
        tombstone_name: String,
        sealed: storage::SealedTreeReceipt,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TemplateRecord {
    version: u8,
    key: String,
    manifest: storage::ManifestReceipt,
    volume: String,
    payload: TemplatePayload,
}

#[derive(Clone)]
struct TemplateCapability {
    basename: Vec<u8>,
    record: TemplateRecord,
    binding: authority::RecordBinding,
}

pub(crate) struct MaintenanceEntry {
    pub(crate) scope: &'static str,
    pub(crate) record_name: Vec<u8>,
    pub(crate) path_name: Vec<u8>,
    pub(crate) state: &'static str,
    pub(crate) code: &'static str,
}

#[derive(Default)]
pub(crate) struct MaintenanceReport {
    pub(crate) entries: Vec<MaintenanceEntry>,
    pub(crate) recovery_required: bool,
}

impl MaintenanceReport {
    pub(crate) fn entry(
        &mut self,
        scope: &'static str,
        record_name: &[u8],
        path_name: &[u8],
        state: &'static str,
        code: &'static str,
    ) {
        self.entries.push(MaintenanceEntry {
            scope,
            record_name: record_name.to_vec(),
            path_name: path_name.to_vec(),
            state,
            code,
        });
    }

    pub(crate) fn recovery(
        &mut self,
        scope: &'static str,
        record_name: &[u8],
        path_name: &[u8],
        state: &'static str,
    ) {
        self.recovery_required = true;
        self.entry(scope, record_name, path_name, state, "RECOVERY_REQUIRED");
    }
}

struct TemplateCensus {
    capabilities: Vec<TemplateCapability>,
    temporaries: Vec<Vec<u8>>,
    report: MaintenanceReport,
}

struct CheckoutAudit {
    config_fingerprint: String,
    attributes_fingerprint: String,
}

struct ManifestEntry {
    mode: u32,
    oid: String,
    size: u64,
    path: Vec<u8>,
}

pub(crate) fn acquire(
    state: &StateRoot,
    authority: &Authority,
    tree: &str,
) -> Result<Template, Error> {
    validate_oid(tree, &authority.object_format)?;
    state.ensure_containers()?;
    let container = state.open_container(b"templates")?;
    let volume = storage::volume_id(&container)?;
    storage::probe_native_cow(&container)?;
    let semantics = storage::path_semantics(&container)?;
    let audit = checkout_audit(authority)?;
    let version = git_version()?;
    let first = manifest_pass(authority, tree)?;
    let key = template_key(
        authority,
        tree,
        &version,
        &audit,
        &semantics,
        &volume,
        &first.digest,
    );
    let name = record_name(&key);
    if let Some(existing) = read_template_capability(&container, &name)? {
        if existing.record.key != key
            || existing.record.volume != volume
            || existing.record.manifest != first
        {
            return Err(Error::new(
                "TEMPLATE_CORRUPT",
                "template record does not match the immutable create inputs",
            ));
        }
        return match existing.record.payload.clone() {
            TemplatePayload::Ready { .. } => {
                let current = manifest_pass(authority, tree)?;
                if current != first {
                    return Err(Error::new(
                        "TEMPLATE_INPUT_DRIFT",
                        "raw ls-tree changed while checking a READY template",
                    ));
                }
                ready_template(&container, existing, current)
            }
            TemplatePayload::Prepared { .. } => {
                advance_prepared(&container, &name, existing.record, authority, tree)
            }
            TemplatePayload::Materializing { .. } => {
                incomplete_materializing(&container, existing.record)
            }
            TemplatePayload::Publishing { .. } => {
                publish_template(&container, &name, existing.record)
            }
            TemplatePayload::Tombstoned { .. } => Err(Error::new(
                "TEMPLATE_RECOVERY_REQUIRED",
                "template garbage collection is incomplete",
            )),
        };
    }
    let building_name = format!(
        "template-{key}.{}-{}.building",
        std::process::id(),
        NEXT_BUILD.fetch_add(1, Ordering::Relaxed)
    );
    let ready_name = root_name(&key);
    if named_identity(&container, &building_name)?.is_some()
        || named_identity(&container, &ready_name)?.is_some()
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template namespace is occupied before the prepared record",
        ));
    }
    let prepared = TemplateRecord {
        version: 3,
        key: key.clone(),
        volume,
        manifest: first,
        payload: TemplatePayload::Prepared { building_name },
    };
    let prepared_bytes = encode_record(&prepared)?;
    commit_template_record(
        &container,
        &name,
        &prepared_bytes,
        None,
        &key,
        "prepared-record",
    )?;
    advance_prepared(&container, &name, prepared, authority, tree)
}

fn ready_template(
    container: &File,
    capability: TemplateCapability,
    manifest: storage::ManifestReceipt,
) -> Result<Template, Error> {
    let record = capability.record.clone();
    let TemplatePayload::Ready {
        root_name: record_root,
        sealed,
    } = record.payload
    else {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record is not READY",
        ));
    };
    if record_root != root_name(&record.key)
        || sealed.manifest != manifest
        || sealed.volume != record.volume
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "READY template has an invalid durable receipt",
        ));
    }
    let root = sealed_root(container, &record_root, &sealed, &record.volume)?;
    acquire_template_lease(&root, false)?;
    revalidate_template_capability(container, &capability, Some((&root, sealed.root)))?;
    Ok(Template {
        key: record.key,
        sealed,
        root,
    })
}

pub(crate) fn doctor(container: &File) -> Result<MaintenanceReport, Error> {
    Ok(template_census(container, true)?.report)
}

pub(crate) fn validate_session_template(
    container: &File,
    key: &str,
    expected: &storage::SealedTreeReceipt,
) -> Result<(), Error> {
    let name = record_name(key);
    let capability = read_template_capability(container, &name)?
        .ok_or_else(|| template_recovery("session template record is absent"))?;
    if capability.record.key != key
        || capability.record.volume != expected.volume
        || capability.record.manifest != expected.manifest
    {
        return Err(template_recovery(
            "session template record does not match its receipt binding",
        ));
    }
    match &capability.record.payload {
        TemplatePayload::Ready { root_name, sealed } => {
            if sealed != expected {
                return Err(template_recovery(
                    "session template receipt does not match the READY record",
                ));
            }
            let root = sealed_root(container, root_name, sealed, &capability.record.volume)?;
            revalidate_template_capability(container, &capability, Some((&root, sealed.root)))?;
        }
        TemplatePayload::Tombstoned {
            root_name,
            tombstone_name,
            sealed,
        } => {
            if sealed != expected {
                return Err(template_recovery(
                    "session template receipt does not match the TOMBSTONED record",
                ));
            }
            let root = match (
                named_identity(container, root_name)?,
                named_identity(container, tombstone_name)?,
            ) {
                (Some(root), None) if root == sealed.root => {
                    sealed_root(container, root_name, sealed, &capability.record.volume)?
                }
                (None, Some(_)) => {
                    tombstone_root(container, tombstone_name, sealed, &capability.record.volume)?
                }
                _ => {
                    return Err(template_recovery(
                        "session template tombstone names are not safely bound",
                    ))
                }
            };
            storage::verify_sealed_tree(&root, sealed)?;
            revalidate_template_tombstone_capability(container, &capability, &root, sealed)?;
        }
        TemplatePayload::Prepared { .. }
        | TemplatePayload::Materializing { .. }
        | TemplatePayload::Publishing { .. } => {
            return Err(template_recovery(
                "session template record is not in a reachable state",
            ))
        }
    }
    Ok(())
}

fn template_census(container: &File, report_temporary: bool) -> Result<TemplateCensus, Error> {
    let names = storage::directory_names(container.as_raw_fd())?;
    let mut census = TemplateCensus {
        capabilities: Vec::new(),
        temporaries: Vec::new(),
        report: MaintenanceReport::default(),
    };
    let mut authorized = BTreeSet::new();
    for name in &names {
        if !template_record_name(name) {
            continue;
        }
        authorized.insert(name.clone());
        match read_template_capability(container, name) {
            Ok(Some(capability)) => {
                authorized.extend(template_payload_names(&capability.record));
                diagnose_template_capability(container, &capability, &mut census.report);
                census.capabilities.push(capability);
            }
            Ok(None) | Err(_) => census.report.recovery("template", name, name, "CORRUPT"),
        }
    }
    for name in names {
        if authorized.contains(&name) {
            continue;
        }
        if name.starts_with(b".") && name.ends_with(b".tmp") {
            match template_predecessor_temporary(container, &name) {
                Ok(_) => {
                    census.temporaries.push(name.clone());
                    if report_temporary {
                        template_item(&mut census.report, &name, "TMP", "RETAINED");
                    }
                }
                Err(_) => census.report.recovery("template", &name, &name, "TMP"),
            }
        } else {
            census.report.recovery("template", &name, &name, "UNKNOWN");
        }
    }
    Ok(census)
}

pub(crate) fn gc<F>(container: &File, mut census: F) -> Result<MaintenanceReport, Error>
where
    F: FnMut() -> Result<BTreeSet<String>, Error>,
{
    let mut planned = template_census(container, false)?;
    if planned.report.recovery_required {
        return Ok(planned.report);
    }
    planned.report.entries.clear();
    for name in &planned.temporaries {
        match clean_predecessor_temporary(container, name) {
            Ok(()) => template_item(&mut planned.report, name, "TMP", "REMOVED"),
            Err(_) => {
                planned.report.recovery("template", name, name, "TMP");
                return Ok(planned.report);
            }
        }
    }
    for capability in &planned.capabilities {
        let name = &capability.basename;
        match &capability.record.payload {
            TemplatePayload::Tombstoned { .. } => {
                match complete_template_tombstone(container, capability, Some(&mut census)) {
                    Ok(true) => template_item(&mut planned.report, name, "TOMBSTONED", "REMOVED"),
                    Ok(false) => template_item(&mut planned.report, name, "TOMBSTONED", "RETAINED"),
                    Err(_) => {
                        planned
                            .report
                            .recovery("template", name, name, "TOMBSTONED");
                        return Ok(planned.report);
                    }
                }
            }
            TemplatePayload::Ready { .. } => {
                match gc_ready_template(container, capability, &mut census) {
                    Ok(true) => template_item(&mut planned.report, name, "TOMBSTONED", "REMOVED"),
                    Ok(false) => template_item(&mut planned.report, name, "READY", "RETAINED"),
                    Err(error) if error.code == "TEMPLATE_BUSY" => {
                        template_item(&mut planned.report, name, "READY", "BUSY")
                    }
                    Err(_) => {
                        planned.report.recovery("template", name, name, "READY");
                        return Ok(planned.report);
                    }
                }
            }
            TemplatePayload::Prepared { .. }
            | TemplatePayload::Materializing { .. }
            | TemplatePayload::Publishing { .. } => {
                planned
                    .report
                    .recovery("template", name, name, "INCOMPLETE");
                return Ok(planned.report);
            }
        }
    }
    Ok(planned.report)
}

fn gc_ready_template<F>(
    container: &File,
    capability: &TemplateCapability,
    census: &mut F,
) -> Result<bool, Error>
where
    F: FnMut() -> Result<BTreeSet<String>, Error>,
{
    let TemplatePayload::Ready { root_name, sealed } = &capability.record.payload else {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record is not READY",
        ));
    };
    let root = sealed_root(container, root_name, sealed, &capability.record.volume)?;
    acquire_template_lease(&root, true)?;
    revalidate_template_capability(container, capability, Some((&root, sealed.root)))?;
    if census()?.contains(&capability.record.key) {
        return Ok(false);
    }
    let tombstoned = transition_template_tombstone(container, capability)?;
    drop(root);
    complete_template_tombstone(container, &tombstoned, None)?;
    Ok(true)
}

fn transition_template_tombstone(
    container: &File,
    expected: &TemplateCapability,
) -> Result<TemplateCapability, Error> {
    let TemplatePayload::Ready { root_name, sealed } = &expected.record.payload else {
        return Err(template_recovery(
            "only a READY v3 template can enter a tombstone",
        ));
    };
    let mut record = expected.record.clone();
    record.version = 4;
    record.payload = TemplatePayload::Tombstoned {
        root_name: root_name.clone(),
        tombstone_name: tombstone_name(&record.key),
        sealed: sealed.clone(),
    };
    let bytes = encode_record(&record)?;
    let capability =
        replace_template_capability(container, expected, &bytes, "template-tombstoned-record")?;
    #[cfg(git_vws_m4_checkpoint)]
    template_checkpoint(&capability.record.key, "template-tombstoned-record")?;
    Ok(capability)
}

fn complete_template_tombstone(
    container: &File,
    expected: &TemplateCapability,
    reachability: Option<&mut dyn FnMut() -> Result<BTreeSet<String>, Error>>,
) -> Result<bool, Error> {
    let TemplatePayload::Tombstoned {
        root_name,
        tombstone_name,
        sealed,
    } = &expected.record.payload
    else {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record is not TOMBSTONED",
        ));
    };
    let root = cstring(root_name.as_bytes(), "template root")?;
    let tombstone = cstring(tombstone_name.as_bytes(), "template tombstone")?;
    let root_entry = named_identity(container, root_name)?;
    let tombstone_entry = named_identity(container, tombstone_name)?;
    let leased = match (root_entry, tombstone_entry) {
        (Some(root_entry), None) if root_entry == sealed.root => {
            sealed_root(container, root_name, sealed, &expected.record.volume)?
        }
        (None, Some(_)) => {
            tombstone_root(container, tombstone_name, sealed, &expected.record.volume)?
        }
        (None, None) => {
            if let Some(census) = reachability {
                if census()?.contains(&expected.record.key) {
                    return Ok(false);
                }
            }
            remove_template_record(container, expected)?;
            #[cfg(git_vws_m4_checkpoint)]
            template_checkpoint(&expected.record.key, "template-return")?;
            return Ok(true);
        }
        _ => {
            return Err(template_recovery(
                "template root and tombstone names are not safely recoverable",
            ))
        }
    };
    acquire_template_lease(&leased, true)?;
    let current = revalidate_template_tombstone_capability(container, expected, &leased, sealed)?;
    if let Some(census) = reachability {
        if census()?.contains(&current.record.key) {
            return Ok(false);
        }
    }
    promote_template_tombstone(container, &root, &tombstone, sealed.root, &current.record)?;
    let current = revalidate_template_tombstone_capability(container, &current, &leased, sealed)?;
    storage::remove_owned_tree_gc(container, &tombstone, sealed.root)?;
    #[cfg(git_vws_m4_checkpoint)]
    template_checkpoint(&current.record.key, "template-owned-tree-removed")?;
    remove_template_record(container, &current)?;
    #[cfg(git_vws_m4_checkpoint)]
    template_checkpoint(&current.record.key, "template-return")?;
    Ok(true)
}

fn promote_template_tombstone(
    container: &File,
    root: &CStr,
    tombstone: &CStr,
    expected: Identity,
    _record: &TemplateRecord,
) -> Result<(), Error> {
    let root_name = std::str::from_utf8(root.to_bytes())
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "template root name is not UTF-8"))?;
    let tombstone_name = std::str::from_utf8(tombstone.to_bytes())
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "template tombstone name is not UTF-8"))?;
    match (
        named_identity(container, root_name)?,
        named_identity(container, tombstone_name)?,
    ) {
        (Some(root_identity), None) if root_identity == expected => {
            match authority::rename_no_replace(container.as_raw_fd(), root, tombstone) {
                Ok(()) => {
                    #[cfg(git_vws_m4_checkpoint)]
                    template_checkpoint(&_record.key, "template-tombstone-renamed")?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    return Err(Error::io(
                        "TEMPLATE_RECOVERY_REQUIRED",
                        "template tombstone rename has an unknown result",
                        error,
                    ));
                }
                Err(error) => {
                    return Err(Error::io(
                        "TEMPLATE_RECOVERY_REQUIRED",
                        "cannot rename template root into its tombstone namespace",
                        error,
                    ));
                }
            }
            container.sync_all().map_err(|error| {
                Error::io(
                    "TEMPLATE_RECOVERY_REQUIRED",
                    "cannot sync template container after tombstone rename",
                    error,
                )
            })?;
            #[cfg(git_vws_m4_checkpoint)]
            template_checkpoint(&_record.key, "template-tombstone-parent-synced")?;
            if named_identity(container, tombstone_name)? != Some(expected) {
                return Err(Error::new(
                    "TEMPLATE_RECOVERY_REQUIRED",
                    "template tombstone binding changed after rename",
                ));
            }
            Ok(())
        }
        (None, Some(tombstone_identity))
            if storage::owned_tree_binding(tombstone_identity, expected)
                && tombstone_cleanup_mode(tombstone_identity) =>
        {
            Ok(())
        }
        _ => Err(template_recovery(
            "template root and tombstone names are not safely recoverable",
        )),
    }
}

fn remove_template_record(container: &File, expected: &TemplateCapability) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    return authority::remove_record_bound(
        container,
        &expected.basename,
        &expected.binding,
        "gc",
        "-",
        &expected.record.key,
    );
    #[cfg(not(git_vws_m4_checkpoint))]
    authority::remove_record_bound(container, &expected.basename, &expected.binding)
}

fn template_predecessor_temporary(
    container: &File,
    name: &[u8],
) -> Result<(authority::RecordTxnTemporary, TemplateCapability), Error> {
    let Some(temporary) = authority::record_txn_temporary(container, name, MAX_RECORD)? else {
        return Err(template_recovery(
            "temporary template record basename is not a RecordTxn predecessor",
        ));
    };
    if !template_record_name(&temporary.final_name) {
        return Err(template_recovery(
            "temporary record does not name a template record",
        ));
    }
    let current = read_template_capability(container, &temporary.final_name)?
        .ok_or_else(|| template_recovery("temporary template record has no current successor"))?;
    let previous = parse_record(&temporary.binding.bytes)?;
    if !template_precedes(&previous, &current.record) {
        return Err(template_recovery(
            "temporary template record is not the direct predecessor of its current record",
        ));
    }
    Ok((temporary, current))
}

fn clean_predecessor_temporary(container: &File, name: &[u8]) -> Result<(), Error> {
    let (temporary, _current) = template_predecessor_temporary(container, name)?;
    #[cfg(git_vws_m4_checkpoint)]
    authority::remove_record_txn_temporary_bound(
        container,
        name,
        &temporary.binding,
        "gc",
        "-",
        &_current.record.key,
    )?;
    #[cfg(not(git_vws_m4_checkpoint))]
    authority::remove_record_txn_temporary_bound(container, name, &temporary.binding)?;
    #[cfg(git_vws_m4_checkpoint)]
    template_checkpoint(&_current.record.key, "predecessor-tmp-removed")?;
    Ok(())
}

fn template_precedes(previous: &TemplateRecord, current: &TemplateRecord) -> bool {
    template_transition(previous, current) || template_transition(current, previous)
}

fn template_transition(previous: &TemplateRecord, current: &TemplateRecord) -> bool {
    if previous.key != current.key
        || previous.manifest != current.manifest
        || previous.volume != current.volume
        || previous.version != 3
    {
        return false;
    }
    match (&previous.payload, &current.payload) {
        (
            TemplatePayload::Prepared {
                building_name: left,
            },
            TemplatePayload::Materializing {
                building_name: right,
                ..
            },
        ) => current.version == 3 && left == right,
        (
            TemplatePayload::Materializing { building_name, .. },
            TemplatePayload::Publishing {
                building_name: next,
                ..
            },
        ) => current.version == 3 && building_name == next,
        (
            TemplatePayload::Publishing {
                ready_name, sealed, ..
            },
            TemplatePayload::Ready {
                root_name,
                sealed: next,
            },
        ) => current.version == 3 && ready_name == root_name && sealed == next,
        (
            TemplatePayload::Ready { root_name, sealed },
            TemplatePayload::Tombstoned {
                root_name: next_root,
                sealed: next_sealed,
                ..
            },
        ) => current.version == 4 && root_name == next_root && sealed == next_sealed,
        _ => false,
    }
}

fn diagnose_template_capability(
    container: &File,
    capability: &TemplateCapability,
    report: &mut MaintenanceReport,
) {
    let record_name = &capability.basename;
    let (path_name, state, valid, code) = match &capability.record.payload {
        TemplatePayload::Ready { root_name, sealed } => (
            root_name.as_bytes(),
            "READY",
            sealed_root(container, root_name, sealed, &capability.record.volume).is_ok(),
            "OK",
        ),
        TemplatePayload::Tombstoned {
            root_name,
            tombstone_name,
            sealed,
        } => {
            let valid = match (
                named_identity(container, root_name),
                named_identity(container, tombstone_name),
            ) {
                (Ok(Some(root)), Ok(None)) if root == sealed.root => {
                    sealed_root(container, root_name, sealed, &capability.record.volume).is_ok()
                }
                (Ok(None), Ok(Some(_))) => {
                    tombstone_root(container, tombstone_name, sealed, &capability.record.volume)
                        .is_ok()
                }
                (Ok(None), Ok(None)) => true,
                _ => false,
            };
            (tombstone_name.as_bytes(), "TOMBSTONED", valid, "RECOVERY")
        }
        TemplatePayload::Prepared { building_name }
        | TemplatePayload::Materializing { building_name, .. }
        | TemplatePayload::Publishing { building_name, .. } => {
            report.recovery(
                "template",
                record_name,
                building_name.as_bytes(),
                "INCOMPLETE",
            );
            return;
        }
    };
    if valid {
        report.entry("template", record_name, path_name, state, code);
    } else {
        report.recovery("template", record_name, path_name, state);
    }
}

fn template_payload_names(record: &TemplateRecord) -> Vec<Vec<u8>> {
    match &record.payload {
        TemplatePayload::Prepared { building_name }
        | TemplatePayload::Materializing { building_name, .. } => {
            vec![building_name.as_bytes().to_vec()]
        }
        TemplatePayload::Publishing {
            building_name,
            ready_name,
            ..
        } => vec![
            building_name.as_bytes().to_vec(),
            ready_name.as_bytes().to_vec(),
        ],
        TemplatePayload::Ready { root_name, .. } => vec![root_name.as_bytes().to_vec()],
        TemplatePayload::Tombstoned {
            root_name,
            tombstone_name,
            ..
        } => vec![
            root_name.as_bytes().to_vec(),
            tombstone_name.as_bytes().to_vec(),
        ],
    }
}

fn template_recovery(detail: &'static str) -> Error {
    Error::new("TEMPLATE_RECOVERY_REQUIRED", detail)
}

fn template_item(
    report: &mut MaintenanceReport,
    name: &[u8],
    state: &'static str,
    code: &'static str,
) {
    report.entry("template", name, name, state, code);
}

fn acquire_template_lease(root: &File, exclusive: bool) -> Result<(), Error> {
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
                "TEMPLATE_BUSY",
                "template root is leased by session creation",
            ));
        }
        return Err(Error::io(
            "TEMPLATE_RECOVERY_REQUIRED",
            "cannot acquire template lease",
            error,
        ));
    }
}

fn revalidate_template_capability(
    container: &File,
    expected: &TemplateCapability,
    root: Option<(&File, Identity)>,
) -> Result<TemplateCapability, Error> {
    let current = read_template_capability(container, &expected.basename)?
        .ok_or_else(|| template_recovery("template record disappeared while its lease was held"))?;
    if current.binding != expected.binding || current.record != expected.record {
        return Err(template_recovery(
            "template record changed while its lease was held",
        ));
    }
    if let Some((root, identity)) = root {
        if Identity::from_file(root)? != identity {
            return Err(template_recovery(
                "template root changed while its lease was held",
            ));
        }
    }
    Ok(current)
}

fn replace_template_capability(
    container: &File,
    expected: &TemplateCapability,
    bytes: &[u8],
    _stage: &'static str,
) -> Result<TemplateCapability, Error> {
    #[cfg(not(git_vws_m4_checkpoint))]
    let transaction =
        authority::RecordTxn::begin_bound(container, &expected.basename, bytes, &expected.binding)?;
    #[cfg(git_vws_m4_checkpoint)]
    let transaction = authority::RecordTxn::begin_bound_checkpointed(
        container,
        &expected.basename,
        bytes,
        &expected.binding,
        ("gc", "-", &expected.record.key, _stage),
    )?;
    let mut transaction = transaction;
    let binding = transaction.commit()?;
    let record = parse_record(&binding.bytes)?;
    Ok(TemplateCapability {
        basename: expected.basename.clone(),
        record,
        binding,
    })
}

#[cfg(git_vws_m4_checkpoint)]
fn template_checkpoint(key: &str, stage: &str) -> Result<(), Error> {
    crate::m4_checkpoint::checkpoint("gc", "-", key, stage)
}

fn template_record_name(name: &[u8]) -> bool {
    name.starts_with(b"template-") && name.ends_with(b".record")
}

fn advance_prepared(
    container: &File,
    record_name: &[u8],
    record: TemplateRecord,
    authority: &Authority,
    tree: &str,
) -> Result<Template, Error> {
    let TemplatePayload::Prepared { building_name } = &record.payload else {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record is not PREPARED",
        ));
    };
    let building_name = building_name.clone();
    let ready_name = root_name(&record.key);
    #[cfg(git_vws_m4_checkpoint)]
    let m4_key = record.key.clone();
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| crate::m4_checkpoint::checkpoint("template", "-", &m4_key, stage);
    let (root, root_identity) = match (
        named_identity(container, &building_name)?,
        named_identity(container, &ready_name)?,
    ) {
        (None, None) => {
            create_directory(container, &building_name)?;
            #[cfg(git_vws_m4_checkpoint)]
            m4("root-created")?;
            private_root(container, &building_name, &record.volume, None, true)?
        }
        (Some(_), None) => private_root(container, &building_name, &record.volume, None, true)?,
        _ => {
            return Err(Error::new(
                "TEMPLATE_CORRUPT",
                "PREPARED template namespace is contradictory",
            ))
        }
    };
    sync_prepared_root(container, &building_name, &root, root_identity, &record.key)?;
    let prepared_bytes = encode_record(&record)?;
    let mut materializing = record;
    materializing.payload = TemplatePayload::Materializing {
        building_name: building_name.clone(),
        root_identity,
    };
    let materializing_bytes = encode_record(&materializing)?;
    commit_template_record(
        container,
        record_name,
        &materializing_bytes,
        Some(&prepared_bytes),
        &materializing.key,
        "materializing-record",
    )?;
    let second = materialize(&root, root_identity, authority, tree)?;
    if second != materializing.manifest {
        return Err(Error::new(
            "TEMPLATE_INPUT_DRIFT",
            "raw ls-tree changed between template passes",
        ));
    }
    let sealed = storage::seal_tree(&root, materializing.manifest.clone())?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("tree-sealed")?;
    if !storage::sealed_directory(sealed.root) {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "built template root was not sealed",
        ));
    }
    let mut publishing = materializing;
    publishing.payload = TemplatePayload::Publishing {
        building_name,
        ready_name,
        sealed,
    };
    let publishing_bytes = encode_record(&publishing)?;
    commit_template_record(
        container,
        record_name,
        &publishing_bytes,
        Some(&materializing_bytes),
        &publishing.key,
        "publishing-record",
    )?;
    publish_template(container, record_name, publishing)
}

fn incomplete_materializing(container: &File, record: TemplateRecord) -> Result<Template, Error> {
    let TemplatePayload::Materializing {
        building_name,
        root_identity,
    } = &record.payload
    else {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record is not MATERIALIZING",
        ));
    };
    let ready_name = root_name(&record.key);
    match (
        named_identity(container, building_name)?,
        named_identity(container, &ready_name)?,
    ) {
        (None, None) => Err(Error::new(
            "TEMPLATE_RECOVERY_REQUIRED",
            "MATERIALIZING template root is absent",
        )),
        (Some(_), None) => {
            materializing_root(container, building_name, &record.volume, *root_identity)?;
            Err(Error::new(
                "TEMPLATE_INCOMPLETE",
                "template build record was retained for diagnosis",
            ))
        }
        _ => Err(Error::new(
            "TEMPLATE_CORRUPT",
            "MATERIALIZING template namespace is contradictory",
        )),
    }
}

fn publish_template(
    container: &File,
    record_name: &[u8],
    record: TemplateRecord,
) -> Result<Template, Error> {
    let TemplatePayload::Publishing {
        building_name,
        ready_name,
        sealed,
    } = record.payload.clone()
    else {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record is not PUBLISHING",
        ));
    };
    let key = record.key.clone();
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| crate::m4_checkpoint::checkpoint("template", "-", &key, stage);
    match (
        named_identity(container, &building_name)?,
        named_identity(container, &ready_name)?,
    ) {
        (Some(_), None) => {
            let root = publishing_root(container, &building_name, &sealed, &record.volume)?;
            if let Err(error) = rename_ready(
                container,
                &building_name,
                &ready_name,
                &root,
                &sealed,
                &record.volume,
                &record.key,
            ) {
                if error.code != "TEMPLATE_IO_FAILED" {
                    return Err(error);
                }
                match (
                    named_identity(container, &building_name)?,
                    named_identity(container, &ready_name)?,
                ) {
                    (Some(_), None) => {
                        sealed_root(container, &building_name, &sealed, &record.volume)?;
                        return Err(Error::new(
                            "TEMPLATE_INCOMPLETE",
                            "PUBLISHING template rename did not complete",
                        ));
                    }
                    _ => {
                        return Err(Error::new(
                            "TEMPLATE_CORRUPT",
                            "PUBLISHING template namespace changed after rename failure",
                        ))
                    }
                }
            }
        }
        (None, Some(_)) => {
            let root = publishing_root(container, &ready_name, &sealed, &record.volume)?;
            seal_publishing_root(&root, sealed.root, &key, true)?;
            sealed_root(container, &ready_name, &sealed, &record.volume)?;
        }
        _ => {
            return Err(Error::new(
                "TEMPLATE_CORRUPT",
                "PUBLISHING template namespace is contradictory",
            ))
        }
    }
    let publishing_bytes = encode_record(&record)?;
    let mut ready = record;
    ready.payload = TemplatePayload::Ready {
        root_name: ready_name,
        sealed: sealed.clone(),
    };
    let ready_bytes = encode_record(&ready)?;
    let binding = commit_template_record(
        container,
        record_name,
        &ready_bytes,
        Some(&publishing_bytes),
        &key,
        "ready-record",
    )?;
    let template = ready_template(
        container,
        TemplateCapability {
            basename: record_name.to_vec(),
            record: ready,
            binding,
        },
        sealed.manifest.clone(),
    )?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("ready-return")?;
    Ok(template)
}

fn private_root(
    container: &File,
    name: &str,
    volume: &str,
    expected: Option<Identity>,
    empty: bool,
) -> Result<(File, Identity), Error> {
    let entry = named_identity(container, name)?
        .ok_or_else(|| Error::new("TEMPLATE_CORRUPT", "template private root is absent"))?;
    if !storage::private_directory(entry)
        || expected.is_some_and(|identity| !entry.same_node(identity))
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template private root identity is invalid",
        ));
    }
    let name_c = cstring(name.as_bytes(), "template root")?;
    let root = storage::open_directory_at(container.as_raw_fd(), &name_c)
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "template private root type is invalid"))?;
    let descriptor = Identity::from_file(&root)?;
    if !descriptor.same_node(entry)
        || expected.is_some_and(|identity| !descriptor.same_node(identity))
        || storage::volume_id(&root)? != volume
        || (empty && !storage::directory_names(root.as_raw_fd())?.is_empty())
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template private root binding is invalid",
        ));
    }
    Ok((root, descriptor))
}

fn materializing_root(
    container: &File,
    name: &str,
    volume: &str,
    expected: Identity,
) -> Result<(), Error> {
    let entry = named_identity(container, name)?
        .ok_or_else(|| Error::new("TEMPLATE_CORRUPT", "template materializing root is absent"))?;
    let name_c = cstring(name.as_bytes(), "template root")?;
    let root = storage::open_directory_at(container.as_raw_fd(), &name_c).map_err(|_| {
        Error::new(
            "TEMPLATE_CORRUPT",
            "template materializing root type is invalid",
        )
    })?;
    let descriptor = Identity::from_file(&root)?;
    if entry.dev != expected.dev
        || entry.ino != expected.ino
        || !descriptor.same_node(entry)
        || !(storage::private_directory(entry) || storage::sealed_directory(entry))
        || storage::volume_id(&root)? != volume
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template materializing root binding is invalid",
        ));
    }
    Ok(())
}

fn sync_prepared_root(
    container: &File,
    name: &str,
    root: &File,
    expected: Identity,
    _key: &str,
) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| crate::m4_checkpoint::checkpoint("template", "-", _key, stage);
    root.sync_all().map_err(|error| {
        Error::io(
            "TEMPLATE_IO_FAILED",
            "cannot sync prepared template root",
            error,
        )
    })?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("root-synced")?;
    container.sync_all().map_err(|error| {
        Error::io(
            "TEMPLATE_IO_FAILED",
            "cannot sync prepared template parent",
            error,
        )
    })?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("container-synced")?;
    if Identity::from_file(root)? != expected || named_identity(container, name)? != Some(expected)
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "prepared template root binding changed after sync",
        ));
    }
    Ok(())
}

fn sealed_root(
    container: &File,
    name: &str,
    sealed: &storage::SealedTreeReceipt,
    volume: &str,
) -> Result<File, Error> {
    let entry = named_identity(container, name)?
        .ok_or_else(|| Error::new("TEMPLATE_CORRUPT", "sealed template root is absent"))?;
    if entry != sealed.root || !storage::sealed_directory(entry) {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "sealed template root identity is invalid",
        ));
    }
    let name_c = cstring(name.as_bytes(), "template root")?;
    let root = storage::open_directory_at(container.as_raw_fd(), &name_c)
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "sealed template root type is invalid"))?;
    if Identity::from_file(&root)? != sealed.root || storage::volume_id(&root)? != volume {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "sealed template root binding is invalid",
        ));
    }
    storage::verify_sealed_tree(&root, sealed)?;
    Ok(root)
}

fn tombstone_root(
    container: &File,
    name: &str,
    sealed: &storage::SealedTreeReceipt,
    volume: &str,
) -> Result<File, Error> {
    let entry = named_identity(container, name)?
        .ok_or_else(|| template_recovery("template tombstone root is absent"))?;
    let name = cstring(name.as_bytes(), "template tombstone")?;
    let root = storage::open_directory_at(container.as_raw_fd(), &name)
        .map_err(|_| template_recovery("template tombstone root type is invalid"))?;
    let descriptor = Identity::from_file(&root)?;
    if entry != descriptor || !storage::owned_tree_binding(entry, sealed.root) {
        return Err(template_recovery(
            "template tombstone root binding changed while opening",
        ));
    }
    validate_template_tombstone_root(&root, sealed, volume)?;
    Ok(root)
}

fn revalidate_template_tombstone_capability(
    container: &File,
    expected: &TemplateCapability,
    root: &File,
    sealed: &storage::SealedTreeReceipt,
) -> Result<TemplateCapability, Error> {
    let current = revalidate_template_capability(container, expected, None)?;
    validate_template_tombstone_root(root, sealed, &current.record.volume)?;
    Ok(current)
}

fn validate_template_tombstone_root(
    root: &File,
    sealed: &storage::SealedTreeReceipt,
    volume: &str,
) -> Result<(), Error> {
    let identity = Identity::from_file(root)?;
    if !storage::owned_tree_binding(identity, sealed.root)
        || !tombstone_cleanup_mode(identity)
        || storage::volume_id(root)? != volume
    {
        return Err(template_recovery(
            "template tombstone root binding is invalid",
        ));
    }
    if storage::sealed_directory(identity) {
        storage::verify_sealed_tree(root, sealed)?;
    }
    Ok(())
}

fn tombstone_cleanup_mode(identity: Identity) -> bool {
    storage::sealed_directory(identity) || storage::private_directory(identity)
}

fn publishing_root(
    container: &File,
    name: &str,
    sealed: &storage::SealedTreeReceipt,
    volume: &str,
) -> Result<File, Error> {
    let entry = named_identity(container, name)?
        .ok_or_else(|| Error::new("TEMPLATE_CORRUPT", "publishing template root is absent"))?;
    let name_c = cstring(name.as_bytes(), "template root")?;
    let root = storage::open_directory_at(container.as_raw_fd(), &name_c)
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "publishing template root is invalid"))?;
    let descriptor = Identity::from_file(&root)?;
    if !storage::publishing_binding(entry, sealed.root)
        || !storage::publishing_binding(descriptor, sealed.root)
        || storage::volume_id(&root)? != volume
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "publishing template root binding is invalid",
        ));
    }
    storage::verify_publishing_tree(&root, sealed)?;
    Ok(root)
}

fn set_publishing_root_mode(
    root: &File,
    expected: Identity,
    mode: u32,
    _key: &str,
    _stage: Option<&'static str>,
) -> Result<(), Error> {
    if !matches!(mode, 0o555 | 0o755)
        || !storage::publishing_binding(Identity::from_file(root)?, expected)
    {
        return Err(Error::new(
            "TEMPLATE_RECOVERY_REQUIRED",
            "publishing template root changed before mode transition",
        ));
    }
    if unsafe { libc::fchmod(root.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(Error::io(
            "TEMPLATE_RECOVERY_REQUIRED",
            "cannot change publishing template root mode",
            io::Error::last_os_error(),
        ));
    }
    root.sync_all().map_err(|error| {
        Error::io(
            "TEMPLATE_RECOVERY_REQUIRED",
            "cannot sync publishing template root mode",
            error,
        )
    })?;
    #[cfg(git_vws_m4_checkpoint)]
    if let Some(stage) = _stage {
        crate::m4_checkpoint::checkpoint("template", "-", _key, stage)?;
    }
    let current = Identity::from_file(root)?;
    if current.mode != mode || !storage::publishing_binding(current, expected) {
        return Err(Error::new(
            "TEMPLATE_RECOVERY_REQUIRED",
            "publishing template root changed after mode transition",
        ));
    }
    Ok(())
}

fn seal_publishing_root(
    root: &File,
    expected: Identity,
    _key: &str,
    _checkpoint: bool,
) -> Result<(), Error> {
    set_publishing_root_mode(
        root,
        expected,
        0o555,
        _key,
        _checkpoint.then_some("root-resealed-sync"),
    )
}

#[cfg(target_os = "macos")]
fn prepare_publishing_root(root: &File, expected: Identity, _key: &str) -> Result<(), Error> {
    set_publishing_root_mode(root, expected, 0o755, _key, Some("macos-unsealed-sync"))
}

#[cfg(target_os = "linux")]
fn prepare_publishing_root(root: &File, expected: Identity, _key: &str) -> Result<(), Error> {
    if storage::publishing_binding(Identity::from_file(root)?, expected) {
        Ok(())
    } else {
        Err(Error::new(
            "TEMPLATE_RECOVERY_REQUIRED",
            "publishing template root changed before rename",
        ))
    }
}

fn named_identity(container: &File, name: &str) -> Result<Option<Identity>, Error> {
    let name = cstring(name.as_bytes(), "template root")?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            container.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        Ok(Some(Identity::from_stat(&stat)))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(Error::io(
                "TEMPLATE_IO_FAILED",
                "cannot inspect template namespace entry",
                error,
            ))
        }
    }
}

fn manifest_pass(authority: &Authority, tree: &str) -> Result<storage::ManifestReceipt, Error> {
    let args = [
        OsString::from("ls-tree"),
        OsString::from("-rz"),
        OsString::from("-r"),
        OsString::from("--long"),
        OsString::from(tree),
    ];
    let mut child =
        GitChild::spawn_for(&args, Some(&authority.canonical), GIT_TIMEOUT).map_err(git_error)?;
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    while let Some(raw) = child
        .read_nul_record(MAX_LS_TREE_RECORD)
        .map_err(git_error)?
    {
        let entry = parse_ls_tree(&raw, &authority.object_format)?;
        validate_path(&entry.path)?;
        add_entry(&mut hasher, &entry);
        count = count
            .checked_add(1)
            .ok_or_else(|| Error::new("TEMPLATE_INVALID", "manifest entry count overflow"))?;
    }
    finish_clean(child, "ls-tree")?;
    Ok(storage::ManifestReceipt {
        digest: authority::hex(&hasher.finalize()),
        entries: count,
    })
}

fn parse_ls_tree(raw: &[u8], object_format: &str) -> Result<ManifestEntry, Error> {
    let tab = raw
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| Error::new("TEMPLATE_INVALID", "ls-tree entry has no path separator"))?;
    let fields: Vec<_> = raw[..tab]
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty())
        .collect();
    if fields.len() != 4 {
        return Err(Error::new(
            "TEMPLATE_INVALID",
            "ls-tree entry header is invalid",
        ));
    }
    let mode = match fields[0] {
        b"100644" => 0o100644,
        b"100755" => 0o100755,
        b"120000" => 0o120000,
        _ => {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "tree file mode is unsupported",
            ))
        }
    };
    if fields[1] != b"blob" {
        return Err(Error::new(
            "TEMPLATE_UNSUPPORTED",
            "tree contains a non-blob entry",
        ));
    }
    let oid = std::str::from_utf8(fields[2])
        .map_err(|_| Error::new("TEMPLATE_INVALID", "object ID is not ASCII"))?;
    validate_oid(oid, object_format)?;
    let size_text = std::str::from_utf8(fields[3])
        .map_err(|_| Error::new("TEMPLATE_INVALID", "object size is not ASCII"))?;
    if (size_text.starts_with('0') && size_text != "0") || raw[tab + 1..].is_empty() {
        return Err(Error::new(
            "TEMPLATE_INVALID",
            "ls-tree entry is not canonical",
        ));
    }
    Ok(ManifestEntry {
        mode,
        oid: oid.to_owned(),
        size: size_text
            .parse()
            .map_err(|_| Error::new("TEMPLATE_INVALID", "object size is invalid"))?,
        path: raw[tab + 1..].to_vec(),
    })
}

fn materialize(
    root: &File,
    root_identity: Identity,
    authority: &Authority,
    tree: &str,
) -> Result<storage::ManifestReceipt, Error> {
    let listing_args = [
        OsString::from("ls-tree"),
        OsString::from("-rz"),
        OsString::from("-r"),
        OsString::from("--long"),
        OsString::from(tree),
    ];
    let mut listing = GitChild::spawn_for(&listing_args, Some(&authority.canonical), GIT_TIMEOUT)
        .map_err(git_error)?;
    let batch_args = [OsString::from("cat-file"), OsString::from("--batch")];
    let mut batch = GitChild::spawn_with_env_for(
        &batch_args,
        Some(&authority.canonical),
        &[],
        true,
        GIT_TIMEOUT,
        AuditConfig::Isolated,
    )
    .map_err(git_error)?;
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    while let Some(raw) = listing
        .read_nul_record(MAX_LS_TREE_RECORD)
        .map_err(git_error)?
    {
        let entry = parse_ls_tree(&raw, &authority.object_format)?;
        validate_path(&entry.path)?;
        add_entry(&mut hasher, &entry);
        count = count
            .checked_add(1)
            .ok_or_else(|| Error::new("TEMPLATE_INVALID", "manifest entry count overflow"))?;
        batch
            .write_stdin(format!("{}\n", entry.oid).as_bytes())
            .map_err(git_error)?;
        let header = batch.read_line_stdout(512).map_err(git_error)?;
        if header != format!("{} blob {}", entry.oid, entry.size).as_bytes() {
            return Err(Error::new(
                "TEMPLATE_INVALID",
                "cat-file batch header did not match the raw manifest",
            ));
        }
        let parent = destination_parent(root, root_identity, &entry.path)?;
        let leaf = entry
            .path
            .rsplit(|byte| *byte == b'/')
            .next()
            .expect("nonempty path");
        let leaf = cstring(leaf, "template leaf")?;
        match entry.mode {
            0o100644 | 0o100755 => write_regular(&mut batch, &parent, &leaf, &entry)?,
            0o120000 => write_symlink(&mut batch, &parent, &leaf, entry.size)?,
            _ => unreachable!("manifest parser validates modes"),
        }
    }
    finish_clean(listing, "ls-tree")?;
    batch.close_stdin();
    finish_clean(batch, "cat-file")?;
    Ok(storage::ManifestReceipt {
        digest: authority::hex(&hasher.finalize()),
        entries: count,
    })
}

fn write_regular(
    child: &mut GitChild,
    parent: &File,
    name: &CStr,
    entry: &ManifestEntry,
) -> Result<(), Error> {
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "tree path collided under target volume semantics",
            ));
        }
        return Err(Error::io(
            "TEMPLATE_IO_FAILED",
            "cannot create template regular file",
            error,
        ));
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    let mut remaining = entry.size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        child
            .read_exact_stdout(&mut buffer[..length])
            .map_err(git_error)?;
        file.write_all(&buffer[..length]).map_err(|error| {
            Error::io(
                "TEMPLATE_IO_FAILED",
                "cannot write template regular file",
                error,
            )
        })?;
        remaining -= length as u64;
    }
    expect_batch_delimiter(child)?;
    let mode = if entry.mode == 0o100755 { 0o555 } else { 0o444 };
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(Error::io(
            "TEMPLATE_IO_FAILED",
            "cannot seal template regular file",
            io::Error::last_os_error(),
        ));
    }
    file.sync_all().map_err(|error| {
        Error::io(
            "TEMPLATE_IO_FAILED",
            "cannot sync template regular file",
            error,
        )
    })?;
    if !storage::sealed_regular(Identity::from_file(&file)?) {
        return Err(Error::new(
            "TEMPLATE_IO_FAILED",
            "template regular file did not retain its sealed identity",
        ));
    }
    Ok(())
}

fn write_symlink(child: &mut GitChild, parent: &File, name: &CStr, size: u64) -> Result<(), Error> {
    if size > MAX_SYMLINK as u64 {
        return Err(Error::new(
            "TEMPLATE_UNSUPPORTED",
            "symbolic link payload exceeds the supported limit",
        ));
    }
    let mut target = vec![0; size as usize];
    child.read_exact_stdout(&mut target).map_err(git_error)?;
    expect_batch_delimiter(child)?;
    let target = CString::new(target)
        .map_err(|_| Error::new("TEMPLATE_UNSUPPORTED", "symbolic link payload contains NUL"))?;
    if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "tree path collided under target volume semantics",
            ));
        }
        return Err(Error::io(
            "TEMPLATE_IO_FAILED",
            "cannot create template symbolic link",
            error,
        ));
    }
    let identity = storage::identity_at(parent.as_raw_fd(), name)?;
    if identity.kind != SYMLINK_TYPE || identity.uid != current_uid() || identity.nlink != 1 {
        return Err(Error::new(
            "TEMPLATE_IO_FAILED",
            "template symbolic link identity is invalid",
        ));
    }
    Ok(())
}

fn destination_parent(root: &File, root_identity: Identity, path: &[u8]) -> Result<File, Error> {
    let current = Identity::from_file(root)?;
    if !current.same_node(root_identity) || !storage::private_directory(current) {
        return Err(Error::new(
            "TEMPLATE_IO_FAILED",
            "template root binding changed",
        ));
    }
    let mut parent = root
        .try_clone()
        .map_err(|error| Error::io("TEMPLATE_IO_FAILED", "cannot clone root descriptor", error))?;
    let components: Vec<_> = path.split(|byte| *byte == b'/').collect();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let component = *component;
        let name = cstring(component, "template directory")?;
        let child = match storage::open_directory_at(parent.as_raw_fd(), &name) {
            Ok(child) => {
                if !storage::directory_names(parent.as_raw_fd())?
                    .iter()
                    .any(|existing| existing == component)
                {
                    return Err(Error::new(
                        "TEMPLATE_UNSUPPORTED",
                        "tree path collided under target volume semantics",
                    ));
                }
                child
            }
            Err(_) => {
                if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    let error = io::Error::last_os_error();
                    return Err(if error.kind() == io::ErrorKind::AlreadyExists {
                        Error::new(
                            "TEMPLATE_UNSUPPORTED",
                            "tree path collided under target volume semantics",
                        )
                    } else {
                        Error::io(
                            "TEMPLATE_IO_FAILED",
                            "cannot create template directory",
                            error,
                        )
                    });
                }
                let child = storage::open_directory_at(parent.as_raw_fd(), &name)?;
                child.sync_all().map_err(|error| {
                    Error::io(
                        "TEMPLATE_IO_FAILED",
                        "cannot sync new template directory",
                        error,
                    )
                })?;
                parent.sync_all().map_err(|error| {
                    Error::io(
                        "TEMPLATE_IO_FAILED",
                        "cannot sync new template directory parent",
                        error,
                    )
                })?;
                child
            }
        };
        let identity = Identity::from_file(&child)?;
        if !storage::private_directory(identity) {
            return Err(Error::new(
                "TEMPLATE_IO_FAILED",
                "template directory identity is invalid",
            ));
        }
        parent = child;
    }
    Ok(parent)
}

fn checkout_audit(authority: &Authority) -> Result<CheckoutAudit, Error> {
    for relative in [
        "info/attributes",
        "info/grafts",
        "shallow",
        "objects/info/alternates",
    ] {
        reject_present(&authority.canonical.join(relative), relative)?;
    }
    reject_present(
        &authority.canonical.join("refs/replace"),
        "replace references",
    )?;
    reject_promisor_markers(authority)?;
    let config_fingerprint = audit_config(&capture_audit(
        authority,
        &[
            "config",
            "--null",
            "--show-origin",
            "--show-scope",
            "--includes",
            "--list",
        ],
    )?)?;
    let attributes_fingerprint = audit_attributes(authority)?;
    if capture(authority, &["rev-parse", "--is-shallow-repository"])? != b"false\n" {
        return Err(Error::new(
            "TEMPLATE_UNSUPPORTED",
            "shallow repositories are unsupported",
        ));
    }
    Ok(CheckoutAudit {
        config_fingerprint,
        attributes_fingerprint,
    })
}

fn audit_config(raw: &[u8]) -> Result<String, Error> {
    if !raw.is_empty() && !raw.ends_with(&[0]) {
        return Err(Error::new(
            "TEMPLATE_UNSUPPORTED",
            "Git config audit output lacked NUL framing",
        ));
    }
    let body = raw.strip_suffix(&[0]).unwrap_or(raw);
    if body.is_empty() {
        return config_fingerprint(BTreeMap::new());
    }
    let mut fields = body.split(|byte| *byte == 0);
    let mut effective = BTreeMap::new();
    while let Some(scope) = fields.next() {
        let origin = fields
            .next()
            .ok_or_else(|| Error::new("TEMPLATE_UNSUPPORTED", "config row lacked origin"))?;
        let item = fields
            .next()
            .ok_or_else(|| Error::new("TEMPLATE_UNSUPPORTED", "config row lacked value"))?;
        let split = item.iter().position(|byte| *byte == b'\n').ok_or_else(|| {
            Error::new(
                "TEMPLATE_UNSUPPORTED",
                "config row lacked key/value separator",
            )
        })?;
        let scope = std::str::from_utf8(scope)
            .map_err(|_| Error::new("TEMPLATE_UNSUPPORTED", "config scope was not UTF-8"))?;
        let origin = std::str::from_utf8(origin)
            .map_err(|_| Error::new("TEMPLATE_UNSUPPORTED", "config origin was not UTF-8"))?;
        let key = std::str::from_utf8(&item[..split])
            .map_err(|_| Error::new("TEMPLATE_UNSUPPORTED", "config key was not UTF-8"))?
            .to_ascii_lowercase();
        if scope.is_empty() || origin.is_empty() || key.is_empty() {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "config protocol field was empty",
            ));
        }
        if scope.contains('\n') || origin.contains('\n') {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "config protocol was ambiguous",
            ));
        }
        if key.starts_with("include.")
            || key.starts_with("includeif.")
            || key.starts_with("filter.")
            || key.starts_with("lfs.")
        {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "Git config includes, filters, or LFS are unsupported",
            ));
        }
        let relevant = matches!(
            key.as_str(),
            "core.attributesfile"
                | "core.sparsecheckout"
                | "core.sparsecheckoutcone"
                | "extensions.worktreeconfig"
                | "extensions.partialclone"
                | "core.autocrlf"
                | "core.eol"
                | "core.filemode"
                | "core.symlinks"
        ) || (key.starts_with("remote.") && key.ends_with(".promisor"));
        if relevant {
            effective.insert(
                key,
                std::str::from_utf8(&item[split + 1..])
                    .map_err(|_| {
                        Error::new("TEMPLATE_UNSUPPORTED", "checkout config was not UTF-8")
                    })?
                    .to_ascii_lowercase(),
            );
        }
    }
    config_fingerprint(effective)
}

fn config_fingerprint(effective: BTreeMap<String, String>) -> Result<String, Error> {
    for (key, value) in &effective {
        let accepted = match key.as_str() {
            "core.autocrlf" => value == "false",
            "core.eol" => value == "native",
            "core.filemode" | "core.symlinks" => value == "true",
            _ => false,
        };
        if !accepted {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "effective Git config requires unsupported checkout semantics",
            ));
        }
    }
    let mut hasher = Sha256::new();
    lp(&mut hasher, b"git-vws/config-fingerprint/v2");
    for (key, default) in [
        ("core.autocrlf", "false"),
        ("core.eol", "native"),
        ("core.filemode", "true"),
        ("core.symlinks", "true"),
    ] {
        lp(&mut hasher, key.as_bytes());
        lp(
            &mut hasher,
            effective
                .get(key)
                .map_or(default, String::as_str)
                .as_bytes(),
        );
    }
    Ok(authority::hex(&hasher.finalize()))
}

fn audit_attributes(authority: &Authority) -> Result<String, Error> {
    for variable in ["GIT_ATTR_SYSTEM", "GIT_ATTR_GLOBAL"] {
        for raw in capture_audit(authority, &["var", variable])?
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let path = Path::new(std::str::from_utf8(raw).map_err(|_| {
                Error::new("TEMPLATE_UNSUPPORTED", "Git attributes path was not UTF-8")
            })?);
            if !path.is_absolute() {
                return Err(Error::new(
                    "TEMPLATE_UNSUPPORTED",
                    "Git attributes path was not absolute",
                ));
            }
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(Error::new(
                        "TEMPLATE_UNSUPPORTED",
                        "system or global Git attributes are unsupported",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Error::io(
                        "TEMPLATE_UNSUPPORTED",
                        "cannot inspect effective Git attributes",
                        error,
                    ))
                }
            }
        }
    }
    let mut hasher = Sha256::new();
    lp(&mut hasher, b"git-vws/attributes-fingerprint/v1");
    lp(&mut hasher, b"none");
    Ok(authority::hex(&hasher.finalize()))
}

fn reject_promisor_markers(authority: &Authority) -> Result<(), Error> {
    let entries = match fs::read_dir(authority.canonical.join("objects/pack")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::io(
                "TEMPLATE_UNSUPPORTED",
                "cannot inspect authority promisor markers",
                error,
            ))
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            Error::io(
                "TEMPLATE_UNSUPPORTED",
                "cannot inspect authority pack entry",
                error,
            )
        })?;
        if entry.file_name().as_bytes().ends_with(b".promisor") {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "authority has a promisor pack",
            ));
        }
    }
    Ok(())
}

fn reject_present(path: &Path, label: &str) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::new(
            "TEMPLATE_UNSUPPORTED",
            format!("{label} requires unsupported checkout semantics"),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::io(
            "TEMPLATE_UNSUPPORTED",
            &format!("cannot inspect {label}"),
            error,
        )),
    }
}

fn git_version() -> Result<String, Error> {
    let output = GitChild::spawn_for(&[OsString::from("--version")], None, GIT_TIMEOUT)
        .map_err(git_error)?
        .capture(1024)
        .map_err(git_error)?;
    if !output.status.success() || !output.stderr.is_empty() || !output.stdout.ends_with(b"\n") {
        return Err(Error::new(
            "TEMPLATE_INVALID",
            "cannot obtain Git version capability",
        ));
    }
    String::from_utf8(output.stdout[..output.stdout.len() - 1].to_vec())
        .map_err(|_| Error::new("TEMPLATE_INVALID", "Git version was not UTF-8"))
}

fn capture(authority: &Authority, args: &[&str]) -> Result<Vec<u8>, Error> {
    capture_with(authority, args, false)
}

fn capture_audit(authority: &Authority, args: &[&str]) -> Result<Vec<u8>, Error> {
    capture_with(authority, args, true)
}

fn capture_with(authority: &Authority, args: &[&str], audit: bool) -> Result<Vec<u8>, Error> {
    let args: Vec<_> = args.iter().map(OsString::from).collect();
    let output = git::capture(
        &args,
        Some(&authority.canonical),
        GIT_TIMEOUT,
        if audit {
            AuditConfig::Authority
        } else {
            AuditConfig::Isolated
        },
    )
    .map_err(git_error)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(Error::new(
            if audit {
                "TEMPLATE_UNSUPPORTED"
            } else {
                "TEMPLATE_INVALID"
            },
            "Git preflight did not complete cleanly",
        ));
    }
    Ok(output.stdout)
}

fn finish_clean(child: GitChild, command: &str) -> Result<(), Error> {
    let output = child.finish().map_err(git_error)?;
    if output.status.success() && output.stdout.is_empty() && output.stderr.is_empty() {
        Ok(())
    } else {
        Err(Error::new(
            "TEMPLATE_INVALID",
            format!("Git {command} did not complete cleanly"),
        ))
    }
}

fn expect_batch_delimiter(child: &mut GitChild) -> Result<(), Error> {
    if child.read_byte_stdout().map_err(git_error)? == b'\n' {
        Ok(())
    } else {
        Err(Error::new(
            "TEMPLATE_INVALID",
            "cat-file payload lacked its delimiter",
        ))
    }
}

fn read_template_capability(
    container: &File,
    name: &[u8],
) -> Result<Option<TemplateCapability>, Error> {
    let name_string = std::str::from_utf8(name)
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "template record name is not UTF-8"))?;
    if named_identity(container, name_string)?.is_none() {
        return Ok(None);
    }
    let binding = authority::read_file_binding(container.as_raw_fd(), name, MAX_RECORD)?;
    let record = parse_record(&binding.bytes)?;
    if name != record_name(&record.key) {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record basename does not match its key",
        ));
    }
    Ok(Some(TemplateCapability {
        basename: name.to_vec(),
        record,
        binding,
    }))
}

fn parse_record(bytes: &[u8]) -> Result<TemplateRecord, Error> {
    let record: TemplateRecord = serde_json::from_slice(bytes)
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "template record was not JSON"))?;
    if encode_record(&record)? != bytes {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record was not canonical",
        ));
    }
    validate_record(&record)?;
    Ok(record)
}

fn encode_record(record: &TemplateRecord) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(record).map_err(|error| {
        Error::new(
            "TEMPLATE_IO_FAILED",
            format!("cannot encode template record: {error}"),
        )
    })
}

fn validate_record(record: &TemplateRecord) -> Result<(), Error> {
    if !valid_hash(&record.key) || !valid_hash(&record.manifest.digest) || record.volume.is_empty()
    {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record fields are invalid",
        ));
    }
    let valid = match &record.payload {
        TemplatePayload::Prepared { building_name } => {
            record.version == 3 && valid_building_name(building_name, &record.key)
        }
        TemplatePayload::Materializing {
            building_name,
            root_identity,
        } => {
            record.version == 3
                && valid_building_name(building_name, &record.key)
                && storage::private_directory(*root_identity)
        }
        TemplatePayload::Publishing {
            building_name,
            ready_name,
            sealed,
        } => {
            record.version == 3
                && valid_building_name(building_name, &record.key)
                && ready_name == &root_name(&record.key)
                && sealed.manifest == record.manifest
                && sealed.volume == record.volume
                && storage::sealed_directory(sealed.root)
                && valid_hash(&sealed.content_digest)
        }
        TemplatePayload::Ready {
            root_name: ready_root,
            sealed,
        } => {
            record.version == 3
                && ready_root == &root_name(&record.key)
                && sealed.manifest == record.manifest
                && sealed.volume == record.volume
                && storage::sealed_directory(sealed.root)
                && valid_hash(&sealed.content_digest)
        }
        TemplatePayload::Tombstoned {
            root_name: tombstoned_root,
            tombstone_name: tombstone,
            sealed,
        } => {
            record.version == 4
                && tombstoned_root == &root_name(&record.key)
                && tombstone == &tombstone_name(&record.key)
                && sealed.manifest == record.manifest
                && sealed.volume == record.volume
                && storage::sealed_directory(sealed.root)
                && valid_hash(&sealed.content_digest)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template record stage bindings are invalid",
        ))
    }
}

fn create_directory(parent: &File, basename: &str) -> Result<File, Error> {
    let name = cstring(basename.as_bytes(), "template root")?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(Error::io(
            "TEMPLATE_IO_FAILED",
            "cannot create template root",
            io::Error::last_os_error(),
        ));
    }
    let directory = storage::open_directory_at(parent.as_raw_fd(), &name)?;
    if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0
        || !storage::private_directory(Identity::from_file(&directory)?)
    {
        return Err(Error::new(
            "TEMPLATE_IO_FAILED",
            "template root identity is invalid",
        ));
    }
    Ok(directory)
}

fn rename_ready(
    parent: &File,
    building: &str,
    ready: &str,
    root: &File,
    sealed: &storage::SealedTreeReceipt,
    volume: &str,
    _key: &str,
) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    let m4 = |stage| crate::m4_checkpoint::checkpoint("template", "-", _key, stage);
    let building = cstring(building.as_bytes(), "building root")?;
    let ready = cstring(ready.as_bytes(), "ready root")?;
    if !storage::publishing_binding(
        storage::identity_at(parent.as_raw_fd(), &building)?,
        sealed.root,
    ) {
        return Err(Error::new(
            "TEMPLATE_CORRUPT",
            "template root changed before READY rename",
        ));
    }
    prepare_publishing_root(root, sealed.root, _key)?;
    match authority::rename_no_replace(parent.as_raw_fd(), &building, &ready) {
        Ok(()) => {
            #[cfg(git_vws_m4_checkpoint)]
            m4("root-renamed")?;
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            return Err(Error::io(
                "TEMPLATE_RECOVERY_REQUIRED",
                "READY template rename has an unknown result",
                error,
            ))
        }
        Err(error) => {
            seal_publishing_root(root, sealed.root, _key, false)?;
            return Err(Error::io(
                "TEMPLATE_IO_FAILED",
                "cannot publish READY template root",
                error,
            ));
        }
    }
    seal_publishing_root(root, sealed.root, _key, true)?;
    if storage::identity_at(parent.as_raw_fd(), &ready)? != sealed.root {
        return Err(Error::new(
            "TEMPLATE_RECOVERY_REQUIRED",
            "READY template binding changed after rename",
        ));
    }
    parent.sync_all().map_err(|error| {
        Error::io(
            "TEMPLATE_RECOVERY_REQUIRED",
            "cannot sync READY template parent",
            error,
        )
    })?;
    #[cfg(git_vws_m4_checkpoint)]
    m4("rename-parent-synced")?;
    if storage::identity_at(parent.as_raw_fd(), &ready)? != sealed.root {
        return Err(Error::new(
            "TEMPLATE_RECOVERY_REQUIRED",
            "READY template binding changed after sync",
        ));
    }
    let ready_name = std::str::from_utf8(ready.to_bytes())
        .map_err(|_| Error::new("TEMPLATE_CORRUPT", "READY root name is not UTF-8"))?;
    sealed_root(parent, ready_name, sealed, volume)?;
    Ok(())
}

fn commit_template_record(
    container: &File,
    name: &[u8],
    bytes: &[u8],
    expected: Option<&[u8]>,
    _key: &str,
    _stage: &'static str,
) -> Result<authority::RecordBinding, Error> {
    #[cfg(not(git_vws_m4_checkpoint))]
    let transaction = authority::RecordTxn::begin(container, name, bytes, expected)?;
    #[cfg(git_vws_m4_checkpoint)]
    let transaction = authority::RecordTxn::begin_checkpointed(
        container,
        name,
        bytes,
        expected,
        ("template", "-", _key, _stage),
    )?;
    let mut transaction = transaction;
    transaction.commit()
}

fn template_key(
    authority: &Authority,
    tree: &str,
    version: &str,
    audit: &CheckoutAudit,
    semantics: &storage::PathSemantics,
    volume: &str,
    manifest: &str,
) -> String {
    let mut hasher = Sha256::new();
    let platform = semantics.fingerprint();
    for value in [
        b"git-vws/template-key/v1".as_slice(),
        authority.object_format.as_bytes(),
        tree.as_bytes(),
        POLICY_VERSION,
        version.as_bytes(),
        audit.config_fingerprint.as_bytes(),
        audit.attributes_fingerprint.as_bytes(),
        platform.as_bytes(),
        volume.as_bytes(),
        manifest.as_bytes(),
    ] {
        lp(&mut hasher, value);
    }
    authority::hex(&hasher.finalize())
}

fn add_entry(hasher: &mut Sha256, entry: &ManifestEntry) {
    lp(hasher, b"entry");
    lp(hasher, format!("{:o}", entry.mode).as_bytes());
    lp(hasher, entry.oid.as_bytes());
    lp(hasher, entry.size.to_string().as_bytes());
    lp(hasher, &entry.path);
}

fn validate_path(path: &[u8]) -> Result<(), Error> {
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty()
            || component == b"."
            || component == b".."
            || component.eq_ignore_ascii_case(b".git")
            || component.eq_ignore_ascii_case(b".gitattributes")
            || component.eq_ignore_ascii_case(b".lfsconfig")
        {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "tree path is unsupported",
            ));
        }
    }
    Ok(())
}

fn validate_oid(oid: &str, object_format: &str) -> Result<(), Error> {
    let length = match object_format {
        "sha1" => 40,
        "sha256" => 64,
        _ => {
            return Err(Error::new(
                "TEMPLATE_UNSUPPORTED",
                "object format is unsupported",
            ))
        }
    };
    if oid.len() == length && oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(Error::new("TEMPLATE_INVALID", "Git object ID is invalid"))
    }
}

fn record_name(key: &str) -> Vec<u8> {
    format!("template-{key}.record").into_bytes()
}

fn root_name(key: &str) -> String {
    format!("template-{key}.root")
}

fn tombstone_name(key: &str) -> String {
    format!("template-{key}.tombstone")
}

fn valid_building_name(name: &str, key: &str) -> bool {
    name.starts_with(&format!("template-{key}."))
        && name.ends_with(".building")
        && cstring(name.as_bytes(), "building root").is_ok()
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn cstring(bytes: &[u8], label: &str) -> Result<CString, Error> {
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(Error::new(
            "TEMPLATE_INVALID",
            format!("invalid {label} basename"),
        ));
    }
    CString::new(bytes)
        .map_err(|_| Error::new("TEMPLATE_INVALID", format!("invalid {label} bytes")))
}

fn git_error(error: git::Error) -> Error {
    Error::new(error.code, error.detail)
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
