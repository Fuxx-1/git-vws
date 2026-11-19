use crate::authority::{self, Authority, Error, Identity, StateRoot};
use crate::storage;
use crate::template::MaintenanceReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const CACHE_RECORD_LIMIT: usize = 64 * 1024;
const CONFIG_LIMIT: usize = 64 * 1024;
const MAX_CONFIG_PATHS: usize = 128;
const MAX_CONFIG_PATH_BYTES: usize = 4096;
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_CACHE: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SessionCacheReceipt {
    pub(crate) base: String,
    pub(crate) config_digest: String,
    pub(crate) paths: Vec<SessionCachePath>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SessionCachePath {
    pub(crate) path_hex: String,
    pub(crate) directory: bool,
    pub(crate) snapshot: Option<CacheSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct CacheSnapshot {
    pub(crate) key: String,
    pub(crate) tree: storage::SealedTreeReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CacheRecord {
    version: u8,
    key: String,
    authority_path: String,
    authority_identity: Identity,
    base: String,
    config_digest: String,
    path_hex: String,
    volume: String,
    root_name: String,
    tree: storage::SealedTreeReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CacheSelection {
    version: u8,
    scope: String,
    key: Option<String>,
}

enum SnapshotLookup {
    NoSelection,
    Empty,
    Snapshot(CacheSnapshot),
}

struct CacheLock<'a> {
    file: &'a File,
}

impl Drop for CacheLock<'_> {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn lock_container(file: &File) -> Result<CacheLock<'_>, Error> {
    let deadline = Instant::now() + CACHE_LOCK_TIMEOUT;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(CacheLock { file });
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EWOULDBLOCK) => {}
            _ => {
                return Err(Error::io(
                    "CACHE_RECOVERY_REQUIRED",
                    "cannot lock cache container",
                    error,
                ))
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                "CACHE_RECOVERY_REQUIRED",
                "cache container is held by another git-vws command; wait for it to finish, then retry",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Clone)]
struct ConfigPath {
    bytes: Vec<u8>,
    directory: bool,
}

struct Config {
    digest: String,
    paths: Vec<ConfigPath>,
}

pub(crate) struct CachePlan {
    pub(crate) receipt: Option<SessionCacheReceipt>,
    pub(crate) container: Option<File>,
}

pub(crate) fn prepare(
    state: &StateRoot,
    repository: &Path,
    authority: &Authority,
    base: &str,
) -> Result<CachePlan, Error> {
    let Some(workspace) = workspace_root(repository) else {
        return Ok(CachePlan {
            receipt: None,
            container: None,
        });
    };
    let Some(config) = read_config(&workspace)? else {
        return Ok(CachePlan {
            receipt: None,
            container: None,
        });
    };
    if config.paths.is_empty() {
        return Ok(CachePlan {
            receipt: None,
            container: None,
        });
    }
    let caches = state.ensure_container(b"caches")?;
    let _lock = lock_container(&caches)?;
    let volume = storage::volume_id(&caches)?;
    let mut paths = Vec::with_capacity(config.paths.len());
    for configured in config.paths {
        let scope = cache_scope_key(authority, base, &config.digest, &configured.bytes, &volume);
        let snapshot = match find_snapshot(
            &caches,
            authority,
            base,
            &config.digest,
            &configured.bytes,
            &volume,
        )? {
            SnapshotLookup::Snapshot(snapshot) => Some(snapshot),
            SnapshotLookup::Empty => None,
            SnapshotLookup::NoSelection => {
                let snapshot = source_snapshot(
                    &caches,
                    &workspace,
                    authority,
                    base,
                    &configured,
                    &config.digest,
                    &volume,
                )?;
                publish_selection(
                    &caches,
                    &scope,
                    snapshot.as_ref().map(|value| value.key.as_str()),
                )?;
                snapshot
            }
        };
        paths.push(SessionCachePath {
            path_hex: authority::hex(&configured.bytes),
            directory: configured.directory,
            snapshot,
        });
    }
    drop(_lock);
    Ok(CachePlan {
        receipt: Some(SessionCacheReceipt {
            base: base.to_owned(),
            config_digest: config.digest,
            paths,
        }),
        container: Some(caches),
    })
}

pub(crate) fn materialize(
    caches: &File,
    worktree: &File,
    receipt: &SessionCacheReceipt,
) -> Result<(), Error> {
    validate_receipt(receipt)?;
    for configured in &receipt.paths {
        let path = decode_hex(&configured.path_hex)?;
        let (parent, name) = ensure_destination_parent(worktree, &path)?;
        if entry_if_present(parent.as_raw_fd(), &name)?.is_some() {
            return Err(Error::new(
                "CACHE_CONFIG_CONFLICT",
                "a .vwscached path is already present in the Git tree",
            ));
        }
        let destination = storage::create_worktree_directory(&parent, &name)?;
        if let Some(snapshot) = &configured.snapshot {
            let record = read_cache_record_by_key(caches, &snapshot.key)?;
            verify_cache_record(caches, &record)?;
            if record.tree != snapshot.tree {
                return Err(Error::new(
                    "CACHE_RECOVERY_REQUIRED",
                    "session cache receipt does not match its immutable snapshot",
                ));
            }
            let destination_identity = Identity::from_file(&destination)?;
            let source = open_cache_root(caches, &record)?;
            storage::cow_clone_subtree(storage::CowPlan {
                source: &source,
                destination_parent: &parent,
                destination_parent_identity: Identity::from_file(&parent)?,
                destination_name: &name,
                source_receipt: &record.tree,
                destination_identity,
            })?;
        }
        parent.sync_all().map_err(|error| {
            Error::io(
                "CACHE_RECOVERY_REQUIRED",
                "cannot sync cached worktree parent",
                error,
            )
        })?;
    }
    Ok(())
}

pub(crate) fn write_excludes(
    root_path: &Path,
    receipt: &SessionCacheReceipt,
) -> Result<PathBuf, Error> {
    let path = root_path.join(".git-vws-cached-exclude");
    let mut bytes = Vec::new();
    for configured in &receipt.paths {
        let path_bytes = decode_hex(&configured.path_hex)?;
        bytes.extend_from_slice(&path_bytes);
        if configured.directory {
            bytes.push(b'/');
        }
        bytes.push(b'\n');
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| {
            Error::io(
                "CACHE_RECOVERY_REQUIRED",
                "cannot create cache excludes",
                error,
            )
        })?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            Error::io(
                "CACHE_RECOVERY_REQUIRED",
                "cannot sync cache excludes",
                error,
            )
        })?;
    Ok(path)
}

pub(crate) fn capture(
    caches: &File,
    authority: &Authority,
    base: &str,
    worktree: &Path,
    receipt: &SessionCacheReceipt,
) -> Result<SessionCacheReceipt, Error> {
    validate_receipt(receipt)?;
    let _lock = lock_container(caches)?;
    let volume = storage::volume_id(caches)?;
    let mut captured = receipt.clone();
    captured.base = base.to_owned();
    for configured in &mut captured.paths {
        let path = decode_hex(&configured.path_hex)?;
        let scope = cache_scope_key(
            authority,
            &captured.base,
            &captured.config_digest,
            &path,
            &volume,
        );
        let source = worktree.join(OsString::from_vec(path.clone()));
        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                configured.snapshot = None;
                publish_selection(caches, &scope, None)?;
                continue;
            }
            Err(error) => {
                return Err(Error::io(
                    "CACHE_CAPTURE_FAILED",
                    "cannot inspect configured cache path",
                    error,
                ))
            }
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::new(
                "CACHE_CAPTURE_UNSUPPORTED",
                "configured cache paths must be real directories",
            ));
        }
        let source = File::open(&source).map_err(|error| {
            Error::io(
                "CACHE_CAPTURE_FAILED",
                "cannot open configured cache directory",
                error,
            )
        })?;
        let snapshot = create_snapshot(
            caches,
            &source,
            authority,
            &captured.base,
            &captured.config_digest,
            &path,
            &volume,
        )?;
        publish_selection(caches, &scope, Some(&snapshot.key))?;
        configured.snapshot = Some(snapshot);
    }
    Ok(captured)
}

pub(crate) fn reference_receipt(
    receipt: &SessionCacheReceipt,
    authority: &Authority,
    volume: &str,
    keys: &mut BTreeSet<String>,
    scopes: &mut BTreeSet<String>,
) -> Result<(), Error> {
    validate_receipt(receipt)?;
    for path in &receipt.paths {
        let bytes = decode_hex(&path.path_hex)?;
        scopes.insert(cache_scope_key(
            authority,
            &receipt.base,
            &receipt.config_digest,
            &bytes,
            volume,
        ));
        if let Some(snapshot) = &path.snapshot {
            keys.insert(snapshot.key.clone());
        }
    }
    Ok(())
}

pub(crate) fn validate_receipt(receipt: &SessionCacheReceipt) -> Result<(), Error> {
    if !valid_oid(&receipt.base)
        || !valid_hash(&receipt.config_digest)
        || receipt.paths.is_empty()
        || receipt.paths.iter().any(|path| {
            !valid_hex(&path.path_hex)
                || path.path_hex.is_empty()
                || path.snapshot.as_ref().is_some_and(|snapshot| {
                    !valid_hash(&snapshot.key)
                        || !valid_hash(&snapshot.tree.manifest.digest)
                        || !valid_hash(&snapshot.tree.content_digest)
                        || !storage::sealed_directory(snapshot.tree.root)
                })
        })
    {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "session cache receipt contains invalid bindings",
        ));
    }
    let mut paths = BTreeSet::new();
    for path in &receipt.paths {
        let bytes = decode_hex(&path.path_hex)?;
        validate_config_path(&bytes, path.directory)?;
        if !paths.insert(bytes) {
            return Err(Error::new(
                "CACHE_RECOVERY_REQUIRED",
                "session cache receipt contains duplicate paths",
            ));
        }
    }
    Ok(())
}

pub(crate) fn maintenance(
    caches: &File,
    reachable: &BTreeSet<String>,
    reachable_scopes: &BTreeSet<String>,
    cleanup: bool,
) -> Result<MaintenanceReport, Error> {
    let _lock = lock_container(caches)?;
    let mut report = MaintenanceReport::default();
    let names = storage::directory_names(caches.as_raw_fd())?;
    let mut records = Vec::new();
    let mut record_names = BTreeSet::new();
    let mut tree_names = BTreeSet::new();
    let mut selections = Vec::new();
    for name in &names {
        if authority::is_ignorable_system_metadata(caches.as_raw_fd(), name)? {
            continue;
        }
        if is_cache_record(name) {
            record_names.insert(name.clone());
            match read_cache_record(caches, name).and_then(|record| {
                if cache_record_name(&record.key).as_bytes() != name.as_slice() {
                    return Err(Error::new(
                        "CACHE_RECOVERY_REQUIRED",
                        "cache record filename does not match its key",
                    ));
                }
                verify_cache_record(caches, &record)?;
                Ok(record)
            }) {
                Ok(record) => records.push((name.clone(), record)),
                Err(_) => report.recovery("cache", name, name, "CORRUPT"),
            }
        } else if is_cache_tree(name) {
            tree_names.insert(name.clone());
        } else if is_cache_selection(name) {
            let scope_bytes = name
                .strip_prefix(b"cache-")
                .and_then(|value| value.strip_suffix(b".selection"));
            let scope = scope_bytes.and_then(|value| std::str::from_utf8(value).ok());
            match scope.and_then(|scope| {
                read_cache_selection(caches, scope)
                    .ok()
                    .flatten()
                    .map(|selection| (scope.to_owned(), selection))
            }) {
                Some((scope, selection)) => selections.push((name.clone(), scope, selection)),
                None => report.recovery("cache", name, name, "SELECTION"),
            }
        } else if name.starts_with(b".") && name.ends_with(b".tmp") {
            report.recovery("cache", name, name, "TMP");
        } else {
            report.recovery("cache", name, name, "UNKNOWN");
        }
    }
    let mut active_keys = BTreeSet::new();
    for (name, scope, selection) in &selections {
        let live = selection_is_live(selection, scope, reachable, reachable_scopes);
        if let Some(key) = &selection.key {
            let valid = read_cache_record_by_key(caches, key).and_then(|record| {
                verify_cache_record(caches, &record)?;
                if record.key != *key || cache_scope_key_from_record(&record)? != *scope {
                    return Err(Error::new(
                        "CACHE_RECOVERY_REQUIRED",
                        "cache selection does not match its snapshot scope",
                    ));
                }
                Ok(())
            });
            if valid.is_err() {
                report.recovery("cache", name, key.as_bytes(), "SELECTION");
                continue;
            }
            if live {
                active_keys.insert(key.clone());
            }
            report.entry(
                "cache",
                name,
                key.as_bytes(),
                "SELECTION",
                if live { "RETAINED" } else { "UNREFERENCED" },
            );
        } else {
            report.entry(
                "cache",
                name,
                scope.as_bytes(),
                "SELECTION",
                if live { "RETAINED" } else { "UNREFERENCED" },
            );
        }
    }
    let mut removed_keys = BTreeSet::new();
    for (name, record) in records {
        if !tree_names.contains(record.root_name.as_bytes()) {
            report.recovery("cache", &name, record.root_name.as_bytes(), "MISSING");
            continue;
        }
        let unreferenced = !reachable.contains(&record.key) && !active_keys.contains(&record.key);
        if cleanup && unreferenced {
            let root_name = cstring(record.root_name.as_bytes(), "cache root")?;
            if storage::remove_owned_tree_gc(caches, &root_name, record.tree.root).is_err() {
                report.recovery("cache", &name, record.root_name.as_bytes(), "REMOVAL");
                continue;
            }
            let binding =
                authority::read_file_binding(caches.as_raw_fd(), &name, CACHE_RECORD_LIMIT)?;
            if remove_cache_record(caches, &name, &binding).is_err() {
                report.recovery("cache", &name, &name, "REMOVAL");
                continue;
            }
            report.entry(
                "cache",
                &name,
                record.root_name.as_bytes(),
                "CACHE",
                "REMOVED",
            );
            removed_keys.insert(record.key);
        } else {
            report.entry(
                "cache",
                &name,
                record.root_name.as_bytes(),
                "CACHE",
                if unreferenced {
                    "UNREFERENCED"
                } else {
                    "RETAINED"
                },
            );
        }
    }
    for (name, scope, selection) in selections {
        if cleanup && !selection_is_live(&selection, &scope, reachable, reachable_scopes) {
            let removable = selection
                .key
                .as_ref()
                .is_none_or(|key| removed_keys.contains(key));
            if !removable {
                report.recovery("cache", &name, scope.as_bytes(), "SELECTION");
                continue;
            }
            let binding =
                match authority::read_file_binding(caches.as_raw_fd(), &name, CACHE_RECORD_LIMIT) {
                    Ok(binding) => binding,
                    Err(_) => {
                        report.recovery("cache", &name, scope.as_bytes(), "SELECTION");
                        continue;
                    }
                };
            if remove_cache_record(caches, &name, &binding).is_err() {
                report.recovery("cache", &name, scope.as_bytes(), "SELECTION");
                continue;
            }
            report.entry("cache", &name, scope.as_bytes(), "SELECTION", "REMOVED");
        }
    }
    for name in tree_names {
        let expected_record = name
            .strip_prefix(b"cache-")
            .and_then(|key| key.strip_suffix(b".tree"))
            .map(|key| {
                let mut value = b"cache-".to_vec();
                value.extend_from_slice(key);
                value.extend_from_slice(b".record");
                value
            });
        if expected_record.is_none_or(|record| !record_names.contains(&record)) {
            report.recovery("cache", &name, &name, "ORPHAN");
        }
    }
    Ok(report)
}

fn source_snapshot(
    caches: &File,
    workspace: &Path,
    authority: &Authority,
    base: &str,
    config: &ConfigPath,
    config_digest: &str,
    volume: &str,
) -> Result<Option<CacheSnapshot>, Error> {
    let source_path = workspace.join(OsString::from_vec(config.bytes.clone()));
    let metadata = match fs::symlink_metadata(&source_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::io(
                "CACHE_SOURCE_FAILED",
                "cannot inspect .vwscached source path",
                error,
            ))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::new(
            "CACHE_CONFIG_UNSUPPORTED",
            ".vwscached entries must name real directories",
        ));
    }
    let canonical = fs::canonicalize(&source_path).map_err(|error| {
        Error::io(
            "CACHE_SOURCE_FAILED",
            "cannot canonicalize .vwscached source path",
            error,
        )
    })?;
    if !canonical.starts_with(workspace) {
        return Err(Error::new(
            "CACHE_CONFIG_UNSUPPORTED",
            ".vwscached source path leaves the project directory",
        ));
    }
    let source = File::open(&source_path).map_err(|error| {
        Error::io(
            "CACHE_SOURCE_FAILED",
            "cannot open .vwscached source directory",
            error,
        )
    })?;
    Ok(Some(create_snapshot(
        caches,
        &source,
        authority,
        base,
        config_digest,
        &config.bytes,
        volume,
    )?))
}

fn create_snapshot(
    caches: &File,
    source: &File,
    authority: &Authority,
    base: &str,
    config_digest: &str,
    path: &[u8],
    volume: &str,
) -> Result<CacheSnapshot, Error> {
    let temp_name = format!(
        ".cache-{}-{}.tmp",
        std::process::id(),
        NEXT_CACHE.fetch_add(1, Ordering::Relaxed)
    );
    let temp = create_private_directory(caches, temp_name.as_bytes(), "cache snapshot")?;
    let temp_c = cstring(temp_name.as_bytes(), "cache snapshot")?;
    let result = (|| {
        let tree = storage::snapshot_tree(source, &temp)?;
        let key = cache_key(authority, base, config_digest, path, &tree.content_digest);
        let final_name = cache_tree_name(&key);
        let record_name = cache_record_name(&key);
        let final_c = cstring(final_name.as_bytes(), "cache snapshot")?;
        let record = CacheRecord {
            version: 1,
            key: key.clone(),
            authority_path: authority::hex(authority.canonical.as_os_str().as_bytes()),
            authority_identity: authority.identity,
            base: base.to_owned(),
            config_digest: config_digest.to_owned(),
            path_hex: authority::hex(path),
            volume: volume.to_owned(),
            root_name: final_name,
            tree: tree.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|error| {
            Error::new(
                "CACHE_RECOVERY_REQUIRED",
                format!("cannot encode cache record: {error}"),
            )
        })?;
        if bytes.len() > CACHE_RECORD_LIMIT {
            return Err(Error::new(
                "CACHE_UNSUPPORTED",
                "cache record exceeds the supported size",
            ));
        }
        let record_c = cstring(record_name.as_bytes(), "cache record")?;
        if let Some(existing) = entry_if_present(caches.as_raw_fd(), &final_c)? {
            if !existing.directory() {
                return Err(Error::new(
                    "CACHE_RECOVERY_REQUIRED",
                    "cache snapshot name is occupied by a non-directory",
                ));
            }
            let stored = read_cache_record_by_key(caches, &key)?;
            verify_cache_record(caches, &stored)?;
            cleanup_snapshot_temp(caches, &temp_c, &temp)?;
            return Ok(CacheSnapshot {
                key,
                tree: stored.tree,
            });
        }
        publish_snapshot_tree(caches, &temp, &temp_c, &final_c, &tree)?;
        caches.sync_all().map_err(|error| {
            Error::io(
                "CACHE_RECOVERY_REQUIRED",
                "cannot sync cache snapshot container",
                error,
            )
        })?;
        if entry_if_present(caches.as_raw_fd(), &record_c)?.is_none() {
            let mut transaction =
                authority::RecordTxn::begin(caches, record_name.as_bytes(), &bytes, None)
                    .map_err(|error| Error::new("CACHE_RECOVERY_REQUIRED", error.detail))?;
            transaction
                .commit()
                .map_err(|error| Error::new("CACHE_RECOVERY_REQUIRED", error.detail))?;
        }
        let stored = read_cache_record_by_key(caches, &key)?;
        verify_cache_record(caches, &stored)?;
        Ok(CacheSnapshot {
            key,
            tree: stored.tree,
        })
    })();
    match result {
        Ok(snapshot) => Ok(snapshot),
        Err(error) => {
            cleanup_snapshot_temp(caches, &temp_c, &temp)?;
            Err(error)
        }
    }
}

fn publish_snapshot_tree(
    caches: &File,
    tree: &File,
    temporary: &CStr,
    final_name: &CStr,
    receipt: &storage::SealedTreeReceipt,
) -> Result<(), Error> {
    prepare_snapshot_rename(tree, receipt)?;
    match authority::rename_no_replace(caches.as_raw_fd(), temporary, final_name) {
        Ok(()) => restore_snapshot_seal(tree, receipt),
        Err(error) => {
            restore_snapshot_seal(tree, receipt)?;
            Err(Error::io(
                "CACHE_RECOVERY_REQUIRED",
                "cannot publish cache snapshot",
                error,
            ))
        }
    }
}

fn prepare_snapshot_rename(tree: &File, receipt: &storage::SealedTreeReceipt) -> Result<(), Error> {
    storage::verify_sealed_tree(tree, receipt).map_err(|error| {
        Error::new(
            "CACHE_RECOVERY_REQUIRED",
            format!(
                "cache snapshot changed before publication: {}",
                error.detail
            ),
        )
    })?;
    #[cfg(target_os = "macos")]
    {
        set_snapshot_root_mode(tree, 0o755)?;
        if let Err(error) = storage::verify_publishing_tree(tree, receipt) {
            restore_snapshot_seal(tree, receipt)?;
            return Err(Error::new(
                "CACHE_RECOVERY_REQUIRED",
                format!(
                    "cache snapshot changed before publication: {}",
                    error.detail
                ),
            ));
        }
        if let Err(error) = tree.sync_all() {
            restore_snapshot_seal(tree, receipt)?;
            return Err(Error::io(
                "CACHE_RECOVERY_REQUIRED",
                "cannot sync cache snapshot before publication",
                error,
            ));
        }
    }
    Ok(())
}

fn restore_snapshot_seal(tree: &File, receipt: &storage::SealedTreeReceipt) -> Result<(), Error> {
    #[cfg(target_os = "macos")]
    set_snapshot_root_mode(tree, 0o555)?;
    storage::verify_sealed_tree(tree, receipt).map_err(|error| {
        Error::new(
            "CACHE_RECOVERY_REQUIRED",
            format!("cache snapshot changed while publishing: {}", error.detail),
        )
    })?;
    #[cfg(target_os = "macos")]
    tree.sync_all().map_err(|error| {
        Error::io(
            "CACHE_RECOVERY_REQUIRED",
            "cannot sync sealed cache snapshot",
            error,
        )
    })?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_snapshot_root_mode(tree: &File, mode: libc::mode_t) -> Result<(), Error> {
    if unsafe { libc::fchmod(tree.as_raw_fd(), mode) } != 0 {
        return Err(Error::io(
            "CACHE_RECOVERY_REQUIRED",
            "cannot change cache snapshot root mode",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn cleanup_snapshot_temp(caches: &File, name: &CStr, temp: &File) -> Result<(), Error> {
    if entry_if_present(caches.as_raw_fd(), name)?.is_none() {
        return Ok(());
    }
    let identity = Identity::from_file(temp)?;
    storage::remove_owned_tree(caches, name, identity).map_err(|error| {
        Error::new(
            "CACHE_RECOVERY_REQUIRED",
            format!("cannot clean up temporary cache snapshot: {}", error.detail),
        )
    })
}

fn find_snapshot(
    caches: &File,
    authority: &Authority,
    base: &str,
    config_digest: &str,
    path: &[u8],
    volume: &str,
) -> Result<SnapshotLookup, Error> {
    let scope = cache_scope_key(authority, base, config_digest, path, volume);
    let Some(selection) = read_cache_selection(caches, &scope)? else {
        return Ok(SnapshotLookup::NoSelection);
    };
    let Some(key) = selection.key else {
        return Ok(SnapshotLookup::Empty);
    };
    let record = read_cache_record_by_key(caches, &key)?;
    verify_cache_record(caches, &record)?;
    let expected_authority_path = authority::hex(authority.canonical.as_os_str().as_bytes());
    if record.key != key
        || record.authority_path != expected_authority_path
        || !record.authority_identity.same_node(authority.identity)
        || record.base != base
        || record.config_digest != config_digest
        || record.path_hex != authority::hex(path)
        || record.volume != volume
        || cache_scope_key_from_record(&record)? != scope
    {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache selection does not match its requested scope",
        ));
    }
    Ok(SnapshotLookup::Snapshot(CacheSnapshot {
        key: record.key,
        tree: record.tree,
    }))
}

fn read_cache_record_by_key(caches: &File, key: &str) -> Result<CacheRecord, Error> {
    let name = cache_record_name(key);
    let name_c = cstring(name.as_bytes(), "cache record")?;
    read_cache_record(caches, name_c.to_bytes())
}

fn read_cache_record(caches: &File, name: &[u8]) -> Result<CacheRecord, Error> {
    let name_c = cstring(name, "cache record")?;
    let bytes = storage::read_regular_at(caches.as_raw_fd(), &name_c, CACHE_RECORD_LIMIT)
        .map_err(|error| Error::new("CACHE_RECOVERY_REQUIRED", error.detail))?;
    let record: CacheRecord = serde_json::from_slice(&bytes).map_err(|error| {
        Error::new(
            "CACHE_RECOVERY_REQUIRED",
            format!("cannot decode cache record: {error}"),
        )
    })?;
    if serde_json::to_vec(&record).ok().as_deref() != Some(bytes.as_slice()) {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache record is not canonically encoded",
        ));
    }
    if record.version != 1
        || !valid_hash(&record.key)
        || !valid_hash(&record.config_digest)
        || !valid_hex(&record.authority_path)
        || !valid_hex(&record.path_hex)
        || !valid_oid(&record.base)
        || !valid_hash(&record.tree.manifest.digest)
        || !valid_hash(&record.tree.content_digest)
        || record.volume.is_empty()
        || record.root_name != cache_tree_name(&record.key)
        || record.path_hex.is_empty()
    {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache record contains invalid fields",
        ));
    }
    Ok(record)
}

fn verify_cache_record(caches: &File, record: &CacheRecord) -> Result<(), Error> {
    let root_name = cstring(record.root_name.as_bytes(), "cache root")?;
    let root = storage::open_directory_at(caches.as_raw_fd(), &root_name)?;
    if Identity::from_file(&root)? != record.tree.root
        || storage::volume_id(&root)? != record.volume
        || !storage::sealed_directory(record.tree.root)
    {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache snapshot root binding changed",
        ));
    }
    storage::verify_sealed_tree(&root, &record.tree).map_err(|_| {
        Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache snapshot content no longer matches its receipt",
        )
    })
}

fn open_cache_root(caches: &File, record: &CacheRecord) -> Result<File, Error> {
    let name = cstring(record.root_name.as_bytes(), "cache root")?;
    let root = storage::open_directory_at(caches.as_raw_fd(), &name)?;
    verify_cache_record(caches, record)?;
    Ok(root)
}

fn ensure_destination_parent(worktree: &File, path: &[u8]) -> Result<(File, CString), Error> {
    let mut components = path.split(|byte| *byte == b'/');
    let first = components
        .next()
        .filter(|component| !component.is_empty())
        .ok_or_else(|| Error::new("CACHE_CONFIG_INVALID", "cache path is empty"))?;
    let mut parent = worktree.try_clone().map_err(|error| {
        Error::io(
            "CACHE_RECOVERY_REQUIRED",
            "cannot retain cached worktree descriptor",
            error,
        )
    })?;
    let mut current = first;
    loop {
        let Some(next) = components.next() else {
            return Ok((parent, cstring(current, "cached path")?));
        };
        let name = cstring(current, "cached parent")?;
        let directory = match entry_if_present(parent.as_raw_fd(), &name)? {
            Some(identity) if identity.directory() => {
                storage::open_directory_at(parent.as_raw_fd(), &name)?
            }
            Some(_) => {
                return Err(Error::new(
                    "CACHE_CONFIG_CONFLICT",
                    "a cached path parent is not a directory",
                ))
            }
            None => storage::create_worktree_directory(&parent, &name)?,
        };
        parent = directory;
        current = next;
    }
}

fn create_private_directory(parent: &File, name: &[u8], label: &str) -> Result<File, Error> {
    let name = cstring(name, label)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(Error::io(
            "CACHE_RECOVERY_REQUIRED",
            &format!("cannot create {label}"),
            io::Error::last_os_error(),
        ));
    }
    let directory = storage::open_directory_at(parent.as_raw_fd(), &name)?;
    if !storage::private_directory(Identity::from_file(&directory)?) {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            format!("{label} has an invalid identity"),
        ));
    }
    Ok(directory)
}

fn workspace_root(repository: &Path) -> Option<PathBuf> {
    let input = fs::canonicalize(repository).ok()?;
    let candidate = if input.file_name() == Some(OsStr::new(".git")) {
        input.parent()?.to_path_buf()
    } else if input.join(".git").is_dir() {
        input
    } else {
        return None;
    };
    Some(candidate)
}

fn read_config(workspace: &Path) -> Result<Option<Config>, Error> {
    let config_path = workspace.join(".vwscached");
    let metadata = match fs::symlink_metadata(&config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::io(
                "CACHE_CONFIG_INVALID",
                "cannot inspect .vwscached",
                error,
            ))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::new(
            "CACHE_CONFIG_INVALID",
            ".vwscached must be an ordinary file",
        ));
    }
    let bytes = fs::read(&config_path)
        .map_err(|error| Error::io("CACHE_CONFIG_INVALID", "cannot read .vwscached", error))?;
    if bytes.len() > CONFIG_LIMIT {
        return Err(Error::new(
            "CACHE_CONFIG_INVALID",
            ".vwscached exceeds the supported size",
        ));
    }
    let mut paths = Vec::new();
    for raw_line in bytes.split(|byte| *byte == b'\n') {
        let mut line = raw_line;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        line = trim_ascii(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let directory = line.last() == Some(&b'/');
        if directory {
            line = &line[..line.len() - 1];
        }
        if line.starts_with(b"./") {
            line = &line[2..];
        }
        validate_config_path(line, directory)?;
        paths.push(ConfigPath {
            bytes: line.to_vec(),
            directory,
        });
        if paths.len() > MAX_CONFIG_PATHS {
            return Err(Error::new(
                "CACHE_CONFIG_INVALID",
                ".vwscached contains too many paths",
            ));
        }
    }
    paths.sort_by(|left, right| left.bytes.cmp(&right.bytes));
    for pair in paths.windows(2) {
        if pair[1].bytes == pair[0].bytes
            || pair[1].bytes.starts_with(&pair[0].bytes)
                && pair[1].bytes.get(pair[0].bytes.len()) == Some(&b'/')
        {
            return Err(Error::new(
                "CACHE_CONFIG_INVALID",
                ".vwscached contains duplicate or overlapping paths",
            ));
        }
    }
    Ok(Some(Config {
        digest: hash_bytes(&bytes),
        paths,
    }))
}

fn validate_config_path(bytes: &[u8], _directory: bool) -> Result<(), Error> {
    if bytes.is_empty()
        || bytes.len() > MAX_CONFIG_PATH_BYTES
        || bytes.starts_with(b"/")
        || bytes.contains(&0)
        || bytes
            .iter()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'!'))
        || bytes.split(|byte| *byte == b'/').any(|component| {
            component.is_empty()
                || component == b"."
                || component == b".."
                || component.eq_ignore_ascii_case(b".git")
                || component.eq_ignore_ascii_case(b".vwscached")
        })
    {
        return Err(Error::new(
            "CACHE_CONFIG_INVALID",
            ".vwscached accepts only safe repository-relative literal paths",
        ));
    }
    Ok(())
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn cache_key(
    authority: &Authority,
    base: &str,
    config_digest: &str,
    path: &[u8],
    content_digest: &str,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        b"git-vws/cache/v1".as_slice(),
        authority.canonical.as_os_str().as_bytes(),
        &authority.identity.dev.to_be_bytes(),
        &authority.identity.ino.to_be_bytes(),
        base.as_bytes(),
        config_digest.as_bytes(),
        path,
        content_digest.as_bytes(),
    ] {
        lp(&mut hasher, field);
    }
    authority::hex(&hasher.finalize())
}

fn cache_scope_key(
    authority: &Authority,
    base: &str,
    config_digest: &str,
    path: &[u8],
    volume: &str,
) -> String {
    let authority_path = authority::hex(authority.canonical.as_os_str().as_bytes());
    cache_scope_key_parts(
        &authority_path,
        authority.identity,
        base,
        config_digest,
        path,
        volume,
    )
}

fn cache_scope_key_from_record(record: &CacheRecord) -> Result<String, Error> {
    let path = decode_hex(&record.path_hex)?;
    Ok(cache_scope_key_parts(
        &record.authority_path,
        record.authority_identity,
        &record.base,
        &record.config_digest,
        &path,
        &record.volume,
    ))
}

fn selection_is_live(
    selection: &CacheSelection,
    scope: &str,
    reachable: &BTreeSet<String>,
    reachable_scopes: &BTreeSet<String>,
) -> bool {
    reachable_scopes.contains(scope)
        || selection
            .key
            .as_ref()
            .is_some_and(|key| reachable.contains(key))
}

fn cache_scope_key_parts(
    authority_path: &str,
    authority_identity: Identity,
    base: &str,
    config_digest: &str,
    path: &[u8],
    volume: &str,
) -> String {
    let mut hasher = Sha256::new();
    let dev = authority_identity.dev.to_be_bytes();
    let ino = authority_identity.ino.to_be_bytes();
    for field in [
        b"git-vws/cache-scope/v1".as_slice(),
        authority_path.as_bytes(),
        &dev,
        &ino,
        base.as_bytes(),
        config_digest.as_bytes(),
        path,
        volume.as_bytes(),
    ] {
        lp(&mut hasher, field);
    }
    authority::hex(&hasher.finalize())
}

fn cache_tree_name(key: &str) -> String {
    format!("cache-{key}.tree")
}

fn cache_record_name(key: &str) -> String {
    format!("cache-{key}.record")
}

fn cache_selection_name(scope: &str) -> String {
    format!("cache-{scope}.selection")
}

fn is_cache_record(name: &[u8]) -> bool {
    name.starts_with(b"cache-") && name.ends_with(b".record")
}

fn is_cache_tree(name: &[u8]) -> bool {
    name.starts_with(b"cache-") && name.ends_with(b".tree")
}

fn is_cache_selection(name: &[u8]) -> bool {
    name.starts_with(b"cache-") && name.ends_with(b".selection")
}

fn read_cache_selection(caches: &File, scope: &str) -> Result<Option<CacheSelection>, Error> {
    if !valid_hash(scope) {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache selection scope is invalid",
        ));
    }
    let name = cache_selection_name(scope);
    let name_c = cstring(name.as_bytes(), "cache selection")?;
    if entry_if_present(caches.as_raw_fd(), &name_c)?.is_none() {
        return Ok(None);
    }
    let bytes = storage::read_regular_at(caches.as_raw_fd(), &name_c, CACHE_RECORD_LIMIT)
        .map_err(|error| Error::new("CACHE_RECOVERY_REQUIRED", error.detail))?;
    let selection: CacheSelection = serde_json::from_slice(&bytes).map_err(|error| {
        Error::new(
            "CACHE_RECOVERY_REQUIRED",
            format!("cannot decode cache selection: {error}"),
        )
    })?;
    if serde_json::to_vec(&selection).ok().as_deref() != Some(bytes.as_slice())
        || selection.version != 1
        || selection.scope != scope
        || selection.key.as_ref().is_some_and(|key| !valid_hash(key))
    {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache selection contains invalid fields",
        ));
    }
    Ok(Some(selection))
}

fn publish_selection(caches: &File, scope: &str, key: Option<&str>) -> Result<(), Error> {
    if !valid_hash(scope) || key.is_some_and(|value| !valid_hash(value)) {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache selection binding is invalid",
        ));
    }
    let selection = CacheSelection {
        version: 1,
        scope: scope.to_owned(),
        key: key.map(str::to_owned),
    };
    let bytes = serde_json::to_vec(&selection).map_err(|error| {
        Error::new(
            "CACHE_RECOVERY_REQUIRED",
            format!("cannot encode cache selection: {error}"),
        )
    })?;
    let name = cache_selection_name(scope);
    let name_c = cstring(name.as_bytes(), "cache selection")?;
    let expected_old = if entry_if_present(caches.as_raw_fd(), &name_c)?.is_some() {
        let current = read_cache_selection(caches, scope)?.ok_or_else(|| {
            Error::new(
                "CACHE_RECOVERY_REQUIRED",
                "cache selection disappeared while being replaced",
            )
        })?;
        Some(serde_json::to_vec(&current).map_err(|error| {
            Error::new(
                "CACHE_RECOVERY_REQUIRED",
                format!("cannot encode existing cache selection: {error}"),
            )
        })?)
    } else {
        None
    };
    let mut transaction =
        authority::RecordTxn::begin(caches, name.as_bytes(), &bytes, expected_old.as_deref())
            .map_err(cache_record_error)?;
    transaction.commit().map_err(cache_record_error)?;
    Ok(())
}

fn cache_record_error(error: Error) -> Error {
    Error::new("CACHE_RECOVERY_REQUIRED", error.detail)
}

fn remove_cache_record(
    caches: &File,
    name: &[u8],
    binding: &authority::RecordBinding,
) -> Result<(), Error> {
    #[cfg(git_vws_m4_checkpoint)]
    return authority::remove_record_bound(caches, name, binding, "gc", "-", "cache")
        .map_err(cache_record_error);
    #[cfg(not(git_vws_m4_checkpoint))]
    authority::remove_record_bound(caches, name, binding).map_err(cache_record_error)
}

fn entry_if_present(parent: i32, name: &CStr) -> Result<Option<Identity>, Error> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        Ok(Some(Identity::from_stat(&stat)))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(Error::io(
                "CACHE_RECOVERY_REQUIRED",
                "cannot inspect cache entry",
                error,
            ))
        }
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if !valid_hex(value) {
        return Err(Error::new(
            "CACHE_RECOVERY_REQUIRED",
            "cache path is not lowercase hexadecimal",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let left = hex_digit(pair[0]).ok_or_else(|| {
                Error::new("CACHE_RECOVERY_REQUIRED", "cache path is not hexadecimal")
            })?;
            let right = hex_digit(pair[1]).ok_or_else(|| {
                Error::new("CACHE_RECOVERY_REQUIRED", "cache path is not hexadecimal")
            })?;
            Ok((left << 4) | right)
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

fn valid_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len() % 2 == 0
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hash_bytes(bytes: &[u8]) -> String {
    authority::hex(&Sha256::digest(bytes))
}

fn lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn cstring(bytes: &[u8], label: &str) -> Result<CString, Error> {
    CString::new(bytes).map_err(|_| Error::new("CACHE_CONFIG_INVALID", format!("invalid {label}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_rejects_globs_and_parent_paths() {
        for value in [b"target/*.o".as_slice(), b"../target/", b".git/", b"/tmp/"] {
            assert!(validate_config_path(value.strip_suffix(b"/").unwrap_or(value), true).is_err());
        }
        assert!(validate_config_path(b"target", true).is_ok());
    }

    #[test]
    fn config_paths_are_literal_and_non_overlapping() {
        let raw = b"# build\n node_modules/\ntarget/\n";
        let mut paths = Vec::new();
        for line in raw.split(|byte| *byte == b'\n') {
            let line = trim_ascii(line);
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            let bytes = line.strip_suffix(b"/").unwrap_or(line);
            paths.push(bytes.to_vec());
        }
        paths.sort();
        assert_eq!(paths, vec![b"node_modules".to_vec(), b"target".to_vec()]);
    }
}
