use crate::authority::{self, Error, Identity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_SYMLINK: usize = 4096;
static NEXT_PROBE: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "linux")]
const DIRECTORY_TYPE: u32 = libc::S_IFDIR;
#[cfg(target_os = "linux")]
const REGULAR_TYPE: u32 = libc::S_IFREG;
#[cfg(target_os = "linux")]
const SYMLINK_TYPE: u32 = libc::S_IFLNK;
#[cfg(target_os = "macos")]
const DIRECTORY_TYPE: u32 = libc::S_IFDIR as u32;
#[cfg(target_os = "macos")]
const REGULAR_TYPE: u32 = libc::S_IFREG as u32;
#[cfg(target_os = "macos")]
const SYMLINK_TYPE: u32 = libc::S_IFLNK as u32;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
    fn acl_free(acl: *mut libc::c_void) -> libc::c_int;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ManifestReceipt {
    pub(crate) digest: String,
    pub(crate) entries: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SealedTreeReceipt {
    pub(crate) root: Identity,
    pub(crate) volume: String,
    pub(crate) manifest: ManifestReceipt,
    pub(crate) content_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct CowReceipt {
    pub(crate) source: SealedTreeReceipt,
    pub(crate) destination: Identity,
}

pub(crate) struct CowPlan<'a> {
    pub(crate) source: &'a File,
    pub(crate) destination_parent: &'a File,
    pub(crate) destination_parent_identity: Identity,
    pub(crate) destination_name: &'a CStr,
    pub(crate) source_receipt: &'a SealedTreeReceipt,
    pub(crate) destination_identity: Identity,
}

pub(crate) fn cow_clone(plan: CowPlan<'_>) -> Result<CowReceipt, Error> {
    if !valid_digest(&plan.source_receipt.manifest.digest)
        || !valid_digest(&plan.source_receipt.content_digest)
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "clone plan lacks canonical manifest or content bindings",
        ));
    }
    let source = Identity::from_file(plan.source)?;
    let parent = Identity::from_file(plan.destination_parent)?;
    let destination =
        open_directory_at(plan.destination_parent.as_raw_fd(), plan.destination_name)?;
    let destination_entry =
        identity_at(plan.destination_parent.as_raw_fd(), plan.destination_name)?;
    let source_volume = volume_id(plan.source)?;
    let destination_volume = volume_id(&destination)?;
    if !stable_directory_node(source, plan.source_receipt.root)
        || !stable_directory_node(parent, plan.destination_parent_identity)
        || !stable_directory_node(destination_entry, plan.destination_identity)
        || !stable_directory_node(
            Identity::from_file(&destination)?,
            plan.destination_identity,
        )
        || source_volume != plan.source_receipt.volume
        || destination_volume != plan.source_receipt.volume
        || !sealed_directory(source)
        || !clone_destination_directory(plan.destination_identity)
        || !linked_worktree_metadata(&destination)?
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "clone plan root, volume, or linked-worktree binding changed",
        ));
    }
    let mut hasher = content_hasher();
    let mut entries = 0;
    walk_tree(
        plan.source,
        &[],
        Walk::Clone(&destination),
        &mut hasher,
        &mut entries,
    )?;
    let content_digest = authority::hex(&hasher.finalize());
    let final_source = Identity::from_file(plan.source)?;
    if !stable_directory_node(final_source, plan.source_receipt.root)
        || entries != plan.source_receipt.manifest.entries
        || content_digest != plan.source_receipt.content_digest
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "clone receipt did not match its sealed source plan",
        ));
    }
    chmod(&destination, 0o755)?;
    let final_destination = Identity::from_file(&destination)?;
    if !final_destination.same_node(plan.destination_identity)
        || !clone_destination_directory(final_destination)
        || final_destination.mode != 0o755
        || metadata_present_fd(destination.as_raw_fd())?
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "clone destination root did not retain its receipt binding",
        ));
    }
    destination
        .sync_all()
        .map_err(|error| Error::io("STORAGE_UNSUPPORTED", "cannot sync cloned root", error))?;
    plan.destination_parent.sync_all().map_err(|error| {
        Error::io(
            "STORAGE_UNSUPPORTED",
            "cannot sync cloned root parent",
            error,
        )
    })?;
    if !stable_directory_node(
        identity_at(plan.destination_parent.as_raw_fd(), plan.destination_name)?,
        final_destination,
    ) {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "clone destination parent binding changed after sync",
        ));
    }
    Ok(CowReceipt {
        source: plan.source_receipt.clone(),
        destination: final_destination,
    })
}

pub(crate) fn seal_tree(
    root: &File,
    manifest: ManifestReceipt,
) -> Result<SealedTreeReceipt, Error> {
    if !valid_digest(&manifest.digest) {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed tree lacks a canonical manifest receipt",
        ));
    }
    let mut hasher = content_hasher();
    let mut entries = 0;
    walk_tree(root, &[], Walk::Seal, &mut hasher, &mut entries)?;
    if entries != manifest.entries {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed tree entry count did not match its manifest receipt",
        ));
    }
    let root_identity = Identity::from_file(root)?;
    if !sealed_directory(root_identity) {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed tree root did not retain its immutable binding",
        ));
    }
    Ok(SealedTreeReceipt {
        root: root_identity,
        volume: volume_id(root)?,
        manifest,
        content_digest: authority::hex(&hasher.finalize()),
    })
}

pub(crate) fn verify_sealed_tree(root: &File, expected: &SealedTreeReceipt) -> Result<(), Error> {
    if !valid_digest(&expected.manifest.digest) || !valid_digest(&expected.content_digest) {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed tree has an invalid expected content digest",
        ));
    }
    let mut hasher = content_hasher();
    let mut entries = 0;
    walk_tree(root, &[], Walk::Verify, &mut hasher, &mut entries)?;
    if stable_directory_node(Identity::from_file(root)?, expected.root)
        && volume_id(root)? == expected.volume
        && entries == expected.manifest.entries
        && authority::hex(&hasher.finalize()) == expected.content_digest
    {
        Ok(())
    } else {
        Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed tree content or metadata does not match its receipt",
        ))
    }
}

pub(crate) fn verify_worktree(root: &File, expected: &CowReceipt) -> Result<(), Error> {
    let root_identity = Identity::from_file(root)?;
    if !stable_directory_node(root_identity, expected.destination)
        || !worktree_directory(root_identity)
        || volume_id(root)? != expected.source.volume
        || !valid_digest(&expected.source.manifest.digest)
        || !valid_digest(&expected.source.content_digest)
        || !linked_worktree_entry(root, c".git")?
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "cloned worktree no longer matches its durable receipt",
        ));
    }
    let mut hasher = content_hasher();
    let mut entries = 0;
    walk_tree(root, &[], Walk::Worktree, &mut hasher, &mut entries)?;
    if entries != expected.source.manifest.entries
        || authority::hex(&hasher.finalize()) != expected.source.content_digest
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "cloned worktree content no longer matches its sealed template receipt",
        ));
    }
    Ok(())
}

pub(crate) fn volume_id(directory: &File) -> Result<String, Error> {
    let identity = Identity::from_file(directory)?;
    if !identity.directory() || identity.uid != current_uid() {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "volume probe directory is not an owned directory",
        ));
    }
    let kind = filesystem_kind(directory)?;
    let mount = mount_id(directory)?;
    Ok(format!("{kind}:dev={}:mnt={mount}", identity.dev))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PathSemantics {
    pub(crate) case_insensitive: bool,
    pub(crate) normalization_insensitive: bool,
}

impl PathSemantics {
    pub(crate) fn fingerprint(self) -> String {
        format!(
            "{}:case={}:normalization={}",
            std::env::consts::OS,
            self.case_insensitive as u8,
            self.normalization_insensitive as u8
        )
    }
}

pub(crate) fn path_semantics(parent: &File) -> Result<PathSemantics, Error> {
    let parent_identity = Identity::from_file(parent)?;
    if !clone_destination_directory(parent_identity) {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "path-semantics probe parent is not an owned state directory",
        ));
    }
    let serial = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
    let case_left = format!(".git-vws-path-{serial}-a");
    let case_right = format!(".git-vws-path-{serial}-A");
    let normalization_left = format!(".git-vws-path-{serial}-\u{00e9}");
    let normalization_right = format!(".git-vws-path-{serial}-e\u{301}");
    Ok(PathSemantics {
        case_insensitive: probe_name_collision(parent, &case_left, &case_right)?,
        normalization_insensitive: probe_name_collision(
            parent,
            &normalization_left,
            &normalization_right,
        )?,
    })
}

fn probe_name_collision(parent: &File, left: &str, right: &str) -> Result<bool, Error> {
    let left = CString::new(left).expect("fixed path semantics probe name");
    let right = CString::new(right).expect("fixed path semantics probe name");
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            left.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(storage_io("cannot create path-semantics probe source"));
    }
    let left_file = unsafe { File::from_raw_fd(raw) };
    let left_identity = Identity::from_file(&left_file)?;
    drop(left_file);
    let second = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    let (collision, right_identity, primary) = if second >= 0 {
        let file = unsafe { File::from_raw_fd(second) };
        let identity = Identity::from_file(&file)?;
        drop(file);
        (false, Some(identity), Ok(()))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            (true, None, Ok(()))
        } else {
            (
                false,
                None,
                Err(Error::io(
                    "STORAGE_UNSUPPORTED",
                    "cannot create path-semantics probe destination",
                    error,
                )),
            )
        }
    };
    let right_cleanup = right_identity.map(|identity| {
        unlink_owned(
            parent.as_raw_fd(),
            &right,
            identity,
            "path-semantics probe destination",
        )
    });
    let left_cleanup = unlink_owned(
        parent.as_raw_fd(),
        &left,
        left_identity,
        "path-semantics probe source",
    );
    let sync = parent.sync_all().map_err(|error| {
        Error::io(
            "STORAGE_RECOVERY_REQUIRED",
            "cannot sync path-semantics probe cleanup",
            error,
        )
    });
    if let Some(Err(error)) = right_cleanup {
        return Err(error);
    }
    left_cleanup?;
    sync?;
    primary?;
    Ok(collision)
}

pub(crate) fn probe_native_cow(parent: &File) -> Result<(), Error> {
    let parent_identity = Identity::from_file(parent)?;
    if !clone_destination_directory(parent_identity) || parent_identity.mode != 0o700 {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "native COW probe parent is not an owned state directory",
        ));
    }
    let serial = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
    let source_name = CString::new(format!(
        ".git-vws-cow-{}-{serial}.source",
        std::process::id()
    ))
    .expect("fixed probe basename");
    let destination_name = CString::new(format!(
        ".git-vws-cow-{}-{serial}.destination",
        std::process::id()
    ))
    .expect("fixed probe basename");
    let mut source_identity = None;
    let mut destination_identity = None;
    let result = (|| {
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                source_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(storage_io("cannot create native COW probe source"));
        }
        let mut source = unsafe { File::from_raw_fd(raw) };
        let mut source_node = Identity::from_file(&source)?;
        source_identity = Some(source_node);
        let probe_payload = vec![b'g'; 64 * 1024];
        source
            .write_all(&probe_payload)
            .and_then(|_| source.sync_all())
            .map_err(|error| {
                Error::io(
                    "STORAGE_UNSUPPORTED",
                    "cannot write native COW probe",
                    error,
                )
            })?;
        chmod(&source, 0o444)?;
        source_node = Identity::from_file(&source)?;
        source_identity = Some(source_node);
        let destination_readonly = native_clone_file(
            parent.as_raw_fd(),
            parent.as_raw_fd(),
            &source_name,
            &destination_name,
            &source,
            source_node,
            0o600,
        )?;
        let destination_node = Identity::from_file(&destination_readonly)?;
        destination_identity = Some(destination_node);
        chmod(&destination_readonly, 0o600)?;
        let destination = open_regular_at(parent.as_raw_fd(), &destination_name, libc::O_RDWR)?;
        let destination_node = Identity::from_file(&destination)?;
        destination_identity = Some(destination_node);
        if source_node.dev != destination_node.dev
            || source_node.ino == destination_node.ino
            || !source_node.regular()
            || !destination_node.regular()
        {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "native COW probe did not create an independent inode",
            ));
        }
        let mut original = [0_u8; 24];
        let mut cloned = [0_u8; 24];
        let source_count = source.read_at(&mut original, 0).map_err(|error| {
            Error::io("STORAGE_UNSUPPORTED", "cannot read COW probe source", error)
        })?;
        let destination_count = destination.read_at(&mut cloned, 0).map_err(|error| {
            Error::io(
                "STORAGE_UNSUPPORTED",
                "cannot read COW probe destination",
                error,
            )
        })?;
        if original[..source_count] != cloned[..destination_count] {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "native COW probe content differs before mutation",
            ));
        }
        destination
            .write_at(b"X", 0)
            .and_then(|_| destination.sync_all())
            .map_err(|error| {
                Error::io(
                    "STORAGE_UNSUPPORTED",
                    "cannot mutate native COW probe destination",
                    error,
                )
            })?;
        let mut source_after = [0_u8; 1];
        source.read_at(&mut source_after, 0).map_err(|error| {
            Error::io(
                "STORAGE_UNSUPPORTED",
                "cannot verify COW probe isolation",
                error,
            )
        })?;
        if source_after != [b'g'] {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "native COW probe mutation changed its source",
            ));
        }
        Ok(())
    })();
    let destination_cleanup = destination_identity.map(|identity| {
        unlink_owned(
            parent.as_raw_fd(),
            &destination_name,
            identity,
            "native COW probe destination",
        )
    });
    let source_cleanup = source_identity.map(|identity| {
        unlink_owned(
            parent.as_raw_fd(),
            &source_name,
            identity,
            "native COW probe source",
        )
    });
    let sync = parent.sync_all().map_err(|error| {
        Error::io(
            "STORAGE_RECOVERY_REQUIRED",
            "cannot sync native COW probe cleanup",
            error,
        )
    });
    if let Some(Err(error)) = destination_cleanup {
        return Err(error);
    }
    if let Some(Err(error)) = source_cleanup {
        return Err(error);
    }
    sync?;
    result
}

#[derive(Clone, Copy)]
enum Walk<'a> {
    Seal,
    Verify,
    Clone(&'a File),
    Worktree,
}

fn walk_tree(
    source: &File,
    prefix: &[u8],
    walk: Walk<'_>,
    hasher: &mut Sha256,
    entries: &mut u64,
) -> Result<(), Error> {
    let source_identity = Identity::from_file(source)?;
    let source_is_private = matches!(walk, Walk::Seal);
    let worktree = matches!(walk, Walk::Worktree);
    let valid_source = if source_is_private {
        private_directory(source_identity)
    } else if worktree {
        worktree_directory(source_identity)
    } else {
        sealed_directory(source_identity)
    };
    if !valid_source || metadata_present_fd(source.as_raw_fd())? {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed-tree directory binding or metadata is unsupported",
        ));
    }
    let destination = match walk {
        Walk::Clone(destination) => Some(destination),
        Walk::Seal | Walk::Verify | Walk::Worktree => None,
    };
    if let Some(destination) = destination {
        if !clone_destination_directory(Identity::from_file(destination)?)
            || metadata_present_fd(destination.as_raw_fd())?
        {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "clone destination directory binding or metadata is unsupported",
            ));
        }
    }
    if worktree && prefix.is_empty() && !linked_worktree_entry(source, c".git")? {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "cloned worktree is missing its private linked-worktree metadata",
        ));
    }
    for bytes in directory_names(source.as_raw_fd())? {
        if worktree && prefix.is_empty() && bytes == b".git" {
            continue;
        }
        validate_basename(&bytes)?;
        let name = cstring(&bytes)?;
        let stat = stat_at(source.as_raw_fd(), &name)?;
        let entry = Identity::from_stat(&stat);
        if entry.uid != current_uid() || entry.dev != source_identity.dev {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "sealed-tree entry changed ownership or volume",
            ));
        }
        let mut path = prefix.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(&bytes);
        match entry.kind {
            kind if kind == DIRECTORY_TYPE => {
                let valid_directory = if source_is_private {
                    private_directory(entry)
                } else if worktree {
                    worktree_directory(entry)
                } else {
                    sealed_directory(entry)
                };
                if !valid_directory {
                    return Err(Error::new(
                        "STORAGE_UNSUPPORTED",
                        "sealed-tree child directory is invalid",
                    ));
                }
                let child = open_directory_at(source.as_raw_fd(), &name)?;
                if !stable_directory_node(Identity::from_file(&child)?, entry) {
                    return Err(Error::new(
                        "STORAGE_UNSUPPORTED",
                        "sealed-tree directory changed while opening",
                    ));
                }
                if let Some(destination) = destination {
                    mkdirat(destination.as_raw_fd(), &name, 0o755)?;
                    let destination_child = open_directory_at(destination.as_raw_fd(), &name)?;
                    if !worktree_directory(Identity::from_file(&destination_child)?) {
                        return Err(Error::new(
                            "STORAGE_UNSUPPORTED",
                            "native COW destination directory is invalid",
                        ));
                    }
                    walk_tree(
                        &child,
                        &path,
                        Walk::Clone(&destination_child),
                        hasher,
                        entries,
                    )?;
                    destination_child.sync_all().map_err(|error| {
                        Error::io(
                            "STORAGE_UNSUPPORTED",
                            "cannot sync nested native COW destination",
                            error,
                        )
                    })?;
                    destination.sync_all().map_err(|error| {
                        Error::io(
                            "STORAGE_UNSUPPORTED",
                            "cannot sync nested native COW destination parent",
                            error,
                        )
                    })?;
                } else {
                    walk_tree(&child, &path, walk, hasher, entries)?;
                }
            }
            kind if kind == REGULAR_TYPE => {
                if !(if worktree {
                    worktree_regular(entry)
                } else {
                    sealed_regular(entry)
                }) {
                    return Err(Error::new(
                        "STORAGE_UNSUPPORTED",
                        "sealed-tree regular file is invalid",
                    ));
                }
                let file = open_regular_at(source.as_raw_fd(), &name, libc::O_RDONLY)?;
                if Identity::from_file(&file)? != entry || metadata_present_fd(file.as_raw_fd())? {
                    return Err(Error::new(
                        "STORAGE_UNSUPPORTED",
                        "sealed-tree regular file binding or metadata changed",
                    ));
                }
                hash_regular(
                    &file,
                    entry,
                    if worktree {
                        sealed_mode(entry.mode)
                    } else {
                        entry.mode
                    },
                    &path,
                    hasher,
                )?;
                if let Some(destination) = destination {
                    clone_regular(
                        source.as_raw_fd(),
                        destination.as_raw_fd(),
                        &name,
                        &file,
                        entry,
                    )?;
                    destination.sync_all().map_err(|error| {
                        Error::io(
                            "STORAGE_UNSUPPORTED",
                            "cannot sync native COW file parent",
                            error,
                        )
                    })?;
                }
                *entries = entries.checked_add(1).ok_or_else(|| {
                    Error::new("STORAGE_UNSUPPORTED", "sealed-tree entry count overflow")
                })?;
            }
            kind if kind == SYMLINK_TYPE => {
                if entry.nlink != 1 || link_metadata_present(source.as_raw_fd(), &name, &stat)? {
                    return Err(Error::new(
                        "STORAGE_UNSUPPORTED",
                        "sealed-tree symbolic link has unsupported metadata",
                    ));
                }
                let target = read_link_at(source.as_raw_fd(), &name)?;
                hash_symlink(target.to_bytes(), &path, hasher);
                if let Some(destination) = destination {
                    if unsafe {
                        libc::symlinkat(target.as_ptr(), destination.as_raw_fd(), name.as_ptr())
                    } != 0
                    {
                        return Err(storage_io("cannot clone symbolic link"));
                    }
                    let destination_stat = stat_at(destination.as_raw_fd(), &name)?;
                    if Identity::from_stat(&destination_stat).kind != SYMLINK_TYPE
                        || link_metadata_present(destination.as_raw_fd(), &name, &destination_stat)?
                        || read_link_at(destination.as_raw_fd(), &name)? != target
                    {
                        return Err(Error::new(
                            "STORAGE_UNSUPPORTED",
                            "cloned symbolic link binding or metadata changed",
                        ));
                    }
                    destination.sync_all().map_err(|error| {
                        Error::io(
                            "STORAGE_UNSUPPORTED",
                            "cannot sync native COW symbolic-link parent",
                            error,
                        )
                    })?;
                }
                *entries = entries.checked_add(1).ok_or_else(|| {
                    Error::new("STORAGE_UNSUPPORTED", "sealed-tree entry count overflow")
                })?;
            }
            _ => {
                return Err(Error::new(
                    "STORAGE_UNSUPPORTED",
                    "sealed tree contains a special file",
                ));
            }
        }
    }
    if matches!(walk, Walk::Seal) {
        chmod(source, 0o555)?;
    }
    let final_identity = Identity::from_file(source)?;
    let valid_final = if worktree {
        worktree_directory(final_identity)
    } else {
        sealed_directory(final_identity)
    };
    if !valid_final || metadata_present_fd(source.as_raw_fd())? {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed-tree directory was not retained as immutable",
        ));
    }
    if matches!(walk, Walk::Seal) {
        source.sync_all().map_err(|error| {
            Error::io(
                "STORAGE_UNSUPPORTED",
                "cannot sync sealed-tree directory",
                error,
            )
        })?;
    }
    lp(hasher, b"directory");
    lp(hasher, prefix);
    lp(hasher, b"555");
    Ok(())
}

fn clone_regular(
    source_parent: RawFd,
    destination_parent: RawFd,
    name: &CStr,
    source: &File,
    source_entry: Identity,
) -> Result<(), Error> {
    let destination = native_clone_file(
        source_parent,
        destination_parent,
        name,
        name,
        source,
        source_entry,
        session_mode(source_entry.mode),
    )?;
    chmod(&destination, session_mode(source_entry.mode))?;
    let entry = Identity::from_file(&destination)?;
    if entry.dev != source_entry.dev
        || entry.ino == source_entry.ino
        || entry.uid != current_uid()
        || entry.nlink != 1
        || !entry.regular()
        || entry.mode != session_mode(source_entry.mode)
        || metadata_present_fd(destination.as_raw_fd())?
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "native COW destination metadata is unsupported",
        ));
    }
    destination
        .sync_all()
        .map_err(|error| Error::io("STORAGE_UNSUPPORTED", "cannot sync cloned file", error))
}

fn native_clone_file(
    source_parent: RawFd,
    destination_parent: RawFd,
    source_name: &CStr,
    destination_name: &CStr,
    source: &File,
    expected_source: Identity,
    destination_mode: u32,
) -> Result<File, Error> {
    #[cfg(target_os = "macos")]
    {
        const CLONE_NOFOLLOW: libc::c_uint = 0x0001;
        let _ = destination_mode;
        if unsafe {
            libc::clonefileat(
                source_parent,
                source_name.as_ptr(),
                destination_parent,
                destination_name.as_ptr(),
                CLONE_NOFOLLOW,
            )
        } != 0
        {
            return Err(storage_io(
                "clonefileat cannot provide native copy-on-write",
            ));
        }
        let destination_identity = identity_at(destination_parent, destination_name)?;
        let destination =
            match open_regular_at(destination_parent, destination_name, libc::O_RDONLY) {
                Ok(destination) => destination,
                Err(error) => {
                    return Err(cleanup_clone_destination(
                        destination_parent,
                        destination_name,
                        destination_identity,
                        "clonefileat destination",
                        error,
                    ));
                }
            };
        let result = (|| {
            if Identity::from_file(source)? != expected_source
                || Identity::from_stat(&stat_at(source_parent, source_name)?) != expected_source
                || Identity::from_file(&destination)? != destination_identity
                || Identity::from_stat(&stat_at(destination_parent, destination_name)?)
                    != destination_identity
            {
                return Err(Error::new(
                    "STORAGE_UNSUPPORTED",
                    "clonefileat descriptor or basename binding changed",
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            drop(destination);
            return Err(cleanup_clone_destination(
                destination_parent,
                destination_name,
                destination_identity,
                "clonefileat destination",
                error,
            ));
        }
        Ok(destination)
    }
    #[cfg(target_os = "linux")]
    {
        let raw = unsafe {
            libc::openat(
                destination_parent,
                destination_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                destination_mode,
            )
        };
        if raw < 0 {
            return Err(storage_io("cannot create FICLONE destination"));
        }
        let destination = unsafe { File::from_raw_fd(raw) };
        let destination_identity = Identity::from_file(&destination)?;
        let cleanup = |primary| {
            cleanup_clone_destination(
                destination_parent,
                destination_name,
                destination_identity,
                "FICLONE destination",
                primary,
            )
        };
        if Identity::from_file(source)? != expected_source
            || Identity::from_stat(&stat_at(source_parent, source_name)?) != expected_source
        {
            return Err(cleanup(Error::new(
                "STORAGE_UNSUPPORTED",
                "FICLONE source binding changed before clone",
            )));
        }
        if unsafe {
            libc::ioctl(
                destination.as_raw_fd(),
                libc::FICLONE as libc::c_ulong,
                source.as_raw_fd(),
            )
        } != 0
        {
            return Err(cleanup(storage_io(
                "FICLONE cannot provide native copy-on-write",
            )));
        }
        let shared = match fiemap_proves_shared(source, &destination) {
            Ok(shared) => shared,
            Err(error) => return Err(cleanup(error)),
        };
        if !shared {
            return Err(cleanup(Error::new(
                "STORAGE_UNSUPPORTED",
                "FICLONE did not provide shared-extent evidence",
            )));
        }
        if Identity::from_file(&destination)?
            != Identity::from_stat(&stat_at(destination_parent, destination_name)?)
        {
            return Err(cleanup(Error::new(
                "STORAGE_UNSUPPORTED",
                "FICLONE destination binding changed after clone",
            )));
        }
        Ok(destination)
    }
}

fn linked_worktree_metadata(directory: &File) -> Result<bool, Error> {
    let names = directory_names(directory.as_raw_fd())?;
    Ok(names.len() == 1 && names[0] == b".git" && linked_worktree_entry(directory, c".git")?)
}

fn linked_worktree_entry(directory: &File, name: &CStr) -> Result<bool, Error> {
    let entry = Identity::from_stat(&stat_at(directory.as_raw_fd(), name)?);
    if !entry.regular() || entry.uid != current_uid() || entry.nlink != 1 || entry.mode & 0o022 != 0
    {
        return Ok(false);
    }
    let file = open_regular_at(directory.as_raw_fd(), name, libc::O_RDONLY)?;
    Ok(Identity::from_file(&file)? == entry && !metadata_present_fd(file.as_raw_fd())?)
}

fn hash_regular(
    file: &File,
    entry: Identity,
    digest_mode: u32,
    path: &[u8],
    hasher: &mut Sha256,
) -> Result<(), Error> {
    let size = file
        .metadata()
        .map_err(|error| {
            Error::io(
                "STORAGE_UNSUPPORTED",
                "cannot stat sealed regular file",
                error,
            )
        })?
        .len();
    lp(hasher, b"file");
    lp(hasher, path);
    lp(hasher, format!("{:o}", digest_mode).as_bytes());
    lp(hasher, &size.to_be_bytes());
    let mut file = file.try_clone().map_err(|error| {
        Error::io(
            "STORAGE_UNSUPPORTED",
            "cannot duplicate sealed regular descriptor",
            error,
        )
    })?;
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..length]).map_err(|error| {
            Error::io(
                "STORAGE_UNSUPPORTED",
                "cannot read sealed regular file",
                error,
            )
        })?;
        if count == 0 {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "sealed regular file was truncated",
            ));
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if Identity::from_file(&file)? != entry
        || file
            .metadata()
            .map_err(|error| {
                Error::io(
                    "STORAGE_UNSUPPORTED",
                    "cannot restat sealed regular file",
                    error,
                )
            })?
            .len()
            != size
    {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed regular file changed while hashing",
        ));
    }
    Ok(())
}

fn hash_symlink(target: &[u8], path: &[u8], hasher: &mut Sha256) {
    lp(hasher, b"symlink");
    lp(hasher, path);
    lp(hasher, b"120000");
    lp(hasher, &(target.len() as u64).to_be_bytes());
    hasher.update(target);
}

fn content_hasher() -> Sha256 {
    let mut hasher = Sha256::new();
    lp(&mut hasher, b"git-vws/template-content/v1");
    hasher
}

fn filesystem_kind(directory: &File) -> Result<String, Error> {
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } != 0 {
        return Err(storage_io("cannot inspect native COW filesystem"));
    }
    let fsid = unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(stat.f_fsid).cast::<u64>()) };
    #[cfg(target_os = "macos")]
    {
        let kind = unsafe { CStr::from_ptr(stat.f_fstypename.as_ptr()) }.to_bytes();
        if kind != b"apfs" {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "native COW requires an APFS volume on macOS",
            ));
        }
        Ok(format!("apfs:{fsid:016x}"))
    }
    #[cfg(target_os = "linux")]
    {
        let kind = stat.f_type as u64;
        if matches!(kind, 0x0102_1994 | 0x6969 | 0x794c_7630) {
            return Err(Error::new(
                "STORAGE_UNSUPPORTED",
                "native COW is unavailable on this Linux filesystem",
            ));
        }
        Ok(format!("linux-{kind:x}:{fsid:016x}"))
    }
}

#[cfg(target_os = "macos")]
fn mount_id(directory: &File) -> Result<u64, Error> {
    Ok(Identity::from_file(directory)?.dev)
}

#[cfg(target_os = "linux")]
fn mount_id(directory: &File) -> Result<u64, Error> {
    let mut stat: libc::statx = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::statx(
            directory.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_MNT_ID,
            &mut stat,
        )
    } != 0
    {
        return Err(storage_io("cannot obtain Linux mount id"));
    }
    if stat.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "Linux did not return a mount id for native COW",
        ));
    }
    Ok(stat.stx_mnt_id)
}

pub(crate) fn private_directory(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode == 0o700
        && identity.nlink >= 2
}

pub(crate) fn sealed_directory(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode == 0o555
        && identity.nlink >= 2
}

pub(crate) fn sealed_regular(identity: Identity) -> bool {
    identity.regular()
        && identity.uid == current_uid()
        && identity.nlink == 1
        && matches!(identity.mode, 0o444 | 0o555)
}

fn worktree_directory(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && identity.mode == 0o755
        && identity.nlink >= 2
}

fn worktree_regular(identity: Identity) -> bool {
    identity.regular()
        && identity.uid == current_uid()
        && identity.nlink == 1
        && matches!(identity.mode, 0o644 | 0o755)
}

fn sealed_mode(mode: u32) -> u32 {
    if mode == 0o755 {
        0o555
    } else {
        0o444
    }
}

fn clone_destination_directory(identity: Identity) -> bool {
    identity.directory()
        && identity.uid == current_uid()
        && matches!(identity.mode, 0o700 | 0o755)
        && identity.nlink >= 2
}

fn stable_directory_node(current: Identity, expected: Identity) -> bool {
    current.directory() && expected.directory() && current.same_node(expected)
}

#[cfg(test)]
#[test]
fn stable_directory_node_allows_only_link_count_drift() {
    let expected = Identity {
        dev: 1,
        ino: 2,
        uid: 3,
        mode: 0o700,
        kind: DIRECTORY_TYPE,
        nlink: 2,
    };
    let mut link_drift = expected;
    link_drift.nlink = 9;
    assert!(stable_directory_node(link_drift, expected));
    for current in [
        Identity { dev: 4, ..expected },
        Identity { ino: 4, ..expected },
        Identity { uid: 4, ..expected },
        Identity {
            mode: 0o755,
            ..expected
        },
        Identity {
            kind: REGULAR_TYPE,
            ..expected
        },
    ] {
        assert!(!stable_directory_node(current, expected));
    }
}

fn session_mode(source_mode: u32) -> u32 {
    if source_mode == 0o555 {
        0o755
    } else {
        0o644
    }
}

pub(crate) fn identity_at(parent: RawFd, name: &CStr) -> Result<Identity, Error> {
    Ok(Identity::from_stat(&stat_at(parent, name)?))
}

fn stat_at(parent: RawFd, name: &CStr) -> Result<libc::stat, Error> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        Err(storage_io("cannot stat native COW entry"))
    } else {
        Ok(stat)
    }
}

pub(crate) fn open_directory_at(parent: RawFd, name: &CStr) -> Result<File, Error> {
    let raw = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        Err(storage_io("cannot open native COW directory"))
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

fn open_regular_at(parent: RawFd, name: &CStr, access: libc::c_int) -> Result<File, Error> {
    let raw = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        Err(storage_io("cannot open native COW regular file"))
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

fn mkdirat(parent: RawFd, name: &CStr, mode: u32) -> Result<(), Error> {
    if unsafe { libc::mkdirat(parent, name.as_ptr(), mode as libc::mode_t) } != 0 {
        Err(storage_io("cannot create native COW directory"))
    } else {
        Ok(())
    }
}

fn read_link_at(parent: RawFd, name: &CStr) -> Result<CString, Error> {
    let mut buffer = [0_u8; MAX_SYMLINK + 1];
    let count = unsafe {
        libc::readlinkat(
            parent,
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if count < 0 {
        return Err(storage_io("cannot read sealed symbolic link"));
    }
    if count as usize > MAX_SYMLINK {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed symbolic link exceeds the supported limit",
        ));
    }
    CString::new(&buffer[..count as usize])
        .map_err(|_| Error::new("STORAGE_UNSUPPORTED", "symbolic link contains NUL"))
}

pub(crate) fn directory_names(fd: RawFd) -> Result<Vec<Vec<u8>>, Error> {
    let stream_fd = unsafe {
        libc::openat(
            fd,
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if stream_fd < 0 {
        return Err(storage_io("cannot enumerate native COW directory"));
    }
    let directory = unsafe { libc::fdopendir(stream_fd) };
    if directory.is_null() {
        unsafe { libc::close(stream_fd) };
        return Err(storage_io("cannot open native COW directory stream"));
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
                    "STORAGE_UNSUPPORTED",
                    "cannot enumerate native COW directory",
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
        return Err(storage_io("cannot close native COW directory stream"));
    }
    names.sort();
    Ok(names)
}

fn metadata_present_fd(fd: RawFd) -> Result<bool, Error> {
    Ok(has_xattrs_fd(fd)? || has_acl_fd(fd)? || has_platform_flags_fd(fd)?)
}

#[cfg(target_os = "macos")]
fn macos_xattr_name_list_allowed(names: &[u8]) -> bool {
    names.is_empty() || names == b"com.apple.provenance\0"
}

#[cfg(target_os = "macos")]
fn macos_xattr_names(
    mut list: impl FnMut(*mut libc::c_char, usize) -> libc::ssize_t,
    context: &str,
) -> Result<Vec<u8>, Error> {
    let size = list(std::ptr::null_mut(), 0);
    if size < 0 {
        return Err(storage_io(context));
    }
    let mut names = vec![0; size as usize];
    let count = list(names.as_mut_ptr().cast(), names.len());
    if count < 0 {
        return Err(storage_io(context));
    }
    if count != size {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "native COW xattr list changed while reading",
        ));
    }
    Ok(names)
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn macos_xattr_name_list_accepts_only_provenance() {
    for names in [b"".as_slice(), b"com.apple.provenance\0".as_slice()] {
        assert!(macos_xattr_name_list_allowed(names));
    }
    for names in [
        b"com.apple.quarantine\0".as_slice(),
        b"com.apple.provenance\0user.note\0".as_slice(),
        b"com.apple.provenance\0com.apple.provenance\0".as_slice(),
        b"\0".as_slice(),
        b"com.apple.provenance".as_slice(),
        b"com.apple.provenance\0\0".as_slice(),
        b"com.apple.Provenance\0".as_slice(),
    ] {
        assert!(!macos_xattr_name_list_allowed(names));
    }
}

#[cfg(target_os = "macos")]
fn link_metadata_present(parent: RawFd, name: &CStr, _stat: &libc::stat) -> Result<bool, Error> {
    let expected = Identity::from_stat(_stat);
    let raw = unsafe { libc::openat(parent, name.as_ptr(), libc::O_SYMLINK | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(storage_io("cannot inspect symbolic-link xattrs"));
    }
    let link = unsafe { File::from_raw_fd(raw) };
    if Identity::from_file(&link)? != expected {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "symbolic-link xattr descriptor binding changed",
        ));
    }
    let first_flags = has_platform_flags_fd(link.as_raw_fd())?;
    let names = macos_xattr_names(
        |list, size| unsafe { libc::flistxattr(link.as_raw_fd(), list, size, 0) },
        "cannot inspect symbolic-link xattrs",
    )?;
    let final_identity = Identity::from_file(&link)?;
    let final_flags = has_platform_flags_fd(link.as_raw_fd())?;
    let final_stat = stat_at(parent, name)?;
    if final_identity != expected || Identity::from_stat(&final_stat) != expected {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "symbolic-link xattr descriptor binding changed",
        ));
    }
    Ok(has_platform_flags(_stat)
        || first_flags
        || final_flags
        || has_platform_flags(&final_stat)
        || !macos_xattr_name_list_allowed(&names))
}

#[cfg(target_os = "linux")]
fn link_metadata_present(parent: RawFd, name: &CStr, _stat: &libc::stat) -> Result<bool, Error> {
    #[cfg(target_os = "linux")]
    let size = unsafe {
        libc::llistxattr(
            descriptor_link(parent, name).as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size < 0 {
        return Err(Error::io(
            "STORAGE_UNSUPPORTED",
            "cannot inspect symbolic-link xattrs",
            io::Error::last_os_error(),
        ));
    }
    #[cfg(target_os = "linux")]
    Ok(size > 0)
}

#[cfg(target_os = "linux")]
fn descriptor_link(parent: RawFd, name: &CStr) -> CString {
    #[cfg(target_os = "macos")]
    let prefix = format!("/dev/fd/{parent}/");
    #[cfg(target_os = "linux")]
    let prefix = format!("/proc/self/fd/{parent}/");
    let mut bytes = prefix.into_bytes();
    bytes.extend_from_slice(name.to_bytes());
    CString::new(bytes).expect("descriptor path has no NUL")
}

#[cfg(target_os = "macos")]
fn has_xattrs_fd(fd: RawFd) -> Result<bool, Error> {
    #[cfg(target_os = "macos")]
    {
        let names = macos_xattr_names(
            |list, size| unsafe { libc::flistxattr(fd, list, size, 0) },
            "cannot inspect native COW xattrs",
        )?;
        Ok(!macos_xattr_name_list_allowed(&names))
    }
}

#[cfg(target_os = "linux")]
fn has_xattrs_fd(fd: RawFd) -> Result<bool, Error> {
    #[cfg(target_os = "linux")]
    let size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(Error::io(
            "STORAGE_UNSUPPORTED",
            "cannot inspect native COW xattrs",
            io::Error::last_os_error(),
        ));
    }
    Ok(size > 0)
}

#[cfg(target_os = "macos")]
fn has_acl_fd(fd: RawFd) -> Result<bool, Error> {
    unsafe {
        let acl = acl_get_fd_np(fd, 0x100);
        if acl.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(Error::io(
                "STORAGE_UNSUPPORTED",
                "cannot inspect native COW ACL",
                error,
            ));
        }
        if acl_free(acl) != 0 {
            return Err(storage_io("cannot release native COW ACL"));
        }
        Ok(true)
    }
}

#[cfg(target_os = "linux")]
fn has_acl_fd(_fd: RawFd) -> Result<bool, Error> {
    Ok(false)
}

fn has_platform_flags_fd(fd: RawFd) -> Result<bool, Error> {
    #[cfg(target_os = "macos")]
    {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            return Err(storage_io("cannot inspect native COW file flags"));
        }
        Ok(has_platform_flags(&stat))
    }
    #[cfg(target_os = "linux")]
    {
        let mut flags: libc::c_int = 0;
        if unsafe { libc::ioctl(fd, libc::FS_IOC_GETFLAGS as libc::c_ulong, &mut flags) } != 0 {
            return Err(storage_io("cannot inspect native COW file flags"));
        }
        Ok(flags != 0)
    }
}

#[cfg(target_os = "macos")]
fn has_platform_flags(stat: &libc::stat) -> bool {
    stat.st_flags != 0
}

fn chmod(file: &File, mode: u32) -> Result<(), Error> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        Err(storage_io("cannot set native COW file mode"))
    } else {
        Ok(())
    }
}

fn unlink_owned(parent: RawFd, name: &CStr, expected: Identity, label: &str) -> Result<(), Error> {
    let current = identity_at(parent, name)?;
    if current != expected || current.uid != current_uid() || !current.regular() {
        return Err(Error::new(
            "STORAGE_UNSUPPORTED",
            format!("{label} identity changed before cleanup"),
        ));
    }
    if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } != 0 {
        Err(storage_io("cannot clean up native COW probe"))
    } else {
        Ok(())
    }
}

fn cleanup_clone_destination(
    parent: RawFd,
    name: &CStr,
    expected: Identity,
    label: &str,
    primary: Error,
) -> Error {
    if let Err(error) = unlink_owned(parent, name, expected, label) {
        return error;
    }
    if unsafe { libc::fsync(parent) } != 0 {
        return Error::io(
            "STORAGE_RECOVERY_REQUIRED",
            "cannot sync native COW destination parent after cleanup",
            io::Error::last_os_error(),
        );
    }
    primary
}

pub(crate) fn remove_owned_tree(
    parent: &File,
    name: &CStr,
    expected: Identity,
) -> Result<(), Error> {
    if !stable_directory_node(identity_at(parent.as_raw_fd(), name)?, expected)
        || !private_directory(expected)
    {
        return Err(Error::new(
            "STORAGE_RECOVERY_REQUIRED",
            "owned tree binding changed before cleanup",
        ));
    }
    let root = open_directory_at(parent.as_raw_fd(), name)?;
    if !stable_directory_node(Identity::from_file(&root)?, expected) {
        return Err(Error::new(
            "STORAGE_RECOVERY_REQUIRED",
            "owned tree descriptor changed before cleanup",
        ));
    }
    remove_owned_children(&root, expected.dev)?;
    if !stable_directory_node(identity_at(parent.as_raw_fd(), name)?, expected) {
        return Err(Error::new(
            "STORAGE_RECOVERY_REQUIRED",
            "owned tree binding changed during cleanup",
        ));
    }
    drop(root);
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(storage_io("cannot remove owned tree root"));
    }
    parent.sync_all().map_err(|error| {
        Error::io(
            "STORAGE_RECOVERY_REQUIRED",
            "cannot sync owned tree cleanup parent",
            error,
        )
    })
}

fn remove_owned_children(directory: &File, device: u64) -> Result<(), Error> {
    let directory_identity = Identity::from_file(directory)?;
    if !directory_identity.directory()
        || directory_identity.uid != current_uid()
        || directory_identity.dev != device
    {
        return Err(Error::new(
            "STORAGE_RECOVERY_REQUIRED",
            "owned tree directory drifted during cleanup",
        ));
    }
    for bytes in directory_names(directory.as_raw_fd())? {
        let name = cstring(&bytes)?;
        let entry = identity_at(directory.as_raw_fd(), &name)?;
        if entry.uid != current_uid() || entry.dev != device {
            return Err(Error::new(
                "STORAGE_RECOVERY_REQUIRED",
                "owned tree entry drifted during cleanup",
            ));
        }
        match entry.kind {
            kind if kind == DIRECTORY_TYPE => {
                let child = open_directory_at(directory.as_raw_fd(), &name)?;
                if !stable_directory_node(Identity::from_file(&child)?, entry) {
                    return Err(Error::new(
                        "STORAGE_RECOVERY_REQUIRED",
                        "owned tree child binding changed before cleanup",
                    ));
                }
                remove_owned_children(&child, device)?;
                if !stable_directory_node(identity_at(directory.as_raw_fd(), &name)?, entry) {
                    return Err(Error::new(
                        "STORAGE_RECOVERY_REQUIRED",
                        "owned tree child binding changed during cleanup",
                    ));
                }
                drop(child);
                if unsafe {
                    libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                } != 0
                {
                    return Err(storage_io("cannot remove owned tree directory"));
                }
            }
            kind if kind == REGULAR_TYPE || kind == SYMLINK_TYPE => {
                if identity_at(directory.as_raw_fd(), &name)? != entry {
                    return Err(Error::new(
                        "STORAGE_RECOVERY_REQUIRED",
                        "owned tree entry binding changed before cleanup",
                    ));
                }
                if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(storage_io("cannot remove owned tree entry"));
                }
            }
            _ => {
                return Err(Error::new(
                    "STORAGE_RECOVERY_REQUIRED",
                    "owned tree contains a special entry during cleanup",
                ));
            }
        }
    }
    directory.sync_all().map_err(|error| {
        Error::io(
            "STORAGE_RECOVERY_REQUIRED",
            "cannot sync owned tree directory cleanup",
            error,
        )
    })
}

fn validate_basename(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.eq_ignore_ascii_case(b".git")
    {
        Err(Error::new(
            "STORAGE_UNSUPPORTED",
            "sealed tree contains an invalid pathname component",
        ))
    } else {
        Ok(())
    }
}

fn cstring(bytes: &[u8]) -> Result<CString, Error> {
    CString::new(bytes).map_err(|_| Error::new("STORAGE_UNSUPPORTED", "pathname contains NUL"))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn lp(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn storage_io(context: &str) -> Error {
    Error::io("STORAGE_UNSUPPORTED", context, io::Error::last_os_error())
}

#[cfg(target_os = "linux")]
fn fiemap_proves_shared(source: &File, destination: &File) -> Result<bool, Error> {
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
    const REQUEST: libc::c_ulong = 0xc020_660b;
    const SYNC: u32 = 0x0000_0001;
    const LAST: u32 = 0x0000_0001;
    const UNKNOWN: u32 = 0x0000_0002;
    const DELALLOC: u32 = 0x0000_0004;
    const ENCODED: u32 = 0x0000_0008;
    const DATA_ENCRYPTED: u32 = 0x0000_0080;
    const NOT_ALIGNED: u32 = 0x0000_0100;
    const INLINE: u32 = 0x0000_0200;
    const TAIL: u32 = 0x0000_0400;
    const UNWRITTEN: u32 = 0x0000_0800;
    const SHARED: u32 = 0x0000_2000;
    let source_size = source
        .metadata()
        .map_err(|error| Error::io("STORAGE_UNSUPPORTED", "cannot stat FIEMAP source", error))?
        .len();
    if source_size
        != destination
            .metadata()
            .map_err(|error| {
                Error::io(
                    "STORAGE_UNSUPPORTED",
                    "cannot stat FIEMAP destination",
                    error,
                )
            })?
            .len()
    {
        return Ok(false);
    }
    let mut source_map: Buffer = unsafe { std::mem::zeroed() };
    let mut destination_map: Buffer = unsafe { std::mem::zeroed() };
    for map in [&mut source_map, &mut destination_map] {
        map.map.length = u64::MAX;
        map.map.flags = SYNC;
        map.map.extent_count = map.extents.len() as u32;
    }
    if unsafe { libc::ioctl(source.as_raw_fd(), REQUEST, &mut source_map) } != 0
        || unsafe { libc::ioctl(destination.as_raw_fd(), REQUEST, &mut destination_map) } != 0
    {
        return Err(storage_io("cannot obtain FIEMAP shared-extent evidence"));
    }
    let count = source_map.map.mapped as usize;
    if count != destination_map.map.mapped as usize || count > source_map.extents.len() {
        return Ok(false);
    }
    if count == 0 {
        return Ok(source_size == 0);
    }
    if source_map.extents[count - 1].flags & LAST == 0
        || destination_map.extents[count - 1].flags & LAST == 0
    {
        return Ok(false);
    }
    let forbidden =
        UNKNOWN | DELALLOC | ENCODED | DATA_ENCRYPTED | NOT_ALIGNED | INLINE | TAIL | UNWRITTEN;
    let mut covered = 0_u64;
    for (index, (left, right)) in source_map.extents[..count]
        .iter()
        .zip(&destination_map.extents[..count])
        .enumerate()
    {
        let last = index + 1 == count;
        if left.logical != covered
            || left.logical != right.logical
            || left.physical != right.physical
            || left.length == 0
            || left.length != right.length
            || left.flags & forbidden != 0
            || right.flags & forbidden != 0
            || left.flags & SHARED == 0
            || right.flags & SHARED == 0
            || (left.flags & LAST != 0) != last
            || (right.flags & LAST != 0) != last
        {
            return Ok(false);
        }
        let Some(next) = covered.checked_add(left.length) else {
            return Ok(false);
        };
        covered = next;
    }
    Ok(covered == source_size)
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}
