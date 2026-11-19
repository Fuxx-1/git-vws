# Configuration

[English](configuration.md) | [中文](../zh/configuration.md) | [Back to English README](README.md)

git-vws keeps its operational state under $HOME/.git-vws. There is no runtime configuration file for the extension itself. Repository selection is explicit with --repo, or inferred from the current directory for commands that operate on one authority.

## Repository selection

init accepts an existing bare repository, an ordinary project directory, or that project's .git directory. An ordinary project is registered by its canonical .git path. The authority must be a sole Git directory: its git-dir and common-dir must be identical, and it must not already contain linked-worktree registration or object alternates.

    git vws init /path/to/project
    git vws init /path/to/repository.git
    git vws --repo /path/to/project create feature-a

list --all, doctor, and gc operate on every registered authority and cannot be combined with --repo.

## Create options

    git vws create NAME [--from REV] [--target BRANCH] [--path MANAGED_PATH]

NAME identifies the local session. By default it is also the publication target branch. --target selects another branch, and --from selects the starting commit. Without either option, an existing target tip is used; if the target does not exist, the authority HEAD is used.

--path is an advanced assertion for recovery and topology checks. It must match the exact managed session root and is not a general-purpose output directory option.

## Non-Git cache manifest

.vwscached is an optional project file. It is intentionally the inverse of .gitignore: each nonempty, non-comment line names one repository-relative directory whose contents may be captured and reused.

    # .vwscached
    target/
    node_modules/
    .gradle/

The parser accepts literal paths only. Paths cannot be absolute, contain glob characters, name .git or .vwscached, escape the project, overlap another entry, or refer to a regular file. A missing directory is recorded as an empty selection; an old snapshot is never used as a substitute.

The cache key includes the authority identity, base commit, exact manifest bytes, configured path, content digest, and state-root volume. This prevents a cache from silently crossing repositories, commits, configuration revisions, or incompatible storage volumes.

## Cache lifecycle

Create a session after adding .vwscached, build in its normal worktree, and capture only after Git is clean:

    git vws --repo . create build-cache
    git vws --repo . exec build-cache -- cargo build
    git vws --repo . cache build-cache

The captured tree is sealed and immutable. A later session receives its own writable native-COW copy. Cache directories are excluded from that session's Git status through its private core.excludesFile; they are not part of a commit and are never included in publish.

git vws cache rejects dirty Git state, unsafe entries, and inconsistent receipts. git vws gc removes only snapshots that the complete session census proves unreferenced.

## Storage requirements

The state root and all native-COW trees must be on one supported volume. macOS requires APFS and uses the platform clone primitive. Linux requires FICLONE plus verified shared FIEMAP extents. Unsupported filesystems return STORAGE_UNSUPPORTED; git-vws does not silently perform a full copy.

Measured on Linux:

| Filesystem | Supported | Notes |
| --- | --- | --- |
| XFS | Yes | Must be created with `mkfs.xfs -m reflink=1` |
| btrfs | Yes | Native reflink |
| **ext4** | **No** | The kernel has no reflink support, so FICLONE returns EOPNOTSUPP (errno 95) |
| tmpfs / NFS / overlayfs | No | No reflink capability |

init does not probe storage; the first create fails when COW is probed. If the state root lands on ext4, move $HOME/.git-vws to an XFS or btrfs volume.

The current release rejects LFS, submodules, sparse or partial clone layouts, clean/smudge filters, and unsupported ACL, xattr, file-flag, special-file, or hard-link combinations.

## Names and machine output

Session names are OS byte strings. Human-readable names are accepted normally; exec, cache, and remove also accept --name-hex when an exact lowercase hexadecimal byte sequence is required. list, doctor, and gc emit NDJSON so scripts can process one record at a time.
