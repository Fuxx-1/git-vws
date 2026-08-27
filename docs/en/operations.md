# Operations

[English](operations.md) | [中文](../zh/operations.md) | [Back to English README](README.md)

This page describes installation, normal session use, publication, cleanup, and recovery. Keep the exact session root printed by create; it is the only path that should be edited for that session.

## Install

Build from source or download the matching archive from GitHub Releases. Put the git-vws executable on PATH, then verify that Git discovers it:

    git vws --version
    git vws -h

The current release supports macOS APFS and Linux filesystems that pass the native COW checks. It does not install FUSE, a kernel extension, a background service, or an administrator helper.

## Session lifecycle

    git vws init /path/to/project
    git vws --repo /path/to/project create feature-a --target feature/a
    git vws --repo /path/to/project list
    git vws --repo /path/to/project exec feature-a -- "$SHELL"

Edit the printed session-root/worktree directory with any editor. Use ordinary Git there:

    git status
    git diff
    git add .
    git commit -m "Implement feature"
    git checkout other-branch
    git rebase main

The parent project worktree remains usable. A session has private Git metadata, branch state, index, uncommitted edits, and build output; it does not lock the parent directory.

## Publish

publish publishes committed session work to the session target branch. It first validates the private commit closure, imports missing objects into the authority, and performs an expected-old CAS on the target ref. It never creates a commit and never publishes uncommitted files.

    git vws --repo /path/to/project publish feature-a

New-target, same-tip, and fast-forward publication are supported. If another writer changes the target before the CAS, the command returns a conflict and leaves that writer's ref untouched. Rebase or merge in the session, then retry. A recovery-required result means the CAS outcome is not safely replayable; preserve the session and run doctor.

## Remove and garbage collection

Remove a clean session normally:

    git vws --repo /path/to/project remove feature-a
    git vws gc

Removal refuses tracked, untracked, ignored, or private Git content that may be lost. --force is explicit and destructive; it does not bypass integrity or recovery checks. Removal first uses a tombstone transition so an interrupted cleanup remains diagnosable.

gc performs a complete census and removes only unreferenced templates, private objects, session tombstones, and cache snapshots. It is safe to run repeatedly after successful cleanup.

## Doctor and recovery

doctor inspects registered state without deleting it:

    git vws doctor
    git vws doctor | jq -c .

On SESSION_RECOVERY_REQUIRED, PUBLISH_RECOVERY_REQUIRED, CACHE_RECOVERY_REQUIRED, GC_RECOVERY_REQUIRED, SESSION_CORRUPT, or a related nonzero result, stop destructive actions. Preserve $HOME/.git-vws, keep the printed session root, and use doctor output to identify the affected record. Do not manually delete state files.

Busy sessions are reported rather than forcibly detached. Stop editors, shells, compilers, and child processes that use the session, then retry the ordinary command.

## Cache operations

To share expensive but non-Git data safely, list directories in .vwscached, create a session, build there, and capture it after Git becomes clean:

    printf 'target/\nnode_modules/\n' > .vwscached
    git vws --repo . create build-a
    git vws --repo . exec build-a -- cargo build
    git vws --repo . cache build-a

The snapshot is immutable and each new session receives an independent writable COW copy. Cache data is neither committed nor published. Run git vws gc after removing sessions to reclaim snapshots no longer referenced by any live session.

## Release verification

Download the archive and SHA256SUMS, verify the archive digest, and inspect the included BUILD-METADATA.json. Public releases also include the SPDX SBOM, third-party license inventory, and PROVENANCE.sigstore.json. GitHub CLI can verify an asset's attestation using the source commit and immutable signer workflow recorded in the release notes.
