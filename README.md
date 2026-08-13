# git-vws

[![CI](https://github.com/Fuxx-1/git-vws/actions/workflows/ci.yml/badge.svg)](https://github.com/Fuxx-1/git-vws/actions/workflows/ci.yml)

`git-vws` is a native copy-on-write virtual worktree prototype for bare Git repositories. It creates isolated private Git metadata and worktree directories while sharing unchanged file data through APFS clones on macOS or `FICLONE` on supported Linux filesystems.

This is an alpha build. The implemented command surface is currently limited to:

```text
git vws init <bare-path>
git vws create <name> [--from <rev>] [--target <branch>] [--path <managed-path>]
```

`list`, `exec`, `remove`, `publish`, `gc`, and `doctor` are not included yet. Do not use this alpha as the only copy of important work.

## Requirements

- Git 2.34 or newer.
- macOS on APFS, or Linux on a filesystem that provides `FICLONE` and matching shared-extent `FIEMAP` evidence.
- No FUSE driver, kernel extension, administrator installation, daemon, or network service.

Unsupported filesystems fail with `STORAGE_UNSUPPORTED`; `git-vws` does not silently fall back to a full worktree copy.

## Install

Download the archive for your platform from the private repository's [Releases](https://github.com/Fuxx-1/git-vws/releases), verify it against `SHA256SUMS`, and place `git-vws` on `PATH`. Git then discovers it as an external subcommand:

```sh
git vws -h
```

## Build

Rust 1.85 or newer is required.

```sh
cargo build --locked --release
cargo test --locked --all-targets -- --test-threads=1
```

The GitHub workflow runs macOS tests on APFS and Linux tests inside an ephemeral XFS `reflink=1` filesystem. The Linux job treats failure to obtain `FICLONE` plus shared `FIEMAP` extents as a failed release gate rather than a skipped test.
