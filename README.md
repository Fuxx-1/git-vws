# git-vws

[![CI](https://github.com/Fuxx-1/git-vws/actions/workflows/ci.yml/badge.svg)](https://github.com/Fuxx-1/git-vws/actions/workflows/ci.yml)

`git-vws` provides native copy-on-write virtual worktrees for bare Git repositories. Each session has private Git metadata, branch state, index, working changes, and build output while unchanged file data is shared through APFS clones on macOS or `FICLONE` on supported Linux filesystems.

This is an alpha build. Back up important repositories and review command output before removing sessions or publishing branches.

## Commands

```text
git vws init <bare-path>
git vws create <name> [--from <rev>] [--target <branch>] [--path <managed-path>]
git vws list [--all]
git vws exec <name> -- <program> [args...]
git vws remove <name> [--force]
git vws publish <name>
git vws doctor
git vws gc
```

Commands that operate on one repository use the current directory by default. Pass `--repo <bare-path>` before the subcommand to select another authority repository. `list --all`, `doctor`, and `gc` operate on the registered repository set and do not accept `--repo`.

`publish` supports new-target creation, same-tip publication, and fast-forward expected-old CAS. If another writer changes the target first, publication fails without overwriting that update.

## Requirements

- Git 2.34 or newer.
- macOS on APFS, or Linux on a filesystem that provides `FICLONE` and matching shared-extent `FIEMAP` evidence.
- No FUSE driver, kernel extension, administrator installation, daemon, or network service.

Unsupported filesystems fail with `STORAGE_UNSUPPORTED`; `git-vws` does not silently fall back to a full worktree copy.

## Install

Download the archive for your platform from the private repository's [Releases](https://github.com/Fuxx-1/git-vws/releases), verify it against `SHA256SUMS`, and place `git-vws` on `PATH`. Each release also includes per-archive checksums, an SPDX 2.3 SBOM, a third-party license inventory, build metadata, and GitHub artifact attestations.

After installation, Git discovers the binary as an external subcommand:

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
