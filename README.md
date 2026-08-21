# git-vws

[![CI](https://github.com/Fuxx-1/git-vws/actions/workflows/ci.yml/badge.svg)](https://github.com/Fuxx-1/git-vws/actions/workflows/ci.yml)

`git-vws` provides native copy-on-write virtual worktrees for Git repositories. Each session has private Git metadata, branch state, index, working changes, and build output while unchanged file data is shared through APFS clones on macOS or `FICLONE` on supported Linux filesystems.

Version 1.0.2 is the stable release for the supported macOS and Linux filesystems. Review command output before removing sessions or publishing branches.

## Commands

```text
git vws init <repository-or-project>
git vws create <name> [--from <rev>] [--target <branch>] [--path <managed-path>]
git vws list [--all]
git vws exec <name> -- <program> [args...]
git vws remove <name> [--force]
git vws publish <name>
git vws doctor
git vws gc
```

Commands that operate on one repository use the current directory by default. Pass `--repo <path>` before the subcommand to select another repository or project. For a normal project, git-vws records its canonical `.git` directory. `list --all`, `doctor`, and `gc` operate on the registered repository set and do not accept `--repo`.

All registry, session, template, and cleanup state is stored under `$HOME/.git-vws`; no `.git-vws` directory is created inside a project.

`publish` supports new-target creation, same-tip publication, and fast-forward expected-old CAS. If another writer changes the target first, publication fails without overwriting that update. For a normal project authority, publish only to a branch that is not checked out by any of that repository's worktrees; use a bare authority when the branch may be concurrently checked out.

## Requirements

- Git 2.34 or newer.
- macOS on APFS, or Linux on a filesystem that provides `FICLONE` and matching shared-extent `FIEMAP` evidence.
- No FUSE driver, kernel extension, administrator installation, daemon, or network service.

Unsupported filesystems fail with `STORAGE_UNSUPPORTED`; `git-vws` does not silently fall back to a full worktree copy.

## Install

Download the archive for your platform from [Releases](https://github.com/Fuxx-1/git-vws/releases), verify it against `SHA256SUMS`, and place `git-vws` on `PATH`. `SHA256SUMS` covers every unsigned release asset. Each release also includes per-archive checksums, an SPDX 2.3 SBOM, a third-party license inventory, build metadata, and `PROVENANCE.sigstore.json`.

The public repository uses GitHub artifact attestations and the public Sigstore service. Verify an asset against the retained bundle, immutable signer workflow, source tag, and repository identity with GitHub CLI:

```sh
gh attestation verify '<release-asset>' \
  --bundle PROVENANCE.sigstore.json \
  --repo Fuxx-1/git-vws \
  --signer-workflow Fuxx-1/git-vws/.github/workflows/release-sign.yml \
  --signer-digest '<signer-workflow-commit-from-release-notes>' \
  --source-digest '<source-commit-from-release-notes>' \
  --source-ref refs/tags/v1.0.2 \
  --deny-self-hosted-runners
```

The annotated tag binds the exact successful pre-tag CI run. The attestation binds every release asset digest to the tag source, immutable reusable signer workflow, GitHub-hosted runner, and public transparency log without a repository-managed signing key.

Copyright (C) 2026 git-vws contributors. git-vws is free software licensed under the GNU General Public License, version 3 only (`GPL-3.0-only`), without any warranty. See [`LICENSE`](LICENSE).

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
