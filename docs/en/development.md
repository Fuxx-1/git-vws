# Development And Releases

[English](development.md) | [中文](../zh/development.md) | [Back to English README](README.md)

git-vws is a Rust 2021 project with Rust 1.85 as its minimum supported version. The binary is intentionally a Git extension: Git discovers git-vws as the external git vws subcommand. The implementation does not fork Git, change Git object formats, or require a daemon.

## Repository layout

| Path | Responsibility |
| --- | --- |
| src/main.rs | CLI parsing, help, exit status, and command dispatch. |
| src/authority.rs | Authority registration, state root, record transactions, and identity checks. |
| src/git.rs | Isolated Git process execution, output limits, and direct child handling. |
| src/template.rs | Immutable Git-tree templates and template maintenance. |
| src/storage.rs | Native COW, file identities, extent checks, sealing, and owned-tree cleanup. |
| src/session.rs | Session lifecycle, linked-worktree metadata, publish CAS, maintenance, and leases. |
| src/cache.rs | .vwscached parsing, immutable snapshots, cache materialization, and cache GC. |
| tests/ | Authority, lifecycle, parity, publish, maintenance, and cache integration tests. |
| .github/workflows/ | Quality checks, native filesystem validation, and releases. |

## Local quality gate

Run the same broad checks used by CI before committing:

    cargo fmt --all -- --check
    cargo check --locked --all-targets
    cargo clippy --locked --all-targets --all-features -- -D warnings
    cargo test --locked --all-targets -- --test-threads=1
    cargo build --locked --release

The native COW tests must run on their intended filesystem. A local pass on an unsupported volume is not evidence for the macOS APFS or Linux reflink release gates.

## Change rules

Keep Git operations ordinary and visible to users. New state must have an explicit record, identity binding, cleanup path, and recovery behavior. Do not add a scan-and-adopt fallback, a full-copy fallback, a second mutable truth, or a new daemon.

Changes to .vwscached must cover parsing, scope isolation, snapshot sealing, independent session mutation, status exclusion, dirty capture rejection, missing-source behavior, and safe GC. Changes to publish must preserve expected-old CAS and must not reset or overwrite a target changed by another writer.

Every user-facing command must keep git vws -h and its command-specific help actionable for both humans and automation. Stable error codes and NDJSON fields are part of the interface.

## CI

CI runs formatting, compilation, Clippy, and tests on Linux, then exercises macOS APFS and Linux reflink behavior on native runners. The native jobs verify the Git source contract, filesystem identity, COW evidence, lifecycle tests, publish behavior, cache cleanup, and absence of checkpoint-only markers. The Linux release build uses musl.

The release workflow builds x86_64 and ARM64 macOS assets and an x86_64 static Linux asset. Windows is not part of the current release.

## Release process

The release version is kept in Cargo.toml and Cargo.lock. A release tag must be an annotated semantic-version tag matching the package version and must point at the exact commit of a successful main push CI run. The tag annotation records the source commit and pre-tag CI run identity.

    git tag -a v1.2.0 -m "git-vws v1.2.0"
    git push origin main
    git push origin v1.2.0

GitHub Actions creates deterministic archives, SHA256SUMS, SPDX 2.3 SBOM metadata, a third-party license inventory, build metadata, and the public Sigstore provenance bundle. Do not publish a tag before the source commit's full CI run succeeds.

## Documentation maintenance

The root README.md is the Chinese entry point. docs/en/ and docs/zh/ contain one-to-one topic pages with the same filenames. Update facts in both languages when command behavior, storage scope, supported platforms, or release artifacts change.
