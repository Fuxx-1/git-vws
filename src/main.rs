mod authority;
mod git;
#[cfg(git_vws_m4_checkpoint)]
mod m4_checkpoint;
mod session;
mod storage;
mod template;

use clap::{Parser, Subcommand};
use std::env;
use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitCode, ExitStatus};

#[derive(Parser)]
#[command(
    name = "git-vws",
    version,
    about = "Native copy-on-write Git worktrees with isolated Git state",
    arg_required_else_help = true,
    after_help = r#"
QUICK START
  Use `git vws` (Git discovers the `git-vws` executable on PATH). Start with an
  existing bare repository or a normal project checkout.

  git clone --bare <source-url> <repo.git>
  git vws init <repo.git>
  git vws init <project>
  git vws --repo <repo.git> create feature-a --target feature/a
  git vws --repo <project> create feature-a --target feature/a
  git vws --repo <repo.git> list
  git vws --repo <repo.git> exec feature-a -- "$SHELL"
  # Edit files and run normal Git commands in the session shell:
  #   git status; git add .; git commit
  git vws --repo <repo.git> publish feature-a
  git vws --repo <repo.git> remove feature-a
  git vws gc

OPERATING MODEL
  A session is a normal writable directory with private HEAD, index, refs,
  uncommitted changes, and build output. Edit it with any editor; no editor
  plugin, FUSE mount, daemon, administrator service, or network is required.
  Initial file contents use native copy-on-write: APFS clonefile on macOS or
  FICLONE with shared-extent evidence on Linux. There is no full-copy fallback.
  Unsupported storage is rejected with STORAGE_UNSUPPORTED.

COMMAND ORDER
  init       Register and validate an existing Git repository.
  create     Create an isolated session and print its managed session root.
  list       Inspect sessions as one JSON object per line (NDJSON).
  exec       Run a program with the session worktree as its current directory.
  publish    Publish committed session work using expected-old fast-forward CAS.
  remove     Safely discard a session; --force permits destructive removal.
  doctor     Diagnose all registered state without reclaiming anything.
  gc         Reclaim only state that can be proven safe to remove.

REPOSITORY SELECTION
  Commands for one authority use --repo <PATH>; without it, the current
  directory is used. `init` takes a project or bare repository path. Normal
  project paths are canonicalized to their `.git` directory.
  `list --all`, `doctor`, and `gc` operate on all registered authorities and
  reject --repo. State is kept under $HOME/.git-vws and is shared by all
  registered repositories.

EDITING AND PUBLISHING
  After create, edit <printed-session-root>/worktree or use exec. Git sees a
  standard linked worktree, so status, diff, add, commit, checkout, reset,
  merge, and rebase are ordinary Git commands. publish does not commit for you:
  commit first, then publish with --repo. Publication never overwrites a target
  changed by another writer; resolve a conflict in the session and retry only
  after the target relation is valid.

OUTPUT AND RECOVERY
  list, doctor, and gc emit NDJSON intended for scripts and agents. Names and
  paths in list are hex-encoded OS-byte fields. Errors use stable codes such as
  SESSION_DISCARD_RISK, PUBLISH_RECOVERY_REQUIRED, and STORAGE_UNSUPPORTED.
  A recovery-required result is fail-closed: stop destructive actions, inspect
  the output with doctor, and preserve the session until the state is resolved.

SAFETY RULES
  remove refuses dirty sessions unless --force is explicit. Integrity and
  recovery failures are always refused. `--force` can discard uncommitted files
  and private Git objects. Run gc after successful removals. Do not put two
  sessions on the same target branch and expect both publishes to win;
  publication is intentionally CAS serialized by Git.

SUPPORTED SCOPE
  Git 2.34+ and Rust 1.85+ for builds. The ~/.git-vws state root must be on
  macOS APFS or a Linux filesystem that provides FICLONE plus verified shared
  FIEMAP extents. Windows, LFS, submodules, sparse or partial clones,
  clean/smudge filters, and unsupported ACL/xattr or file-flag combinations
  are outside the current release.

LICENSE
  GPL-3.0-only. Copyright (C) 2026 git-vws contributors. This program comes
  without any warranty; see the LICENSE file distributed with the source and
  release archive.

AI / AUTOMATION ENTRYPOINT
  First run `git vws -h`. Then run `git vws <command> -h` before executing an
  unfamiliar command. Use list/doctor/gc as machine-readable NDJSON streams,
  keep the exact session root returned by create, edit only
  <session-root>/worktree, and treat any non-zero exit or recovery code as a
  stop signal rather than guessing or deleting state.

Run `git vws <command> -h` for command-specific arguments and examples.
"#
)]
struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Select an existing Git repository; default: current directory"
    )]
    repo: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(
        about = "Register an existing Git repository as an authority",
        after_help = r#"
WHAT IT DOES
  Validates that PATH is a supported, sole Git repository and records it in the
  local $HOME/.git-vws registry. PATH may be a bare repository, a project root,
  or its `.git` directory. It does not create or clone a repository.

EXAMPLES
  git clone --bare <source-url> repo.git
  git vws init repo.git
  git vws init .
  git vws --repo repo.git create feature-a
  git vws --repo . create feature-a

REQUIREMENTS
  The authority must have git-dir == common-dir, use a supported object/ref
  format, and have no linked-worktree registry or object alternates. A bare
  path must be the Git directory itself; a normal project is recorded by its
  canonical `.git` directory.
  Initialization is idempotence-checked and fails closed if the path changes.
  Native COW support for $HOME/.git-vws is probed when a template is first
  created.
"#
    )]
    Init {
        #[arg(
            value_name = "PATH",
            help = "Existing Git repository or project to register and validate"
        )]
        repository_path: PathBuf,
    },
    #[command(
        about = "Create an isolated writable session",
        after_help = r#"
WHAT IT DOES
  Creates a private Git state directory and a normal writable worktree. The
  worktree is populated with native copy-on-write file clones. The command
  prints the managed session root; the editable directory is
  <session-root>/worktree. Unchanged file data is shared; edits, new files, and
  build output belong only to this session.

DEFAULTS
  NAME is the local session name and, unless --target is supplied, also the
  target branch name. The starting commit is the existing target tip; if the
  target does not exist, HEAD is used. --from overrides the starting commit.

EXAMPLES
  git vws --repo repo.git create feature-a
  git vws --repo repo.git create bugfix --from main --target bugfix/login
  git vws --repo repo.git exec feature-a -- "$SHELL"

NEXT STEPS
  Open <printed-session-root>/worktree in an editor, or use exec. Inside the
  worktree, use ordinary Git commands: git status, git diff, git add,
  git commit, git checkout, git reset, git merge, and git rebase. Run publish
  with --repo only after committing changes you want on the target branch.

OPTIONS
  --path is an advanced recovery/topology assertion. It must equal the exact
  path managed by git-vws; it is not a general-purpose custom output path.
"#
    )]
    Create {
        #[arg(value_name = "NAME", help = "Local session name")]
        name: OsString,
        #[arg(
            long,
            value_name = "REV",
            help = "Starting commit; default: target tip, otherwise HEAD"
        )]
        from: Option<OsString>,
        #[arg(
            long,
            value_name = "BRANCH",
            help = "Target branch for publication; default: NAME"
        )]
        target: Option<OsString>,
        #[arg(
            long,
            value_name = "MANAGED_PATH",
            help = "Assert the exact managed path (advanced; usually omit)"
        )]
        path: Option<PathBuf>,
    },
    #[command(
        about = "List trusted sessions as newline-delimited JSON",
        after_help = r#"
OUTPUT
  Each healthy session is one JSON object. Fields such as name_hex and
  managed_path_hex contain lowercase hexadecimal OS bytes so non-UTF-8 names
  remain unambiguous. A corrupt record is also emitted as JSON, then the command
  exits non-zero with SESSION_CORRUPT.

EXAMPLES
  git vws --repo repo.git list
  git vws list --all
  git vws --repo repo.git list | jq -c .

SELECTION
  Without --all, list inspects the selected authority (the current directory
  by default). --all scans every registered authority. --all and --repo cannot
  be combined. An empty, valid registry produces no data lines.
"#
    )]
    List {
        #[arg(
            long,
            conflicts_with = "repo",
            help = "List sessions for every registered authority"
        )]
        all: bool,
    },
    #[command(
        about = "Run a program inside a session worktree",
        after_help = r#"
WHAT IT DOES
  Runs PROGRAM with the session worktree as its current directory, inherits
  standard input/output/error, and returns the child exit status. It does not
  start a daemon or alter the editor. Inherited GIT_* environment variables are
  removed so the child resolves Git metadata from this session.

EXAMPLES
  git vws --repo repo.git exec feature-a -- "$SHELL"
  git vws --repo repo.git exec feature-a -- cargo test
  git vws --repo repo.git exec feature-a -- git status --short

SYNTAX
  Put `--` before the program. NAME selects a session by its normal name. Use
  --name-hex when an exact lowercase hexadecimal OS-byte name is required.
  The command's exit code is the program's exit code; a git-vws failure uses a
  non-zero code and prints a stable error code.
"#
    )]
    Exec {
        #[arg(
            value_name = "NAME",
            required_unless_present = "name_hex",
            conflicts_with = "name_hex",
            help = "Session name"
        )]
        name: Option<OsString>,
        #[arg(
            long,
            value_name = "HEX",
            help = "Exact lowercase hexadecimal session-name bytes"
        )]
        name_hex: Option<String>,
        #[arg(
            last = true,
            required = true,
            num_args = 1..,
            value_name = "PROGRAM",
            help = "Program and arguments after --"
        )]
        program: Vec<OsString>,
    },
    #[command(
        about = "Safely remove a managed session",
        after_help = r#"
DEFAULT BEHAVIOR
  Refuses to remove a READY session when it has tracked, untracked, ignored, or
  private Git content that could be lost. Stop programs using the worktree
  first. Removal uses a tombstone transition so an interrupted cleanup can be
  diagnosed and completed by gc.

EXAMPLES
  git vws --repo repo.git remove feature-a
  git vws --repo repo.git remove feature-a --force
  git vws gc

WARNING
  --force is destructive. It permits discarding uncommitted files and private
  Git objects. It does not bypass integrity or recovery checks. If the command
  returns SESSION_RECOVERY_REQUIRED, preserve the session and run doctor; do
  not remove its files by hand.

OUTPUT
  A successful removal emits one JSON event. Removing an already absent name
  is an idempotent event for the selected authority.
"#
    )]
    Remove {
        #[arg(
            value_name = "NAME",
            required_unless_present = "name_hex",
            conflicts_with = "name_hex",
            help = "Session name"
        )]
        name: Option<OsString>,
        #[arg(
            long,
            value_name = "HEX",
            help = "Exact lowercase hexadecimal session-name bytes"
        )]
        name_hex: Option<String>,
        #[arg(long, help = "Allow destructive removal of session content")]
        force: bool,
    },
    #[command(
        about = "Publish committed session work with Git CAS",
        after_help = r#"
WHAT IT DOES
  Publishes the session's committed target branch to the registered authority.
  It first verifies the private commit closure, imports missing
  objects, and performs an expected-old compare-and-swap on the target ref.

REQUIRED WORKFLOW
  1. Edit files in the session worktree.
  2. Run git add and git commit there.
  3. Run publish with --repo from any directory.

EXAMPLES
  git vws --repo repo.git exec feature-a -- git status
  git vws --repo repo.git exec feature-a -- git add .
  git vws --repo repo.git exec feature-a -- git commit -m "Implement change"
  git vws --repo repo.git publish feature-a

CONFLICTS AND RECOVERY
  New-target, same-tip, and fast-forward publication are supported. If another
  writer changes the target first, publish exits non-zero and never overwrites
  that update; rebase or merge in the session, then retry. A
  PUBLISH_RECOVERY_REQUIRED result means a CAS outcome is not safely replayable:
  stop publishing and inspect the state with doctor before taking action.

NOTE
  publish does not create a commit and does not publish uncommitted edits.
"#
    )]
    Publish {
        #[arg(
            value_name = "NAME",
            required_unless_present = "name_hex",
            conflicts_with = "name_hex",
            help = "Session name"
        )]
        name: Option<OsString>,
        #[arg(
            long,
            value_name = "HEX",
            help = "Exact lowercase hexadecimal session-name bytes"
        )]
        name_hex: Option<String>,
    },
    #[command(
        about = "Diagnose all registered state without deleting anything",
        after_help = r#"
WHAT IT DOES
  Scans the local $HOME/.git-vws registry, sessions, templates, bindings, and
  private Git storage. It emits NDJSON item/finding records plus a summary.
  doctor is read-only and never reclaims tombstones or objects.

EXAMPLES
  git vws doctor
  git vws doctor | jq -c .

EXIT STATUS
  A recovery finding produces DOCTOR_RECOVERY_REQUIRED. Preserve affected
  state and use the emitted scope, path_hex, and code to decide the next
  operation. This command operates globally; --repo is rejected.
"#
    )]
    Doctor,
    #[command(
        about = "Reclaim only provably safe global state",
        after_help = r#"
WHAT IT DOES
  Removes completed tombstones and transaction leftovers, drops unreferenced
  templates, and reclaims authority-duplicate loose objects when the complete
  state census proves it safe. It emits the same NDJSON item/finding/summary
  shape as doctor.

EXAMPLES
  git vws doctor
  git vws gc
  git vws gc | jq -c .

SAFETY
  gc is fail-closed. Any uncertain binding, busy session, dirty state, or
  recovery condition is retained and reported instead of being force-deleted.
  Run remove first for sessions you intentionally want to discard, then run
  gc. This command operates globally; --repo is rejected.
"#
    )]
    Gc,
}

enum CommandOutput {
    Text(String),
    Silent,
    Exit(ExitStatus),
}

fn main() -> ExitCode {
    #[cfg(git_vws_m4_checkpoint)]
    if let Err(error) = m4_checkpoint::arm() {
        eprintln!("git-vws: {error}");
        return ExitCode::from(1);
    }
    let Cli { repo, command } = Cli::parse();
    let result = match command {
        Command::Init { repository_path } => {
            authority::init(&repository_path).map(CommandOutput::Text)
        }
        Command::Create {
            name,
            from,
            target,
            path,
        } => {
            let repository = repository(repo);
            repository.and_then(|repository| {
                session::create(
                    &repository,
                    session::CreateRequest {
                        name,
                        from,
                        target,
                        path,
                    },
                )
                .map(|root| CommandOutput::Text(format!("created session {}", root.display())))
            })
        }
        Command::List { all } => {
            let repository = if all && repo.is_some() {
                Err(authority::Error::new(
                    "SESSION_USAGE",
                    "--all cannot be combined with --repo",
                ))
            } else if all {
                Ok(None)
            } else {
                repository(repo).map(Some)
            };
            repository
                .and_then(|repository| session::list(repository.as_deref(), all))
                .map(|_| CommandOutput::Silent)
        }
        Command::Exec {
            name,
            name_hex,
            program,
        } => repository(repo)
            .and_then(|repository| session::exec(&repository, name, name_hex, program))
            .map(CommandOutput::Exit),
        Command::Remove {
            name,
            name_hex,
            force,
        } => repository(repo)
            .and_then(|repository| session::remove(&repository, name, name_hex, force))
            .map(CommandOutput::Text),
        Command::Publish { name, name_hex } => repository(repo)
            .and_then(|repository| session::publish(&repository, name, name_hex))
            .map(CommandOutput::Text),
        Command::Doctor => global_maintenance(repo, session::doctor),
        Command::Gc => global_maintenance(repo, session::gc),
    };
    match result {
        Ok(CommandOutput::Text(message)) => {
            if !message.is_empty() {
                println!("{message}");
            }
            ExitCode::SUCCESS
        }
        Ok(CommandOutput::Silent) => ExitCode::SUCCESS,
        Ok(CommandOutput::Exit(status)) => ExitCode::from(exit_status_code(status)),
        Err(error) => {
            eprintln!("git-vws: {error}");
            ExitCode::from(1)
        }
    }
}

fn global_maintenance(
    repository: Option<PathBuf>,
    command: fn() -> Result<(), authority::Error>,
) -> Result<CommandOutput, authority::Error> {
    if repository.is_some() {
        return Err(authority::Error::new(
            "SESSION_USAGE",
            "global maintenance commands do not accept --repo",
        ));
    }
    command().map(|_| CommandOutput::Silent)
}

fn repository(repo: Option<PathBuf>) -> Result<PathBuf, authority::Error> {
    match repo {
        Some(repository) => Ok(repository),
        None => env::current_dir().map_err(|error| {
            authority::Error::io(
                "AUTHORITY_INVALID",
                "cannot determine current directory",
                error,
            )
        }),
    }
}

fn exit_status_code(status: ExitStatus) -> u8 {
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    u8::try_from(code).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::{error::ErrorKind, CommandFactory, Parser};

    fn rendered_help(command_name: Option<&str>) -> String {
        match command_name {
            Some(name) => match Cli::try_parse_from(["git-vws", name, "-h"]) {
                Ok(_) => panic!("{name} help unexpectedly parsed as a command"),
                Err(error) => {
                    assert_eq!(error.kind(), ErrorKind::DisplayHelp);
                    error.to_string()
                }
            },
            None => Cli::command().render_help().to_string(),
        }
    }

    fn normalized_help(command_name: &str) -> String {
        rendered_help(Some(command_name))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn top_level_help_is_a_complete_getting_started_contract() {
        let help = rendered_help(None);
        for required in [
            "QUICK START",
            "git clone --bare <source-url> <repo.git>",
            "git vws init <repo.git>",
            "git vws --repo <repo.git> create feature-a --target feature/a",
            "git vws --repo <repo.git> exec feature-a -- \"$SHELL\"",
            "git vws --repo <repo.git> publish feature-a",
            "git vws --repo <repo.git> remove feature-a",
            "git vws gc",
            "OPERATING MODEL",
            "<printed-session-root>/worktree",
            "REPOSITORY SELECTION",
            "OUTPUT AND RECOVERY",
            "SESSION_DISCARD_RISK",
            "PUBLISH_RECOVERY_REQUIRED",
            "STORAGE_UNSUPPORTED",
            "SUPPORTED SCOPE",
            "GPL-3.0-only",
            "AI / AUTOMATION ENTRYPOINT",
        ] {
            assert!(
                help.contains(required),
                "top-level help omitted {required:?}"
            );
        }
    }

    #[test]
    fn every_public_subcommand_has_reference_help_and_examples() {
        for name in [
            "init", "create", "list", "exec", "remove", "publish", "doctor", "gc",
        ] {
            let help = rendered_help(Some(name));
            assert!(
                help.contains("EXAMPLES"),
                "{name} help omitted executable examples"
            );
            assert!(
                help.contains("--help"),
                "{name} help omitted its help entry"
            );
            assert!(
                help.lines().count() >= 14,
                "{name} help regressed to a parameter-only summary"
            );
        }
    }

    #[test]
    fn short_help_and_missing_command_surface_the_getting_started_contract() {
        for (arguments, expected_kind) in [
            (vec!["git-vws", "-h"], ErrorKind::DisplayHelp),
            (
                vec!["git-vws"],
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
            ),
        ] {
            let error = match Cli::try_parse_from(arguments) {
                Ok(_) => panic!("help request unexpectedly parsed as a command"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), expected_kind);
            let help = error.to_string();
            assert!(help.contains("QUICK START"));
            assert!(help.contains("AI / AUTOMATION ENTRYPOINT"));
        }
    }

    #[test]
    fn command_help_preserves_destructive_and_machine_output_boundaries() {
        let create = normalized_help("create");
        assert!(create.contains("prints the managed session root"));
        assert!(create.contains("<printed-session-root>/worktree"));

        let list = normalized_help("list");
        assert!(list.contains("name_hex"));
        assert!(list.contains("managed_path_hex"));
        assert!(list.contains("lowercase hexadecimal OS bytes"));

        let remove = normalized_help("remove");
        assert!(remove.contains("--force is destructive"));
        assert!(remove.contains("do not remove its files by hand"));

        let publish = normalized_help("publish");
        assert!(publish.contains("publish does not create a commit"));
        assert!(publish.contains("never overwrites"));

        let doctor = normalized_help("doctor");
        assert!(doctor.contains("read-only"));
        assert!(doctor.contains("--repo is rejected"));

        let gc = normalized_help("gc");
        assert!(gc.contains("fail-closed"));
        assert!(gc.contains("--repo is rejected"));
    }
}
