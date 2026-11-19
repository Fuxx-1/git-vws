mod authority;
mod cache;
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
  git vws --repo <repo.git> cache feature-a
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
  cache      Capture configured non-Git directories into the shared COW cache.
  publish    Publish committed session work using expected-old fast-forward CAS.
  remove     Safely discard a session; --force permits destructive removal.
  forget     Unregister an authority whose repository was moved or deleted.
  doctor     Diagnose all registered state without reclaiming anything.
  gc         Reclaim only state that can be proven safe to remove.
  man        Print a man page generated from this help text.

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
  merge, and rebase are ordinary Git commands.

  A session has its own private Git directory and does NOT inherit the
  authority's local config, so user.name and user.email are usually unset
  there. Set them inside the session before the first commit:

    git vws --repo <repo> exec feature-a -- git config user.name "<name>"
    git vws --repo <repo> exec feature-a -- git config user.email "<email>"

  Run git vws commands from outside the session worktree. Inside a worktree the
  directory is a linked worktree, not a sole authority, so commands such as
  list or publish report AUTHORITY_NOT_SOLE.

  publish does not commit for you:
  commit first, then publish with --repo. Publication never overwrites a target
  changed by another writer; resolve a conflict in the session and retry only
  after the target relation is valid.

OUTPUT AND RECOVERY
  list, doctor, and gc emit NDJSON intended for scripts and agents. Names and
  paths in list are hex-encoded OS-byte fields. Pass --human to any of them for
  a readable table instead; the NDJSON contract is unchanged without it. Errors
  use stable codes such as
  SESSION_DISCARD_RISK, PUBLISH_RECOVERY_REQUIRED, and STORAGE_UNSUPPORTED.
  A recovery-required result is fail-closed: stop destructive actions, inspect
  the output with doctor, and preserve the session until the state is resolved.
  Leases are bounded: a lock held by another command yields STATE_BUSY (state
  root) or SESSION_BUSY (session root) instead of blocking forever, and
  list/doctor/gc scans never wait on the state write lease.
  If you move, rename, or delete a registered repository, run `git vws forget
  <old-path>` and then `git vws init <new-path>`. forget reclaims sessions that
  hold no unpublished work and releases the stale registry record. When an
  orphaned session still holds unpublished commits, forget refuses and explains
  the two options: restore the repository at its recorded path to publish them,
  or re-run `git vws forget <old-path> --force` to discard them.

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
  unfamiliar command. Git routes `git vws --help` to `man`, so install the
  manual page once:

    git-vws man --install

  Until then use `git vws -h`, or invoke the binary directly: `git-vws --help`.
  The page is generated from this help text, so it cannot drift from the CLI.

  Use list/doctor/gc as machine-readable NDJSON streams, or add --human for a
  readable table. Keep the exact session root returned by create, edit only
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
        help = "Select an existing Git repository; default: current directory. \
                Rejected by forget, doctor, gc, and man, which always operate globally"
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
        #[arg(long, help = "Print a readable table instead of NDJSON")]
        human: bool,
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
        about = "Capture configured non-Git directories into shared COW cache",
        after_help = r#"
WHAT IT DOES
  Captures the configured directories from a clean session into an immutable
  shared snapshot. `.vwscached` is read from the authority working tree, one
  repository-relative directory per line; blank lines and lines beginning with
  `#` are ignored. The file is snapshotted when the session is created, so a
  session only has a cache receipt if `.vwscached` was committed before that
  create. A later session created from the same commit and configuration reuses
  the snapshot, then receives its own writable copy-on-write directory.

REQUIRED WORKFLOW
  1. Commit `.vwscached` in the authority (paths such as `target/` or
     `node_modules/`), then create the session. Adding the file later does not
     retrofit an existing session; create a new one.
  2. Build or otherwise populate those directories in the session.
  3. Ensure the session has no Git changes, then capture it:
     `git vws --repo repo.git cache feature-a`.
  4. Run `git vws gc` after removing sessions to reclaim unreferenced snapshots.

EXAMPLES
  printf 'target/\nnode_modules/\n' > .vwscached
  git vws --repo repo.git create feature-a
  git vws --repo repo.git exec feature-a -- cargo build
  git vws --repo repo.git cache feature-a
  git vws --repo repo.git list

SAFETY AND SCOPE
  The command refuses dirty Git state and never captures `.git`, symlinks,
  files, overlapping paths, globs, or paths outside the project. Cache data is
  not a Git commit and is not published; each session gets an independent
  writable directory. A non-zero result or CACHE_RECOVERY_REQUIRED means keep
  the state intact and inspect it with `git vws doctor`.
"#
    )]
    Cache {
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
        about = "Safely remove a managed session",
        after_help = r#"
DEFAULT BEHAVIOR
  Refuses to remove a READY session when it has tracked, untracked, ignored, or
  unpublished private commits that could be lost. These two checks are
  independent: publishing does not clear uncommitted worktree changes, and
  committing does not publish. Both must be resolved before removal succeeds.
  `list --human` reports which check blocks removal. Stop programs using the
  worktree first.
  Removal uses a tombstone transition so an interrupted cleanup can be
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
        #[arg(long, help = "Print a readable result instead of a JSON event")]
        human: bool,
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
  that update. A session has no remote by default, so rebasing needs the
  authority added explicitly. Run these inside the session, then publish again:

    git remote add authority <authority-path>
    git fetch authority
    git rebase authority/<target>

  A PUBLISH_RECOVERY_REQUIRED result means a CAS outcome is not safely
  replayable: stop publishing and inspect the state with doctor before acting.

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
  A recovery finding produces DOCTOR_RECOVERY_REQUIRED. Preserve affected state
  and use the emitted scope, path_hex, and code to decide the next operation.

  The usual cause is a repository that was moved, renamed, or deleted while it
  was registered. For those findings path_hex holds the recorded repository
  path (not a record name), and --human prints the exact repair commands:

    git vws forget <recorded-path>
    git vws init <new-path>

  This command operates globally; --repo is rejected.
"#
    )]
    Doctor {
        #[arg(long, help = "Print a readable summary instead of NDJSON")]
        human: bool,
    },
    #[command(
        about = "Forget a registered authority whose repository is gone",
        after_help = r#"
WHAT IT DOES
  Removes the registry record for PATH when the recorded repository identity no
  longer matches reality: the path is gone, or the repository still exists but
  its device or inode changed (for example after a volume was remounted or the
  directory was moved). Use it after you move, rename, or delete a registered
  repository, so the path can be registered again and doctor stops reporting the
  stale record. Sessions under that authority that hold no unpublished work are
  reclaimed at the same time.

REFUSALS
  forget refuses while the authority still exists and validates, and refuses
  while it still has managed sessions. Remove those sessions first; this command
  never deletes session data.

EXAMPLES
  git vws doctor
  git vws forget /path/to/old/repository.git
  git vws init /path/to/new/repository.git

SAFETY
  Only the registry record is unlinked while sessions hold no unpublished work.
  When an orphaned session still holds unpublished commits, forget refuses and
  names both options: restore the repository at its recorded path to publish
  them, or add --force to discard them.
"#
    )]
    Forget {
        #[arg(
            value_name = "PATH",
            help = "Registered repository path whose record should be forgotten"
        )]
        repository_path: PathBuf,
        #[arg(
            long,
            help = "Also discard orphaned sessions whose commits were never published"
        )]
        force: bool,
    },
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
    Gc {
        #[arg(long, help = "Print a readable summary instead of NDJSON")]
        human: bool,
    },
    #[command(
        about = "Print a man page for this extension",
        after_help = r#"
WHAT IT DOES
  Writes a roff man page to stdout, generated from this binary's own help text
  so the manual can never drift from the CLI. Git routes `git vws --help` to
  `man`, which fails when no page is installed; installing the generated page
  makes that command work.

EXAMPLES
  git-vws man --install      # install into ~/.local/share/man/man1
  git vws --help             # now resolves through man
  git-vws man > git-vws.1    # or capture the page for packaging

  The page is generated from the same definitions as `git vws -h`, so it needs
  no separate maintenance.
"#
    )]
    Man {
        #[arg(
            long,
            help = "Install the page into the user man directory instead of printing it"
        )]
        install: bool,
    },
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
            // init takes the repository as a positional argument, so a global
            // --repo would silently be ignored. Refuse it instead of guessing.
            if repo.is_some() {
                Err(authority::Error::new(
                    "SESSION_USAGE",
                    "init takes the repository as an argument, not --repo; run `git vws init <path>`",
                ))
            } else {
                authority::init(&repository_path).map(CommandOutput::Text)
            }
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
                .map(|outcome| {
                    CommandOutput::Text(match outcome {
                        session::CreateOutcome::Created(root) => {
                            format!("created session {}", root.display())
                        }
                        session::CreateOutcome::Reused(root) => format!(
                            "session already exists at {} with identical create inputs; nothing changed",
                            root.display()
                        ),
                    })
                })
            })
        }
        Command::List { all, human } => {
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
                .and_then(|repository| session::list(repository.as_deref(), all, human))
                .map(|_| CommandOutput::Silent)
        }
        Command::Exec {
            name,
            name_hex,
            program,
        } => repository(repo)
            .and_then(|repository| session::exec(&repository, name, name_hex, program))
            .map(CommandOutput::Exit),
        Command::Cache { name, name_hex } => repository(repo)
            .and_then(|repository| session::cache(&repository, name, name_hex))
            .map(CommandOutput::Text),
        Command::Remove {
            name,
            name_hex,
            force,
            human,
        } => repository(repo)
            .and_then(|repository| session::remove(&repository, name, name_hex, force, human))
            .map(CommandOutput::Text),
        Command::Publish { name, name_hex } => repository(repo)
            .and_then(|repository| session::publish(&repository, name, name_hex))
            .map(CommandOutput::Text),
        Command::Forget {
            repository_path,
            force,
        } => authority::forget(&repository_path, force).map(CommandOutput::Text),
        Command::Doctor { human } => global_maintenance(repo, || session::doctor(human)),
        Command::Gc { human } => global_maintenance(repo, || session::gc(human)),
        Command::Man { install } => {
            if repo.is_some() {
                Err(authority::Error::new(
                    "SESSION_USAGE",
                    "man does not accept --repo",
                ))
            } else if install {
                install_man_page().map(CommandOutput::Text)
            } else {
                Ok(CommandOutput::Text(render_man_page()))
            }
        }
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

/// Render a roff man page from this binary's own help text, so the manual and
/// the CLI can never disagree.
/// Install the generated page where `man` will find it, so `git vws --help`
/// works. Git routes that form to man; without a page it fails with a message
/// that does not explain how to fix it.
fn install_man_page() -> Result<String, authority::Error> {
    let home = env::var_os("HOME")
        .ok_or_else(|| authority::Error::new("STATE_UNAVAILABLE", "HOME is not set"))?;
    let directory = PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("man")
        .join("man1");
    std::fs::create_dir_all(&directory).map_err(|error| {
        authority::Error::io(
            "STATE_UNAVAILABLE",
            "cannot create the man directory",
            error,
        )
    })?;
    let target = directory.join("git-vws.1");
    std::fs::write(&target, render_man_page()).map_err(|error| {
        authority::Error::io("STATE_UNAVAILABLE", "cannot write the man page", error)
    })?;
    Ok(format!(
        "installed {}\nrun `man git-vws` or `git vws --help` to read it",
        target.display()
    ))
}

fn render_man_page() -> String {
    use clap::CommandFactory;
    let mut command = Cli::command();
    let help = command.render_long_help().to_string();
    let version = env!("CARGO_PKG_VERSION");
    let mut page = String::new();
    page.push_str(".TH GIT-VWS 1 \"2026-11-19\" \"git-vws ");
    page.push_str(version);
    page.push_str("\" \"Git Manual\"\n");
    page.push_str(".SH NAME\n");
    page.push_str("git-vws \\- native copy-on-write Git worktrees with isolated Git state\n");
    page.push_str(".SH SYNOPSIS\n");
    page.push_str(".B git vws\n[\\-\\-repo <path>] <command> [<args>]\n");
    page.push_str(".SH DESCRIPTION\n");
    for line in help.lines() {
        page.push_str(&roff_line(line));
        page.push('\n');
    }
    page.push_str(".SH SEE ALSO\n");
    page.push_str(".BR git (1)\n");
    page
}

fn roff_line(line: &str) -> String {
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return ".PP".to_owned();
    }
    // Escape the characters roff treats as control characters, then protect
    // leading dots so help text cannot inject a macro.
    let escaped = trimmed
        .replace('\\', "\\\\")
        .replace('-', "\\-")
        .replace('\'', "\\'");
    if escaped.starts_with('.') || escaped.starts_with('\'') {
        format!(".br\n\\&{escaped}")
    } else {
        escaped
    }
}

fn global_maintenance(
    repository: Option<PathBuf>,
    command: impl FnOnce() -> Result<(), authority::Error>,
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
            "git vws --repo <repo.git> cache feature-a",
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
            "init", "create", "list", "exec", "remove", "publish", "forget", "doctor", "gc", "man",
            "cache",
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
    fn generated_man_page_covers_the_cli_and_is_valid_roff() {
        let page = super::render_man_page();
        for required in [
            ".TH GIT-VWS 1",
            ".SH NAME",
            ".SH SYNOPSIS",
            ".SH DESCRIPTION",
            ".SH SEE ALSO",
            "git\\-vws",
            "QUICK START",
            "SAFETY RULES",
        ] {
            assert!(page.contains(required), "man page omitted {required:?}");
        }
        // No line may begin with an unescaped control character, and every
        // macro line must be a known section or font directive.
        for line in page.lines() {
            if let Some(rest) = line.strip_prefix('.') {
                let macro_name = rest.split_whitespace().next().unwrap_or("");
                assert!(
                    matches!(macro_name, "TH" | "SH" | "PP" | "br" | "B" | "BR"),
                    "man page emitted an unexpected macro: {line:?}"
                );
            }
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

        let cache = normalized_help("cache");
        assert!(cache.contains(".vwscached"));
        assert!(cache.contains("clean session"));
        assert!(cache.contains("independent writable directory"));
    }
}
