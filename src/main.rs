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
#[command(name = "git-vws", version, about = "Native COW virtual Git worktrees")]
struct Cli {
    #[arg(long, global = true, value_name = "BARE_PATH")]
    repo: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(value_name = "BARE_PATH")]
        bare_path: PathBuf,
    },
    Create {
        #[arg(value_name = "NAME")]
        name: OsString,
        #[arg(long, value_name = "REV")]
        from: Option<OsString>,
        #[arg(long, value_name = "BRANCH")]
        target: Option<OsString>,
        #[arg(long, value_name = "MANAGED_PATH")]
        path: Option<PathBuf>,
    },
    List {
        #[arg(long, conflicts_with = "repo")]
        all: bool,
    },
    Exec {
        #[arg(
            value_name = "NAME",
            required_unless_present = "name_hex",
            conflicts_with = "name_hex"
        )]
        name: Option<OsString>,
        #[arg(long, value_name = "HEX")]
        name_hex: Option<String>,
        #[arg(last = true, required = true, num_args = 1.., value_name = "PROGRAM")]
        program: Vec<OsString>,
    },
    Remove {
        #[arg(
            value_name = "NAME",
            required_unless_present = "name_hex",
            conflicts_with = "name_hex"
        )]
        name: Option<OsString>,
        #[arg(long, value_name = "HEX")]
        name_hex: Option<String>,
        #[arg(long)]
        force: bool,
    },
    Publish {
        #[arg(
            value_name = "NAME",
            required_unless_present = "name_hex",
            conflicts_with = "name_hex"
        )]
        name: Option<OsString>,
        #[arg(long, value_name = "HEX")]
        name_hex: Option<String>,
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
        Command::Init { bare_path } => authority::init(&bare_path).map(CommandOutput::Text),
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
