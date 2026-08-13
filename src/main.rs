mod authority;
mod git;
mod session;
mod storage;
mod template;

use clap::{Parser, Subcommand};
use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Init { bare_path } => authority::init(&bare_path),
        Command::Create {
            name,
            from,
            target,
            path,
        } => {
            let repository = match cli.repo {
                Some(repository) => Ok(repository),
                None => env::current_dir().map_err(|error| {
                    authority::Error::io(
                        "AUTHORITY_INVALID",
                        "cannot determine current directory",
                        error,
                    )
                }),
            };
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
                .map(|root| format!("created session {}", root.display()))
            })
        }
    };
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("git-vws: {error}");
            ExitCode::from(1)
        }
    }
}
