use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_SANDBOX: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(env::temp_dir())
            .expect("canonicalize M7 temporary directory")
            .join(format!(
                "git-vws-m7-{}-{}",
                std::process::id(),
                NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&root).expect("create M7 sandbox");
        let home = root.join("home");
        let project = root.join("project");
        fs::create_dir(&home).expect("create M7 home");
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).expect("protect M7 home");
        fs::create_dir(&project).expect("create M7 project");
        git(&project, &["init"]);
        git(&project, &["config", "user.name", "M7 Test"]);
        git(&project, &["config", "user.email", "m7@example.invalid"]);
        fs::write(project.join(".gitignore"), b"target/\nnode_modules/\n")
            .expect("write M7 ignore");
        fs::write(
            project.join(".vwscached"),
            b"# native build cache\ntarget/\nnode_modules/\n",
        )
        .expect("write M7 cache config");
        fs::create_dir(project.join("target")).expect("create source target");
        fs::write(project.join("target/seed.txt"), b"seed\n").expect("write source cache");
        fs::create_dir(project.join("node_modules")).expect("create source node_modules");
        fs::write(project.join("node_modules/package.txt"), b"package\n")
            .expect("write source node_modules");
        fs::write(project.join("tracked.txt"), b"tracked\n").expect("write tracked source");
        git(&project, &["add", "."]);
        git(&project, &["commit", "-m", "M7 base"]);
        let fixture = Self {
            root,
            home,
            project,
        };
        assert_success(
            &fixture.vws(vec![
                OsString::from("init"),
                fixture.project.as_os_str().to_os_string(),
            ]),
            "initialize M7 authority",
        );
        fixture
    }

    fn vws(&self, args: Vec<OsString>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-vws"));
        remove_git_environment(&mut command);
        command
            .args(args)
            .current_dir(&self.root)
            .env("HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("run git-vws")
    }

    fn repo_args(&self, command: &[&str]) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--repo"),
            self.project.as_os_str().to_os_string(),
        ];
        args.extend(command.iter().map(OsString::from));
        args
    }

    fn create(&self, name: &str) -> PathBuf {
        let output = self.vws(self.repo_args(&["create", name]));
        assert_success(&output, "create M7 session");
        let line = String::from_utf8(output.stdout).expect("session path output");
        PathBuf::from(
            line.trim()
                .strip_prefix("created session ")
                .expect("created session prefix"),
        )
    }

    fn cache(&self, name: &str) -> Output {
        self.vws(self.repo_args(&["cache", name]))
    }

    fn remove(&self, name: &str) -> Output {
        self.vws(self.repo_args(&["remove", name]))
    }

    fn cache_entries(&self) -> Vec<PathBuf> {
        let caches = self.home.join(".git-vws/caches");
        let mut entries: Vec<_> = fs::read_dir(caches)
            .expect("read M7 cache container")
            .map(|entry| entry.expect("read M7 cache entry").path())
            .filter(|path| path.extension().is_some_and(|suffix| suffix == "tree"))
            .collect();
        entries.sort();
        entries
    }

    fn cache_selection_entries(&self) -> Vec<PathBuf> {
        let caches = self.home.join(".git-vws/caches");
        let mut entries: Vec<_> = fs::read_dir(caches)
            .expect("read M7 cache container")
            .map(|entry| entry.expect("read M7 cache entry").path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.as_encoded_bytes().ends_with(b".selection"))
            })
            .collect();
        entries.sort();
        entries
    }

    fn cache_temporary_entries(&self) -> Vec<PathBuf> {
        let caches = self.home.join(".git-vws/caches");
        let mut entries: Vec<_> = fs::read_dir(caches)
            .expect("read M7 cache container")
            .map(|entry| entry.expect("read M7 cache entry").path())
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    name.as_encoded_bytes().starts_with(b".cache-")
                        && name.as_encoded_bytes().ends_with(b".tmp")
                })
            })
            .collect();
        entries.sort();
        entries
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            make_directories_removable(&self.root);
            fs::remove_dir_all(&self.root).expect("cleanup M7 sandbox");
        }
    }
}

fn make_directories_removable(path: &Path) {
    let metadata = fs::symlink_metadata(path).expect("stat M7 cleanup path");
    if !metadata.is_dir() {
        return;
    }
    for entry in fs::read_dir(path).expect("read M7 cleanup directory") {
        make_directories_removable(&entry.expect("read M7 cleanup entry").path());
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("protect M7 cleanup directory");
}

fn git(cwd: &Path, args: &[&str]) -> Output {
    let mut command = Command::new("git");
    remove_git_environment(&mut command);
    let output = command
        .current_dir(cwd)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("run fixture git");
    assert_success(&output, "fixture git");
    output
}

fn remove_git_environment(command: &mut Command) {
    for (name, _) in env::vars_os() {
        if name.to_string_lossy().starts_with("GIT_") {
            command.env_remove(name);
        }
    }
}

fn assert_success(output: &Output, context: &str) {
    assert!(output.status.success(), "{context}: {output:?}");
}

fn assert_error(output: &Output, code: &str, context: &str) {
    assert!(
        !output.status.success() && String::from_utf8_lossy(&output.stderr).contains(code),
        "{context}: {output:?}"
    );
}

fn assert_clean_git(path: &Path) {
    let output = git(path, &["status", "--porcelain=v1", "--untracked-files=all"]);
    assert!(
        output.stdout.is_empty(),
        "Git status was not clean: {output:?}"
    );
}

#[test]
fn vwscached_cow_cache_follows_session_lifecycle() {
    let fixture = Fixture::new();
    let alpha = fixture.create("alpha");
    let beta = fixture.create("beta");
    let alpha_worktree = alpha.join("worktree");
    let beta_worktree = beta.join("worktree");

    assert_eq!(
        fs::read(alpha_worktree.join("target/seed.txt")).expect("read alpha target"),
        b"seed\n"
    );
    assert_eq!(
        fs::read(beta_worktree.join("node_modules/package.txt")).expect("read beta modules"),
        b"package\n"
    );
    assert_eq!(
        fixture.cache_entries().len(),
        2,
        "sessions did not reuse snapshots"
    );
    assert_clean_git(&alpha_worktree);
    assert_clean_git(&beta_worktree);

    fs::write(alpha_worktree.join("target/alpha.txt"), b"alpha\n").expect("write alpha cache");
    fs::write(beta_worktree.join("target/beta.txt"), b"beta\n").expect("write beta cache");
    assert!(!beta_worktree.join("target/alpha.txt").exists());
    assert!(!alpha_worktree.join("target/beta.txt").exists());
    assert_clean_git(&alpha_worktree);
    assert_clean_git(&beta_worktree);

    assert_success(&fixture.cache("alpha"), "capture alpha cache");
    assert_eq!(
        fixture.cache_entries().len(),
        3,
        "cache capture did not create snapshots"
    );
    let gamma = fixture.create("gamma");
    assert!(
        gamma.join("worktree/target/alpha.txt").exists(),
        "a new session did not reuse the updated cache snapshot"
    );
    assert!(!gamma.join("worktree/target/beta.txt").exists());
    assert_success(&fixture.remove("gamma"), "remove gamma with managed cache");
    assert_success(&fixture.remove("beta"), "remove beta with managed cache");
    assert_success(&fixture.remove("alpha"), "remove alpha with managed cache");
    let gc = fixture.vws(vec![OsString::from("gc")]);
    assert_success(&gc, "collect unreferenced cache snapshots");
    assert!(
        fixture.cache_entries().is_empty(),
        "gc retained cache snapshots"
    );
}

#[test]
fn missing_capture_does_not_fall_back_to_an_old_snapshot() {
    let fixture = Fixture::new();
    let alpha = fixture.create("alpha");
    let target = alpha.join("worktree/target");
    fs::remove_dir_all(&target).expect("remove alpha target cache");
    assert_success(&fixture.cache("alpha"), "capture missing alpha cache");

    let beta = fixture.create("beta");
    assert!(
        !beta.join("worktree/target/seed.txt").exists(),
        "new session fell back to a stale cache snapshot"
    );

    assert_success(&fixture.remove("beta"), "remove beta");
    assert_success(&fixture.remove("alpha"), "remove alpha");
    assert_success(&fixture.vws(vec![OsString::from("gc")]), "gc missing cache");
    assert!(
        fixture.cache_entries().is_empty(),
        "gc retained cache snapshots"
    );
}

#[test]
fn cache_capture_tracks_the_session_head_for_empty_selections() {
    let fixture = Fixture::new();
    let alpha = fixture.create("alpha");
    let worktree = alpha.join("worktree");
    git(&worktree, &["config", "user.name", "M7 Session"]);
    git(
        &worktree,
        &["config", "user.email", "m7-session@example.invalid"],
    );
    fs::write(worktree.join("session.txt"), b"session\n").expect("write M7 session change");
    git(&worktree, &["add", "session.txt"]);
    git(
        &worktree,
        &["-c", "commit.gpgSign=false", "commit", "-m", "M7 session"],
    );
    fs::remove_dir_all(worktree.join("target")).expect("remove M7 target cache");

    assert_success(&fixture.cache("alpha"), "capture cache at session HEAD");
    assert_success(
        &fixture.vws(vec![OsString::from("gc")]),
        "collect stale cache scopes",
    );
    assert_eq!(
        fixture.cache_entries().len(),
        1,
        "GC did not reclaim stale pre-commit snapshots"
    );
    assert_eq!(
        fixture.cache_selection_entries().len(),
        2,
        "GC discarded the live empty selection for the session HEAD"
    );
}

#[test]
fn corrupt_existing_snapshot_does_not_leave_a_temporary_tree() {
    let fixture = Fixture::new();
    fixture.create("alpha");
    let tree = fixture
        .cache_entries()
        .into_iter()
        .next()
        .expect("initial cache snapshot");
    let file_name = tree
        .file_name()
        .and_then(|name| name.to_str())
        .expect("cache tree UTF-8 name");
    let key = file_name
        .strip_prefix("cache-")
        .and_then(|name| name.strip_suffix(".tree"))
        .expect("cache tree key");
    let caches = fixture.home.join(".git-vws/caches");
    fs::remove_file(caches.join(format!("cache-{key}.record"))).expect("remove cache record");
    for selection in fixture.cache_selection_entries() {
        if fs::read(&selection)
            .expect("read cache selection")
            .windows(key.len())
            .any(|value| value == key.as_bytes())
        {
            fs::remove_file(selection).expect("remove cache selection");
        }
    }

    let output = fixture.vws(fixture.repo_args(&["create", "beta"]));
    assert_error(
        &output,
        "CACHE_RECOVERY_REQUIRED",
        "reject corrupt pre-existing cache snapshot",
    );
    assert!(
        fixture.cache_temporary_entries().is_empty(),
        "failed snapshot creation left a temporary cache tree"
    );
}
