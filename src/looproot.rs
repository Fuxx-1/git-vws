use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::authority::Error;

const DEFAULT_SIZE: &str = "8G";
const MINIMUM_BYTES: u64 = 256 * 1024 * 1024;
const IMAGE_NAME: &str = ".git-vws.img";
const MOUNT_NAME: &str = ".git-vws";
const STATE_NAME: &str = ".git-vws";
const FSTAB_MARKER: &str = "# git-vws loop state root";

/// A loop-backed state root lets an ext4 (or other non-reflink) host still use
/// git-vws: the state root lives on a small btrfs image inside a sparse file,
/// so FICLONE works while the surrounding filesystem stays untouched.
pub(crate) struct LoopPlan {
    pub(crate) home: PathBuf,
    pub(crate) image: PathBuf,
    pub(crate) mount: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) size: String,
    /// Previous state root contents waiting to be copied into the image.
    pub(crate) staged: Option<PathBuf>,
}

impl LoopPlan {
    pub(crate) fn discover(size: Option<&str>) -> Result<Self, Error> {
        let home = home_directory()?;
        Ok(Self {
            image: home.join(IMAGE_NAME),
            mount: home.join(MOUNT_NAME),
            state: home.join(MOUNT_NAME),
            home,
            size: size.unwrap_or(DEFAULT_SIZE).to_owned(),
            staged: None,
        })
    }

    fn is_mounted(&self) -> bool {
        let output = Command::new("mountpoint")
            .arg("-q")
            .arg(&self.mount)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        matches!(output, Ok(status) if status.success())
    }

    fn loop_device(&self) -> Option<String> {
        let output = Command::new("losetup")
            .arg("-j")
            .arg(&self.image)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .next()?
            .split(':')
            .next()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }
}

fn home_directory() -> Result<PathBuf, Error> {
    let home =
        env::var_os("HOME").ok_or_else(|| Error::new("STATE_UNAVAILABLE", "HOME is not set"))?;
    let path = PathBuf::from(home);
    if !path.is_absolute() {
        return Err(Error::new("STATE_UNAVAILABLE", "HOME is not absolute"));
    }
    Ok(path)
}

/// Parse a human size such as `8G`, `512M`, or `1073741824` into bytes.
pub(crate) fn parse_size(value: &str) -> Result<u64, Error> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Error::new("SESSION_USAGE", "size is empty"));
    }
    let (digits, multiplier) = match trimmed.as_bytes().last().copied() {
        Some(b'K' | b'k') => (&trimmed[..trimmed.len() - 1], 1024_u64),
        Some(b'M' | b'm') => (&trimmed[..trimmed.len() - 1], 1024_u64.pow(2)),
        Some(b'G' | b'g') => (&trimmed[..trimmed.len() - 1], 1024_u64.pow(3)),
        Some(b'T' | b't') => (&trimmed[..trimmed.len() - 1], 1024_u64.pow(4)),
        _ => (trimmed, 1_u64),
    };
    let number: u64 = digits
        .parse()
        .map_err(|_| Error::new("SESSION_USAGE", format!("cannot parse size {value:?}")))?;
    number
        .checked_mul(multiplier)
        .ok_or_else(|| Error::new("SESSION_USAGE", "size overflows u64"))
}

fn run(command: &mut Command, action: &str) -> Result<(), Error> {
    let output = command
        .output()
        .map_err(|error| Error::io("STATE_UNAVAILABLE", &format!("cannot run {action}"), error))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(Error::new(
        "STATE_UNAVAILABLE",
        format!("{action} failed: {}", stderr.trim()),
    ))
}

fn require_root(action: &str) -> Result<(), Error> {
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    Err(Error::new(
        "SESSION_USAGE",
        format!("{action} needs root; re-run it with sudo"),
    ))
}

/// Create the image, format it, mount it, and move any existing state root in.
pub(crate) fn setup(plan: &LoopPlan, adopt: bool) -> Result<String, Error> {
    let bytes = parse_size(&plan.size)?;
    if bytes < MINIMUM_BYTES {
        return Err(Error::new(
            "SESSION_USAGE",
            format!(
                "size {} is below the {} MiB btrfs minimum; pass --size with a larger value",
                plan.size,
                MINIMUM_BYTES / (1024 * 1024)
            ),
        ));
    }
    if plan.is_mounted() {
        return Err(Error::new(
            "STATE_UNAVAILABLE",
            format!("{} is already a mount point", plan.mount.display()),
        ));
    }
    if plan.image.exists() {
        return Err(Error::new(
            "STATE_UNAVAILABLE",
            format!(
                "{} already exists; remove it first if you want a fresh state root",
                plan.image.display()
            ),
        ));
    }
    require_root("git vws setup-loop")?;

    // A sparse image keeps the initial footprint near zero and lets the file
    // grow on demand until it reaches the apparent size.
    create_sparse_image(&plan.image, bytes)?;
    run(
        Command::new("mkfs.btrfs")
            .arg("-q")
            .arg("-f")
            .arg(&plan.image),
        "mkfs.btrfs",
    )?;
    // A previous state root would be hidden by the mount, so move it aside
    // before mounting and copy it in afterwards.
    let mut plan = LoopPlan {
        staged: None,
        ..LoopPlan::discover(Some(&plan.size))?
    };
    let previous = plan.home.join(STATE_NAME);
    if previous.is_dir() {
        if !adopt {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                format!(
                    "{} already holds state; re-run with --adopt to move it into the image, \
                     or move it away first",
                    previous.display()
                ),
            ));
        }
        let staged = plan.home.join(".git-vws.adopting");
        if staged.exists() {
            return Err(Error::new(
                "STATE_UNAVAILABLE",
                format!(
                    "{} already exists; inspect it before retrying",
                    staged.display()
                ),
            ));
        }
        fs::rename(&previous, &staged).map_err(|error| {
            Error::io(
                "STATE_UNAVAILABLE",
                "cannot move the previous state root aside",
                error,
            )
        })?;
        plan.staged = Some(staged);
    }
    fs::create_dir_all(&plan.mount)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot create the mount point", error))?;
    run(
        Command::new("mount")
            .arg("-o")
            .arg("loop")
            .arg(&plan.image)
            .arg(&plan.mount),
        "loop mount",
    )?;
    let owner = current_owner();
    if let Some((uid, gid)) = owner {
        run(
            Command::new("chown")
                .arg(format!("{uid}:{gid}"))
                .arg(&plan.mount),
            "chown of the mount point",
        )?;
    }

    let mut notes = Vec::new();
    // The mount point is the state root, so any previous contents must already
    // have been moved aside before mounting. setup() stages them first.
    if let Some(staged) = &plan.staged {
        copy_tree(staged, &plan.mount)?;
        notes.push(format!(
            "moved the previous state root from {} into the image",
            staged.display()
        ));
    }
    if let Some((uid, gid)) = owner {
        run(
            Command::new("chown")
                .arg("-R")
                .arg(format!("{uid}:{gid}"))
                .arg(&plan.mount),
            "chown of the state root",
        )?;
    }
    // The state root and its containers must be owner-only (0700). A freshly
    // formatted mount point is 0755, and copied entries can keep a wider mode,
    // so normalize the root and the container directories explicitly.
    run(
        Command::new("chmod").arg("700").arg(&plan.mount),
        "chmod of the state root",
    )?;
    for container in ["sessions", "templates", "caches"] {
        let path = plan.mount.join(container);
        if path.is_dir() {
            run(
                Command::new("chmod").arg("700").arg(&path),
                "chmod of a state container",
            )?;
        }
    }
    let fstab = install_fstab(&plan)?;
    notes.push(fstab);
    notes.push(format!(
        "state root is {} on a {} image at {}",
        plan.state.display(),
        plan.size,
        plan.image.display()
    ));
    notes.push(
        "authority records copied from the old filesystem no longer match their new \
         device identity; re-run `git vws init <repository>` for each repository you \
         still use, then `git vws doctor`"
            .to_owned(),
    );
    Ok(notes.join("\n"))
}

fn create_sparse_image(path: &Path, bytes: u64) -> Result<(), Error> {
    let file = File::create(path)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot create the state image", error))?;
    file.set_len(bytes)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot size the state image", error))?;
    file.sync_all()
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot sync the state image", error))
}

fn current_owner() -> Option<(u32, u32)> {
    let uid = env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid = env::var("SUDO_GID").ok()?.parse().ok()?;
    Some((uid, gid))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), Error> {
    fs::create_dir_all(destination).map_err(|error| {
        Error::io(
            "STATE_UNAVAILABLE",
            "cannot create the adopted directory",
            error,
        )
    })?;
    let entries = fs::read_dir(source)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot read the state root", error))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot read a state entry", error))?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&from)
            .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot stat a state entry", error))?;
        if metadata.is_dir() {
            copy_tree(&from, &to)?;
        } else if metadata.is_symlink() {
            let target = fs::read_link(&from).map_err(|error| {
                Error::io("STATE_UNAVAILABLE", "cannot read a state symlink", error)
            })?;
            std::os::unix::fs::symlink(target, &to).map_err(|error| {
                Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot recreate a state symlink",
                    error,
                )
            })?;
        } else {
            fs::copy(&from, &to).map_err(|error| {
                Error::io("STATE_UNAVAILABLE", "cannot copy a state file", error)
            })?;
            fs::set_permissions(&to, metadata.permissions()).map_err(|error| {
                Error::io(
                    "STATE_UNAVAILABLE",
                    "cannot restore state permissions",
                    error,
                )
            })?;
        }
    }
    Ok(())
}

fn install_fstab(plan: &LoopPlan) -> Result<String, Error> {
    let path = Path::new("/etc/fstab");
    let existing = fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|line| line.contains(FSTAB_MARKER)) {
        return Ok("/etc/fstab already mounts the image".to_owned());
    }
    let entry = format!(
        "{FSTAB_MARKER}\n{} {} btrfs loop,defaults,nofail,x-systemd.device-timeout=10s 0 0\n",
        plan.image.display(),
        plan.mount.display()
    );
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot open /etc/fstab", error))?;
    file.write_all(entry.as_bytes())
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot append to /etc/fstab", error))?;
    file.sync_all()
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot sync /etc/fstab", error))?;
    Ok("added an /etc/fstab entry so the image mounts on boot".to_owned())
}

/// Grow the image and its filesystem in place.
pub(crate) fn resize(plan: &LoopPlan, size: Option<&str>) -> Result<String, Error> {
    let size = size.ok_or_else(|| {
        Error::new(
            "SESSION_USAGE",
            "resize needs --size, for example `git vws loop-resize --size 16G`",
        )
    })?;
    let bytes = parse_size(size)?;
    require_root("git vws loop-resize")?;
    if !plan.image.is_file() {
        return Err(Error::new(
            "STATE_UNAVAILABLE",
            format!("{} is not a state image", plan.image.display()),
        ));
    }
    let current = fs::metadata(&plan.image)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot stat the image", error))?
        .len();
    if bytes <= current {
        return Err(Error::new(
            "SESSION_USAGE",
            format!(
                "new size {size} is not larger than the current {} bytes",
                current
            ),
        ));
    }
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&plan.image)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot open the image", error))?;
    file.set_len(bytes)
        .map_err(|error| Error::io("STATE_UNAVAILABLE", "cannot grow the image", error))?;
    if let Some(device) = plan.loop_device() {
        // The loop device caches the old capacity, so refresh it before the
        // filesystem can grow into the new space.
        let _ = Command::new("losetup")
            .arg("-c")
            .arg(&device)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    run(
        Command::new("btrfs")
            .arg("filesystem")
            .arg("resize")
            .arg("max")
            .arg(&plan.mount),
        "btrfs filesystem resize",
    )?;
    Ok(format!(
        "grew the state image to {size} and resized the filesystem"
    ))
}

/// Report whether the current state root is a loop image, so maintenance can
/// explain an unmounted image instead of reporting a missing state root.
pub(crate) fn describe_state_root(state_root: &Path) -> Option<String> {
    let home = home_directory().ok()?;
    let image = home.join(IMAGE_NAME);
    if !image.is_file() {
        return None;
    }
    let mounted = Command::new("mountpoint")
        .arg("-q")
        .arg(state_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    Some(if mounted {
        format!(
            "the state root is a loop image at {} (mounted)",
            image.display()
        )
    } else {
        format!(
            "the state root is a loop image at {} that is not mounted; run `sudo mount {}` and retry",
            image.display(),
            state_root.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_human_sizes_with_binary_multipliers() {
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("8G").unwrap(), 8 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1T").unwrap(), 1024_u64.pow(4));
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size(" 2g ").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn rejects_sizes_that_cannot_be_parsed() {
        for value in ["", "  ", "abc", "8X", "-1G", "1.5G"] {
            assert!(
                parse_size(value).is_err(),
                "{value:?} should not parse as a size"
            );
        }
    }

    #[test]
    fn rejects_sizes_below_the_btrfs_minimum() {
        // The minimum guard lives in setup; confirm the threshold matches the
        // smallest image mkfs.btrfs accepts in practice.
        assert_eq!(MINIMUM_BYTES, 256 * 1024 * 1024);
        assert!(parse_size("128M").unwrap() < MINIMUM_BYTES);
        assert!(parse_size("512M").unwrap() >= MINIMUM_BYTES);
    }
}
