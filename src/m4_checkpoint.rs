use crate::authority::Error;
use std::env;
use std::io::{Read, Write};
use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
const FD_ENV: &str = "GIT_VWS_M4_CONTROL_FD";
const NONCE_ENV: &str = "GIT_VWS_M4_NONCE";
const TARGET_ENV: &str = "GIT_VWS_M4_TARGET";
const MAX_FRAME: usize = 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
struct Control {
    socket: Mutex<UnixStream>,
    nonce: String,
    pid: i32,
    pgid: i32,
    sequence: AtomicU64,
}
static CONTROL: OnceLock<Control> = OnceLock::new();
pub(crate) fn arm() -> Result<(), Error> {
    let fd = parse_fd(&value(FD_ENV)?)?;
    let nonce = value(NONCE_ENV)?;
    if !lower_hex(&nonce, 32) {
        return Err(fail("checkpoint nonce is invalid"));
    }
    let target = value(TARGET_ENV)?;
    let Some((operation, stage)) = target.split_once('/') else {
        return Err(fail("checkpoint target is invalid"));
    };
    if !matches!(operation, "template" | "create" | "remove") || !token(stage) {
        return Err(fail("checkpoint target is invalid"));
    }
    validate_socket(fd)?;
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(fail("cannot isolate checkpoint process group"));
    }
    let pid = unsafe { libc::getpid() };
    let pgid = unsafe { libc::getpgrp() };
    if pid != pgid {
        return Err(fail("checkpoint process group is not private"));
    }
    let mut socket = unsafe { UnixStream::from_raw_fd(fd) };
    socket
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|_| socket.set_write_timeout(Some(TIMEOUT)))
        .map_err(|_| fail("cannot configure checkpoint control timeout"))?;
    send(&mut socket, &format!("M4CP/1 HELLO {nonce} {pid} {pgid}\n"))?;
    if receive(&mut socket)? != format!("M4CP/1 ARM {nonce} {pid} {pgid} {target}\n") {
        return Err(fail("controller ARM did not exactly match HELLO"));
    }
    let control_fd = socket.as_raw_fd();
    let flags = unsafe { libc::fcntl(control_fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(control_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
    {
        return Err(fail("cannot protect checkpoint control FD"));
    }
    env::remove_var(FD_ENV);
    env::remove_var(NONCE_ENV);
    env::remove_var(TARGET_ENV);
    CONTROL
        .set(Control {
            socket: Mutex::new(socket),
            nonce,
            pid,
            pgid,
            sequence: AtomicU64::new(1),
        })
        .map_err(|_| fail("checkpoint control was armed twice"))
}
pub(crate) fn checkpoint(operation: &str, sid: &str, key: &str, stage: &str) -> Result<(), Error> {
    let control = CONTROL
        .get()
        .ok_or_else(|| fail("checkpoint control was not armed"))?;
    if !matches!(operation, "template" | "create" | "remove")
        || !(sid == "-" || lower_hex(sid, 64))
        || !(key == "-" || lower_hex(key, 64))
        || !token(stage)
    {
        return Err(fail("checkpoint fields are invalid"));
    }
    let sequence = control.sequence.fetch_add(1, Ordering::Relaxed);
    if sequence == u64::MAX {
        return Err(fail("checkpoint sequence overflowed"));
    }
    let tx = format!("{}.{}", control.nonce, sequence);
    let cp = message("CP", control, sequence, &tx, [operation, sid, key, stage]);
    let mut socket = control
        .socket
        .lock()
        .map_err(|_| fail("checkpoint lock failed"))?;
    send(&mut socket, &cp)?;
    if receive(&mut socket)? != message("GO", control, sequence, &tx, [operation, sid, key, stage])
    {
        return Err(fail("controller GO did not exactly match checkpoint"));
    }
    send(
        &mut socket,
        &message("ACK", control, sequence, &tx, [operation, sid, key, stage]),
    )
}
fn message(kind: &str, control: &Control, sequence: u64, tx: &str, fields: [&str; 4]) -> String {
    let [operation, sid, key, stage] = fields;
    format!(
        "M4CP/1 {kind} {} {} {} {sequence} {tx} {operation} {sid} {key} {stage}\n",
        control.nonce, control.pid, control.pgid
    )
}
fn value(name: &str) -> Result<String, Error> {
    env::var(name).map_err(|_| fail("checkpoint control environment is incomplete"))
}
fn parse_fd(value: &str) -> Result<RawFd, Error> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse())
        .ok_or_else(|| fail("checkpoint control FD is invalid"))?
        .map_err(|_| fail("checkpoint control FD is invalid"))
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}
fn validate_socket(fd: RawFd) -> Result<(), Error> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if fd < 0
        || unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_uid != unsafe { libc::getuid() }
        || (stat.st_mode as u32 & libc::S_IFMT as u32) != libc::S_IFSOCK as u32
    {
        return Err(fail("checkpoint control FD is not an owned socket"));
    }
    let mut kind = 0;
    let mut kind_length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut kind as *mut libc::c_int as *mut libc::c_void,
            &mut kind_length,
        )
    } != 0
        || kind != libc::SOCK_STREAM
    {
        return Err(fail("checkpoint control FD is not a stream socket"));
    }
    if !anonymous_unix_address(fd, false) || !anonymous_unix_address(fd, true) {
        return Err(fail("checkpoint socketpair is invalid"));
    }
    Ok(())
}
fn anonymous_unix_address(fd: RawFd, peer: bool) -> bool {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut length = size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let result = unsafe {
        if peer {
            libc::getpeername(
                fd,
                &mut address as *mut libc::sockaddr_un as *mut libc::sockaddr,
                &mut length,
            )
        } else {
            libc::getsockname(
                fd,
                &mut address as *mut libc::sockaddr_un as *mut libc::sockaddr,
                &mut length,
            )
        }
    };
    let (length, offset) = (length as usize, offset_of!(libc::sockaddr_un, sun_path));
    result == 0
        && length >= offset
        && length <= size_of::<libc::sockaddr_un>()
        && address.sun_family as libc::c_int == libc::AF_UNIX
        && address.sun_path[..length - offset]
            .iter()
            .all(|byte| *byte == 0)
}
fn send(socket: &mut UnixStream, frame: &str) -> Result<(), Error> {
    if frame.len() > MAX_FRAME || !frame.is_ascii() {
        return Err(fail("checkpoint frame is invalid"));
    }
    let length = (frame.len() as u32).to_be_bytes();
    socket
        .write_all(&length)
        .and_then(|_| socket.write_all(frame.as_bytes()))
        .map_err(|_| fail("checkpoint control socket write failed"))
}
fn receive(socket: &mut UnixStream) -> Result<String, Error> {
    let mut length = [0; size_of::<u32>()];
    socket
        .read_exact(&mut length)
        .map_err(|_| fail("checkpoint control socket read failed"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(fail("checkpoint frame length is invalid"));
    }
    let mut frame = vec![0; length];
    socket
        .read_exact(&mut frame)
        .map_err(|_| fail("checkpoint control socket read failed"))?;
    let frame = String::from_utf8(frame).map_err(|_| fail("checkpoint frame is not ASCII"))?;
    frame
        .is_ascii()
        .then_some(frame)
        .ok_or_else(|| fail("checkpoint frame is not ASCII"))
}
fn fail(detail: &'static str) -> Error {
    Error::new("M4_CHECKPOINT_FAILED", detail)
}
