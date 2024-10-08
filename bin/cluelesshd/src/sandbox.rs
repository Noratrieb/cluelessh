use std::{
    fs::File,
    io::{Read, Write},
    os::fd::RawFd,
    path::Path,
};

use eyre::{bail, Result, WrapErr};
use rustix::{
    fs::UnmountFlags,
    process::WaitOptions,
    thread::{Pid, UnshareFlags},
};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use tracing::{debug, trace, warn};

use crate::{
    SerializedConnectionState, PRIVSEP_CONNECTION_RPC_CLIENT_FD, PRIVSEP_CONNECTION_STREAM_FD,
};

#[tracing::instrument(skip(state), ret)]
pub fn drop_privileges(state: &SerializedConnectionState) -> Result<()> {
    if rustix::process::getuid().is_root() {
        crate::sandbox::unshare_namespaces()?;
    } else {
        // TODO: We can still do it if we're careful with the uid map.
        debug!("Not unsharing namespaces as the daemon was not started as root");
    }

    if let Some(gid) = state.setgid {
        debug!(?gid, "Setting GID to drop privileges");
        let result = unsafe { libc::setgid(gid) };
        if result == -1 {
            return Err(std::io::Error::last_os_error()).wrap_err("failed to setgid");
        }
    }
    if let Some(uid) = state.setuid {
        debug!(?uid, "Setting UID to drop privileges");
        let result = unsafe { libc::setuid(uid) };
        if result == -1 {
            return Err(std::io::Error::last_os_error()).wrap_err("failed to setuid");
        }
    }

    rustix::thread::set_no_new_privs(true)?;

    if state.config.security.experimental_seccomp {
        seccomp().wrap_err("setting up seccomp")?;
    }

    Ok(())
}

enum Fork {
    Child,
    Parent(rustix::process::Pid),
}

unsafe fn fork() -> Result<Fork> {
    unsafe {
        let result = libc::fork();
        if result == -1 {
            return Err(std::io::Error::last_os_error()).wrap_err("setting propagation flags")?;
        }
        if result > 0 {
            Ok(Fork::Parent(Pid::from_raw_unchecked(result)))
        } else {
            Ok(Fork::Child)
        }
    }
}

fn pipe() -> Result<(File, File)> {
    let (read, write) = rustix::pipe::pipe()?;

    Ok((File::from(read), File::from(write)))
}

/// Unshare namespaces to set up a sandbox.
/// If this fails, there might be zombie child processes.
/// Therefore, the caller must exit if this function fails.
#[tracing::instrument]
fn unshare_namespaces() -> Result<()> {
    // TODO: respect unprivileged_uid config and stuff
    let (mut child_ready_read, mut child_ready_write) = pipe()?;
    let (mut uid_map_ready_read, mut uid_map_ready_write) = pipe()?;

    match unsafe { fork()? } {
        Fork::Parent(child) => {
            // In an error condition, we will not wait on the child.
            // But this is fine, as any error from this function will cause the caller to exit.
            let mut read = [0; 1];
            child_ready_read.read_exact(&mut read)?;
            if read[0] != 1 {
                bail!("child failed to write");
            }

            trace!("Parent: child is ready");

            let result1 = std::fs::write(
                format!("/proc/{}/uid_map", child.as_raw_nonzero().get()),
                "0 1000000 1000000",
            );
            let result2 = std::fs::write(
                format!("/proc/{}/gid_map", child.as_raw_nonzero().get()),
                "0 1000000 1000000",
            );

            let result = result1.and(result2);

            let value = if result.is_ok() { 1 } else { 0 };
            trace!(?value, "Parent: signaling uid_map write result");

            uid_map_ready_write.write_all(&[value])?;

            result?;

            let code = rustix::process::waitpid(Some(child), WaitOptions::empty());
            match code {
                Err(_) => std::process::exit(2),
                Ok(None) => std::process::exit(1),
                Ok(Some(code)) => std::process::exit(code.as_raw() as i32),
            }
        }
        Fork::Child => {} // Move on
    }

    // The complicated incarnation to get a mount namespace working.
    let result = rustix::thread::unshare(
        UnshareFlags::NEWNS
            | UnshareFlags::NEWNET
            | UnshareFlags::NEWIPC
            | UnshareFlags::NEWPID
            | UnshareFlags::NEWTIME
            | UnshareFlags::NEWUTS
            | UnshareFlags::NEWUSER,
    )
    .wrap_err("unsharing namespaces");

    let value = if result.is_ok() { 1 } else { 0 };

    trace!(?value, "Child: signaling unshare result");
    child_ready_write.write_all(&[value])?;

    result?;

    let mut read = [0; 1];
    uid_map_ready_read.read_exact(&mut read)?;
    if read[0] != 1 {
        bail!("parent failed to write");
    }
    trace!("Child: uid mappings set up, continue");

    //std::thread::sleep(std::time::Duration::from_secs(1000));

    // After creating the PID namespace, we fork immediately so we can get PID 1.
    // We never exec, we just let the child live on happily.
    // The parent immediately waits for it, and then doesn't do anything really.
    // TODO: this is a bit sus....

    match unsafe { fork()? } {
        Fork::Parent(child) => {
            let code = rustix::process::waitpid(Some(child), WaitOptions::empty());
            match code {
                Err(_) => std::process::exit(2),
                Ok(None) => std::process::exit(1),
                Ok(Some(code)) => std::process::exit(code.as_raw() as i32),
            }
        }
        Fork::Child => {} // Move on
    }

    let result = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error()).wrap_err("setting propagation flags")?;
    }

    let new_root = Path::new("empty-new-root");
    let old_root = &new_root.join("old-root");

    std::fs::create_dir_all(new_root)?;
    std::fs::create_dir_all(&old_root)?;

    rustix::fs::bind_mount(new_root, new_root).wrap_err("bind mount the empty dir")?;

    rustix::process::pivot_root(new_root, old_root).wrap_err("pivoting root")?;

    // TODO: can we get rid of it entirely?
    rustix::fs::unmount("/old-root", UnmountFlags::DETACH).wrap_err("unmounting old root")?;

    Ok(())
}

#[tracing::instrument]
fn seccomp() -> Result<()> {
    use seccompiler::{SeccompCmpArgLen as ArgLen, SeccompCmpOp as Op, SeccompCondition as Cond};

    let arch = match std::env::consts::ARCH {
        "x86_64" => TargetArch::x86_64,
        "aarch64" => TargetArch::aarch64,
        arch => {
            warn!("Seccomp not supported for architecture ({arch})m skipping");
            return Ok(());
        }
    };

    let limit_fd = |fd: RawFd| {
        SeccompRule::new(vec![Cond::new(
            0, // fd
            ArgLen::Dword,
            Op::Eq,
            fd as u64,
        )
        .unwrap()])
        .unwrap()
    };

    let filter = SeccompFilter::new(
        vec![
            (libc::SYS_write, vec![]),
            (libc::SYS_epoll_create1, vec![]),
            (libc::SYS_eventfd2, vec![]),
            (libc::SYS_epoll_wait, vec![]),
            (libc::SYS_epoll_ctl, vec![]),
            (libc::SYS_fcntl, vec![]), // todo: restrict this
            (libc::SYS_socketpair, vec![]),
            (
                libc::SYS_sendmsg,
                vec![limit_fd(PRIVSEP_CONNECTION_RPC_CLIENT_FD)],
            ),
            (
                libc::SYS_recvmsg,
                vec![limit_fd(PRIVSEP_CONNECTION_RPC_CLIENT_FD)],
            ),
            (
                libc::SYS_sendto,
                vec![limit_fd(PRIVSEP_CONNECTION_STREAM_FD)],
            ),
            (
                libc::SYS_recvfrom,
                vec![limit_fd(PRIVSEP_CONNECTION_STREAM_FD)],
            ),
            (libc::SYS_getrandom, vec![]),
            (libc::SYS_rt_sigaction, vec![]),
            (libc::SYS_rt_sigprocmask, vec![]),
            (libc::SYS_mmap, vec![]),
            (libc::SYS_munmap, vec![]),
            (libc::SYS_sched_getaffinity, vec![]),
            (libc::SYS_sigaltstack, vec![]),
            (libc::SYS_futex, vec![]),
            (libc::SYS_read, vec![]),
            (libc::SYS_mprotect, vec![]),
            (libc::SYS_rseq, vec![]),
            (libc::SYS_set_robust_list, vec![]),
            (libc::SYS_prctl, vec![]),
            (libc::SYS_close, vec![]),
            (libc::SYS_madvise, vec![]),
            (libc::SYS_exit, vec![]),
            (libc::SYS_exit_group, vec![]),
            (libc::SYS_sched_yield, vec![]),
            (
                libc::SYS_ioctl,
                vec![SeccompRule::new(vec![Cond::new(
                    1, // op
                    // dword for musl, qword for glibc :D.
                    // but since FIONBIO is <u32::MAX, we can use dword.
                    ArgLen::Dword,
                    Op::Eq,
                    libc::FIONBIO, // non-blocking
                )?])?],
            ),
        ]
        .into_iter()
        .collect(),
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
    )
    .wrap_err("creating seccomp filter")?;

    let program: BpfProgram = filter.try_into().wrap_err("compiling seccomp filter")?;

    debug!("Installing seccomp filter");
    seccompiler::apply_filter(&program).wrap_err("installing seccomp filter")?;

    Ok(())
}
