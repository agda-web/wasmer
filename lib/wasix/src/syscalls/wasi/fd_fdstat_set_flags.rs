use super::*;
use crate::syscalls::*;

/// ### `fd_fdstat_set_flags()`
/// Set file descriptor flags for a file descriptor
/// Inputs:
/// - `Fd fd`
///     The file descriptor to apply the new flags to
/// - `Fdflags flags`
///     The flags to apply to `fd`
#[instrument(level = "debug", skip_all, fields(%fd), ret)]
pub fn fd_fdstat_set_flags(
    mut ctx: FunctionEnvMut<'_, WasiEnv>,
    fd: WasiFd,
    flags: Fdflags,
) -> Result<Errno, WasiError> {
    {
        let env = ctx.data();
        let (_, mut state, inodes) = unsafe { env.get_memory_and_wasi_state_and_inodes(&ctx, 0) };
        let mut fd_map = state.fs.fd_map.write().unwrap();
        let fd_entry = wasi_try_ok!(fd_map.get_mut(&fd).ok_or(Errno::Badf));
        let inode = fd_entry.inode.clone();

        if !fd_entry.rights.contains(Rights::FD_FDSTAT_SET_FLAGS) {
            return Ok(Errno::Access);
        }
    }

    let env = ctx.data();
    let (_, mut state, inodes) = unsafe { env.get_memory_and_wasi_state_and_inodes(&ctx, 0) };
    let mut fd_map = state.fs.fd_map.write().unwrap();
    let fd_entry = wasi_try_ok!(fd_map.get_mut(&fd).ok_or(Errno::Badf));
    fd_entry.flags = flags;

    #[cfg(unix)]
    {
        // apply O_NONBLOCK state to the underlying file descriptor via fcntl
        let guard = fd_entry.inode.read();

        let maybe_sys_fd = match guard.deref() {
            Kind::File { handle, .. } => {
                if let Some(handle) = handle {
                    let handle = handle.clone();
                    let handle = wasi_try_ok!(handle.read().map_err(|_| { Errno::Badf }));
                    handle.get_special_fd()
                } else { None }
            },
            _ => None,
        };

        if let Some(sys_fd) = maybe_sys_fd {
            let sys_fd = wasi_try_ok!(i32::try_from(sys_fd).map_err(|_| { Errno::Badf }));
            return set_nonblocking_mode(sys_fd, flags.contains(Fdflags::NONBLOCK));
        }
    }

    Ok(Errno::Success)
}

#[cfg(unix)]
fn set_nonblocking_mode(host_fd: i32, new_value: bool) -> Result<Errno, WasiError> {
    let fcntl_flags = unsafe { libc::fcntl(host_fd, libc::F_GETFL) };
    wasi_try_ok!((fcntl_flags >= 0).then(|| ()).ok_or(Errno::Access));

    let fcntl_flags = if new_value {
        fcntl_flags | libc::O_NONBLOCK
    } else {
        fcntl_flags & !libc::O_NONBLOCK
    };

    let ret = unsafe { libc::fcntl(host_fd, libc::F_SETFL, fcntl_flags) };
    wasi_try_ok!((ret == 0).then(|| ()).ok_or(Errno::Access));

    Ok(Errno::Success)
}
