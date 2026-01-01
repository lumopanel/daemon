//! Peer credential verification using SO_PEERCRED.
//!
//! Verifies that the connecting process is running as an allowed UID.

use std::os::unix::io::AsRawFd;

use crate::error::{AuthErrorKind, DaemonError};

/// Information about the connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// User ID of the peer process.
    pub uid: u32,
    /// Group ID of the peer process.
    pub gid: u32,
    /// Process ID of the peer process (may be 0 on some platforms).
    pub pid: i32,
}

/// Verify that the peer is authorized to connect.
///
/// Checks the peer's UID against the list of allowed UIDs.
/// Returns the peer info if authorized.
#[cfg(target_os = "linux")]
pub fn verify_peer<S: std::os::fd::AsFd>(
    stream: &S,
    allowed_uids: &[u32],
) -> Result<PeerInfo, DaemonError> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let creds = getsockopt(stream, PeerCredentials).map_err(|e| DaemonError::Socket {
        message: format!("Failed to get peer credentials: {}", e),
    })?;

    let peer = PeerInfo {
        uid: creds.uid(),
        gid: creds.gid(),
        pid: creds.pid(),
    };

    // Security: Fail-closed on empty UID list - reject all if no UIDs configured
    if allowed_uids.is_empty() {
        return Err(DaemonError::Auth {
            kind: AuthErrorKind::UnauthorizedPeer { uid: peer.uid },
        });
    }

    if !allowed_uids.contains(&peer.uid) {
        return Err(DaemonError::Auth {
            kind: AuthErrorKind::UnauthorizedPeer { uid: peer.uid },
        });
    }

    Ok(peer)
}

/// Verify that the peer is authorized to connect (macOS version).
///
/// Note: macOS uses LOCAL_PEERCRED instead of SO_PEERCRED.
/// The implementation differs from Linux.
#[cfg(target_os = "macos")]
pub fn verify_peer<S: AsRawFd>(stream: &S, allowed_uids: &[u32]) -> Result<PeerInfo, DaemonError> {
    use nix::libc;
    use std::mem;
    use std::os::raw::c_int;

    // On macOS, we use LOCAL_PEERCRED
    const LOCAL_PEERCRED: c_int = 0x001;
    const SOL_LOCAL: c_int = 0;

    #[repr(C)]
    struct XuCred {
        cr_version: u32,
        cr_uid: u32,
        cr_ngroups: i16,
        cr_groups: [u32; 16],
    }

    // SAFETY: XuCred is a repr(C) struct with no padding requirements beyond what
    // mem::zeroed provides. All fields are primitive types (u32, i16, [u32; 16])
    // that have valid bit patterns for zero values.
    let mut cred: XuCred = unsafe { mem::zeroed() };
    cred.cr_version = 0; // XUCRED_VERSION
    let mut len = mem::size_of::<XuCred>() as u32;

    // SAFETY: getsockopt is a well-defined syscall. We ensure:
    // 1. stream.as_raw_fd() returns a valid file descriptor for the socket
    // 2. SOL_LOCAL and LOCAL_PEERCRED are valid socket option constants for macOS
    // 3. &mut cred points to valid, aligned memory of sufficient size
    // 4. len is initialized to the correct struct size
    // The kernel will write peer credentials into cred and update len.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result != 0 {
        return Err(DaemonError::Socket {
            message: format!(
                "Failed to get peer credentials: {}",
                std::io::Error::last_os_error()
            ),
        });
    }

    let peer = PeerInfo {
        uid: cred.cr_uid,
        gid: if cred.cr_ngroups > 0 {
            cred.cr_groups[0]
        } else {
            0
        },
        pid: 0, // macOS LOCAL_PEERCRED doesn't provide PID
    };

    // Security: Fail-closed on empty UID list - reject all if no UIDs configured
    if allowed_uids.is_empty() {
        return Err(DaemonError::Auth {
            kind: AuthErrorKind::UnauthorizedPeer { uid: peer.uid },
        });
    }

    if !allowed_uids.contains(&peer.uid) {
        return Err(DaemonError::Auth {
            kind: AuthErrorKind::UnauthorizedPeer { uid: peer.uid },
        });
    }

    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_info_debug() {
        let peer = PeerInfo {
            uid: 1000,
            gid: 1000,
            pid: 12345,
        };
        let debug = format!("{:?}", peer);
        assert!(debug.contains("uid: 1000"));
        assert!(debug.contains("pid: 12345"));
    }
}
