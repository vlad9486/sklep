use std::{
    ffi::{CStr, OsStr},
    io::{Read, Write},
    os::{
        raw::{c_char, c_int, c_uint},
        unix::{ffi::OsStrExt, net::UnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr, thread,
    time::Duration,
};

use pam_sys::*;
use zeroize::Zeroize;
use nix::libc;

mod log {
    #[macro_export]
    macro_rules! pam_log {
        ($pamh:expr, $level:expr, $($arg:tt)*) => {{
            extern "C" {
                fn pam_syslog(pamh: *mut pam_sys::pam_handle_t, priority: std::os::raw::c_int, format: *const std::os::raw::c_char, ...);
            }

            let s = format!($($arg)*);
            let pamh = $pamh;
            let level = $level;

            unsafe { pam_syslog(pamh, level, s.as_ptr().cast()) };
        }};
    }

    #[macro_export]
    macro_rules! error {
        ($pamh:expr, $($arg:tt)*) => {$crate::pam_log!($pamh, 3, $($arg)*)}
    }

    #[macro_export]
    macro_rules! debug {
        ($pamh:expr, $($arg:tt)*) => {$crate::pam_log!($pamh, 7, $($arg)*)}
    }

    pub use {error, debug};
}

#[no_mangle]
extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut pam_handle_t,
    _flags: c_uint,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let _ = pamh;

    PAM_SUCCESS
}

fn passwd(pamh: *mut pam_handle_t) -> Result<libc::passwd, String> {
    let mut name = ptr::null();
    let code = unsafe { pam_get_item(pamh, PAM_USER, &mut name) };
    if code != PAM_SUCCESS {
        Err(unsafe { CStr::from_ptr(pam_strerror(pamh, code)) }
            .to_string_lossy()
            .to_string())
    } else {
        Ok(unsafe { *libc::getpwnam(name.cast()) })
    }
}

#[no_mangle]
unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_uint,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let passwd = match passwd(pamh) {
        Ok(v) => v,
        Err(err) => {
            log::error!(pamh, "Failed to get user info: {err}.\0");
            return PAM_AUTH_ERR;
        }
    };

    fn launch_sklep(passwd: &libc::passwd) -> anyhow::Result<()> {
        let home_dir = unsafe { CStr::from_ptr(passwd.pw_dir) };
        let home_dir = PathBuf::from(OsStr::from_bytes(home_dir.to_bytes()));
        let uid = passwd.pw_uid;
        let gid = passwd.pw_gid;

        let mut cmd = Command::new("sklep");
        cmd.current_dir(home_dir)
            .envs(None::<(&str, &str)>)
            .uid(uid)
            .gid(gid)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe { cmd.pre_exec(|| nix::unistd::setsid().map(drop).map_err(From::from)) };
        cmd.spawn()?;

        Ok(())
    }

    let path = PathBuf::from(format!("/var/run/user/{}/sklep.sock", passwd.pw_uid));
    let stream = match UnixStream::connect(&path) {
        Ok(v) => v,
        Err(_) => {
            if let Err(err) = launch_sklep(&passwd) {
                log::error!(pamh, "Failed to launch sklep: \"{err}\".\0");
                return PAM_AUTH_ERR;
            }

            let mut tries = 20;
            loop {
                thread::sleep(Duration::from_millis(50));
                if let Ok(stream) = UnixStream::connect(&path) {
                    break stream;
                }

                tries -= 1;
                if tries == 0 {
                    log::error!(
                        pamh,
                        "Failed to connect to sklep socket at {}.\0",
                        path.display()
                    );
                    return PAM_AUTH_ERR;
                }
            }
        }
    };

    let mut token = ptr::null();
    let code = pam_get_authtok(pamh, PAM_AUTHTOK, &mut token, ptr::null());
    if code != PAM_SUCCESS {
        let err = CStr::from_ptr(pam_strerror(pamh, code)).to_string_lossy();
        log::error!(pamh, "Failed to get password: {err}.\0");
        return PAM_AUTH_ERR;
    }
    let mut password = [0u8; 0x100];
    libc::strncpy(password.as_mut_ptr().cast(), token, password.len());

    fn handshake(mut stream: UnixStream, password: &[u8; 0x100]) -> anyhow::Result<()> {
        stream.write_all(b"+")?;
        stream.write_all(password)?;

        let mut response = [0; 8];
        stream.read_exact(&mut response)?;

        if response == *b"success\n" {
            Ok(())
        } else {
            Err(anyhow::anyhow!("wrong password"))
        }
    }

    let res = handshake(stream, &password);
    password.zeroize();
    if let Err(err) = res {
        log::error!(pamh, "Cannot authorize on sklep: \"{err}\".\0");
        PAM_AUTH_ERR
    } else {
        PAM_SUCCESS
    }
}

#[no_mangle]
extern "C" fn pam_sm_chauthtok(
    pamh: *mut pam_handle_t,
    flags: c_uint,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let _ = (pamh, flags);

    PAM_SUCCESS
}

#[no_mangle]
unsafe extern "C" fn pam_sm_close_session(
    pamh: *mut pam_handle_t,
    _flags: c_uint,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let passwd = match passwd(pamh) {
        Ok(v) => v,
        Err(err) => {
            log::error!(pamh, "Failed to get user info: {err}.\0");
            return PAM_AUTH_ERR;
        }
    };
    let path = PathBuf::from(format!("/var/run/user/{}/sklep.sock", passwd.pw_uid));
    log::debug!(pamh, "Close session, uid: {}\0", passwd.pw_uid);

    fn terminate_sklep(path: impl AsRef<Path>) -> anyhow::Result<()> {
        let mut stream = UnixStream::connect(&path)?;
        stream.write_all(b"-")?;

        Ok(())
    }

    if let Err(err) = terminate_sklep(path) {
        log::error!(pamh, "Failed to terminate sklep: \"{err}\".\0");
        PAM_SESSION_ERR
    } else {
        PAM_SUCCESS
    }
}

#[no_mangle]
extern "C" fn pam_sm_open_session(
    pamh: *mut pam_handle_t,
    _flags: c_uint,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let _ = pamh;

    PAM_SUCCESS
}

#[no_mangle]
extern "C" fn pam_sm_setcred(
    pamh: *mut pam_handle_t,
    flags: c_uint,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let _ = (pamh, flags);

    PAM_SUCCESS
}
