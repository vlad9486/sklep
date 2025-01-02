use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    process, str,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    thread,
};

use fuser::{BackgroundSession, MountOption};
use zeroize::Zeroize;

use sklep_fuse::SklepFs;

fn init_logger() -> Box<dyn log::Log> {
    use syslog::{BasicLogger, Facility, Formatter3164};
    use env_logger::Builder;

    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "sklep".to_owned(),
        pid: process::id(),
    };
    syslog::unix(formatter)
        .map(BasicLogger::new)
        .map(|l| Box::new(l) as Box<dyn log::Log>)
        .unwrap_or_else(|_| {
            // fallback
            let logger = Builder::default().parse_env("info").build();
            Box::new(logger) as Box<dyn log::Log>
        })
}

fn main() {
    log::set_boxed_logger(init_logger()).unwrap_or_default();
    log::set_max_level(log::LevelFilter::max());

    let counter = Arc::new(AtomicU32::new(0));
    let session = Arc::new(Mutex::new(None));

    let uid = unsafe { nix::libc::getuid() };
    let path = move || PathBuf::from(format!("/var/run/user/{uid}/sklep.sock"));
    match UnixListener::bind(path()) {
        Ok(listener) => {
            for mut stream in listener.incoming().flatten() {
                log::debug!("New stream");
                let counter = counter.clone();
                let session = session.clone();
                thread::spawn(move || {
                    let mut action = [0; 1];
                    let mut buffer = [0; 0x100];
                    stream.read_exact(&mut action).unwrap();
                    let action = action[0] as char;
                    log::debug!(
                        "Counter {}, action '{action}'",
                        counter.load(Ordering::SeqCst),
                    );
                    match action {
                        '+' => {
                            stream.read_exact(&mut buffer).unwrap();
                            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                                match new_session(&mut stream, &mut buffer, uid) {
                                    Ok(new) => *session.lock().expect("poisoned") = Some(new),
                                    Err(err) => {
                                        log::error!("{err}");
                                        fs::remove_file(path()).unwrap_or_default();
                                        process::exit(0);
                                    }
                                }
                            } else {
                                // TODO: validate
                                buffer.zeroize();
                                stream.write_all(b"success\n").unwrap();
                            }
                        }
                        '-' => {
                            if counter.fetch_sub(1, Ordering::SeqCst) == 1 {
                                *session.lock().expect("poisoned") = None;
                                fs::remove_file(path()).unwrap_or_default();
                                process::exit(0);
                            }
                        }
                        _ => {}
                    }
                });
            }
        }
        Err(_) => {
            log::warn!("Already running");
        }
    }
}

fn new_session(
    stream: &mut UnixStream,
    buffer: &mut [u8; 0x100],
    uid: u32,
) -> anyhow::Result<BackgroundSession> {
    let len = buffer
        .iter()
        .enumerate()
        .find_map(|(n, x)| (*x == 0).then_some(n))
        .unwrap_or(256);
    let passphrase = str::from_utf8(&buffer[..len])?;

    fn validate(passphrase: &str) -> Option<(u32, u32, &str)> {
        let (f, rest) = passphrase.split_at_checked(3)?;
        let [time, memory_exp, memory_unit] = f.as_bytes() else {
            return None;
        };
        if time.is_ascii_digit()
            && memory_exp.is_ascii_digit()
            && [b'k', b'M', b'G'].contains(memory_unit)
        {
            let time = *time - b'0';
            let memory_exp = *memory_exp - b'0';
            log::debug!(
                "complexity: time={time}, mem={}{}",
                1 << memory_exp,
                *memory_unit as char
            );
            let memory_unit = match *memory_unit {
                b'k' => 0,
                b'M' => 10,
                b'G' => 20,
                _ => unreachable!(),
            };
            let memory = 1 << (memory_exp + memory_unit);
            return Some((time.into(), memory, rest));
        }

        None
    }

    let Some((time, memory, passphrase)) = validate(passphrase) else {
        return Err(anyhow::anyhow!(
            "wrong password format: should be [%d][%d][k|M|G]..."
        ));
    };

    let path = PathBuf::from(".sklep.db");
    let filesystem = match SklepFs::new(passphrase, time, memory, path, uid) {
        Ok(v) => v,
        Err(err) => {
            buffer.zeroize();
            stream.write_all(b"failure\n")?;
            return Err(err.into());
        }
    };
    buffer.zeroize();
    stream.write_all(b"success\n")?;

    let options = [
        MountOption::FSName("sklep".to_string()),
        MountOption::NoDev,
        MountOption::RW,
        MountOption::Exec,
    ];
    fuser::spawn_mount2(filesystem, ".sklep", &options).map_err(Into::into)
}
