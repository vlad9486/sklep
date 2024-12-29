use std::{
    ffi::OsStr,
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request};
use zeroize::Zeroize;
use nix::errno::Errno;

use super::schema;

const TTL: Duration = Duration::from_secs(1); // 1 second

const TEMPLATE_DIR_ATTR: FileAttr = FileAttr {
    ino: 0,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 0,
    gid: 0,
    rdev: 0,
    flags: 0,
    blksize: 0x1000,
};

const TEMPLATE_FILE_ATTR: FileAttr = FileAttr {
    ino: 0,
    size: 0,
    blocks: 1,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 0,
    gid: 0,
    rdev: 0,
    flags: 0,
    blksize: 0x1000,
};

fn unwrap_time(v: fuser::TimeOrNow) -> SystemTime {
    match v {
        fuser::TimeOrNow::Now => SystemTime::now(),
        fuser::TimeOrNow::SpecificTime(t) => t,
    }
}

// ino -> data
const DATA_TABLE_ID: u32 = 10;

pub struct SklepFs {
    db: rej::Db,
    seed: [u64; 4],
}

impl SklepFs {
    pub fn new(
        passphrase: &str,
        time: u32,
        memory: u32,
        path: impl AsRef<Path>,
    ) -> Result<Self, schema::SchemaError> {
        let mut seed = [0; 64];
        let secret = rej::Secret::Pw {
            pw: passphrase,
            time,
            memory: 1 << (10 + memory),
        };
        let exist = path.as_ref().exists();
        let params = if exist {
            rej::Params::Open { secret }
        } else {
            getrandom::getrandom(&mut seed)
                .map_err(|err| io::Error::from_raw_os_error(err.code().get() as i32))
                .map_err(rej::DbError::Io)?;
            rej::Params::Create {
                secret,
                seed: &seed[..32],
            }
        };
        let res = rej::Db::new(&path, Default::default(), params);
        seed[..32].zeroize();
        let db = res?;

        let seed = schema::init_seed(&db, &mut seed[32..])?;

        db.m_lock();
        let s = SklepFs { db, seed };
        if !exist {
            s.populate()?;
        } else {
            s.check()?;
        }
        Ok(s)
    }

    fn populate(&self) -> Result<(), schema::SchemaError> {
        schema::insert_ino(&self.db, self.seed, 1, 1, OsStr::new("."), false)?;
        schema::insert_ino(&self.db, self.seed, 1, 1, OsStr::new(".."), false)?;
        let mut attr = TEMPLATE_DIR_ATTR;
        attr.ino = 1;
        attr.uid = 1000;
        attr.gid = 1000;
        schema::insert_attr(&self.db, 1, &attr)?;

        Ok(())
    }

    fn check(&self) -> Result<(), rej::DbError> {
        log::info!("check...");
        // TODO: versioning, migration

        Ok(())
    }
}

impl Filesystem for SklepFs {
    fn lookup(&mut self, _req: &Request, parent_ino: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(ino) = schema::lookup_ino(&self.db, self.seed, parent_ino, name) else {
            reply.error(Errno::ENOENT as _);
            return;
        };
        let Some(attr) = schema::retrieve_attr(&self.db, ino) else {
            reply.error(Errno::ENOENT as _);
            return;
        };
        reply.entry(&TTL, &attr, 0);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(attr) = schema::retrieve_attr(&self.db, ino) else {
            reply.error(Errno::ENOENT as _);
            return;
        };
        reply.attr(&TTL, &attr);
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(mut attr) = schema::retrieve_attr(&self.db, ino) else {
            reply.error(Errno::ENOENT as _);
            return;
        };
        if let Some(mode) = mode {
            attr.perm = mode as u16;
            // TODO:?
        }
        if let Some(v) = uid {
            attr.uid = v;
        }
        if let Some(v) = gid {
            attr.gid = v;
        }
        if let Some(v) = size {
            attr.size = v;
        }
        if let Some(v) = atime {
            attr.atime = unwrap_time(v);
        }
        if let Some(v) = mtime {
            attr.mtime = unwrap_time(v);
        }
        if let Some(v) = ctime {
            attr.ctime = v;
        }
        if let Some(v) = crtime {
            attr.crtime = v;
        }
        if let Some(v) = flags {
            attr.flags = v;
        }
        if let Err(err) = schema::insert_attr(&self.db, ino, &attr) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }
        reply.attr(&TTL, &attr);
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let key = ino.to_le_bytes();
        let Some(entry) = self.db.entry(DATA_TABLE_ID, &key).occupied() else {
            reply.error(Errno::ENOENT as _);
            return;
        };
        let value = entry.into_value();

        if offset < 0 {
            reply.data(&[]);
            return;
        }
        let offset = offset as usize;
        let size = size as usize;
        if size + offset > value.length() {
            reply.data(&[]);
            return;
        }
        let size = (offset + (size as usize)).min(value.length()) - offset;
        let mut data = vec![0; size];
        value.read(offset, &mut data);
        reply.data(&data);
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        parent_ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let mut it = schema::iter_ino(&self.db, parent_ino);
        let mut this_offset = 0;
        loop {
            match schema::next_ino(&self.db, parent_ino, &mut it) {
                Err(err) => {
                    log::error!("{err}");
                    reply.error(Errno::EIO as _);
                    return;
                }
                Ok(None) => break,
                Ok(Some(value)) => {
                    let ino = value.ino();
                    let fty = value.fty();
                    let Some(name) = value.name() else {
                        log::error!("{}", schema::SchemaError::LongFilename);
                        reply.error(Errno::EIO as _);
                        return;
                    };
                    if this_offset >= offset && reply.add(ino, this_offset + 1, fty, name) {
                        break;
                    }
                    this_offset += 1;
                }
            }
        }

        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent_ino: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        // TODO: 3?
        let ino = 3u64;
        if let Err(err) = schema::insert_ino(&self.db, self.seed, parent_ino, ino, name, false) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }
        let mut attr = TEMPLATE_FILE_ATTR;
        attr.ino = ino;
        attr.uid = 1000;
        attr.gid = 1000;
        if let Err(err) = schema::insert_attr(&self.db, ino, &attr) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }

        reply.created(&TTL, &attr, 0, 0, 0);
    }
}
