use std::{
    ffi::OsStr,
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fuser::{FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request};
use zeroize::Zeroize;
use nix::errno::Errno;

use super::{
    schema,
    plain::{PlainData, Attributes, DirectoryEntry},
};

const TTL: Duration = Duration::from_secs(1); // 1 second

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
        let attr = Attributes::new(FileType::Directory, false, false).inc_link();
        schema::insert_attr(&self.db, 1, &attr)?;
        let entry = DirectoryEntry::from_attr(1, &attr, OsStr::new("."));
        schema::insert_dir_entry(&self.db, self.seed, 1, entry, false)?;
        let entry = DirectoryEntry::from_attr(1, &attr, OsStr::new(".."));
        schema::insert_dir_entry(&self.db, self.seed, 1, entry, false)?;

        Ok(())
    }

    fn check(&self) -> Result<(), schema::SchemaError> {
        log::info!("check...");

        let mut it = self.db.entry(schema::INODE_TABLE_ID, &[]).into_db_iter();
        while let Some((schema::INODE_TABLE_ID, k, v)) = self.db.next(&mut it) {
            let (dir_entry, rewrite) = DirectoryEntry::recognize(&v)?;
            if rewrite {
                log::warn!("fix directory entry {dir_entry}");
                if let Err(err) = self
                    .db
                    .entry(schema::INODE_TABLE_ID, &k)
                    .occupied()
                    .expect("just checked")
                    .into_value()
                    .rewrite(dir_entry.as_bytes())
                {
                    log::error!("error during fix: {err}");
                }
            }
        }

        let mut it = self.db.entry(schema::ATTR_TABLE_ID, &[]).into_db_iter();
        while let Some((schema::ATTR_TABLE_ID, k, v)) = self.db.next(&mut it) {
            let (attr, rewrite) = Attributes::recognize(&v)?;
            if rewrite {
                log::warn!("fix attributes {attr}");
            }
            if let Err(err) = self
                .db
                .entry(schema::ATTR_TABLE_ID, &k)
                .occupied()
                .expect("just checked")
                .into_value()
                .rewrite(attr.as_bytes())
            {
                log::error!("error during fix: {err}");
            }
        }

        Ok(())
    }
}

impl Filesystem for SklepFs {
    fn lookup(&mut self, _req: &Request, parent_ino: u64, name: &OsStr, reply: ReplyEntry) {
        let ino = match schema::lookup_dir(&self.db, self.seed, parent_ino, name) {
            Err(err) => {
                log::error!("lookup dir, name={}, error {err}", name.to_string_lossy());
                reply.error(Errno::EIO as _);
                return;
            }
            Ok(None) => {
                reply.error(Errno::ENOENT as _);
                return;
            }
            Ok(Some(v)) => v,
        };
        let attr = match schema::retrieve_attr(&self.db, ino) {
            Err(err) => {
                log::error!("lookup attr ino={ino}, error: {err}");
                reply.error(Errno::EIO as _);
                return;
            }
            Ok(None) => {
                reply.error(Errno::ENOENT as _);
                return;
            }
            Ok(Some(v)) => v,
        };
        reply.entry(&TTL, &attr.posix_attr(1000, ino), 0);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match schema::retrieve_attr(&self.db, ino) {
            Err(err) => {
                log::error!("lookup attr ino={ino}, error: {err}");
                reply.error(Errno::EIO as _);
            }
            Ok(None) => {
                reply.error(Errno::ENOENT as _);
            }
            Ok(Some(attr)) => reply.attr(&TTL, &attr.posix_attr(1000, ino)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<u64>,
        crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let mut attr = match schema::retrieve_attr(&self.db, ino) {
            Err(err) => {
                log::error!("lookup attr ino={ino}, error: {err}");
                reply.error(Errno::EIO as _);
                return;
            }
            Ok(None) => {
                reply.error(Errno::ENOENT as _);
                return;
            }
            Ok(Some(v)) => v,
        };
        if let Some(v) = size {
            attr.size = v;
        }
        if let Some(v) = mtime {
            attr.mtime_sec = unwrap_time(v)
                .duration_since(UNIX_EPOCH)
                .as_ref()
                .map(Duration::as_secs)
                .unwrap_or_default();
        }
        if let Some(v) = crtime {
            attr.crtime_sec = v
                .duration_since(UNIX_EPOCH)
                .as_ref()
                .map(Duration::as_secs)
                .unwrap_or_default();
        }
        if let Err(err) = schema::insert_attr(&self.db, ino, &attr) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }
        reply.attr(&TTL, &attr.posix_attr(1000, ino));
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
        let size = (offset + size).min(value.length()) - offset;
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
        let mut it = schema::iter_dir(&self.db, parent_ino);
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
                    let name = value.name();
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
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let ro = mode & 0o200 == 0;
        let ex = mode & 0o100 != 0;
        let attr = Attributes::new(FileType::RegularFile, ro, ex).inc_link();
        // TODO: 2?
        let ino = 2u64;
        // should return inode number (ino)
        if let Err(err) = schema::insert_attr(&self.db, ino, &attr) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }

        let entry = DirectoryEntry::from_attr(ino, &attr, name);
        if let Err(err) = schema::insert_dir_entry(&self.db, self.seed, parent_ino, entry, false) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }

        reply.created(&TTL, &attr.posix_attr(1000, ino), 0, 0, 0);
    }
}
