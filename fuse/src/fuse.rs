use std::{
    ffi::OsStr,
    io,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fuser::{
    FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyWrite, Request,
};
use zeroize::Zeroize;
use nix::errno::Errno;

use super::{
    schema,
    plain::{PlainData, Attributes, DirectoryEntry},
};

const TTL: Duration = Duration::from_secs(1); // 1 second

pub struct SklepFs {
    db: rej::Db,
    seed: [u64; 4],
    uid: u32,
}

impl SklepFs {
    pub fn new(
        pw: &str,
        time: u32,
        memory: u32,
        path: impl AsRef<Path>,
        uid: u32,
    ) -> Result<Self, schema::SchemaError> {
        let mut seed = [0; 64];
        let secret = rej::Secret::Pw { pw, time, memory };
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
        log::info!("opened db");
        seed[..32].zeroize();
        let db = res?;

        let seed = schema::init_seed(&db, &mut seed[32..])?;

        db.m_lock();
        let s = SklepFs { db, seed, uid };
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
        let entry = DirectoryEntry::from_attr(1, &attr, OsStr::new(".."));
        schema::insert_dir_entry(&self.db, self.seed, 1, entry, true)?;

        Ok(())
    }

    fn check(&self) -> Result<(), schema::SchemaError> {
        log::info!("check...");

        let mut it = self.db.entry(schema::INODE_TABLE_ID, &[]).into_db_iter();
        while let Some((schema::INODE_TABLE_ID, key, v)) = self.db.next(&mut it) {
            let (dir_entry, rewrite) = DirectoryEntry::recognize(&v.read_to_vec(true, 0, 0x1000))?;

            let ino = <[u8; 8]>::try_from(&key[..8])
                .map(u64::from_le_bytes)
                .unwrap_or_default();
            log::debug!("directory: {ino}, entry: {dir_entry}");

            if rewrite {
                log::warn!("fix directory entry {dir_entry}");
                if let Err(err) = self.db.write_at(v, true, 0, dir_entry.as_bytes()) {
                    log::error!("error during fix: {err}");
                }
            }
        }

        let mut it = self.db.entry(schema::ATTR_TABLE_ID, &[]).into_db_iter();
        let mut keys = vec![];
        while let Some((schema::ATTR_TABLE_ID, key, v)) = self.db.next(&mut it) {
            let ino = <[u8; 8]>::try_from(key.as_slice())
                .map(u64::from_le_bytes)
                .unwrap_or_default();
            match Attributes::recognize(&mut v.read_to_vec(true, 0, 0x1000)) {
                Ok((attributes, _)) => log::debug!("item: {ino}, attributes: {attributes}"),
                Err(err) => {
                    log::warn!("bad attribute {ino}, error: {err}");
                    keys.push((ino, key));
                }
            }
        }

        for (ino, key) in keys {
            if let Err(err) = self
                .db
                .entry(schema::ATTR_TABLE_ID, &key)
                .occupied()
                .expect("must exist")
                .remove()
            {
                log::warn!("failed to remove attribute {ino}, error: {err}");
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
        let mut page = [0; 0x100];
        match schema::retrieve_attr(&self.db, ino, &mut page) {
            None => reply.error(Errno::ENOENT as _),
            Some((_, attr, _)) => reply.entry(&TTL, &attr.posix_attr(self.uid, ino), 0),
        };
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let mut page = [0; 0x100];
        match schema::retrieve_attr(&self.db, ino, &mut page) {
            None => reply.error(Errno::ENOENT as _),
            Some((_, attr, _)) => reply.attr(&TTL, &attr.posix_attr(self.uid, ino)),
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
        fn unwrap_time(v: fuser::TimeOrNow) -> SystemTime {
            match v {
                fuser::TimeOrNow::Now => SystemTime::now(),
                fuser::TimeOrNow::SpecificTime(t) => t,
            }
        }

        let mut page = [0; 0x100];
        let attr = match schema::retrieve_attr(&self.db, ino, &mut page) {
            None => {
                reply.error(Errno::ENOENT as _);
                return;
            }
            Some((_, v, _)) => v,
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
        if let Err(err) = schema::insert_attr(&self.db, ino, &*attr) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }
        reply.attr(&TTL, &attr.posix_attr(self.uid, ino));
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent_ino: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let ro = mode & 0o200 == 0;
        let attr = Attributes::new(FileType::Directory, ro, false).inc_link();

        // TODO:
        let ino = 5u64;
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

        let entry = DirectoryEntry::from_attr(parent_ino, &attr, OsStr::new(".."));
        if let Err(err) = schema::insert_dir_entry(&self.db, self.seed, ino, entry, false) {
            log::error!("{err}");
            reply.error(Errno::EIO as _);
            return;
        }

        reply.entry(&TTL, &attr.posix_attr(self.uid, ino), 0);
    }

    fn rmdir(
        &mut self,
        _req: &Request<'_>,
        parent_ino: u64,
        name: &OsStr,
        reply: fuser::ReplyEmpty,
    ) {
        match schema::remove_dir_entry(&self.db, self.seed, parent_ino, name) {
            Err(err) => {
                log::error!("{err}");
                reply.error(Errno::EIO as _);
            }
            Ok(None) => {
                reply.error(Errno::ENOENT as _);
            }
            Ok(Some(entry)) => {
                if let Err(err) =
                    schema::remove_dir_entry(&self.db, self.seed, entry.ino(), OsStr::new(".."))
                {
                    log::error!("{err}");
                    reply.error(Errno::EIO as _);
                    return;
                }
                if let Err(err) = schema::remove_attribute(&self.db, entry.ino()) {
                    log::error!("{err}");
                    reply.error(Errno::EIO as _);
                    return;
                }
                reply.ok();
            }
        }
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
        let mut page = [0; 0x1000];
        let (_, attr, data) = match schema::retrieve_attr(&self.db, ino, &mut page) {
            None => {
                reply.error(Errno::ENOENT as _);
                return;
            }
            Some(v) => v,
        };

        if offset < 0 {
            reply.error(Errno::EINVAL as _);
            return;
        }
        let offset = offset as usize;
        let size = size as usize;

        if offset > attr.size as usize {
            reply.data(&[]);
            return;
        }
        let size = (offset + size).min(attr.size as usize) - offset;

        // TODO: big value
        reply.data(&data[..size]);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let mut page = [0; 0x1000];
        let (value, attr, old) = match schema::retrieve_attr(&self.db, ino, &mut page) {
            None => {
                reply.error(Errno::ENOENT as _);
                return;
            }
            Some(v) => v,
        };

        if offset < 0 {
            reply.error(Errno::EINVAL as _);
            return;
        }
        let offset = offset as usize;

        let available = (old.len() + offset).min(0xf00);
        if available <= offset {
            reply.error(Errno::ENOSPC as _);
            return;
        }
        let cut = &mut old[offset..];
        let written = cut.len().min(data.len());
        cut[..written].clone_from_slice(&data[..written]);

        let new_edge = (offset + written) as u64;
        if new_edge > attr.size {
            attr.size = new_edge;
        }
        attr.set_mtime();
        if let Err(err) = self.db.write_at(value, true, 0, &page) {
            log::error!("failed to write ino: {ino}, error: {err}");
            reply.error(Errno::EIO as _);
            return;
        }

        reply.written(written as u32);
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
        let iter = schema::DirIterator::new(&self.db, parent_ino)
            .enumerate()
            .skip(offset as usize);
        for (offset, entry) in iter {
            let offset = (offset + 1) as i64;
            match entry {
                Ok(entry) => {
                    if reply.add(entry.ino(), offset, entry.fty(), entry.name()) {
                        break;
                    }
                }
                Err(err) => {
                    log::error!("{err}");
                    reply.error(Errno::EIO as _);
                    return;
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
        // TODO:
        let ino = 4u64;
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

        reply.created(&TTL, &attr.posix_attr(self.uid, ino), 0, 0, 0);
    }
}
