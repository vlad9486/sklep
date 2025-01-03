use std::{ffi::OsStr, io, path::Path};

use fuser::{
    FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite,
    Request,
};
use thiserror::Error;
use zeroize::Zeroize;
use nix::errno::Errno;

use super::{
    schema, time,
    plain::{PlainData, Attributes, DirectoryEntry},
};

#[derive(Debug, Error)]
pub enum FsError {
    #[error("{0}")]
    Schema(#[from] schema::SchemaError),
    #[error("no such entry")]
    NoEntry,
    #[error("limit on file size")]
    NoSpace,
}

impl FsError {
    pub fn errno(&self) -> i32 {
        match self {
            Self::Schema(_) => Errno::EIO as _,
            Self::NoEntry => Errno::ENOENT as _,
            Self::NoSpace => Errno::ENOSPC as _,
        }
    }
}

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

        let mut it = self.db.entry(schema::DIR_TABLE, &[]).into_db_iter();
        while let Some((schema::DIR_TABLE, key, v)) = self.db.next(&mut it) {
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

        let mut it = self.db.entry(schema::INODE_TABLE, &[]).into_db_iter();
        let mut keys = vec![];
        while let Some((schema::INODE_TABLE, key, v)) = self.db.next(&mut it) {
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
                .entry(schema::INODE_TABLE, &key)
                .occupied()
                .expect("must exist")
                .remove()
            {
                log::warn!("failed to remove attribute {ino}, error: {err}");
            }
        }

        Ok(())
    }

    pub fn fs_lookup(&self, parent_ino: u64, name: &OsStr) -> Result<(Attributes, u64), FsError> {
        let ino =
            schema::lookup_dir(&self.db, self.seed, parent_ino, name)?.ok_or(FsError::NoEntry)?;
        let mut page = [0; 0x100];
        let (_, attr, _) =
            schema::retrieve_attr(&self.db, ino, &mut page).ok_or(FsError::NoEntry)?;
        Ok((*attr, ino))
    }

    pub fn fs_change_attributes<F>(&self, ino: u64, f: F) -> Result<Attributes, FsError>
    where
        F: Fn(&mut Attributes),
    {
        let mut page = [0; 0x100];
        let (_, attr, _) =
            schema::retrieve_attr(&self.db, ino, &mut page).ok_or(FsError::NoEntry)?;
        f(attr);
        schema::insert_attr(&self.db, ino, &*attr).map_err(FsError::Schema)?;

        Ok(*attr)
    }

    pub fn fs_mkdir(
        &self,
        parent_ino: u64,
        name: &OsStr,
        attr: Attributes,
    ) -> Result<u64, FsError> {
        // TODO:
        let ino = 5u64;
        schema::insert_attr(&self.db, ino, &attr)?;
        let entry = DirectoryEntry::from_attr(ino, &attr, name);
        schema::insert_dir_entry(&self.db, self.seed, parent_ino, entry, false)?;
        let entry = DirectoryEntry::from_attr(parent_ino, &attr, OsStr::new(".."));
        schema::insert_dir_entry(&self.db, self.seed, ino, entry, false)?;

        Ok(ino)
    }

    pub fn fs_unlink(&self, parent_ino: u64, name: &OsStr) -> Result<(), FsError> {
        let entry = schema::remove_dir_entry(&self.db, self.seed, parent_ino, name)?
            .ok_or(FsError::NoEntry)?;

        let mut page = [0; 0x100];
        let (value, attr, _) =
            schema::retrieve_attr(&self.db, entry.ino(), &mut page).ok_or(FsError::NoEntry)?;
        if attr.unlink() {
            schema::remove_attribute(&self.db, entry.ino())?;
        } else {
            self.db
                .write_at(value, true, 0, &page)
                .map_err(schema::SchemaError::Db)?;
        }

        Ok(())
    }

    pub fn fs_remove_dir(&self, parent_ino: u64, name: &OsStr) -> Result<(), FsError> {
        let entry = schema::remove_dir_entry(&self.db, self.seed, parent_ino, name)?
            .ok_or(FsError::NoEntry)?;
        schema::remove_dir_entry(&self.db, self.seed, entry.ino(), OsStr::new(".."))?;

        let mut page = [0; 0x100];
        let (value, attr, _) =
            schema::retrieve_attr(&self.db, entry.ino(), &mut page).ok_or(FsError::NoEntry)?;
        if attr.unlink() {
            schema::remove_attribute(&self.db, entry.ino())?;
        } else {
            self.db
                .write_at(value, true, 0, &page)
                .map_err(schema::SchemaError::Db)?;
        }

        Ok(())
    }

    pub fn fs_read<'a>(
        &self,
        ino: u64,
        offset: usize,
        size: usize,
        page: &'a mut [u8],
    ) -> Result<&'a [u8], FsError> {
        let (_, attr, data) = schema::retrieve_attr(&self.db, ino, page).ok_or(FsError::NoEntry)?;
        let offset = offset.min(attr.size as usize);

        Ok(&data[offset..(offset + size).min(attr.size as usize)])
    }

    pub fn fs_write(&self, ino: u64, offset: usize, data: &[u8]) -> Result<usize, FsError> {
        let mut page = [0; 0x1000];
        let (value, attr, old) =
            schema::retrieve_attr(&self.db, ino, &mut page).ok_or(FsError::NoEntry)?;

        let available = (old.len() + offset).min(0xf00);
        if available <= offset {
            return Err(FsError::NoSpace);
        }
        let cut = &mut old[offset..];
        let written = cut.len().min(data.len());
        cut[..written].clone_from_slice(&data[..written]);

        let new_edge = (offset + written) as u64;
        if new_edge > attr.size {
            attr.size = new_edge;
        }
        attr.set_mtime();
        self.db
            .write_at(value, true, 0, &page)
            .map_err(schema::SchemaError::Db)?;

        Ok(written)
    }

    pub fn fs_create(
        &self,
        parent_ino: u64,
        name: &OsStr,
        attr: Attributes,
    ) -> Result<u64, FsError> {
        // TODO:
        let ino = 4u64;
        // should return inode number (ino)
        schema::insert_attr(&self.db, ino, &attr)?;
        let entry = DirectoryEntry::from_attr(ino, &attr, name);
        schema::insert_dir_entry(&self.db, self.seed, parent_ino, entry, false)?;

        Ok(ino)
    }
}

impl Filesystem for SklepFs {
    fn lookup(&mut self, _req: &Request, parent_ino: u64, name: &OsStr, reply: ReplyEntry) {
        match self.fs_lookup(parent_ino, name) {
            Ok((attr, ino)) => reply.entry(&time::TTL, &attr.posix_attr(self.uid, ino), 0),
            Err(err) => {
                log::error!("lookup dir, parent={parent_ino}, name={name:?}, error {err}");
                reply.error(err.errno());
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let mut page = [0; 0x100];
        match schema::retrieve_attr(&self.db, ino, &mut page) {
            None => reply.error(Errno::ENOENT as _),
            Some((_, attr, _)) => reply.attr(&time::TTL, &attr.posix_attr(self.uid, ino)),
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
        let res = self.fs_change_attributes(ino, |attr| {
            if let Some(v) = size {
                attr.size = v;
            }
            if let Some(v) = mtime {
                attr.mtime_sec = time::fuser(v).0;
            }
            if let Some(v) = crtime {
                attr.crtime_sec = time::system(v).0;
            }
        });
        match res {
            Ok(attr) => reply.attr(&time::TTL, &attr.posix_attr(self.uid, ino)),
            Err(err) => {
                log::error!("change attr, ino={ino}, error {err}");
                reply.error(err.errno());
            }
        }
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
        match self.fs_mkdir(parent_ino, name, attr) {
            Ok(ino) => reply.entry(&time::TTL, &attr.posix_attr(self.uid, ino), 0),
            Err(err) => {
                log::error!("remove dir, parent={parent_ino}, name={name:?}, error {err}");
                reply.error(err.errno());
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent_ino: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.fs_unlink(parent_ino, name) {
            Err(err) => {
                log::error!("unlink, parent={parent_ino}, name={name:?}, error {err}");
                reply.error(err.errno());
            }
            Ok(()) => reply.ok(),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent_ino: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.fs_unlink(parent_ino, name) {
            Err(err) => {
                log::error!("rmdir, parent={parent_ino}, name={name:?}, error {err}");
                reply.error(err.errno());
            }
            Ok(()) => reply.ok(),
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
        match self.fs_read(ino, offset as usize, size as usize, &mut page) {
            Err(err) => {
                log::error!("read, ino={ino}, error {err}");
                reply.error(err.errno());
            }
            Ok(data) => reply.data(data),
        }
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
        match self.fs_write(ino, offset as usize, data) {
            Err(err) => {
                log::error!("write, ino={ino}, error {err}");
                reply.error(err.errno());
            }
            Ok(written) => reply.written(written as u32),
        }
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
                    log::error!("readdir, offset={offset}, error {err}");
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
        match self.fs_create(parent_ino, name, attr) {
            Err(err) => {
                log::error!("create, parent={parent_ino}, error {err}");
                reply.error(err.errno());
            }
            Ok(ino) => reply.created(&time::TTL, &attr.posix_attr(self.uid, ino), 0, 0, 0),
        }
    }
}
