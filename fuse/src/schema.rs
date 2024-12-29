use std::{ffi::OsStr, hash::Hasher, os::unix::ffi::OsStrExt};

use fuser::{FileAttr, FileType};
use rej::{Db, DbError, DbIterator, Entry};
use seahash::SeaHasher;
use thiserror::Error;

/// () -> seed
const SPECIAL_TABLE_ID: u32 = 0;
/// (parent_ino, hash(filename)) -> (ino, filename)
pub const INODE_TABLE_ID: u32 = 1;
/// ino -> attr
pub const ATTR_TABLE_ID: u32 = 9;

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("{0}")]
    Db(#[from] DbError),
    #[error("too long filename")]
    LongFilename,
    #[error("hash collision")]
    HashCollision,
}

pub fn init_seed(db: &Db, seed: &mut [u8]) -> Result<[u64; 4], DbError> {
    match db.entry(SPECIAL_TABLE_ID, &[]) {
        Entry::Vacant(e) => e.insert()?.rewrite(&*seed)?,
        Entry::Occupied(e) => e.into_value().read(0, seed),
    }
    let mut it = seed
        .chunks(8)
        .map(|x| u64::from_le_bytes(x.try_into().expect("seed is big enough")));
    Ok([
        it.next().expect("seed is big enough"),
        it.next().expect("seed is big enough"),
        it.next().expect("seed is big enough"),
        it.next().expect("seed is big enough"),
    ])
}

struct InoKey {
    raw: [u8; 0x10],
}

impl InoKey {
    pub fn new(seed: [u64; 4], parent_ino: u64, name: &OsStr) -> Self {
        let [k1, k2, k3, k4] = seed;
        let mut hasher = SeaHasher::with_seeds(k1, k2, k3, k4);
        Hasher::write(&mut hasher, name.as_encoded_bytes());
        let hash = hasher.finish().to_le_bytes();

        let mut raw = [0; 0x10];
        raw[..8].clone_from_slice(&parent_ino.to_le_bytes());
        raw[8..].clone_from_slice(&hash);

        InoKey { raw }
    }
}

pub struct InoValue {
    raw: [u8; 0x100],
}

impl InoValue {
    pub fn new(ino: u64, name: &OsStr) -> Option<Self> {
        let mut raw = [0; 0x100];
        raw[..8].clone_from_slice(&ino.to_le_bytes());
        if name.len() > 0xf0 {
            return None;
        }
        raw[8] = name.len() as u8;
        raw[9..][..name.len()].clone_from_slice(&name.as_bytes());

        Some(InoValue { raw })
    }

    pub fn ino(&self) -> u64 {
        u64::from_le_bytes(self.raw[..8].try_into().expect("cannot fail"))
    }

    pub fn name(&self) -> Option<&OsStr> {
        let len = self.raw[8] as usize;
        if len > 0xf0 {
            return None;
        }
        Some(OsStr::from_bytes(&self.raw[9..][..len]))
    }

    pub fn fty(&self) -> FileType {
        byte_to_fty(self.raw[0xff])
    }
}

pub fn insert_ino(
    db: &Db,
    seed: [u64; 4],
    parent_ino: u64,
    ino: u64,
    name: &OsStr,
    rewrite: bool,
) -> Result<(), SchemaError> {
    let key = InoKey::new(seed, parent_ino, name);
    let value = InoValue::new(ino, name).ok_or(SchemaError::LongFilename)?;
    match db.entry(INODE_TABLE_ID, &key.raw) {
        Entry::Vacant(e) => e.insert()?.rewrite(&value.raw)?,
        Entry::Occupied(e) if rewrite => e.into_value().rewrite(&value.raw)?,
        Entry::Occupied(_) => return Err(SchemaError::HashCollision),
    }

    Ok(())
}

pub fn lookup_ino(db: &Db, seed: [u64; 4], parent_ino: u64, name: &OsStr) -> Option<u64> {
    let key = InoKey::new(seed, parent_ino, name);
    let entry = db.entry(INODE_TABLE_ID, &key.raw).occupied()?;
    let mut ino_bytes = [0; 8];
    entry.into_value().read(0, &mut ino_bytes);
    Some(u64::from_le_bytes(ino_bytes))
}

pub fn iter_ino(db: &Db, parent_ino: u64) -> DbIterator {
    let mut key = [0; 16];
    key[..8].clone_from_slice(&parent_ino.to_le_bytes());
    db.entry(INODE_TABLE_ID, &key).into_db_iter()
}

pub fn next_ino(
    db: &Db,
    parent_ino: u64,
    iter: &mut DbIterator,
) -> Result<Option<InoValue>, SchemaError> {
    let Some((table_id, key, value)) = db.next(iter) else {
        return Ok(None);
    };
    if table_id != INODE_TABLE_ID {
        return Ok(None);
    }
    let Some((prefix, _)) = key.split_first_chunk() else {
        return Ok(None);
    };
    if *prefix != parent_ino.to_le_bytes() {
        return Ok(None);
    }
    let Ok(raw) = <[u8; 0x100]>::try_from(value.as_slice()) else {
        return Err(SchemaError::LongFilename);
    };
    Ok(Some(InoValue { raw }))
}

fn fty_to_byte(fty: &FileType) -> u8 {
    match fty {
        FileType::NamedPipe => 1,
        FileType::CharDevice => 2,
        FileType::BlockDevice => 3,
        FileType::Directory => 4,
        FileType::RegularFile => 5,
        FileType::Symlink => 6,
        FileType::Socket => 7,
    }
}

fn byte_to_fty(b: u8) -> FileType {
    match b {
        1 => FileType::NamedPipe,
        2 => FileType::CharDevice,
        3 => FileType::BlockDevice,
        4 => FileType::Directory,
        5 => FileType::RegularFile,
        6 => FileType::Symlink,
        _ => FileType::Socket,
    }
}

pub fn insert_attr(db: &Db, ino: u64, attr: &FileAttr) -> Result<(), DbError> {
    use std::{
        io::{self, Write},
        time::{SystemTime, UNIX_EPOCH},
    };

    unsafe fn write_time(c: &mut impl Write, v: &SystemTime) {
        let dur = v.duration_since(UNIX_EPOCH).unwrap_unchecked();
        c.write(&dur.as_secs().to_le_bytes()).unwrap_unchecked();
        c.write(&dur.subsec_nanos().to_le_bytes())
            .unwrap_unchecked();
    }

    let mut buf = [0; 0x70];
    unsafe {
        let mut c = io::Cursor::<&mut [u8]>::new(&mut buf);
        let v = attr;
        c.write(&v.ino.to_le_bytes()).unwrap_unchecked();
        c.write(&v.size.to_le_bytes()).unwrap_unchecked();
        c.write(&v.blocks.to_le_bytes()).unwrap_unchecked();
        write_time(&mut c, &v.atime);
        write_time(&mut c, &v.mtime);
        write_time(&mut c, &v.ctime);
        write_time(&mut c, &v.crtime);
        c.write(&(fty_to_byte(&v.kind) as u16).to_le_bytes())
            .unwrap_unchecked();
        c.write(&v.perm.to_le_bytes()).unwrap_unchecked();
        c.write(&v.nlink.to_le_bytes()).unwrap_unchecked();
        c.write(&v.uid.to_le_bytes()).unwrap_unchecked();
        c.write(&v.gid.to_le_bytes()).unwrap_unchecked();
        c.write(&v.rdev.to_le_bytes()).unwrap_unchecked();
        c.write(&v.blksize.to_le_bytes()).unwrap_unchecked();
        c.write(&v.flags.to_le_bytes()).unwrap_unchecked();
    }

    let ino_bytes = ino.to_le_bytes();
    let entry = db.entry(ATTR_TABLE_ID, &ino_bytes);
    let mut value = match entry {
        Entry::Occupied(e) => e.into_value(),
        Entry::Vacant(e) => e.insert()?,
    };

    value.rewrite(&buf)?;

    Ok(())
}

pub fn retrieve_attr(db: &Db, ino: u64) -> Option<FileAttr> {
    use std::time::{SystemTime, Duration, UNIX_EPOCH};

    let mut ino_bytes = [0; 8];
    ino_bytes.clone_from_slice(&ino.to_le_bytes());

    let entry = db.entry(ATTR_TABLE_ID, &ino_bytes).occupied()?;
    let mut buf = [0; 0x70];
    let value = entry.into_value();
    value.read(0, &mut buf);

    fn cut<const N: usize>(by: &mut &[u8]) -> [u8; N] {
        let (x, rest) = unsafe { by.split_first_chunk().unwrap_unchecked() };
        *by = rest;
        *x
    }

    fn cut_time(by: &mut &[u8]) -> SystemTime {
        UNIX_EPOCH
            + Duration::from_secs(u64::from_le_bytes(cut(by)))
            + Duration::from_nanos(u32::from_le_bytes(cut(by)) as u64)
    }

    let mut by = buf.as_ref();
    Some(FileAttr {
        ino: u64::from_le_bytes(cut(&mut by)),
        size: u64::from_le_bytes(cut(&mut by)),
        blocks: u64::from_le_bytes(cut(&mut by)),
        atime: cut_time(&mut by),
        mtime: cut_time(&mut by),
        ctime: cut_time(&mut by),
        crtime: cut_time(&mut by),
        kind: byte_to_fty(u16::from_le_bytes(cut(&mut by)) as u8),
        perm: u16::from_le_bytes(cut(&mut by)),
        nlink: u32::from_le_bytes(cut(&mut by)),
        uid: u32::from_le_bytes(cut(&mut by)),
        gid: u32::from_le_bytes(cut(&mut by)),
        rdev: u32::from_le_bytes(cut(&mut by)),
        blksize: u32::from_le_bytes(cut(&mut by)),
        flags: u32::from_le_bytes(cut(&mut by)),
    })
}
