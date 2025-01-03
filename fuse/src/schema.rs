use std::{ffi::OsStr, hash::Hasher, mem};

use fuser::FileType;
use rej::{Db, DbError, DbIterator, Entry, Value};
use seahash::SeaHasher;
use thiserror::Error;

use super::plain::{PlainData, RecognizeError, Attributes, DirectoryEntry};

/// () -> seed
const SPECIAL_TABLE_ID: u32 = 0;
/// (parent_ino, hash(filename)) -> (ino, filename)
pub const DIR_TABLE: u32 = 1;
/// ino -> attr
pub const INODE_TABLE: u32 = 9;

#[derive(Debug, Error)]
pub enum SchemaError {
    #[error("{0}")]
    Db(#[from] DbError),
    #[error("parse {0}")]
    Parse(#[from] RecognizeError),
    #[error("hash collision")]
    HashCollision,
}

pub fn init_seed(db: &Db, seed: &mut [u8]) -> Result<[u64; 4], DbError> {
    match db.entry(SPECIAL_TABLE_ID, &[]) {
        Entry::Vacant(e) => db.write_at(e.insert()?, true, 0, &*seed)?,
        Entry::Occupied(e) => e.into_value().read(true, 0, seed),
    }
    let it = seed
        .chunks(8)
        .map(|x| u64::from_le_bytes(x.try_into().expect("seed is big enough")));
    Ok(<[u64; 4]>::try_from(it.collect::<Vec<_>>().as_slice()).expect("seed is big enough"))
}

pub fn dir_entry_key(seed: [u64; 4], parent_ino: u64, name: &OsStr) -> [u8; 0x10] {
    let [k1, k2, k3, k4] = seed;
    let mut hasher = SeaHasher::with_seeds(k1, k2, k3, k4);
    Hasher::write(&mut hasher, name.as_encoded_bytes());
    let hash = hasher.finish().to_le_bytes();

    let mut raw = [0; 0x10];
    raw[..8].clone_from_slice(&parent_ino.to_le_bytes());
    raw[8..].clone_from_slice(&hash);
    raw
}

pub fn insert_dir_entry(
    db: &Db,
    seed: [u64; 4],
    parent_ino: u64,
    entry: DirectoryEntry,
    rewrite: bool,
) -> Result<(), SchemaError> {
    let key = dir_entry_key(seed, parent_ino, entry.name());
    match db.entry(DIR_TABLE, &key) {
        Entry::Vacant(e) => db.write_at(e.insert()?, true, 0, entry.as_bytes())?,
        Entry::Occupied(e) if rewrite => db.write_at(e.into_value(), true, 0, entry.as_bytes())?,
        Entry::Occupied(_) => return Err(SchemaError::HashCollision),
    }

    Ok(())
}

pub fn remove_dir_entry(
    db: &Db,
    seed: [u64; 4],
    parent_ino: u64,
    name: &OsStr,
) -> Result<Option<DirectoryEntry>, SchemaError> {
    let key = dir_entry_key(seed, parent_ino, name);
    match db.entry(DIR_TABLE, &key) {
        Entry::Occupied(e) => {
            let mut value = [0; mem::size_of::<DirectoryEntry>()];
            e.remove()?.read(true, 0, &mut value);
            let (entry, _) = DirectoryEntry::recognize(&value)?;
            Ok(Some(entry))
        }
        Entry::Vacant(_) => Ok(None),
    }
}

pub fn lookup_dir(
    db: &Db,
    seed: [u64; 4],
    parent_ino: u64,
    name: &OsStr,
) -> Result<Option<u64>, SchemaError> {
    if name == "." {
        return Ok(Some(parent_ino));
    }

    let key = dir_entry_key(seed, parent_ino, name);
    let Some(entry) = db.entry(DIR_TABLE, &key).occupied() else {
        return Ok(None);
    };
    let data = entry
        .into_value()
        .read_to_vec(true, 0, mem::size_of::<DirectoryEntry>());
    let entry = DirectoryEntry::recognize(&data)?.0;
    Ok(Some(entry.ino()))
}

pub struct DirIterator<'a> {
    db: &'a Db,
    parent_ino: u64,
    inner: DbIterator,
    dot: bool,
}

impl<'a> DirIterator<'a> {
    pub fn new(db: &'a Db, parent_ino: u64) -> Self {
        let mut key = [0; 16];
        key[..8].clone_from_slice(&parent_ino.to_le_bytes());
        let inner = db.entry(DIR_TABLE, &key).into_db_iter();
        DirIterator {
            db,
            parent_ino,
            inner,
            dot: false,
        }
    }
}

impl Iterator for DirIterator<'_> {
    type Item = Result<DirectoryEntry, SchemaError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.dot {
            self.dot = true;
            Some(Ok(DirectoryEntry::new(
                self.parent_ino,
                FileType::Directory,
                false,
                true,
                OsStr::new("."),
            )))
        } else {
            let (table_id, key, value) = self.db.next(&mut self.inner)?;
            if table_id != DIR_TABLE {
                return None;
            }
            let (prefix, _) = key.split_first_chunk()?;
            if *prefix != self.parent_ino.to_le_bytes() {
                return None;
            }

            let data = value.read_to_vec(true, 0, mem::size_of::<DirectoryEntry>());
            Some(
                DirectoryEntry::recognize(&data)
                    .map_err(Into::into)
                    .map(|(entry, _)| entry),
            )
        }
    }
}

pub fn insert_attr(db: &Db, ino: u64, attr: &Attributes) -> Result<(), SchemaError> {
    let ino_bytes = ino.to_le_bytes();
    let entry = db.entry(INODE_TABLE, &ino_bytes);
    let value = match entry {
        Entry::Occupied(e) => e.into_value(),
        Entry::Vacant(e) => e.insert()?,
    };
    db.write_at(value, true, 0, attr.as_bytes())?;

    Ok(())
}

pub fn remove_attribute(db: &Db, ino: u64) -> Result<(), SchemaError> {
    let ino_bytes = ino.to_le_bytes();
    let entry = db.entry(INODE_TABLE, &ino_bytes);
    let Entry::Occupied(entry) = entry else {
        return Ok(());
    };
    entry.remove().map(drop)?;

    Ok(())
}

pub fn retrieve_attr<'db, 'data>(
    db: &'db Db,
    ino: u64,
    page: &'data mut [u8],
) -> Option<(Value<'db>, &'data mut Attributes, &'data mut [u8])> {
    let mut ino_bytes = [0; 8];
    ino_bytes.clone_from_slice(&ino.to_le_bytes());

    let value = match db.entry(INODE_TABLE, &ino_bytes) {
        Entry::Occupied(e) => e.into_value(),
        Entry::Vacant(_e) => {
            log::warn!("missing attributes for ino={ino}, creating...");
            return None;
        }
    };
    value.read(true, 0, page);
    let (attributes, data) = page.split_at_mut(0x100);
    match Attributes::recognize(attributes) {
        Err(err) => {
            log::warn!("bad attribute {ino}, error: {err}");
            if let Err(err) = db.entry(INODE_TABLE, &ino_bytes).occupied()?.remove() {
                log::warn!("failed to remove attribute {ino}, error: {err}");
            }
            None
        }
        Ok((attributes, true)) => {
            log::warn!("fix attributes {attributes}");
            if let Err(err) = db.write_at(value, true, 0, attributes.as_bytes()) {
                log::warn!("failed to write fixed attribute {ino}, error: {err}");
            }
            Some((value, attributes, data))
        }
        Ok((attributes, false)) => Some((value, attributes, data)),
    }
}
