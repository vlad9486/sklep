use std::{ffi::OsStr, hash::Hasher, mem};

use rej::{Db, DbError, DbIterator, Entry, Value};
use seahash::SeaHasher;
use thiserror::Error;

use super::plain::{PlainData, RecognizeError, Attributes, DirectoryEntry};

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

struct DirEntryKey {
    raw: [u8; 0x10],
}

impl DirEntryKey {
    pub fn new(seed: [u64; 4], parent_ino: u64, name: &OsStr) -> Self {
        let [k1, k2, k3, k4] = seed;
        let mut hasher = SeaHasher::with_seeds(k1, k2, k3, k4);
        Hasher::write(&mut hasher, name.as_encoded_bytes());
        let hash = hasher.finish().to_le_bytes();

        let mut raw = [0; 0x10];
        raw[..8].clone_from_slice(&parent_ino.to_le_bytes());
        raw[8..].clone_from_slice(&hash);

        DirEntryKey { raw }
    }
}

pub fn insert_dir_entry(
    db: &Db,
    seed: [u64; 4],
    parent_ino: u64,
    entry: DirectoryEntry,
    rewrite: bool,
) -> Result<(), SchemaError> {
    let key = DirEntryKey::new(seed, parent_ino, entry.name());
    match db.entry(INODE_TABLE_ID, &key.raw) {
        Entry::Vacant(e) => db.write_at(e.insert()?, true, 0, entry.as_bytes())?,
        Entry::Occupied(e) if rewrite => db.write_at(e.into_value(), true, 0, entry.as_bytes())?,
        Entry::Occupied(_) => return Err(SchemaError::HashCollision),
    }

    Ok(())
}

pub fn lookup_dir(
    db: &Db,
    seed: [u64; 4],
    parent_ino: u64,
    name: &OsStr,
) -> Result<Option<u64>, RecognizeError> {
    let key = DirEntryKey::new(seed, parent_ino, name);
    let Some(entry) = db.entry(INODE_TABLE_ID, &key.raw).occupied() else {
        return Ok(None);
    };
    let data = entry
        .into_value()
        .read_to_vec(true, 0, mem::size_of::<DirectoryEntry>());
    let entry = DirectoryEntry::recognize(&data)?.0;
    Ok(Some(entry.ino()))
}

pub fn iter_dir(db: &Db, parent_ino: u64) -> DbIterator {
    let mut key = [0; 16];
    key[..8].clone_from_slice(&parent_ino.to_le_bytes());
    db.entry(INODE_TABLE_ID, &key).into_db_iter()
}

pub fn next_ino(
    db: &Db,
    parent_ino: u64,
    iter: &mut DbIterator,
) -> Result<Option<DirectoryEntry>, SchemaError> {
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

    let data = value.read_to_vec(true, 0, mem::size_of::<DirectoryEntry>());
    let (dir, _) = DirectoryEntry::recognize(&data)?;
    Ok(Some(dir))
}

pub fn insert_attr(db: &Db, ino: u64, attr: &Attributes) -> Result<(), DbError> {
    let ino_bytes = ino.to_le_bytes();
    let entry = db.entry(ATTR_TABLE_ID, &ino_bytes);
    let value = match entry {
        Entry::Occupied(e) => e.into_value(),
        Entry::Vacant(e) => e.insert()?,
    };
    db.write_at(value, true, 0, attr.as_bytes())?;

    Ok(())
}

pub fn retrieve_attr<'db, 'data>(
    db: &'db Db,
    ino: u64,
    page: &'data mut [u8],
) -> Option<(Value<'db>, &'data mut Attributes, &'data mut [u8])> {
    let mut ino_bytes = [0; 8];
    ino_bytes.clone_from_slice(&ino.to_le_bytes());

    let value = match db.entry(ATTR_TABLE_ID, &ino_bytes) {
        Entry::Occupied(e) => e.into_value(),
        Entry::Vacant(e) => {
            log::warn!("missing attributes for ino={ino}, creating...");
            let value = e.insert().ok()?;
            let attr = Attributes::new(fuser::FileType::RegularFile, false, false).inc_link();
            db.write_at(value, true, 0, attr.as_bytes()).ok()?;
            value
        }
    };
    value.read(true, 0, page);
    let (attributes, data) = page.split_at_mut(0x100);
    match Attributes::recognize(attributes) {
        Err(err) => {
            log::warn!("bad attribute {ino}, error: {err}");
            if let Err(err) = db.entry(ATTR_TABLE_ID, &ino_bytes).occupied()?.remove() {
                log::warn!("failed to remove attribute {ino}, error: {err}");
            }
            None
        }
        Ok((attributes, true)) => {
            log::warn!("fix attributes {attributes}");
            db.write_at(value, true, 0, attributes.as_bytes())
                .unwrap_or_default();
            Some((value, attributes, data))
        }
        Ok((attributes, false)) => Some((value, attributes, data)),
    }
}
