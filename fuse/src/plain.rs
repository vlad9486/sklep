use std::{
    ffi::OsStr,
    fmt, mem,
    num::{NonZeroU16, NonZeroU64},
    os::unix::ffi::OsStrExt,
    slice,
};

use fuser::{FileAttr, FileType};
use thiserror::Error;

/// # Safety
/// `Self` must:
/// - obey `repr(C)`
/// - be bitwise copy
/// - has size less or equal `PAGE_SIZE`.
/// - be free of padding
pub unsafe trait PlainData
where
    Self: Sized,
{
    fn as_this(slice: &[u8]) -> &Self {
        unsafe { &*slice.as_ptr().cast::<Self>() }
    }

    fn as_bytes(&self) -> &[u8] {
        let raw_ptr = (self as *const Self).cast();
        unsafe { slice::from_raw_parts(raw_ptr, mem::size_of::<Self>()) }
    }

    // fn as_this_mut(slice: &mut [u8]) -> &mut Self {
    //     unsafe { &mut *slice.as_mut_ptr().cast::<Self>() }
    // }
}

#[derive(Debug, Error)]
pub enum StParseError {
    #[error("too short: {0}")]
    TooShort(usize),
    #[error("bad file type: {0}")]
    FileType(u16),
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Attributes {
    magic: Option<NonZeroU64>,
    version: u16,
    kind: Option<NonZeroU16>,
    pub nlink: u32,
    pub size: u64,
    pub mtime_sec: u64,
    pub crtime_sec: u64,
}

impl fmt::Display for Attributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:?}, links={}, size={}]",
            self.fty(),
            self.nlink,
            self.size,
        )
    }
}

unsafe impl PlainData for Attributes {}

fn fty_to_u16(value: FileType, ro: bool, ex: bool) -> NonZeroU16 {
    let perm = u16::from(ro) << 5 | u16::from(ex) << 4;
    unsafe {
        match value {
            FileType::NamedPipe => NonZeroU16::new_unchecked(1 + perm),
            FileType::CharDevice => NonZeroU16::new_unchecked(2 + perm),
            FileType::BlockDevice => NonZeroU16::new_unchecked(3 + perm),
            FileType::Directory => NonZeroU16::new_unchecked(4 + perm),
            FileType::RegularFile => NonZeroU16::new_unchecked(5 + perm),
            FileType::Symlink => NonZeroU16::new_unchecked(6 + perm),
            FileType::Socket => NonZeroU16::new_unchecked(7 + perm),
        }
    }
}

fn u16_to_fty(value: u16) -> Option<(FileType, bool, bool)> {
    let ro = (value & 0b0010_0000) != 0;
    let ex = (value & 0b0001_0000) != 0;
    match value & 0b1111 {
        1 => Some((FileType::NamedPipe, ro, ex)),
        2 => Some((FileType::CharDevice, ro, ex)),
        3 => Some((FileType::BlockDevice, ro, ex)),
        4 => Some((FileType::Directory, ro, ex)),
        5 => Some((FileType::RegularFile, ro, ex)),
        6 => Some((FileType::Symlink, ro, ex)),
        7 => Some((FileType::Socket, ro, ex)),
        _ => None,
    }
}

impl Attributes {
    pub const VERSION: u16 = 1;

    pub const MAGIC: NonZeroU64 =
        unsafe { NonZeroU64::new_unchecked(u64::from_be_bytes(*b"sklep_tr")) };

    fn from_older(raw: &[u8]) -> Result<Self, StParseError> {
        // migration, create self from previous version
        // currently no older versions exist
        let _ = raw;
        unimplemented!()
    }

    /// Try to recognize the self from raw data
    /// The `bool` means that need to rewrite the self on the storage
    #[allow(dead_code)]
    pub fn recognize(raw: &[u8]) -> Result<(Self, bool), StParseError> {
        use std::time::{SystemTime, Duration, UNIX_EPOCH};

        let sh = || StParseError::TooShort(raw.len());

        let magic = u64::from_le_bytes(raw[..8].try_into().map_err(|_| sh())?);

        if magic == Self::MAGIC.get() {
            let version = u16::from_le_bytes(raw[8..10].try_into().map_err(|_| sh())?);
            if version < Self::VERSION {
                Self::from_older(raw).map(|s| (s, true))
            } else if raw.len() >= mem::size_of::<Self>() {
                Ok((*Self::as_this(&raw[..mem::size_of::<Self>()]), false))
            } else {
                Err(sh())
            }
        } else if raw.len() == 0x70 {
            // old posix

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

            let mut by = raw;
            let posix = FileAttr {
                ino: u64::from_le_bytes(cut(&mut by)),
                size: u64::from_le_bytes(cut(&mut by)),
                blocks: u64::from_le_bytes(cut(&mut by)),
                atime: cut_time(&mut by),
                mtime: cut_time(&mut by),
                ctime: cut_time(&mut by),
                crtime: cut_time(&mut by),
                kind: {
                    let c = u16::from_le_bytes(cut(&mut by));
                    u16_to_fty(c).ok_or(StParseError::FileType(c))?.0
                },
                perm: u16::from_le_bytes(cut(&mut by)),
                nlink: u32::from_le_bytes(cut(&mut by)),
                uid: u32::from_le_bytes(cut(&mut by)),
                gid: u32::from_le_bytes(cut(&mut by)),
                rdev: u32::from_le_bytes(cut(&mut by)),
                blksize: u32::from_le_bytes(cut(&mut by)),
                flags: u32::from_le_bytes(cut(&mut by)),
            };
            Ok((posix.into(), true))
        } else {
            Err(sh())
        }
    }

    #[allow(dead_code)]
    pub fn posix_attr(self, uid: u32, ino: u64) -> FileAttr {
        use std::time::{UNIX_EPOCH, Duration};

        let mtime = UNIX_EPOCH + Duration::from_secs(self.mtime_sec);
        let crtime = UNIX_EPOCH + Duration::from_secs(self.crtime_sec);

        let (kind, ro, ex) = self.fty();
        let ex = ex | matches!(kind, FileType::Directory);

        let perm = 1 << 8 | u16::from(!ro) << 7 | u16::from(ex) << 6;

        FileAttr {
            ino,
            size: self.size,
            blocks: self.size.div_ceil(0x1000),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime,
            kind,
            perm,
            nlink: self.nlink,
            uid,
            gid: uid,
            rdev: 0,
            flags: 0,
            blksize: 0x1000,
        }
    }

    pub fn new(fty: FileType, ro: bool, ex: bool) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        Attributes {
            magic: Some(Self::MAGIC),
            version: Self::VERSION,
            kind: Some(fty_to_u16(fty, ro, ex)),
            nlink: 0,
            size: 0,
            mtime_sec: 0,
            crtime_sec: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("cannot fail")
                .as_secs(),
        }
    }

    #[must_use]
    pub fn inc_link(mut self) -> Self {
        self.nlink += 1;
        self
    }

    pub fn fty(&self) -> (FileType, bool, bool) {
        // # Safety:
        // the `self` is guaranteed to be valid by construction
        unsafe { u16_to_fty(self.kind.map(NonZeroU16::get).unwrap_or_default()).unwrap_unchecked() }
    }
}

impl From<FileAttr> for Attributes {
    fn from(value: FileAttr) -> Self {
        use std::time::UNIX_EPOCH;

        let ro = value.perm & 0o200 == 0;
        let ex = value.perm & 0o100 != 0;

        Attributes {
            magic: Some(Self::MAGIC),
            version: Self::VERSION,
            kind: Some(fty_to_u16(value.kind, ro, ex)),
            nlink: value.nlink,
            size: value.size,
            mtime_sec: value
                .mtime
                .duration_since(UNIX_EPOCH)
                .expect("cannot fail")
                .as_secs(),
            crtime_sec: value
                .crtime
                .duration_since(UNIX_EPOCH)
                .expect("cannot fail")
                .as_secs(),
        }
    }
}

pub const MAX_FILENAME_SIZE: usize = 0x100;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DirectoryEntry {
    magic: Option<NonZeroU64>,
    version: u16,
    fty: Option<NonZeroU16>,
    filename_size: u16,
    _hole: u16,
    ino: u64,
    _reserved: [u64; 13],
    filename: [u8; MAX_FILENAME_SIZE],
}

impl fmt::Display for DirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ino(), self.name().to_string_lossy())
    }
}

unsafe impl PlainData for DirectoryEntry {}

impl DirectoryEntry {
    pub const VERSION: u16 = 1;

    pub const MAGIC: NonZeroU64 =
        unsafe { NonZeroU64::new_unchecked(u64::from_be_bytes(*b"sklep_dd")) };

    fn from_older(raw: &[u8]) -> Result<Self, StParseError> {
        // migration, create self from previous version
        // currently no older versions exist
        let _ = raw;
        unimplemented!()
    }

    /// Try to recognize the self from raw data
    /// The `bool` means that need to rewrite the self on the storage
    pub fn recognize(raw: &[u8]) -> Result<(Self, bool), StParseError> {
        let sh = || StParseError::TooShort(raw.len());
        let magic = u64::from_le_bytes(raw[..8].try_into().map_err(|_| sh())?);

        if magic == Self::MAGIC.get() {
            let version = u16::from_le_bytes(raw[8..10].try_into().map_err(|_| sh())?);
            if version < Self::VERSION {
                Self::from_older(raw).map(|s| (s, true))
            } else if raw.len() >= mem::size_of::<Self>() {
                Ok((*Self::as_this(&raw[..mem::size_of::<Self>()]), false))
            } else {
                Err(sh())
            }
        } else if raw.len() == 0x100 {
            let (fty, ro, ex) =
                u16_to_fty(raw[0xff] as u16).ok_or(StParseError::FileType(raw[0xff] as u16))?;
            let filename_size = raw[8] as usize;
            let mut s = DirectoryEntry {
                magic: Some(Self::MAGIC),
                version: Self::VERSION,
                fty: Some(fty_to_u16(fty, ro, ex)),
                filename_size: filename_size as u16,
                _hole: 0,
                ino: u64::from_le_bytes(raw[..8].try_into().expect("just checked")),
                _reserved: [0; 13],
                filename: [0; MAX_FILENAME_SIZE],
            };
            s.filename[..filename_size].clone_from_slice(&raw[9..][..filename_size]);

            Ok((s, true))
        } else {
            Err(sh())
        }
    }

    pub fn from_attr(ino: u64, attr: &Attributes, name: &OsStr) -> Self {
        let (fty, ro, ex) = attr.fty();
        Self::new(ino, fty, ro, ex, name)
    }

    pub fn new(ino: u64, fty: FileType, ro: bool, ex: bool, name: &OsStr) -> Self {
        let name = name.as_bytes();
        let mut filename = [0; MAX_FILENAME_SIZE];
        filename[..name.len()].clone_from_slice(name);
        DirectoryEntry {
            magic: Some(Self::MAGIC),
            version: Self::VERSION,
            fty: Some(fty_to_u16(fty, ro, ex)),
            filename_size: name.len() as u16,
            _hole: 0,
            ino,
            _reserved: [0; 13],
            filename,
        }
    }

    pub fn ino(&self) -> u64 {
        self.ino
    }

    pub fn fty(&self) -> FileType {
        // # Safety:
        // the `self` is guaranteed to be valid by construction
        unsafe { u16_to_fty(self.fty.map(NonZeroU16::get).unwrap_or_default()).unwrap_unchecked() }
            .0
    }

    pub fn name(&self) -> &OsStr {
        OsStr::from_bytes(&self.filename[..(self.filename_size as usize)])
    }
}
