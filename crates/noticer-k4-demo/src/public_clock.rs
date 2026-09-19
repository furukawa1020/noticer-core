use std::{
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAGIC: [u8; 16] = *b"NOTICER_CLOCK001";
const FILE_BYTES: u64 = 36;

#[derive(Debug)]
pub enum PublicClockError {
    Io(std::io::Error),
    Corrupt,
    EpochMismatch,
    Rollback,
    Poisoned,
}

impl fmt::Display for PublicClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Io(_) => "durable public clock storage is unavailable",
            Self::Corrupt => "durable public clock file is corrupted",
            Self::EpochMismatch => "durable public clock epoch does not match",
            Self::Rollback => "public clock rollback was rejected",
            Self::Poisoned => "durable public clock is poisoned",
        })
    }
}

impl std::error::Error for PublicClockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PublicClockError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
struct ClockFileLock {
    file: Option<File>,
    path: PathBuf,
}

impl ClockFileLock {
    fn acquire(path: &Path) -> std::io::Result<Self> {
        let mut name = OsString::from(path.as_os_str());
        name.push(".lock");
        let path = PathBuf::from(name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }
}

impl Drop for ClockFileLock {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

/// Single-writer, epoch-bound public slot watermark.
///
/// Advancing syncs the new watermark before returning. Any storage ambiguity
/// poisons the instance and prevents subsequent use.
pub struct DurablePublicClock {
    epoch: u32,
    slot: u64,
    file: File,
    poisoned: bool,
    _lock: ClockFileLock,
}

impl DurablePublicClock {
    pub fn open(
        path: impl AsRef<Path>,
        epoch: u32,
        initial_slot: u64,
    ) -> Result<Self, PublicClockError> {
        let path = path.as_ref();
        let lock = ClockFileLock::acquire(path)?;
        let (mut file, slot) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                write_document(&mut file, epoch, initial_slot)?;
                file.sync_all()?;
                (file, initial_slot)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut file = OpenOptions::new().read(true).write(true).open(path)?;
                let (stored_epoch, stored_slot) = read_document(&mut file)?;
                if stored_epoch != epoch {
                    return Err(PublicClockError::EpochMismatch);
                }
                if initial_slot < stored_slot {
                    return Err(PublicClockError::Rollback);
                }
                if initial_slot > stored_slot {
                    write_document(&mut file, epoch, initial_slot)?;
                    file.sync_all()?;
                }
                (file, initial_slot)
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            epoch,
            slot,
            file,
            poisoned: false,
            _lock: lock,
        })
    }

    pub const fn current_slot(&self) -> u64 {
        self.slot
    }

    pub fn advance(&mut self, slot: u64) -> Result<(), PublicClockError> {
        if self.poisoned {
            return Err(PublicClockError::Poisoned);
        }
        if slot < self.slot {
            return Err(PublicClockError::Rollback);
        }
        if slot == self.slot {
            return Ok(());
        }
        if !matches!(self.file.metadata(), Ok(metadata) if metadata.len() == FILE_BYTES) {
            self.poisoned = true;
            return Err(PublicClockError::Corrupt);
        }
        if write_document(&mut self.file, self.epoch, slot).is_err()
            || self.file.sync_data().is_err()
        {
            self.poisoned = true;
            return Err(PublicClockError::Poisoned);
        }
        self.slot = slot;
        Ok(())
    }
}

fn write_document(file: &mut File, epoch: u32, slot: u64) -> std::io::Result<()> {
    let mut bytes = [0_u8; FILE_BYTES as usize];
    bytes[..16].copy_from_slice(&MAGIC);
    bytes[16..20].copy_from_slice(&epoch.to_le_bytes());
    bytes[20..28].copy_from_slice(&slot.to_le_bytes());
    bytes[28..36].copy_from_slice(&(!slot).to_le_bytes());
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.set_len(FILE_BYTES)
}

fn read_document(file: &mut File) -> Result<(u32, u64), PublicClockError> {
    if file.metadata()?.len() != FILE_BYTES {
        return Err(PublicClockError::Corrupt);
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0_u8; FILE_BYTES as usize];
    file.read_exact(&mut bytes)?;
    if bytes[..16] != MAGIC {
        return Err(PublicClockError::Corrupt);
    }
    let epoch = u32::from_le_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| PublicClockError::Corrupt)?,
    );
    let slot = u64::from_le_bytes(
        bytes[20..28]
            .try_into()
            .map_err(|_| PublicClockError::Corrupt)?,
    );
    let check = u64::from_le_bytes(
        bytes[28..36]
            .try_into()
            .map_err(|_| PublicClockError::Corrupt)?,
    );
    if check != !slot {
        return Err(PublicClockError::Corrupt);
    }
    Ok((epoch, slot))
}
