use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
const MAGIC: &[u8; 16] = b"NOTICER_ACLOCK01";
const N: usize = 68;
pub use noticer_crypto::StateAuthenticationKey as PublicClockAuthKey;
#[derive(Debug)]
pub enum AuthenticatedClockError {
    Io(io::Error),
    UnknownVersion,
    Corrupt,
    Authentication,
    EpochMismatch,
    GenerationMismatch,
    Rollback,
    Poisoned,
}
impl From<io::Error> for AuthenticatedClockError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
struct Lock {
    path: PathBuf,
    _file: File,
}
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
pub struct AuthenticatedDurablePublicClock {
    file: File,
    _lock: Lock,
    key: PublicClockAuthKey,
    epoch: u32,
    generation: u64,
    slot: u64,
    poisoned: bool,
}
impl AuthenticatedDurablePublicClock {
    pub fn open(
        path: impl AsRef<Path>,
        epoch: u32,
        generation: u64,
        initial: u64,
        key: PublicClockAuthKey,
    ) -> Result<Self, AuthenticatedClockError> {
        let path = path.as_ref();
        let mut lp = path.as_os_str().to_os_string();
        lp.push(".lock");
        let lp = PathBuf::from(lp);
        let lock = Lock {
            path: lp.clone(),
            _file: OpenOptions::new().write(true).create_new(true).open(lp)?,
        };
        let (mut file, new) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(f) => (f, true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                (OpenOptions::new().read(true).write(true).open(path)?, false)
            }
            Err(e) => return Err(e.into()),
        };
        let slot = if new {
            write(&mut file, epoch, generation, initial, &key, true)?;
            initial
        } else {
            let old = read(&mut file, epoch, generation, &key)?;
            if initial < old {
                return Err(AuthenticatedClockError::Rollback);
            }
            if initial > old {
                write(&mut file, epoch, generation, initial, &key, true)?;
                initial
            } else {
                old
            }
        };
        Ok(Self {
            file,
            _lock: lock,
            key,
            epoch,
            generation,
            slot,
            poisoned: false,
        })
    }
    pub const fn slot(&self) -> u64 {
        self.slot
    }
    pub fn advance(&mut self, slot: u64) -> Result<(), AuthenticatedClockError> {
        if self.poisoned {
            return Err(AuthenticatedClockError::Poisoned);
        }
        if slot < self.slot {
            return Err(AuthenticatedClockError::Rollback);
        }
        if slot == self.slot {
            return Ok(());
        }
        if let Err(e) = write(
            &mut self.file,
            self.epoch,
            self.generation,
            slot,
            &self.key,
            false,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        self.slot = slot;
        Ok(())
    }
}
fn write(
    f: &mut File,
    e: u32,
    g: u64,
    s: u64,
    k: &PublicClockAuthKey,
    all: bool,
) -> Result<(), AuthenticatedClockError> {
    let mut r = [0; N];
    r[..16].copy_from_slice(MAGIC);
    r[16..20].copy_from_slice(&e.to_le_bytes());
    r[20..28].copy_from_slice(&g.to_le_bytes());
    r[28..36].copy_from_slice(&s.to_le_bytes());
    let t = noticer_crypto::authenticate_state(k, &r[..36]);
    r[36..].copy_from_slice(&t);
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&r)?;
    f.set_len(N as u64)?;
    if all {
        f.sync_all()?
    } else {
        f.sync_data()?
    }
    Ok(())
}
fn read(
    f: &mut File,
    e: u32,
    g: u64,
    k: &PublicClockAuthKey,
) -> Result<u64, AuthenticatedClockError> {
    if f.metadata()?.len() != N as u64 {
        return Err(AuthenticatedClockError::Corrupt);
    }
    let mut r = [0; N];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut r)?;
    if &r[..16] != MAGIC {
        return Err(AuthenticatedClockError::UnknownVersion);
    }
    if !noticer_crypto::verify_state_authentication(k, &r[..36], &r[36..]) {
        return Err(AuthenticatedClockError::Authentication);
    }
    let ep = u32::from_le_bytes(r[16..20].try_into().unwrap());
    let gen = u64::from_le_bytes(r[20..28].try_into().unwrap());
    if ep != e {
        return Err(AuthenticatedClockError::EpochMismatch);
    }
    if gen != g {
        return Err(AuthenticatedClockError::GenerationMismatch);
    }
    Ok(u64::from_le_bytes(r[28..36].try_into().unwrap()))
}
