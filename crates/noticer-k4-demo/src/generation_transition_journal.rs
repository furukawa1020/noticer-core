use noticer_crypto::{authenticate_state, verify_state_authentication, StateAuthenticationKey};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 16] = b"NOTICER_GENTXN01";
const HEADER: usize = 60;
const RECORD: usize = 57;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationTransitionState {
    Clean,
    Prepared { from_slot: u64, to_slot: u64 },
    Committed { from_slot: u64, to_slot: u64 },
}

#[derive(Debug)]
pub enum GenerationTransitionJournalError {
    Io(io::Error),
    Corrupt,
    Authentication,
    EpochMismatch,
    GenerationMismatch,
    InvalidTransition,
    Poisoned,
}

impl From<io::Error> for GenerationTransitionJournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
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

pub struct GenerationTransitionJournal {
    file: File,
    _lock: Lock,
    key: StateAuthenticationKey,
    epoch: u32,
    generation: u64,
    sequence: u64,
    state: GenerationTransitionState,
    last_tag: [u8; 32],
    poisoned: bool,
}

impl GenerationTransitionJournal {
    pub fn open(
        path: impl AsRef<Path>,
        epoch: u32,
        generation: u64,
        key: StateAuthenticationKey,
    ) -> Result<Self, GenerationTransitionJournalError> {
        let path = path.as_ref();
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let lock = Lock {
            path: lock_path.clone(),
            _file: OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(lock_path)?,
        };
        let (mut file, new) = match OpenOptions::new()
            .read(true)
            .append(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (
                OpenOptions::new().read(true).append(true).open(path)?,
                false,
            ),
            Err(error) => return Err(error.into()),
        };
        if new {
            file.write_all(&header(epoch, generation, &key))?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.len() < HEADER || (bytes.len() - HEADER) % RECORD != 0 || &bytes[..16] != MAGIC {
            return Err(GenerationTransitionJournalError::Corrupt);
        }
        if !verify_state_authentication(&key, &bytes[..28], &bytes[28..60]) {
            return Err(GenerationTransitionJournalError::Authentication);
        }
        let stored_epoch = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let stored_generation = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
        if stored_epoch != epoch {
            return Err(GenerationTransitionJournalError::EpochMismatch);
        }
        if stored_generation != generation {
            return Err(GenerationTransitionJournalError::GenerationMismatch);
        }
        let mut state = GenerationTransitionState::Clean;
        let mut previous: [u8; 32] = bytes[28..60].try_into().unwrap();
        let mut sequence = 0;
        for record in bytes[HEADER..].chunks_exact(RECORD) {
            let stored_sequence = u64::from_le_bytes(record[..8].try_into().unwrap());
            if stored_sequence != sequence {
                return Err(GenerationTransitionJournalError::Corrupt);
            }
            let phase = record[8];
            let from_slot = u64::from_le_bytes(record[9..17].try_into().unwrap());
            let to_slot = u64::from_le_bytes(record[17..25].try_into().unwrap());
            let message = record_message(
                epoch, generation, &previous, sequence, phase, from_slot, to_slot,
            );
            if !verify_state_authentication(&key, &message, &record[25..]) {
                return Err(GenerationTransitionJournalError::Authentication);
            }
            state = next_state(state, phase, from_slot, to_slot)?;
            previous.copy_from_slice(&record[25..]);
            sequence += 1;
        }
        Ok(Self {
            file,
            _lock: lock,
            key,
            epoch,
            generation,
            sequence,
            state,
            last_tag: previous,
            poisoned: false,
        })
    }

    pub const fn state(&self) -> GenerationTransitionState {
        self.state
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn prepare(
        &mut self,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<(), GenerationTransitionJournalError> {
        if self.state != GenerationTransitionState::Clean || to_slot <= from_slot {
            return Err(GenerationTransitionJournalError::InvalidTransition);
        }
        self.append(1, from_slot, to_slot)
    }

    pub fn commit(&mut self) -> Result<(), GenerationTransitionJournalError> {
        let GenerationTransitionState::Prepared { from_slot, to_slot } = self.state else {
            return Err(GenerationTransitionJournalError::InvalidTransition);
        };
        self.append(2, from_slot, to_slot)
    }

    pub fn clear(&mut self) -> Result<(), GenerationTransitionJournalError> {
        let GenerationTransitionState::Committed { from_slot, to_slot } = self.state else {
            return Err(GenerationTransitionJournalError::InvalidTransition);
        };
        self.append(3, from_slot, to_slot)
    }

    fn append(
        &mut self,
        phase: u8,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<(), GenerationTransitionJournalError> {
        if self.poisoned {
            return Err(GenerationTransitionJournalError::Poisoned);
        }
        let message = record_message(
            self.epoch,
            self.generation,
            &self.last_tag,
            self.sequence,
            phase,
            from_slot,
            to_slot,
        );
        let tag = authenticate_state(&self.key, &message);
        let mut record = [0; RECORD];
        record[..8].copy_from_slice(&self.sequence.to_le_bytes());
        record[8] = phase;
        record[9..17].copy_from_slice(&from_slot.to_le_bytes());
        record[17..25].copy_from_slice(&to_slot.to_le_bytes());
        record[25..].copy_from_slice(&tag);
        if let Err(error) = self
            .file
            .write_all(&record)
            .and_then(|_| self.file.sync_data())
        {
            self.poisoned = true;
            return Err(error.into());
        }
        self.state = next_state(self.state, phase, from_slot, to_slot)?;
        self.last_tag = tag;
        self.sequence += 1;
        Ok(())
    }
}

fn next_state(
    current: GenerationTransitionState,
    phase: u8,
    from_slot: u64,
    to_slot: u64,
) -> Result<GenerationTransitionState, GenerationTransitionJournalError> {
    match (current, phase) {
        (GenerationTransitionState::Clean, 1) if to_slot > from_slot => {
            Ok(GenerationTransitionState::Prepared { from_slot, to_slot })
        }
        (
            GenerationTransitionState::Prepared {
                from_slot: old_from,
                to_slot: old_to,
            },
            2,
        ) if (old_from, old_to) == (from_slot, to_slot) => {
            Ok(GenerationTransitionState::Committed { from_slot, to_slot })
        }
        (
            GenerationTransitionState::Committed {
                from_slot: old_from,
                to_slot: old_to,
            },
            3,
        ) if (old_from, old_to) == (from_slot, to_slot) => Ok(GenerationTransitionState::Clean),
        _ => Err(GenerationTransitionJournalError::InvalidTransition),
    }
}

fn header(epoch: u32, generation: u64, key: &StateAuthenticationKey) -> [u8; HEADER] {
    let mut header = [0; HEADER];
    header[..16].copy_from_slice(MAGIC);
    header[16..20].copy_from_slice(&epoch.to_le_bytes());
    header[20..28].copy_from_slice(&generation.to_le_bytes());
    let tag = authenticate_state(key, &header[..28]);
    header[28..].copy_from_slice(&tag);
    header
}

fn record_message(
    epoch: u32,
    generation: u64,
    previous: &[u8; 32],
    sequence: u64,
    phase: u8,
    from_slot: u64,
    to_slot: u64,
) -> [u8; 69] {
    let mut message = [0; 69];
    message[..4].copy_from_slice(&epoch.to_le_bytes());
    message[4..12].copy_from_slice(&generation.to_le_bytes());
    message[12..44].copy_from_slice(previous);
    message[44..52].copy_from_slice(&sequence.to_le_bytes());
    message[52] = phase;
    message[53..61].copy_from_slice(&from_slot.to_le_bytes());
    message[61..69].copy_from_slice(&to_slot.to_le_bytes());
    message
}
