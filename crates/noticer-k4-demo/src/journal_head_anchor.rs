use crate::{
    generation_transition_journal::{
        GenerationJournalHead, GenerationTransitionJournal, GenerationTransitionJournalError,
        GenerationTransitionState,
    },
    monotonic_anchor::AnchorBinding,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalHeadAnchorError {
    Unavailable,
    BindingMismatch,
    Stale,
    UpdateFailed,
}

pub trait JournalHeadAnchor {
    fn current(
        &mut self,
        binding: AnchorBinding,
    ) -> Result<GenerationJournalHead, JournalHeadAnchorError>;
    fn advance(
        &mut self,
        binding: AnchorBinding,
        expected: GenerationJournalHead,
        next: GenerationJournalHead,
    ) -> Result<(), JournalHeadAnchorError>;
}

#[derive(Debug)]
pub enum AnchoredJournalError {
    Journal(GenerationTransitionJournalError),
    Anchor(JournalHeadAnchorError),
    HeadMismatch,
    Poisoned,
}

pub struct AnchoredGenerationTransitionJournal<A> {
    journal: GenerationTransitionJournal,
    anchor: A,
    binding: AnchorBinding,
    poisoned: bool,
}

impl<A: JournalHeadAnchor> AnchoredGenerationTransitionJournal<A> {
    pub fn open(
        journal: GenerationTransitionJournal,
        mut anchor: A,
        binding: AnchorBinding,
    ) -> Result<Self, AnchoredJournalError> {
        if anchor
            .current(binding)
            .map_err(AnchoredJournalError::Anchor)?
            != journal.head()
        {
            return Err(AnchoredJournalError::HeadMismatch);
        }
        Ok(Self {
            journal,
            anchor,
            binding,
            poisoned: false,
        })
    }

    pub const fn state(&self) -> GenerationTransitionState {
        self.journal.state()
    }

    pub fn prepare(&mut self, from_slot: u64, to_slot: u64) -> Result<(), AnchoredJournalError> {
        self.transition(|journal| journal.prepare(from_slot, to_slot))
    }

    pub fn commit(&mut self) -> Result<(), AnchoredJournalError> {
        self.transition(GenerationTransitionJournal::commit)
    }

    pub fn clear(&mut self) -> Result<(), AnchoredJournalError> {
        self.transition(GenerationTransitionJournal::clear)
    }

    pub fn abort(&mut self) -> Result<(), AnchoredJournalError> {
        self.transition(GenerationTransitionJournal::abort)
    }

    fn transition(
        &mut self,
        operation: impl FnOnce(
            &mut GenerationTransitionJournal,
        ) -> Result<(), GenerationTransitionJournalError>,
    ) -> Result<(), AnchoredJournalError> {
        if self.poisoned {
            return Err(AnchoredJournalError::Poisoned);
        }
        let previous = self.journal.head();
        operation(&mut self.journal).map_err(AnchoredJournalError::Journal)?;
        if let Err(error) = self
            .anchor
            .advance(self.binding, previous, self.journal.head())
        {
            self.poisoned = true;
            return Err(AnchoredJournalError::Anchor(error));
        }
        Ok(())
    }
}
