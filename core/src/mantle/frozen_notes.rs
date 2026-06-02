use serde::{Deserialize, Serialize};

use crate::mantle::{Note, NoteId};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Note does not exist: {0:?}")]
    NoteDoesNotExist(NoteId),
    #[error("Note isn't frozen: {0:?}")]
    NoteNotFrozen(NoteId),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FrozenNotes {
    frozen_notes: rpds::HashTrieMapSync<NoteId, Note>,
}

impl FrozenNotes {
    #[must_use]
    pub fn new() -> Self {
        Self {
            frozen_notes: rpds::HashTrieMapSync::new_sync(),
        }
    }

    #[must_use]
    pub fn get(&self, id: &NoteId) -> Option<&Note> {
        self.frozen_notes.get(id)
    }

    #[must_use]
    pub fn contains(&self, id: &NoteId) -> bool {
        self.frozen_notes.contains_key(id)
    }

    pub fn freeze(mut self, note: Note, note_id: &NoteId) -> Result<Self, Error> {
        self.frozen_notes = self.frozen_notes.insert(*note_id, note);

        Ok(self)
    }

    pub fn unfreeze(&mut self, note_id: &NoteId) -> Result<Note, Error> {
        if let Some(&mut note) = self.frozen_notes.get_mut(note_id) {
            self.frozen_notes = self.frozen_notes.remove(note_id);
            Ok(note)
        } else {
            Err(Error::NoteNotFrozen(*note_id))
        }
    }
}
