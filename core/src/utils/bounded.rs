use std::{ops::Deref, slice};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum BoundedError {
    #[error("length {actual} exceeds maximum of {max}")]
    TooLong { actual: usize, max: usize },
}

/// `Vec<T>` whose length is statically capped at `MAX`. The cap is enforced at
/// every construction site (`new`, `TryFrom<Vec<T>>`, deserialization), so an
/// instance can never hold more than `MAX` elements.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub const MAX: usize = MAX;

    pub fn new(items: Vec<T>) -> Result<Self, BoundedError> {
        if items.len() > MAX {
            return Err(BoundedError::TooLong {
                actual: items.len(),
                max: MAX,
            });
        }
        Ok(Self(items))
    }

    /// Construct without checking the cap.
    ///
    /// Reserved for callers that have already validated the length. Prefer
    /// [`Self::new`] at trust boundaries.
    #[must_use]
    pub const fn new_unchecked(items: Vec<T>) -> Self {
        Self(items)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.0.iter()
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T, const MAX: usize> Default for BoundedVec<T, MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T, const MAX: usize> TryFrom<Vec<T>> for BoundedVec<T, MAX> {
    type Error = BoundedError;

    fn try_from(v: Vec<T>) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl<T, const MAX: usize> AsRef<[T]> for BoundedVec<T, MAX> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T, const MAX: usize> Deref for BoundedVec<T, MAX> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, const MAX: usize> AsRef<Vec<T>> for BoundedVec<T, MAX> {
    fn as_ref(&self) -> &Vec<T> {
        &self.0
    }
}

impl<'a, T, const MAX: usize> IntoIterator for &'a BoundedVec<T, MAX> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T, const MAX: usize> IntoIterator for BoundedVec<T, MAX> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Serialize, const MAX: usize> Serialize for BoundedVec<T, MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = Vec::<T>::deserialize(deserializer)?;
        Self::new(v).map_err(serde::de::Error::custom)
    }
}

/// `Vec<u8>` whose length is statically capped at `MAX`.
///
/// Same invariant as [`BoundedVec<u8, MAX>`] but serializes as a bytes/hex
/// string (matching `lb_utils::serde::serde_bytes_vec`), preserving the
/// human-readable JSON format used elsewhere in the codebase.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    pub const MAX: usize = MAX;

    pub fn new(bytes: Vec<u8>) -> Result<Self, BoundedError> {
        if bytes.len() > MAX {
            return Err(BoundedError::TooLong {
                actual: bytes.len(),
                max: MAX,
            });
        }
        Ok(Self(bytes))
    }

    /// Construct without checking the cap.
    ///
    /// Reserved for callers that have already validated the length. Prefer
    /// [`Self::new`] at trust boundaries.
    #[must_use]
    pub const fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<const MAX: usize> Default for BoundedBytes<MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<const MAX: usize> TryFrom<Vec<u8>> for BoundedBytes<MAX> {
    type Error = BoundedError;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl<const MAX: usize> AsRef<[u8]> for BoundedBytes<MAX> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const MAX: usize> Deref for BoundedBytes<MAX> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const MAX: usize> AsRef<Vec<u8>> for BoundedBytes<MAX> {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl<const MAX: usize> Serialize for BoundedBytes<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&const_hex::encode(&self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedBytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            const_hex::decode(s).map_err(serde::de::Error::custom)?
        } else {
            Vec::<u8>::deserialize(deserializer)?
        };
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}
