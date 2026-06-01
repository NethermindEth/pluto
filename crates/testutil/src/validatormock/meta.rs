//! Spec metadata and slot/epoch arithmetic used by the validator mock.
//!
//! Mirrors `charon/testutil/validatormock/meta.go`. The types are deliberately
//! plain values: callers pass [`SpecMeta`] in once and the slot/epoch helpers
//! never touch the network. All arithmetic uses `saturating_*` / `checked_*`
//! to satisfy the workspace's `arithmetic_side_effects = deny` lint.

use std::time::{Duration, SystemTime};

/// Spec constants the validator mock needs to translate slots into wall-clock
/// instants and into epochs.
#[derive(Debug, Clone, Copy)]
pub struct SpecMeta {
    /// Genesis time of the chain.
    pub genesis_time: SystemTime,
    /// Wall-clock duration of a single slot.
    pub slot_duration: Duration,
    /// Number of slots per epoch.
    pub slots_per_epoch: u64,
}

impl SpecMeta {
    /// Start time of `slot` (`genesis + slot * slot_duration`). Saturates at
    /// `u32::MAX` slot offsets — well beyond any practical chain age.
    #[must_use]
    pub fn slot_start_time(&self, slot: u64) -> SystemTime {
        let multiplier = u32::try_from(slot).unwrap_or(u32::MAX);
        let offset = self.slot_duration.saturating_mul(multiplier);
        self.genesis_time
            .checked_add(offset)
            .unwrap_or(self.genesis_time)
    }

    /// Epoch number containing `slot`. Returns epoch 0 if
    /// `slots_per_epoch == 0`.
    #[must_use]
    pub fn epoch_from_slot(&self, slot: u64) -> MetaEpoch {
        MetaEpoch {
            epoch: slot.checked_div(self.slots_per_epoch).unwrap_or(0),
            meta: *self,
        }
    }

    /// First slot in `epoch` as a [`MetaSlot`].
    #[must_use]
    pub fn first_slot_in_epoch(&self, epoch: u64) -> MetaSlot {
        MetaSlot {
            slot: epoch.saturating_mul(self.slots_per_epoch),
            meta: *self,
        }
    }

    /// Last slot in `epoch` as a [`MetaSlot`].
    #[must_use]
    pub fn last_slot_in_epoch(&self, epoch: u64) -> MetaSlot {
        let first = epoch.saturating_mul(self.slots_per_epoch);
        MetaSlot {
            slot: first.saturating_add(self.slots_per_epoch).saturating_sub(1),
            meta: *self,
        }
    }
}

/// A slot together with the spec metadata required to ask wall-clock questions
/// about it.
#[derive(Debug, Clone, Copy)]
pub struct MetaSlot {
    /// Slot number.
    pub slot: u64,
    /// Spec metadata.
    pub meta: SpecMeta,
}

impl MetaSlot {
    /// Wall-clock start time of this slot.
    #[must_use]
    pub fn start_time(&self) -> SystemTime {
        self.meta.slot_start_time(self.slot)
    }

    /// Slot duration from the spec.
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.meta.slot_duration
    }

    /// Containing epoch as [`MetaEpoch`].
    #[must_use]
    pub fn epoch(&self) -> MetaEpoch {
        self.meta.epoch_from_slot(self.slot)
    }

    /// Slot immediately following this one. Saturates at `u64::MAX`.
    #[must_use]
    pub fn next(&self) -> MetaSlot {
        MetaSlot {
            slot: self.slot.saturating_add(1),
            meta: self.meta,
        }
    }

    /// Returns true if `t` falls in `[self.start_time, next.start_time)`.
    #[must_use]
    pub fn in_slot(&self, t: SystemTime) -> bool {
        let start = self.start_time();
        let end = self.next().start_time();
        t >= start && t < end
    }

    /// Returns true if this slot is the first slot of its epoch.
    #[must_use]
    pub fn first_in_epoch(&self) -> bool {
        self.slot == self.epoch().first_slot().slot
    }
}

/// An epoch together with the spec metadata required to enumerate its slots.
#[derive(Debug, Clone, Copy)]
pub struct MetaEpoch {
    /// Epoch number.
    pub epoch: u64,
    /// Spec metadata.
    pub meta: SpecMeta,
}

impl MetaEpoch {
    /// First slot of this epoch.
    #[must_use]
    pub fn first_slot(&self) -> MetaSlot {
        self.meta.first_slot_in_epoch(self.epoch)
    }

    /// Last slot of this epoch.
    #[must_use]
    pub fn last_slot(&self) -> MetaSlot {
        self.meta.last_slot_in_epoch(self.epoch)
    }

    /// Slots of this epoch in order.
    #[must_use]
    pub fn slots(&self) -> Vec<MetaSlot> {
        self.slots_for_look_ahead(1)
    }

    /// Slots starting at the first slot of this epoch and spanning
    /// `total_epochs` epochs forward (inclusive of the current epoch).
    #[must_use]
    pub fn slots_for_look_ahead(&self, total_epochs: u64) -> Vec<MetaSlot> {
        let total = total_epochs.saturating_mul(self.meta.slots_per_epoch);
        let capacity = usize::try_from(total).unwrap_or(usize::MAX);
        let mut slot = self.first_slot();
        let mut resp = Vec::with_capacity(capacity);
        for _ in 0..total {
            resp.push(slot);
            slot = slot.next();
        }
        resp
    }

    /// Slots starting `total_epochs - 1` epochs before this one and spanning
    /// `total_epochs` epochs (inclusive of the current epoch).
    #[must_use]
    pub fn slots_for_look_back(&self, total_epochs: u64) -> Vec<MetaSlot> {
        let mut epoch = *self;
        for _ in 0..total_epochs {
            epoch = epoch.prev();
        }
        let total = total_epochs.saturating_mul(self.meta.slots_per_epoch);
        let capacity = usize::try_from(total).unwrap_or(usize::MAX);
        let mut slot = epoch.first_slot();
        let mut resp = Vec::with_capacity(capacity);
        for _ in 0..total {
            resp.push(slot);
            slot = slot.next();
        }
        resp
    }

    /// Next epoch. Saturates at `u64::MAX`.
    #[must_use]
    pub fn next(&self) -> MetaEpoch {
        MetaEpoch {
            epoch: self.epoch.saturating_add(1),
            meta: self.meta,
        }
    }

    /// Previous epoch. Saturates at `0`.
    #[must_use]
    pub fn prev(&self) -> MetaEpoch {
        MetaEpoch {
            epoch: self.epoch.saturating_sub(1),
            meta: self.meta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> SpecMeta {
        SpecMeta {
            genesis_time: SystemTime::UNIX_EPOCH,
            slot_duration: Duration::from_secs(12),
            slots_per_epoch: 32,
        }
    }

    #[test]
    fn slot_start_time_matches_genesis_plus_duration() {
        let m = meta();
        assert_eq!(m.slot_start_time(0), SystemTime::UNIX_EPOCH);
        assert_eq!(
            m.slot_start_time(5),
            SystemTime::UNIX_EPOCH + Duration::from_secs(60)
        );
    }

    #[test]
    fn epoch_from_slot_floors() {
        let m = meta();
        assert_eq!(m.epoch_from_slot(0).epoch, 0);
        assert_eq!(m.epoch_from_slot(31).epoch, 0);
        assert_eq!(m.epoch_from_slot(32).epoch, 1);
        assert_eq!(m.epoch_from_slot(63).epoch, 1);
    }

    #[test]
    fn first_and_last_slot_in_epoch() {
        let m = meta();
        assert_eq!(m.first_slot_in_epoch(1).slot, 32);
        assert_eq!(m.last_slot_in_epoch(1).slot, 63);
    }

    #[test]
    fn meta_slot_in_slot_inclusive_start_exclusive_end() {
        let s = MetaSlot {
            slot: 1,
            meta: meta(),
        };
        let start = s.start_time();
        let end = s.next().start_time();
        assert!(s.in_slot(start));
        assert!(s.in_slot(start + Duration::from_secs(6)));
        assert!(!s.in_slot(end));
    }

    #[test]
    fn meta_slot_first_in_epoch() {
        let m = meta();
        assert!(MetaSlot { slot: 32, meta: m }.first_in_epoch());
        assert!(!MetaSlot { slot: 33, meta: m }.first_in_epoch());
    }

    #[test]
    fn slots_for_look_ahead_walks_forward() {
        let m = meta();
        let e = m.epoch_from_slot(64);
        let slots: Vec<u64> = e
            .slots_for_look_ahead(2)
            .into_iter()
            .map(|s| s.slot)
            .collect();
        assert_eq!(slots.len(), 64);
        assert_eq!(slots.first().copied(), Some(64));
        assert_eq!(slots.last().copied(), Some(127));
    }

    #[test]
    fn slots_for_look_back_walks_backward() {
        let m = meta();
        let e = m.epoch_from_slot(64);
        let slots: Vec<u64> = e
            .slots_for_look_back(2)
            .into_iter()
            .map(|s| s.slot)
            .collect();
        assert_eq!(slots.len(), 64);
        assert_eq!(slots.first().copied(), Some(0));
        assert_eq!(slots.last().copied(), Some(63));
    }
}
