//! Root payments: the tree a root vault records each wave of payments under.
//!
//! A root vault takes a list of storage payments in one call: a *wave*. Each
//! payment pays a quote's amount to the payee the quote names, as the
//! per-quote vault's payments do, but the vault keeps one record for the
//! whole wave instead of one per paid quote, under the wave's *key*. A wave
//! holds 1 to [`LEAF_LIMIT`] payments, in strictly ascending quote-hash
//! order, each with an amount above zero and a payee other than the zero
//! address ([`Wave::new`]).
//!
//! The key comes from a tree of the wave's payments:
//!
//! - leaf = keccak256(0x00 ‖ quote hash ‖ payee ‖ amount) ([`leaf`]);
//! - pair = keccak256(0x01 ‖ left ‖ right) ([`pair`]);
//! - each level pairs its nodes in order, and an unpaired last node is
//!   carried up to the next level unchanged; the last node left is the root,
//!   so a wave of one payment has its leaf as its root ([`Wave::root`]);
//! - key = keccak256(0x02 ‖ vault address ‖ root ‖ leaf count) ([`key`]).
//!
//! Numbers are 32-byte big-endian words, and addresses their 20 bytes.
//!
//! A payment's *path* holds its siblings from the leaf up, one for each level
//! where it has one, and nothing more: at most [`MAX_PATH_LEN`] hashes
//! ([`Wave::path`]). With the payment, its place in the wave and the wave's
//! leaf count, the path gives the key the wave is recorded under
//! ([`leaf_key`]): the check a storer makes before it reads the vault's
//! record under that key.
//!
//! The vault's own test vectors are kept in `src/root/vectors/`, and every
//! function here is checked against them.

use ant_protocol::evm::Amount;
use sha3::{Digest, Keccak256};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use thiserror::Error;

/// The most payments a wave holds: a root vault's leaf limit.
pub const LEAF_LIMIT: u64 = 512;

/// The most hashes a path holds: one for each level above the leaves of a
/// wave of [`LEAF_LIMIT`] payments.
pub const MAX_PATH_LEN: usize = 9;

/// Keccak-256, as Ethereum computes it, over `parts` joined.
fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `n` as a 32-byte big-endian word.
fn word(n: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&n.to_be_bytes());
    word
}

/// A payment's leaf: keccak256(0x00 ‖ quote hash ‖ payee ‖ amount).
#[must_use]
pub fn leaf(quote_hash: &[u8; 32], payee: &[u8; 20], amount: &Amount) -> [u8; 32] {
    keccak256(&[&[0x00], quote_hash, payee, &amount.to_be_bytes::<32>()])
}

/// The node above two others: keccak256(0x01 ‖ left ‖ right).
#[must_use]
pub fn pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    keccak256(&[&[0x01], left, right])
}

/// The key a wave of `leaf_count` payments whose tree has root `root` is
/// recorded under at `vault`: keccak256(0x02 ‖ vault ‖ root ‖ leaf count).
#[must_use]
pub fn key(vault: &[u8; 20], root: &[u8; 32], leaf_count: u64) -> [u8; 32] {
    keccak256(&[&[0x02], vault, root, &word(leaf_count)])
}

/// The root a payment's path leads to, from its leaf, its place `index` in a
/// wave of `leaf_count` payments, and `path`: the leaf is hashed up the tree
/// with each sibling in turn, the place and the leaf count telling left from
/// right and which levels carry the node up unpaired. This is how a root
/// vault checks a payment against its records, up to the read of its record
/// under the root's [`key`].
///
/// `None`, before any hashing, for a leaf count of 0 or above [`LEAF_LIMIT`]
/// or a place outside the wave; and `None` for a path with fewer or more
/// hashes than the place has siblings.
#[must_use]
pub fn root_from_path(
    leaf: &[u8; 32],
    index: u64,
    leaf_count: u64,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    if leaf_count == 0 || leaf_count > LEAF_LIMIT || index >= leaf_count {
        return None;
    }
    let mut siblings = path.iter();
    let mut node = *leaf;
    let mut index = index;
    let mut width = leaf_count;
    while width > 1 {
        if index % 2 == 1 {
            node = pair(siblings.next()?, &node);
        } else if index + 1 < width {
            node = pair(&node, siblings.next()?);
        }
        index /= 2;
        width = width.div_ceil(2);
    }
    siblings.next().is_none().then_some(node)
}

/// The key the wave holding `payment` is recorded under at `vault`, from the
/// payment's place `index` in a wave of `leaf_count` payments and its path:
/// [`root_from_path`] from the payment's leaf, then [`key`]. A storer reads
/// the vault's record under this key. `None` where [`root_from_path`] gives
/// none, so nothing is read.
#[must_use]
pub fn leaf_key(
    vault: &[u8; 20],
    payment: &RootPayment,
    index: u64,
    leaf_count: u64,
    path: &[[u8; 32]],
) -> Option<[u8; 32]> {
    root_from_path(&payment.leaf(), index, leaf_count, path)
        .map(|root| key(vault, &root, leaf_count))
}

/// One payment of a wave, as a root vault takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootPayment {
    /// The paid quote's hash.
    pub quote_hash: [u8; 32],
    /// The payee: the rewards address the quote names.
    pub payee: [u8; 20],
    /// The amount paid.
    pub amount: Amount,
}

impl RootPayment {
    /// The payment's [`leaf`].
    #[must_use]
    pub fn leaf(&self) -> [u8; 32] {
        leaf(&self.quote_hash, &self.payee, &self.amount)
    }
}

/// Why a root vault refuses a wave. Each refusal but the first names the
/// place of the first payment that fails, as the vault's own errors do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WaveError {
    /// The wave holds no payments, or more than [`LEAF_LIMIT`].
    #[error("a wave holds 1 to {limit} payments, not {count}", limit = LEAF_LIMIT, count = .0)]
    LeafCountOutOfRange(usize),
    /// A payment's quote hash is zero.
    #[error("payment {0} has a zero quote hash")]
    ZeroQuoteHash(usize),
    /// A payment's quote hash is the one before it.
    #[error("payment {0} repeats the quote hash before it")]
    RepeatedQuoteHash(usize),
    /// A payment's quote hash is below the one before it.
    #[error("payment {0} has a quote hash below the one before it")]
    QuoteHashesNotAscending(usize),
    /// A payment's amount is zero.
    #[error("payment {0} has a zero amount")]
    ZeroAmount(usize),
    /// A payment's payee is the zero address.
    #[error("payment {0} has the zero address as its payee")]
    ZeroPayee(usize),
    /// The amounts add up past 2^256 - 1, at this payment.
    #[error("the amounts add up past 2^256 - 1 at payment {0}")]
    TotalOverflow(usize),
}

/// A wave a root vault takes, with its tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wave {
    payments: Vec<RootPayment>,
    /// The tree's levels: the leaves first, the root alone last.
    levels: Vec<Vec<[u8; 32]>>,
    total: Amount,
}

impl Wave {
    /// The wave of `payments`, in the order given, checked as a root vault
    /// checks a wave before it pays it: 1 to [`LEAF_LIMIT`] payments; then,
    /// payment by payment, a quote hash above the one before it (the first
    /// above zero), an amount above zero, a payee other than the zero address,
    /// and a total that fits in 256 bits. So a wave refused here is refused by
    /// the vault, at the same payment and for the same reason.
    ///
    /// # Errors
    ///
    /// Returns the first check that fails.
    pub fn new(payments: Vec<RootPayment>) -> Result<Self, WaveError> {
        let count = payments.len();
        if !(1..=LEAF_LIMIT).contains(&(count as u64)) {
            return Err(WaveError::LeafCountOutOfRange(count));
        }
        let mut previous = [0; 32];
        let mut total = Amount::ZERO;
        for (index, payment) in payments.iter().enumerate() {
            if payment.quote_hash <= previous {
                return Err(if payment.quote_hash == [0; 32] {
                    WaveError::ZeroQuoteHash(index)
                } else if payment.quote_hash == previous {
                    WaveError::RepeatedQuoteHash(index)
                } else {
                    WaveError::QuoteHashesNotAscending(index)
                });
            }
            if payment.amount.is_zero() {
                return Err(WaveError::ZeroAmount(index));
            }
            if payment.payee == [0; 20] {
                return Err(WaveError::ZeroPayee(index));
            }
            total = total
                .checked_add(payment.amount)
                .ok_or(WaveError::TotalOverflow(index))?;
            previous = payment.quote_hash;
        }
        let mut levels = vec![payments.iter().map(RootPayment::leaf).collect::<Vec<_>>()];
        while let Some(below) = levels.last().filter(|level| level.len() > 1) {
            let above = below
                .chunks(2)
                .map(|nodes| match nodes {
                    [left, right] => pair(left, right),
                    [carried] => *carried,
                    _ => unreachable!("chunks of one or two"),
                })
                .collect();
            levels.push(above);
        }
        Ok(Self {
            payments,
            levels,
            total,
        })
    }

    /// The payments, in the wave's order.
    #[must_use]
    pub fn payments(&self) -> &[RootPayment] {
        &self.payments
    }

    /// How many payments the wave holds: its leaf count.
    #[must_use]
    pub fn leaf_count(&self) -> u64 {
        // At most LEAF_LIMIT, so it fits.
        self.payments.len() as u64
    }

    /// The tree's root.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or_default()
    }

    /// The [`key`] the wave is recorded under at `vault`.
    #[must_use]
    pub fn key(&self, vault: &[u8; 20]) -> [u8; 32] {
        key(vault, &self.root(), self.leaf_count())
    }

    /// The sum of the amounts: what the wave pays in all.
    #[must_use]
    pub fn total(&self) -> Amount {
        self.total
    }

    /// The path of the payment at place `index`: its siblings from the leaf
    /// up, one for each level where it has one. `None` for a place outside
    /// the wave.
    #[must_use]
    pub fn path(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.payments.len() {
            return None;
        }
        let (_, below_root) = self.levels.split_last()?;
        let mut index = index;
        let mut path = Vec::with_capacity(below_root.len());
        for level in below_root {
            if let Some(sibling) = level.get(index ^ 1) {
                path.push(*sibling);
            }
            index /= 2;
        }
        Some(path)
    }

    /// Each distinct payee with the sum of its payments, in the order the
    /// payees first appear: the token transfers a root vault makes for the
    /// wave, in the order it makes them.
    #[must_use]
    pub fn sums(&self) -> Vec<([u8; 20], Amount)> {
        let mut sums: Vec<([u8; 20], Amount)> = Vec::new();
        let mut places: HashMap<[u8; 20], usize> = HashMap::new();
        for payment in &self.payments {
            match places.entry(payment.payee) {
                // No sum can pass the total, which fits.
                Entry::Occupied(place) => {
                    let sum = &mut sums[*place.get()].1;
                    *sum = sum.saturating_add(payment.amount);
                }
                Entry::Vacant(place) => {
                    place.insert(sums.len());
                    sums.push((payment.payee, payment.amount));
                }
            }
        }
        sums
    }
}

#[cfg(test)]
mod tests;
