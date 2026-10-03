//! Listings: what a node records for each envelope it stores.

use crate::envelope::{Envelope, Metadata};
use ant_protocol::XorName;
use serde::{Deserialize, Serialize};

/// One listed file, with the on-chain payment that put it on the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// The address of the envelope chunk, which is the listed file's address.
    pub address: XorName,
    /// The envelope's metadata.
    pub metadata: Metadata,
    /// The file's size in bytes, when the data map gives it directly.
    pub size: Option<u64>,
    /// The payment for the envelope chunk.
    pub payment: ListingPayment,
}

/// The payment for an envelope chunk, as found on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingPayment {
    /// The payment transaction.
    pub tx_hash: [u8; 32],
    /// The block the transaction is in.
    pub block_number: u64,
    /// The block's timestamp, in Unix seconds.
    pub block_timestamp: u64,
    /// The position in the block of the vault's `DataPaymentMade` event for
    /// this chunk.
    pub log_index: u64,
    /// The paid quote, msgpack-encoded as in payment proofs. It names the
    /// envelope's address and is signed by the node that issued it.
    pub quote: Vec<u8>,
}

/// Where a listing sits in the index: the order its payment was made in.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct ListingKey {
    /// The payment's block.
    pub block_number: u64,
    /// The payment event's position in the block.
    pub log_index: u64,
}

impl ListingKey {
    /// The smallest key after this one, for paging through listings.
    #[must_use]
    pub fn next(self) -> Self {
        match self.log_index.checked_add(1) {
            Some(log_index) => Self {
                block_number: self.block_number,
                log_index,
            },
            None => Self {
                block_number: self.block_number.saturating_add(1),
                log_index: 0,
            },
        }
    }
}

impl Listing {
    /// The listing for an envelope and its payment.
    #[must_use]
    pub fn new(envelope: &Envelope, payment: ListingPayment) -> Self {
        Self {
            address: envelope.address(),
            metadata: envelope.metadata().clone(),
            size: envelope.file_size(),
            payment,
        }
    }

    /// The listing's place in the index.
    #[must_use]
    pub fn key(&self) -> ListingKey {
        ListingKey {
            block_number: self.payment.block_number,
            log_index: self.payment.log_index,
        }
    }

    /// Whether this listing describes `envelope`: the same address, metadata
    /// and size.
    #[must_use]
    pub fn matches(&self, envelope: &Envelope) -> bool {
        self.address == envelope.address()
            && &self.metadata == envelope.metadata()
            && self.size == envelope.file_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_order_by_block_then_log_index() {
        let a = ListingKey {
            block_number: 10,
            log_index: 5,
        };
        let b = ListingKey {
            block_number: 10,
            log_index: 6,
        };
        let c = ListingKey {
            block_number: 11,
            log_index: 0,
        };
        assert!(a < b && b < c);
        assert_eq!(a.next(), b);
        let last = ListingKey {
            block_number: 10,
            log_index: u64::MAX,
        };
        assert_eq!(
            last.next(),
            ListingKey {
                block_number: 11,
                log_index: 0
            }
        );
    }
}
