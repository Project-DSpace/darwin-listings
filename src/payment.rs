//! Finding and checking a listing's payment on chain.
//!
//! These functions do no I/O. The caller fetches the payment transaction's
//! receipt and its block's timestamp from its own RPC provider and passes them
//! in, along with the payment vault's address.

use crate::listing::{Listing, ListingPayment};
use ant_protocol::evm::PaymentQuote;
use ant_protocol::{verify_quote_content, verify_quote_signature, XorName};
use thiserror::Error;

/// `keccak256("DataPaymentMade(address,uint256,bytes32)")`: the event the
/// payment vault emits for each paid quote. All three fields are indexed, so
/// they are topics 1 to 3: rewards address, amount and quote hash.
pub const DATA_PAYMENT_MADE_TOPIC: [u8; 32] = [
    0xf9, 0x98, 0x96, 0x0b, 0x1c, 0x6f, 0x0e, 0x0e, 0x89, 0xb7, 0xbb, 0xe6, 0xb6, 0xfb, 0xf3, 0xe0,
    0x3e, 0x6f, 0x08, 0xee, 0xe5, 0xb8, 0x43, 0x08, 0x77, 0xd8, 0xad, 0xb8, 0xe1, 0x49, 0xd5, 0x80,
];

/// One event log from a transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentLog {
    /// The contract that emitted it.
    pub address: [u8; 20],
    /// Its topics, the event signature first.
    pub topics: Vec<[u8; 32]>,
    /// Its position in the block.
    pub log_index: u64,
}

/// The parts of a transaction receipt that a payment check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentReceipt {
    /// The transaction's hash.
    pub tx_hash: [u8; 32],
    /// Whether the transaction succeeded.
    pub success: bool,
    /// The block the transaction is in.
    pub block_number: u64,
    /// The transaction's event logs.
    pub logs: Vec<PaymentLog>,
}

/// Why a payment can't be found or doesn't check out.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaymentError {
    /// The receipt is for another transaction.
    #[error("the receipt is for a different transaction")]
    WrongTransaction,
    /// The transaction reverted.
    #[error("the payment transaction failed")]
    Failed,
    /// The receipt's block is not the listing's.
    #[error("the payment is in a different block")]
    WrongBlock,
    /// The block's timestamp is not the listing's.
    #[error("the block time does not match")]
    WrongTimestamp,
    /// The listing's quote can't be decoded or encoded.
    #[error("the paid quote cannot be decoded: {0}")]
    BadQuote(String),
    /// The quote is for another address.
    #[error("the paid quote is for a different address")]
    WrongContent,
    /// The quote's ML-DSA-65 signature is invalid.
    #[error("the paid quote's signature is invalid")]
    BadSignature,
    /// The transaction has no vault payment for the quote.
    #[error("no payment to the vault for this quote in the transaction")]
    NotPaid,
}

/// Find the payment for an envelope chunk, as a node does when it stores one.
///
/// `quotes` are the quotes in the chunk's payment proof. Exactly one of them,
/// the one the uploader paid, has a `DataPaymentMade` event in the receipt.
///
/// # Errors
///
/// Returns an error if the transaction failed, no quote for `address` was
/// paid to `vault` in it, or the paid quote's signature is invalid.
pub fn find_payment(
    address: &XorName,
    quotes: &[PaymentQuote],
    receipt: &PaymentReceipt,
    block_timestamp: u64,
    vault: &[u8; 20],
) -> Result<ListingPayment, PaymentError> {
    if !receipt.success {
        return Err(PaymentError::Failed);
    }
    let (quote, log) = quotes
        .iter()
        .filter(|quote| verify_quote_content(quote, address))
        .find_map(|quote| {
            receipt
                .logs
                .iter()
                .find(|log| pays(log, vault, quote))
                .map(|log| (quote, log))
        })
        .ok_or(PaymentError::NotPaid)?;
    if !verify_quote_signature(quote) {
        return Err(PaymentError::BadSignature);
    }
    let quote_bytes =
        rmp_serde::to_vec(quote).map_err(|e| PaymentError::BadQuote(e.to_string()))?;
    Ok(ListingPayment {
        tx_hash: receipt.tx_hash,
        block_number: receipt.block_number,
        block_timestamp,
        log_index: log.log_index,
        quote: quote_bytes,
    })
}

/// Check a listing's payment against the chain, as an indexer, a node
/// receiving a listing from another node, or anyone else can.
///
/// `receipt` is the receipt of the listing's `tx_hash`, and `block_timestamp`
/// the timestamp of its block.
///
/// # Errors
///
/// Returns the first check that fails.
pub fn verify_listing(
    listing: &Listing,
    receipt: &PaymentReceipt,
    block_timestamp: u64,
    vault: &[u8; 20],
) -> Result<(), PaymentError> {
    let payment = &listing.payment;
    if receipt.tx_hash != payment.tx_hash {
        return Err(PaymentError::WrongTransaction);
    }
    if !receipt.success {
        return Err(PaymentError::Failed);
    }
    if receipt.block_number != payment.block_number {
        return Err(PaymentError::WrongBlock);
    }
    if block_timestamp != payment.block_timestamp {
        return Err(PaymentError::WrongTimestamp);
    }
    let quote: PaymentQuote =
        rmp_serde::from_slice(&payment.quote).map_err(|e| PaymentError::BadQuote(e.to_string()))?;
    if !verify_quote_content(&quote, &listing.address) {
        return Err(PaymentError::WrongContent);
    }
    if !verify_quote_signature(&quote) {
        return Err(PaymentError::BadSignature);
    }
    let paid = receipt
        .logs
        .iter()
        .any(|log| log.log_index == payment.log_index && pays(log, vault, &quote));
    if !paid {
        return Err(PaymentError::NotPaid);
    }
    Ok(())
}

/// Whether `log` is the vault's payment, of a non-zero amount, for `quote`.
fn pays(log: &PaymentLog, vault: &[u8; 20], quote: &PaymentQuote) -> bool {
    let mut rewards_topic = [0u8; 32];
    rewards_topic[12..].copy_from_slice(quote.rewards_address.as_slice());
    log.address == *vault
        && log.topics.len() == 4
        && log.topics[0] == DATA_PAYMENT_MADE_TOPIC
        && log.topics[1] == rewards_topic
        && log.topics[2] != [0u8; 32]
        && log.topics[3] == quote.hash().0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, Metadata};
    use ant_protocol::evm::{Amount, RewardsAddress};
    use saorsa_core::MlDsa65;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;
    use saorsa_pqc::pqc::MlDsaOperations;
    use self_encryption::{ChunkInfo, DataMap, XorName as SeXorName};
    use sha3::{Digest, Keccak256};
    use std::time::{Duration, SystemTime};

    const VAULT: [u8; 20] = [0x69; 20];
    const REWARDS: [u8; 20] = [0xab; 20];
    const TX: [u8; 32] = [0x77; 32];
    const BLOCK: u64 = 1_000;
    const BLOCK_TIME: u64 = 1_790_000_000;

    fn envelope() -> Envelope {
        let infos = (0..3)
            .map(|index| ChunkInfo {
                index,
                dst_hash: SeXorName([u8::try_from(index).unwrap() + 1; 32]),
                src_hash: SeXorName([u8::try_from(index).unwrap() + 50; 32]),
                src_size: 10,
            })
            .collect();
        Envelope::new(
            &DataMap::new(infos),
            Metadata {
                content_type: Some("text/plain".into()),
                name: Some("a.txt".into()),
            },
        )
        .unwrap()
    }

    fn signed_quote(content: XorName) -> PaymentQuote {
        let ml_dsa = MlDsa65::new();
        let (public_key, secret_key) = ml_dsa.generate_keypair().unwrap();
        let mut quote = PaymentQuote {
            content: SeXorName(content),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(BLOCK_TIME - 60),
            price: Amount::from(87u64),
            rewards_address: RewardsAddress::new(REWARDS),
            pub_key: public_key.as_bytes().to_vec(),
            signature: Vec::new(),
            committed_key_count: 0,
            commitment_pin: None,
        };
        let secret_key = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).unwrap();
        quote.signature = ml_dsa
            .sign(&secret_key, &quote.bytes_for_sig())
            .unwrap()
            .as_bytes()
            .to_vec();
        quote
    }

    fn payment_log(quote: &PaymentQuote, log_index: u64) -> PaymentLog {
        let mut rewards = [0u8; 32];
        rewards[12..].copy_from_slice(&REWARDS);
        let mut amount = [0u8; 32];
        amount[31] = 87;
        PaymentLog {
            address: VAULT,
            topics: vec![DATA_PAYMENT_MADE_TOPIC, rewards, amount, quote.hash().0],
            log_index,
        }
    }

    fn receipt(logs: Vec<PaymentLog>) -> PaymentReceipt {
        PaymentReceipt {
            tx_hash: TX,
            success: true,
            block_number: BLOCK,
            logs,
        }
    }

    #[test]
    fn topic_is_the_event_signature_hash() {
        let hash = Keccak256::digest(b"DataPaymentMade(address,uint256,bytes32)");
        assert_eq!(hash.as_slice(), DATA_PAYMENT_MADE_TOPIC.as_slice());
    }

    #[test]
    fn finds_and_verifies_a_payment() {
        let envelope = envelope();
        let address = envelope.address();
        let other = signed_quote([9; 32]);
        let paid = signed_quote(address);
        // The receipt also pays another chunk's quote, as a real upload does.
        let receipt = receipt(vec![payment_log(&other, 3), payment_log(&paid, 4)]);

        let payment = find_payment(
            &address,
            &[signed_quote(address), paid.clone()],
            &receipt,
            BLOCK_TIME,
            &VAULT,
        )
        .unwrap();
        assert_eq!(payment.log_index, 4);
        assert_eq!(payment.block_number, BLOCK);

        let listing = Listing::new(&envelope, payment);
        assert!(listing.matches(&envelope));
        assert_eq!(
            verify_listing(&listing, &receipt, BLOCK_TIME, &VAULT),
            Ok(())
        );
    }

    #[test]
    fn rejects_payments_that_do_not_check_out() {
        let envelope = envelope();
        let address = envelope.address();
        let paid = signed_quote(address);
        let good_receipt = receipt(vec![payment_log(&paid, 4)]);
        let listing = Listing::new(
            &envelope,
            find_payment(
                &address,
                std::slice::from_ref(&paid),
                &good_receipt,
                BLOCK_TIME,
                &VAULT,
            )
            .unwrap(),
        );

        let mut failed = good_receipt.clone();
        failed.success = false;
        assert_eq!(
            verify_listing(&listing, &failed, BLOCK_TIME, &VAULT),
            Err(PaymentError::Failed)
        );

        let mut other_tx = good_receipt.clone();
        other_tx.tx_hash = [1; 32];
        assert_eq!(
            verify_listing(&listing, &other_tx, BLOCK_TIME, &VAULT),
            Err(PaymentError::WrongTransaction)
        );

        assert_eq!(
            verify_listing(&listing, &good_receipt, BLOCK_TIME + 1, &VAULT),
            Err(PaymentError::WrongTimestamp)
        );

        assert_eq!(
            verify_listing(&listing, &good_receipt, BLOCK_TIME, &[0x11; 20]),
            Err(PaymentError::NotPaid)
        );

        let mut zero_amount = payment_log(&paid, 4);
        zero_amount.topics[2] = [0; 32];
        assert_eq!(
            verify_listing(&listing, &receipt(vec![zero_amount]), BLOCK_TIME, &VAULT),
            Err(PaymentError::NotPaid)
        );

        let mut moved = listing.clone();
        moved.address = [5; 32];
        assert_eq!(
            verify_listing(&moved, &good_receipt, BLOCK_TIME, &VAULT),
            Err(PaymentError::WrongContent)
        );

        let mut forged = paid.clone();
        forged.price = Amount::from(1u64);
        let mut forged_listing = listing.clone();
        forged_listing.payment.quote = rmp_serde::to_vec(&forged).unwrap();
        assert_eq!(
            verify_listing(&forged_listing, &good_receipt, BLOCK_TIME, &VAULT),
            Err(PaymentError::BadSignature)
        );
    }

    #[test]
    fn finds_nothing_when_the_quote_was_not_paid() {
        let address = envelope().address();
        let unpaid = signed_quote(address);
        let receipt = receipt(vec![payment_log(&signed_quote(address), 0)]);
        assert_eq!(
            find_payment(&address, &[unpaid], &receipt, BLOCK_TIME, &VAULT),
            Err(PaymentError::NotPaid)
        );
    }
}
