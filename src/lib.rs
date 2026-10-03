//! Listed files for storage networks built on Autonomi's `ant-protocol`.
//!
//! A file can be stored three ways: private (the uploader keeps the data map),
//! unlisted (the data map is stored, so anyone with the address can read the
//! file) and listed. A listed file stores its data map inside an [`Envelope`]:
//! a short, versioned header with optional metadata in front of the data map.
//!
//! Nodes recognise envelopes when they store a chunk ([`is_envelope`]) and
//! record a [`Listing`] carrying the on-chain payment for the envelope
//! ([`find_payment`]). They answer the requests in [`message`] on their own
//! topic, [`TOPIC`], so the chunk protocol's message enum is never changed.
//! Anyone can check a listing against the chain with [`verify_listing`].
//!
//! Nothing here does I/O: callers fetch chunks, receipts and block times
//! themselves and pass them in.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod listing;
pub mod message;
pub mod payment;

/// The `self_encryption` version envelopes are built with, re-exported so
/// callers build data maps with the same one.
pub use self_encryption;

pub use envelope::{
    is_envelope, Envelope, EnvelopeError, Metadata, ENVELOPE_VERSION, MAGIC, MAX_CONTENT_TYPE_LEN,
    MAX_NAME_LEN,
};
pub use listing::{Listing, ListingKey, ListingPayment};
pub use message::{ListingsBody, ListingsMessage, MessageError, MAX_LIST_LIMIT, TOPIC};
pub use payment::{
    find_payment, verify_listing, PaymentError, PaymentLog, PaymentReceipt, DATA_PAYMENT_MADE_TOPIC,
};
