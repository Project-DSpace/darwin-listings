//! The listings protocol: requests and responses on [`TOPIC`].
//!
//! Messages are encoded with postcard, like the chunk protocol. Enum variants
//! are numbered by position on the wire, so new ones are only ever appended.

use crate::listing::{Listing, ListingKey};
use ant_protocol::{XorName, MAX_WIRE_MESSAGE_SIZE};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The topic listings messages travel on, separate from the chunk protocol's.
pub const TOPIC: &str = "listings.v1";

/// The most listings one response carries.
pub const MAX_LIST_LIMIT: u32 = 256;

/// A request or response, with an id the response echoes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingsMessage {
    /// Chosen by the sender of a request and echoed in the response.
    pub request_id: u64,
    /// The request or response.
    pub body: ListingsBody,
}

/// The requests and responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListingsBody {
    /// Listings with keys from `from` onwards, oldest first: at most `limit`,
    /// and never more than [`MAX_LIST_LIMIT`].
    ListRequest {
        /// The first key wanted.
        from: ListingKey,
        /// The most listings wanted.
        limit: u32,
    },
    /// Listings in key order. `more` is true if the node holds later ones.
    ListResponse {
        /// The listings.
        listings: Vec<Listing>,
        /// Whether the node holds listings after the last one returned.
        more: bool,
    },
    /// The listing for one address.
    GetRequest {
        /// The listed file's address.
        address: XorName,
    },
    /// The listing, if the node holds it.
    GetResponse {
        /// The listing.
        listing: Option<Listing>,
    },
    /// The node refused the request.
    Error {
        /// Why.
        message: String,
    },
}

/// Why a message can't be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MessageError {
    /// The message exceeds the wire limit.
    #[error("message is {size} bytes, more than {max}")]
    TooLarge {
        /// The message's size.
        size: usize,
        /// The limit.
        max: usize,
    },
    /// Encoding failed.
    #[error("cannot encode message: {0}")]
    Encode(String),
    /// The bytes are not a valid message.
    #[error("cannot decode message: {0}")]
    Decode(String),
}

impl ListingsMessage {
    /// Encode for sending.
    ///
    /// # Errors
    ///
    /// Returns an error if encoding fails or the result exceeds the wire limit.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        let bytes = postcard::to_stdvec(self).map_err(|e| MessageError::Encode(e.to_string()))?;
        if bytes.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(MessageError::TooLarge {
                size: bytes.len(),
                max: MAX_WIRE_MESSAGE_SIZE,
            });
        }
        Ok(bytes)
    }

    /// Decode received bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes exceed the wire limit or are not a valid
    /// message.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        if bytes.len() > MAX_WIRE_MESSAGE_SIZE {
            return Err(MessageError::TooLarge {
                size: bytes.len(),
                max: MAX_WIRE_MESSAGE_SIZE,
            });
        }
        postcard::from_bytes(bytes).map_err(|e| MessageError::Decode(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Metadata;
    use crate::listing::ListingPayment;

    fn listing() -> Listing {
        Listing {
            address: [3; 32],
            metadata: Metadata {
                content_type: Some("application/pdf".into()),
                name: Some("report.pdf".into()),
            },
            size: Some(1234),
            payment: ListingPayment {
                tx_hash: [7; 32],
                block_number: 42,
                block_timestamp: 1_790_000_000,
                log_index: 2,
                quote: vec![1, 2, 3],
            },
        }
    }

    #[test]
    fn every_message_round_trips() {
        let bodies = vec![
            ListingsBody::ListRequest {
                from: ListingKey::default(),
                limit: 10,
            },
            ListingsBody::ListResponse {
                listings: vec![listing(), listing()],
                more: true,
            },
            ListingsBody::GetRequest { address: [3; 32] },
            ListingsBody::GetResponse {
                listing: Some(listing()),
            },
            ListingsBody::GetResponse { listing: None },
            ListingsBody::Error {
                message: "busy".into(),
            },
        ];
        for (request_id, body) in bodies.into_iter().enumerate() {
            let message = ListingsMessage {
                request_id: request_id as u64,
                body,
            };
            assert_eq!(
                ListingsMessage::decode(&message.encode().unwrap()),
                Ok(message)
            );
        }
    }

    #[test]
    fn variant_numbers_are_fixed() {
        // The first byte after the request id is the variant's position.
        let first_byte_after_id = |body: ListingsBody| {
            ListingsMessage {
                request_id: 0,
                body,
            }
            .encode()
            .unwrap()[1]
        };
        assert_eq!(
            first_byte_after_id(ListingsBody::ListRequest {
                from: ListingKey::default(),
                limit: 1
            }),
            0
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::GetRequest { address: [0; 32] }),
            2
        );
        assert_eq!(
            first_byte_after_id(ListingsBody::Error {
                message: String::new()
            }),
            4
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(ListingsMessage::decode(&[0xff; 8]).is_err());
    }
}
