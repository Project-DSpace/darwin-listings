//! The envelope a listed file stores its data map in.
//!
//! Layout, version 1. Fields follow each other with no padding:
//!
//! | Bytes | Field |
//! |---|---|
//! | 8 | [`MAGIC`] |
//! | 1 | version, `1` |
//! | 1 | content type length `n`; `0` means none |
//! | n | content type, printable ASCII |
//! | 1 | name length `m`; `0` means none |
//! | m | name, UTF-8 |
//! | rest | the data map, msgpack-encoded exactly as an unlisted upload stores it |
//!
//! The envelope is stored as one chunk. Its address, `blake3(envelope)`, is the
//! listed file's address.

use ant_protocol::{compute_address, XorName, MAX_CHUNK_SIZE};
use self_encryption::DataMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The first bytes of every envelope. They start with `0x00`, which no
/// msgpack-encoded data map can start with.
pub const MAGIC: [u8; 8] = *b"\0ANTLIST";

/// The envelope version this crate writes and reads.
pub const ENVELOPE_VERSION: u8 = 1;

/// Longest content type, in bytes.
pub const MAX_CONTENT_TYPE_LEN: usize = 127;

/// Longest name, in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// Optional, uploader-declared description of a listed file. It is public and
/// permanent, and nothing checks that it is true.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// A media type such as `application/pdf`, optionally with parameters
    /// (`text/plain; charset=utf-8`). Printable ASCII, at most 127 bytes.
    pub content_type: Option<String>,
    /// A display name such as `report.pdf`. UTF-8, at most 255 bytes, with no
    /// control characters or path separators. Clients must still treat it as
    /// untrusted when saving files.
    pub name: Option<String>,
}

impl Metadata {
    /// Check both fields against the format rules.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::InvalidContentType`] or
    /// [`EnvelopeError::InvalidName`] for the first rule broken.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if let Some(content_type) = &self.content_type {
            validate_content_type(content_type)?;
        }
        if let Some(name) = &self.name {
            validate_name(name)?;
        }
        Ok(())
    }
}

/// Why bytes are not a valid envelope.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    /// The bytes don't start with [`MAGIC`].
    #[error("not an envelope")]
    NotAnEnvelope,
    /// A version this crate doesn't know.
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    /// The bytes end before a field does.
    #[error("envelope ends early")]
    Truncated,
    /// The content type breaks a format rule.
    #[error("invalid content type: {0}")]
    InvalidContentType(&'static str),
    /// The name breaks a format rule.
    #[error("invalid name: {0}")]
    InvalidName(&'static str),
    /// The data map is missing, empty or can't be decoded.
    #[error("invalid data map: {0}")]
    InvalidDataMap(String),
    /// The envelope doesn't fit in one chunk.
    #[error("envelope is {size} bytes, more than one chunk ({max})")]
    TooLarge {
        /// Size of the envelope.
        size: usize,
        /// The chunk size limit.
        max: usize,
    },
}

/// A parsed, valid envelope.
#[derive(Debug, Clone)]
pub struct Envelope {
    metadata: Metadata,
    data_map: DataMap,
    /// The data map exactly as stored, so re-encoding gives the same bytes and
    /// therefore the same address.
    data_map_bytes: Vec<u8>,
}

impl Envelope {
    /// Wrap a data map for a listed upload.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata breaks a format rule, the data map has
    /// no chunks or can't be encoded, or the result wouldn't fit in one chunk.
    pub fn new(data_map: &DataMap, metadata: Metadata) -> Result<Self, EnvelopeError> {
        metadata.validate()?;
        if data_map.infos().is_empty() {
            return Err(EnvelopeError::InvalidDataMap("it lists no chunks".into()));
        }
        let data_map_bytes = rmp_serde::to_vec(data_map)
            .map_err(|e| EnvelopeError::InvalidDataMap(e.to_string()))?;
        let envelope = Self {
            metadata,
            data_map: data_map.clone(),
            data_map_bytes,
        };
        let size = envelope.encoded_len();
        if size > MAX_CHUNK_SIZE {
            return Err(EnvelopeError::TooLarge {
                size,
                max: MAX_CHUNK_SIZE,
            });
        }
        Ok(envelope)
    }

    /// Parse and check an envelope, such as a chunk a node is storing.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not an envelope of a known version, a
    /// field is missing or breaks a format rule, or the data map is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(EnvelopeError::TooLarge {
                size: bytes.len(),
                max: MAX_CHUNK_SIZE,
            });
        }
        let rest = bytes
            .strip_prefix(MAGIC.as_slice())
            .ok_or(EnvelopeError::NotAnEnvelope)?;
        let (&version, rest) = rest.split_first().ok_or(EnvelopeError::Truncated)?;
        if version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let (content_type, rest) = take_field(rest)?;
        let (name, rest) = take_field(rest)?;

        let content_type = content_type
            .map(|field| {
                String::from_utf8(field.to_vec())
                    .map_err(|_| EnvelopeError::InvalidContentType("must be printable ASCII"))
            })
            .transpose()?;
        let name = name
            .map(|field| {
                String::from_utf8(field.to_vec())
                    .map_err(|_| EnvelopeError::InvalidName("must be UTF-8"))
            })
            .transpose()?;
        let metadata = Metadata { content_type, name };
        metadata.validate()?;

        if rest.is_empty() {
            return Err(EnvelopeError::InvalidDataMap("missing".into()));
        }
        let data_map: DataMap = rmp_serde::from_slice(rest)
            .map_err(|e| EnvelopeError::InvalidDataMap(e.to_string()))?;
        if data_map.infos().is_empty() {
            return Err(EnvelopeError::InvalidDataMap("it lists no chunks".into()));
        }
        Ok(Self {
            metadata,
            data_map,
            data_map_bytes: rest.to_vec(),
        })
    }

    /// The envelope's bytes, as stored in its chunk.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&MAGIC);
        out.push(ENVELOPE_VERSION);
        put_field(&mut out, self.metadata.content_type.as_deref());
        put_field(&mut out, self.metadata.name.as_deref());
        out.extend_from_slice(&self.data_map_bytes);
        out
    }

    /// The listed file's address: the address of the envelope chunk.
    #[must_use]
    pub fn address(&self) -> XorName {
        compute_address(&self.to_bytes())
    }

    /// The envelope's metadata.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// The data map, for downloading the file.
    #[must_use]
    pub fn data_map(&self) -> &DataMap {
        &self.data_map
    }

    /// The data map's bytes: what an unlisted upload of the same file stores.
    #[must_use]
    pub fn data_map_bytes(&self) -> &[u8] {
        &self.data_map_bytes
    }

    /// The file's size in bytes, when the data map gives it directly. Data maps
    /// of files over about 12.5 MB are shrunk into child maps, and their size
    /// is only known after resolving them.
    #[must_use]
    pub fn file_size(&self) -> Option<u64> {
        if self.data_map.is_child() {
            return None;
        }
        u64::try_from(self.data_map.original_file_size()).ok()
    }

    fn encoded_len(&self) -> usize {
        let field_len = |field: Option<&String>| 1 + field.map_or(0, String::len);
        MAGIC.len()
            + 1
            + field_len(self.metadata.content_type.as_ref())
            + field_len(self.metadata.name.as_ref())
            + self.data_map_bytes.len()
    }
}

/// Whether a chunk's bytes start like an envelope. A cheap check for every
/// stored chunk; [`Envelope::from_bytes`] does the full one.
#[must_use]
pub fn is_envelope(bytes: &[u8]) -> bool {
    bytes.starts_with(&MAGIC)
}

fn take_field(bytes: &[u8]) -> Result<(Option<&[u8]>, &[u8]), EnvelopeError> {
    let (&len, rest) = bytes.split_first().ok_or(EnvelopeError::Truncated)?;
    let len = usize::from(len);
    if len == 0 {
        return Ok((None, rest));
    }
    if rest.len() < len {
        return Err(EnvelopeError::Truncated);
    }
    let (field, rest) = rest.split_at(len);
    Ok((Some(field), rest))
}

fn put_field(out: &mut Vec<u8>, field: Option<&str>) {
    match field {
        // Validation caps both fields at 255 bytes, so the length fits.
        Some(field) => {
            out.push(u8::try_from(field.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(field.as_bytes());
        }
        None => out.push(0),
    }
}

fn validate_content_type(content_type: &str) -> Result<(), EnvelopeError> {
    use EnvelopeError::InvalidContentType as Invalid;
    if content_type.is_empty() || content_type.len() > MAX_CONTENT_TYPE_LEN {
        return Err(Invalid("must be 1 to 127 bytes"));
    }
    if !content_type.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(Invalid("must be printable ASCII"));
    }
    let essence = content_type.split(';').next().unwrap_or_default();
    match essence.split_once('/') {
        Some((kind, subtype)) if is_token(kind) && is_token(subtype) => Ok(()),
        _ => Err(Invalid("must be type/subtype")),
    }
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
}

fn validate_name(name: &str) -> Result<(), EnvelopeError> {
    use EnvelopeError::InvalidName as Invalid;
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Invalid("must be 1 to 255 bytes"));
    }
    if name.chars().any(char::is_control) {
        return Err(Invalid("must not contain control characters"));
    }
    if name.contains(['/', '\\']) {
        return Err(Invalid("must not contain path separators"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use self_encryption::{ChunkInfo, XorName as SeXorName};

    fn data_map(sizes: &[usize]) -> DataMap {
        let infos = sizes
            .iter()
            .enumerate()
            .map(|(index, &src_size)| ChunkInfo {
                index,
                dst_hash: SeXorName([u8::try_from(index).unwrap_or(0) + 1; 32]),
                src_hash: SeXorName([u8::try_from(index).unwrap_or(0) + 100; 32]),
                src_size,
            })
            .collect();
        DataMap::new(infos)
    }

    fn metadata(content_type: Option<&str>, name: Option<&str>) -> Metadata {
        Metadata {
            content_type: content_type.map(str::to_string),
            name: name.map(str::to_string),
        }
    }

    #[test]
    fn round_trips_with_metadata() {
        let map = data_map(&[100, 100, 98]);
        let envelope = Envelope::new(
            &map,
            metadata(Some("text/plain; charset=utf-8"), Some("notes.txt")),
        )
        .unwrap();
        let bytes = envelope.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(parsed.metadata(), envelope.metadata());
        assert_eq!(parsed.data_map(), &map);
        assert_eq!(parsed.address(), compute_address(&bytes));
        assert_eq!(parsed.file_size(), Some(298));
    }

    #[test]
    fn round_trips_without_metadata() {
        let envelope = Envelope::new(&data_map(&[5, 5, 5]), Metadata::default()).unwrap();
        let parsed = Envelope::from_bytes(&envelope.to_bytes()).unwrap();
        assert_eq!(parsed.metadata(), &Metadata::default());
        assert_eq!(parsed.to_bytes(), envelope.to_bytes());
    }

    #[test]
    fn layout_is_fixed() {
        let map = data_map(&[1, 1, 1]);
        let bytes = Envelope::new(&map, metadata(Some("a/b"), Some("n")))
            .unwrap()
            .to_bytes();
        let map_bytes = rmp_serde::to_vec(&map).unwrap();
        let mut expected = b"\0ANTLIST\x01\x03a/b\x01n".to_vec();
        expected.extend_from_slice(&map_bytes);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn data_map_bytes_are_what_an_unlisted_upload_stores() {
        let map = data_map(&[1, 2, 3]);
        let envelope = Envelope::new(&map, Metadata::default()).unwrap();
        assert_eq!(envelope.data_map_bytes(), rmp_serde::to_vec(&map).unwrap());
    }

    #[test]
    fn a_plain_data_map_is_not_an_envelope() {
        let map_bytes = rmp_serde::to_vec(&data_map(&[1, 2, 3])).unwrap();
        assert!(!is_envelope(&map_bytes));
        assert_eq!(
            Envelope::from_bytes(&map_bytes).unwrap_err(),
            EnvelopeError::NotAnEnvelope
        );
    }

    #[test]
    fn shrunk_data_maps_have_no_direct_size() {
        let child = DataMap::with_child(data_map(&[10, 10, 10]).infos().to_vec(), 1);
        let envelope = Envelope::new(&child, Metadata::default()).unwrap();
        assert_eq!(envelope.file_size(), None);
    }

    #[test]
    fn rejects_unknown_versions() {
        let mut bytes = Envelope::new(&data_map(&[1, 1, 1]), Metadata::default())
            .unwrap()
            .to_bytes();
        bytes[8] = 2;
        assert_eq!(
            Envelope::from_bytes(&bytes).unwrap_err(),
            EnvelopeError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn rejects_every_truncation() {
        let bytes = Envelope::new(&data_map(&[1, 1, 1]), metadata(Some("a/b"), Some("n")))
            .unwrap()
            .to_bytes();
        for len in 0..bytes.len() {
            assert!(
                Envelope::from_bytes(&bytes[..len]).is_err(),
                "a {len}-byte prefix parsed"
            );
        }
    }

    #[test]
    fn rejects_bad_data_maps() {
        let mut bytes = b"\0ANTLIST\x01\x00\x00".to_vec();
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
        bytes.extend_from_slice(b"not a data map");
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
        assert!(matches!(
            Envelope::new(&DataMap::new(Vec::new()), Metadata::default()),
            Err(EnvelopeError::InvalidDataMap(_))
        ));
    }

    #[test]
    fn content_type_rules() {
        for good in [
            "application/pdf",
            "text/plain; charset=utf-8",
            "image/svg+xml",
            "application/vnd.ms-excel",
        ] {
            assert!(validate_content_type(good).is_ok(), "{good}");
        }
        let too_long = format!("a/{}", "b".repeat(126));
        for bad in [
            "",
            "pdf",
            "/pdf",
            "application/",
            "text /plain",
            "text/pl ain",
            "text/plain\n",
            "tëxt/plain",
            too_long.as_str(),
        ] {
            assert!(validate_content_type(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn name_rules() {
        for good in ["report.pdf", "Ünïcødé name.txt", "a"] {
            assert!(validate_name(good).is_ok(), "{good}");
        }
        let too_long = "x".repeat(256);
        for bad in [
            "",
            "a/b",
            "a\\b",
            "line\nbreak",
            "tab\there",
            too_long.as_str(),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_invalid_metadata_when_parsing() {
        let map_bytes = rmp_serde::to_vec(&data_map(&[1, 1, 1])).unwrap();
        let mut bytes = b"\0ANTLIST\x01\x03pdf\x00".to_vec();
        bytes.extend_from_slice(&map_bytes);
        assert!(matches!(
            Envelope::from_bytes(&bytes),
            Err(EnvelopeError::InvalidContentType(_))
        ));
    }
}
