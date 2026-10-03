# ant-listings

Listed files for storage networks built on Autonomi's protocol (`ant-protocol`).

A file can be stored three ways:

| Visibility | What is stored | Who can read it | Listed |
|---|---|---|---|
| private | content chunks; the uploader keeps the data map | whoever holds the data map | no |
| unlisted | content chunks and the data map | anyone with the address | no |
| listed | content chunks and the data map in an envelope | anyone | yes |

Nodes that support listings recognise envelopes as they store chunks, record a
listing with the on-chain payment for each one, and answer listing requests on
their own topic. Anyone can collect listings from the nodes and check each one
against the chain. A listing can't be added any other way than by storing and
paying for a listed file, and its time and order come from its payment.

This crate holds what nodes and clients share: the envelope format, the listing
record, the payment checks and the protocol messages. It does no I/O.

## Envelope format (version 1)

| Bytes | Field |
|---|---|
| 8 | magic, `00 41 4E 54 4C 49 53 54` (`"\0ANTLIST"`) |
| 1 | version, `01` |
| 1 | content type length `n`; `0` means none |
| n | content type, printable ASCII |
| 1 | name length `m`; `0` means none |
| m | name, UTF-8 |
| rest | the data map, msgpack-encoded exactly as an unlisted upload stores it |

- The envelope is stored as one chunk. Its address, `blake3(envelope)`, is the
  listed file's address.
- Content type: `type/subtype` with optional parameters, at most 127 bytes.
- Name: at most 255 bytes, no control characters or path separators.
- Both are declared by the uploader and not checked. Treat names as untrusted
  when saving files.

To read a listed file, fetch its address, check the magic, and download using the
data map that follows the header.

## Listings

A listing holds the envelope's address, its metadata, the file size when the
data map gives it directly, and the payment for the envelope chunk: transaction
hash, block number, block timestamp, the log index of the payment vault's
`DataPaymentMade` event, and the paid quote. Listings are ordered by (block
number, log index), the order their payments were made in.

`verify_listing` checks a listing against the payment transaction's receipt and
its block's timestamp:

1. the transaction succeeded, in the listed block, at the listed time;
2. the paid quote names the listing's address and has a valid ML-DSA-65
   signature;
3. the receipt has the vault's `DataPaymentMade` event at the listed log index,
   for that quote's hash and rewards address, with a non-zero amount.

## Protocol

Messages travel on the topic `listings.v1`, encoded with postcard:

| Message | Meaning |
|---|---|
| `ListRequest { from, limit }` | listings with keys from `from` onwards, at most `min(limit, 256)` |
| `ListResponse { listings, more }` | listings in key order; `more` if the node holds later ones |
| `GetRequest { address }` | the listing for one address |
| `GetResponse { listing }` | the listing, if the node holds it |
| `Error { message }` | the request was refused |

## Licence

MIT or Apache-2.0, at your option.
