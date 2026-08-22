// SPDX-License-Identifier: Apache-2.0

//! Versioned bounded, compressed JSON codecs for cache blobs.
//!
//! The logical wire format is JSON so the envelope stays inspectable and every
//! structural limit below keeps applying to the decoded document. Cache blobs
//! are then zstd-framed on disk: symbol identities repeat their full SCIP
//! string in every symbol, reference, and edge, which compresses by roughly an
//! order of magnitude. Both the pre-compression and post-decompression sizes
//! are bounded, so a corrupt or hostile blob can never expand without limit.

use std::io::{self, Write};

use code2graph::{
    CODE_GRAPH_SCHEMA_VERSION, CodeGraph, FILE_FACTS_SCHEMA_VERSION, FILE_SUBGRAPH_SCHEMA_VERSION,
    FileFacts, FileFactsValidationContext, FileSubgraph, IncrementalGraph, validate_file_facts,
    validate_file_facts_with_context,
};
use serde::{Deserialize, Serialize};

/// Maximum accepted encoded cache blob size.
pub const CACHE_BLOB_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Frame tag for a zstd-compressed cache blob. A blob that does not start with
/// it is from an older layout and is rejected as incompatible rather than
/// guessed at.
const BLOB_FRAME_MAGIC: [u8; 4] = *b"c2gz";
/// Compression level. Level 3 is zstd's default: it captures nearly all of the
/// available ratio on this data while staying fast enough to run on every
/// published file.
const BLOB_COMPRESSION_LEVEL: i32 = 3;
const CACHE_COLLECTION_MAX: usize = 1_000_000;
const CACHE_STRING_MAX: usize = 1_048_576;
const CACHE_OWNER_MAX_BYTES: usize = 4096;

/// Typed cache failures; callers may map these to their public CLI error.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache blob exceeds the size limit")]
    Oversize,
    #[error("cache blob is malformed")]
    Malformed,
    #[error("cache blob has an unsupported format or schema")]
    Incompatible,
    #[error("cache blob violates structural limits")]
    Limits,
    #[error("cache facts failed validation")]
    InvalidFacts,
    #[error("cache subgraph could not be restored")]
    InvalidSubgraph,
    #[error("cache database is missing")]
    Missing,
    #[error("cache database uses an unsupported schema version")]
    UnsupportedSchema,
    #[error("cache database is corrupt")]
    Corrupt,
    #[error("cache database belongs to a different project")]
    RootMismatch,
    #[error("cache database is read-only")]
    ReadOnly,
    #[error("cache database is locked by another writer")]
    LockContention,
    #[error("cache database operation timed out")]
    Timeout,
    #[error("cache database could not be accessed")]
    Access,
    #[error("cache candidate is invalid or internally inconsistent")]
    InvalidCandidate,
    #[error("cache candidate conflicts with an existing candidate id")]
    CandidateConflict,
    #[error("requested cache snapshot is missing")]
    SnapshotMissing,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    format: String,
    schema: u32,
    payload: T,
}

pub fn encode_file_facts(facts: &FileFacts) -> Result<Vec<u8>, CacheError> {
    encode("file-facts", FILE_FACTS_SCHEMA_VERSION, facts)
}
/// Crate-private cache decode failure that preserves bounded validation detail
/// without changing the public `CacheError` shape.
#[derive(Debug)]
pub(crate) enum DetailedFileFactsDecodeError {
    Cache(CacheError),
    InvalidFacts { detail: String },
}

impl From<DetailedFileFactsDecodeError> for CacheError {
    fn from(error: DetailedFileFactsDecodeError) -> Self {
        match error {
            DetailedFileFactsDecodeError::Cache(error) => error,
            DetailedFileFactsDecodeError::InvalidFacts { .. } => CacheError::InvalidFacts,
        }
    }
}

pub fn decode_file_facts(
    blob: &[u8],
    context: Option<FileFactsValidationContext<'_>>,
) -> Result<FileFacts, CacheError> {
    decode_file_facts_detailed(blob, context).map_err(Into::into)
}

pub(crate) fn decode_file_facts_detailed(
    blob: &[u8],
    context: Option<FileFactsValidationContext<'_>>,
) -> Result<FileFacts, DetailedFileFactsDecodeError> {
    let facts = decode("file-facts", FILE_FACTS_SCHEMA_VERSION, blob)
        .map_err(DetailedFileFactsDecodeError::Cache)?;
    match context {
        Some(context) => validate_file_facts_with_context(&facts, context),
        None => validate_file_facts(std::slice::from_ref(&facts)),
    }
    .map_err(|error| DetailedFileFactsDecodeError::InvalidFacts {
        detail: bounded_validation_detail(&error.to_string()),
    })?;
    Ok(facts)
}
fn bounded_validation_detail(detail: &str) -> String {
    const MAX_DETAIL_BYTES: usize = 512;
    let mut value = detail.to_owned();
    if value.len() > MAX_DETAIL_BYTES {
        value.truncate(MAX_DETAIL_BYTES);
        while !value.is_char_boundary(value.len()) {
            value.pop();
        }
    }
    value
}

pub fn encode_subgraph(subgraph: &FileSubgraph) -> Result<Vec<u8>, CacheError> {
    encode("file-subgraph", FILE_SUBGRAPH_SCHEMA_VERSION, subgraph)
}
/// Decode only through the incremental store's checked restore boundary.
pub fn restore_subgraph(
    blob: &[u8],
    owner: String,
    graph: &mut IncrementalGraph,
) -> Result<(), CacheError> {
    if owner.len() > CACHE_OWNER_MAX_BYTES {
        return Err(CacheError::Limits);
    }
    let subgraph = decode("file-subgraph", FILE_SUBGRAPH_SCHEMA_VERSION, blob)?;
    graph
        .try_upsert_subgraph(owner, subgraph)
        .map_err(|_| CacheError::InvalidSubgraph)
}
pub fn encode_graph(graph: &CodeGraph) -> Result<Vec<u8>, CacheError> {
    encode("code-graph", CODE_GRAPH_SCHEMA_VERSION, graph)
}
pub fn decode_graph(blob: &[u8]) -> Result<CodeGraph, CacheError> {
    let graph: CodeGraph = decode("code-graph", CODE_GRAPH_SCHEMA_VERSION, blob)?;
    if graph.symbols.len() > CACHE_COLLECTION_MAX || graph.edges.len() > CACHE_COLLECTION_MAX {
        return Err(CacheError::Limits);
    }
    Ok(graph)
}

fn encode<T: Serialize>(format: &str, schema: u32, payload: &T) -> Result<Vec<u8>, CacheError> {
    let mut writer = BoundedWriter::new(CACHE_BLOB_MAX_BYTES);
    let result = serde_json::to_writer(
        &mut writer,
        &Envelope {
            format: format.to_owned(),
            schema,
            payload,
        },
    );
    match result {
        Ok(()) => frame(&writer.bytes),
        Err(_) if writer.overflowed => Err(CacheError::Oversize),
        Err(_) => Err(CacheError::Malformed),
    }
}

/// Wraps encoded JSON in the compressed cache frame.
fn frame(json: &[u8]) -> Result<Vec<u8>, CacheError> {
    let compressed =
        zstd::bulk::compress(json, BLOB_COMPRESSION_LEVEL).map_err(|_| CacheError::Malformed)?;
    let mut framed = Vec::with_capacity(BLOB_FRAME_MAGIC.len() + compressed.len());
    framed.extend_from_slice(&BLOB_FRAME_MAGIC);
    framed.extend_from_slice(&compressed);
    Ok(framed)
}

/// Recovers the encoded JSON from a compressed cache frame.
///
/// The decompressed size is capped at the same limit the encoder enforces, so a
/// corrupt blob claiming a huge expansion fails instead of allocating it.
fn unframe(blob: &[u8]) -> Result<Vec<u8>, CacheError> {
    let Some(compressed) = blob.strip_prefix(&BLOB_FRAME_MAGIC) else {
        return Err(CacheError::Incompatible);
    };
    zstd::bulk::decompress(compressed, CACHE_BLOB_MAX_BYTES).map_err(|_| CacheError::Malformed)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        if input.len() > remaining {
            self.bytes.extend_from_slice(&input[..remaining]);
            self.overflowed = true;
            return Err(io::Error::other("cache blob limit"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn decode<T: for<'de> Deserialize<'de>>(
    format: &str,
    schema: u32,
    blob: &[u8],
) -> Result<T, CacheError> {
    if blob.len() > CACHE_BLOB_MAX_BYTES {
        return Err(CacheError::Oversize);
    }
    let json = unframe(blob)?;
    let value: serde_json::Value =
        serde_json::from_slice(&json).map_err(|_| CacheError::Malformed)?;
    validate_json_limits(&value)?;
    let envelope: Envelope<T> = serde_json::from_value(value).map_err(|_| CacheError::Malformed)?;
    if envelope.format != format || envelope.schema != schema {
        return Err(CacheError::Incompatible);
    }
    Ok(envelope.payload)
}
fn validate_json_limits(value: &serde_json::Value) -> Result<(), CacheError> {
    match value {
        serde_json::Value::String(text) if text.len() > CACHE_STRING_MAX => Err(CacheError::Limits),
        serde_json::Value::Array(values) => {
            if values.len() > CACHE_COLLECTION_MAX {
                return Err(CacheError::Limits);
            }
            for value in values {
                validate_json_limits(value)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            if values.len() > CACHE_COLLECTION_MAX {
                return Err(CacheError::Limits);
            }
            for (key, value) in values {
                if key.len() > CACHE_STRING_MAX {
                    return Err(CacheError::Limits);
                }
                validate_json_limits(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> FileFacts {
        FileFacts {
            file: "src/a.rs".into(),
            lang: "rust".into(),
            symbols: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            bindings: Vec::new(),
            ffi_exports: Vec::new(),
        }
    }

    #[test]
    fn facts_and_graph_round_trip_with_deterministic_bytes() {
        use code2graph::{ByteSpan, Descriptor, Symbol, SymbolId, SymbolKind, Visibility};

        let facts = facts();
        let first = encode_file_facts(&facts).expect("encode");
        let second = encode_file_facts(&facts).expect("encode");
        assert_eq!(first, second);
        assert!(!String::from_utf8_lossy(&first).contains("\"source\""));
        let restored = decode_file_facts(&first, None).expect("decode");
        assert_eq!(encode_file_facts(&restored).expect("encode"), first);

        let ids = [
            SymbolId::global("rust", vec![Descriptor::Term("run".into())]),
            SymbolId::local("src/a.rs", "scope:0:x"),
        ];
        let graph = CodeGraph {
            symbols: ids
                .iter()
                .enumerate()
                .map(|(index, id)| Symbol {
                    id: id.clone(),
                    name: format!("symbol-{index}"),
                    kind: SymbolKind::Function,
                    visibility: Visibility::Public,
                    entry_points: Vec::new(),
                    file: "src/a.rs".into(),
                    line: 7,
                    span: ByteSpan { start: 2, end: 9 },
                    signature: "fn run()".into(),
                })
                .collect(),
            edges: Vec::new(),
        };
        let encoded = encode_graph(&graph).expect("encode graph");
        let restored = decode_graph(&encoded).expect("decode graph");
        assert_eq!(
            restored
                .symbols
                .iter()
                .map(|symbol| symbol.id.clone())
                .collect::<Vec<_>>(),
            ids
        );
        assert_eq!(encode_graph(&restored).expect("re-encode graph"), encoded);
    }

    #[test]
    fn invalid_facts_preserves_legacy_unit_error_and_private_detail() {
        let blob = encode_file_facts(&facts()).expect("encode");
        let context = FileFactsValidationContext {
            expected_file: "src/other.rs",
            expected_language: code2graph::Language::Rust,
            source_len: 0,
        };
        assert!(matches!(
            decode_file_facts(&blob, Some(context)),
            Err(CacheError::InvalidFacts)
        ));
        let detail = decode_file_facts_detailed(&blob, Some(context)).unwrap_err();
        assert!(matches!(
            detail,
            DetailedFileFactsDecodeError::InvalidFacts { ref detail }
                if detail.contains("file") && detail.len() <= 512
        ));
        let _: CacheError = CacheError::InvalidFacts;
    }

    #[test]
    fn rejects_oversize_malformed_and_wrong_subgraph_owner() {
        assert!(matches!(
            decode_graph(&vec![b'x'; CACHE_BLOB_MAX_BYTES + 1]),
            Err(CacheError::Oversize)
        ));
        assert!(matches!(
            decode_graph(&frame(b"not-json").expect("frame")),
            Err(CacheError::Malformed)
        ));
        // An unframed blob is from an older cache layout: reject it outright
        // rather than trying to parse it as the current one.
        assert!(matches!(
            decode_graph(
                br#"{"format":"code-graph","schema":1,"payload":{"symbols":[],"edges":[]}}"#
            ),
            Err(CacheError::Incompatible)
        ));
        let mut oversized = facts();
        oversized.file = "x".repeat(CACHE_BLOB_MAX_BYTES);
        assert!(matches!(
            encode_file_facts(&oversized),
            Err(CacheError::Oversize)
        ));

        let facts = facts();
        let mut source = IncrementalGraph::new();
        source.upsert(&facts);
        let blob = encode_subgraph(source.subgraph("src/a.rs").expect("subgraph")).expect("encode");
        let mut destination = IncrementalGraph::new();
        assert!(matches!(
            restore_subgraph(&blob, "src/b.rs".into(), &mut destination),
            Err(CacheError::InvalidSubgraph)
        ));
        assert!(destination.is_empty());
        assert!(matches!(
            restore_subgraph(
                &blob,
                "x".repeat(CACHE_OWNER_MAX_BYTES + 1),
                &mut destination
            ),
            Err(CacheError::Limits)
        ));
    }

    #[test]
    fn rejects_schema_string_and_collection_limit_attacks() {
        let wrong_schema =
            br#"{"format":"code-graph","schema":4294967295,"payload":{"symbols":[],"edges":[]}}"#;
        assert!(matches!(
            decode_graph(&frame(wrong_schema).expect("frame")),
            Err(CacheError::Incompatible)
        ));

        let long_string = "x".repeat(CACHE_STRING_MAX + 1);
        let blob = serde_json::to_vec(&serde_json::json!({
            "format": "code-graph",
            "schema": CODE_GRAPH_SCHEMA_VERSION,
            "payload": { "symbols": [], "edges": [], "extra": long_string }
        }))
        .expect("JSON");
        assert!(matches!(
            decode_graph(&frame(&blob).expect("frame")),
            Err(CacheError::Limits)
        ));

        let mut many = String::from("{\"format\":\"code-graph\",\"schema\":1,\"payload\":{");
        many.push_str("\"symbols\":[");
        for index in 0..=CACHE_COLLECTION_MAX {
            if index != 0 {
                many.push(',');
            }
            many.push_str("null");
        }
        many.push_str("],\"edges\":[]}}");
        assert!(many.len() < CACHE_BLOB_MAX_BYTES);
        assert!(matches!(
            decode_graph(&frame(many.as_bytes()).expect("frame")),
            Err(CacheError::Limits)
        ));
    }
}
