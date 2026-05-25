use std::fmt::Display;
use std::str::FromStr;

use base64::{Engine as _, engine::general_purpose::STANDARD as base64};

use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::LogId,
    rekor::v1::{Checkpoint, InclusionPromise, InclusionProof, KindVersion, TransparencyLogEntry},
};

use crate::rekor::models::{
    LogEntry as RekorLogEntry,
    log_entry::{Body, RekorInclusionProof},
};

// Known Sigstore bundle media types.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    Bundle0_1,
    Bundle0_2,
    Bundle0_3,
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self {
            Version::Bundle0_1 => "application/vnd.dev.sigstore.bundle+json;version=0.1",
            Version::Bundle0_2 => "application/vnd.dev.sigstore.bundle+json;version=0.2",
            Version::Bundle0_3 => "application/vnd.dev.sigstore.bundle.v0.3+json",
        })
    }
}

impl FromStr for Version {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "application/vnd.dev.sigstore.bundle+json;version=0.1" => Ok(Version::Bundle0_1),
            "application/vnd.dev.sigstore.bundle+json;version=0.2" => Ok(Version::Bundle0_2),
            "application/vnd.dev.sigstore.bundle.v0.3+json" => Ok(Version::Bundle0_3),
            _ => Err(()),
        }
    }
}

#[inline]
fn decode_hex<S: AsRef<str>>(hex: S) -> Result<Vec<u8>, ()> {
    hex::decode(hex.as_ref()).or(Err(()))
}

impl TryFrom<RekorInclusionProof> for InclusionProof {
    type Error = ();

    fn try_from(value: RekorInclusionProof) -> Result<Self, Self::Error> {
        let hashes = value
            .hashes
            .iter()
            .map(decode_hex)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(InclusionProof {
            checkpoint: Some(Checkpoint {
                envelope: value.checkpoint,
            }),
            hashes,
            log_index: value.log_index,
            root_hash: decode_hex(value.root_hash)?,
            tree_size: value.tree_size as i64,
        })
    }
}

/// Convert log entries returned from Rekor into Sigstore Bundle format entries.
impl TryFrom<RekorLogEntry> for TransparencyLogEntry {
    type Error = ();

    fn try_from(value: RekorLogEntry) -> Result<Self, Self::Error> {
        // Derive kind/version from the actual Rekor body variant so the
        // bundle's tlogEntries[0].kindVersion matches the canonicalized
        // body that downstream verifiers (cosign, sigstore-go) parse. The
        // earlier hardcoded `hashedrekord/0.0.1` produced cross-layer
        // disagreement once `SigningSession::sign_dsse` started submitting
        // dsse@0.0.1 entries (sigstore-go's pkg/tlog/entry.go rejects on
        // "kind and version mismatch").
        let (kind, version) = match &value.body {
            Body::alpine(b) => ("alpine", b.api_version.clone()),
            Body::dsse(b) => ("dsse", b.api_version.clone()),
            Body::helm(b) => ("helm", b.api_version.clone()),
            Body::jar(b) => ("jar", b.api_version.clone()),
            Body::rfc3161(b) => ("rfc3161", b.api_version.clone()),
            Body::rpm(b) => ("rpm", b.api_version.clone()),
            Body::tuf(b) => ("tuf", b.api_version.clone()),
            Body::intoto(b) => ("intoto", b.api_version.clone()),
            Body::hashedrekord(b) => ("hashedrekord", b.api_version.clone()),
            Body::rekord(b) => ("rekord", b.api_version.clone()),
        };
        let canonicalized_body = serde_json_canonicalizer::to_string(&value.body)
            .map_err(|_| ())?
            .into_bytes();
        let inclusion_promise = Some(InclusionPromise {
            signed_entry_timestamp: base64
                .decode(value.verification.signed_entry_timestamp)
                .or(Err(()))?,
        });
        let inclusion_proof = value
            .verification
            .inclusion_proof
            .map(|p| p.try_into())
            .transpose()?;

        Ok(TransparencyLogEntry {
            canonicalized_body,
            inclusion_promise,
            inclusion_proof,
            integrated_time: value.integrated_time,
            kind_version: Some(KindVersion {
                kind: kind.to_owned(),
                version,
            }),
            log_id: Some(LogId {
                key_id: decode_hex(value.log_i_d)?,
            }),
            log_index: value.log_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rekor::models::{DsseAllOf, HashedrekordAllOf};

    #[test]
    fn try_from_dsse_body_emits_dsse_kind_version() {
        let entry = RekorLogEntry {
            body: Body::dsse(DsseAllOf::new("0.0.1".to_owned(), serde_json::json!({}))),
            ..Default::default()
        };
        let tle: TransparencyLogEntry = entry.try_into().expect("dsse conversion ok");
        let kv = tle.kind_version.expect("kind_version present");
        assert_eq!(kv.kind, "dsse");
        assert_eq!(kv.version, "0.0.1");
    }

    #[test]
    fn try_from_hashedrekord_body_emits_hashedrekord_kind_version() {
        let entry = RekorLogEntry {
            body: Body::hashedrekord(HashedrekordAllOf::new(
                "0.0.1".to_owned(),
                serde_json::json!({}),
            )),
            ..Default::default()
        };
        let tle: TransparencyLogEntry =
            entry.try_into().expect("hashedrekord conversion ok");
        let kv = tle.kind_version.expect("kind_version present");
        assert_eq!(kv.kind, "hashedrekord");
        assert_eq!(kv.version, "0.0.1");
    }
}
