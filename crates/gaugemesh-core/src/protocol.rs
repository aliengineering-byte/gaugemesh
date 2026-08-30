use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MCP_2025_11_25: &str = "2025-11-25";
pub const MCP_2026_07_28: &str = "2026-07-28";

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
pub enum McpRevision {
    #[serde(rename = "2025-11-25")]
    V2025_11_25,
    #[serde(rename = "2026-07-28")]
    V2026_07_28,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevisionError {
    #[error("GM_MCP_REVISION_UNSUPPORTED")]
    Unsupported,
    #[error("GM_MCP_REVISION_DISAGREEMENT")]
    HeaderBodyDisagreement,
}

impl McpRevision {
    pub fn parse(value: &str) -> Result<Self, RevisionError> {
        match value {
            MCP_2025_11_25 => Ok(Self::V2025_11_25),
            MCP_2026_07_28 => Ok(Self::V2026_07_28),
            _ => Err(RevisionError::Unsupported),
        }
    }

    pub fn validate_request(
        header: Option<&str>,
        body: Option<&str>,
    ) -> Result<Self, RevisionError> {
        let header = header.map(Self::parse).transpose()?;
        let body = body.map(Self::parse).transpose()?;
        match (header, body) {
            (Some(header), Some(body)) if header != body => {
                Err(RevisionError::HeaderBodyDisagreement)
            }
            (Some(revision), _) | (_, Some(revision)) => Ok(revision),
            (None, None) => Err(RevisionError::Unsupported),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2025_11_25 => MCP_2025_11_25,
            Self::V2026_07_28 => MCP_2026_07_28,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_declared_revisions_are_explicit() {
        assert_eq!(
            McpRevision::parse(MCP_2025_11_25).unwrap().as_str(),
            MCP_2025_11_25
        );
        assert_eq!(
            McpRevision::parse(MCP_2026_07_28).unwrap().as_str(),
            MCP_2026_07_28
        );
    }

    #[test]
    fn header_body_disagreement_fails_closed() {
        assert_eq!(
            McpRevision::validate_request(Some(MCP_2026_07_28), Some(MCP_2025_11_25)),
            Err(RevisionError::HeaderBodyDisagreement)
        );
    }
}
