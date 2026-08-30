use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::digest::Sha256Digest;

macro_rules! capability_id {
    ($name:ident) => {
        #[derive(
            Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);
    };
}

capability_id!(SourceId);
capability_id!(CapabilityRevision);

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Tool,
    Resource,
    ResourceTemplate,
    Prompt,
    Model,
}

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct CapabilityId {
    pub source: SourceId,
    pub kind: CapabilityKind,
    pub native_identity_digest: Sha256Digest,
    pub schema_digest: Sha256Digest,
    pub revision: CapabilityRevision,
    pub source_configuration_digest: Sha256Digest,
}

impl CapabilityId {
    pub fn new(
        source: SourceId,
        kind: CapabilityKind,
        native_identity: &str,
        schema_digest: Sha256Digest,
        revision: CapabilityRevision,
        source_configuration_digest: Sha256Digest,
    ) -> Self {
        Self {
            source,
            kind,
            native_identity_digest: Sha256Digest::of_bytes(
                native_identity.nfc().collect::<String>(),
            ),
            schema_digest,
            revision,
            source_configuration_digest,
        }
    }

    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::of_json(&serde_json::to_value(self).expect("capability serializes"))
    }

    pub fn readable_alias(&self, native_name: &str) -> String {
        let safe = native_name
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        format!("{}__{}", self.source.0, safe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(source: &str, name: &str) -> CapabilityId {
        let zero = Sha256Digest::default();
        CapabilityId::new(
            SourceId(source.into()),
            CapabilityKind::Tool,
            name,
            zero,
            CapabilityRevision("2026-07-28".into()),
            zero,
        )
    }

    #[test]
    fn colliding_names_have_distinct_authorization_identities() {
        assert_ne!(
            capability("docs-a", "search"),
            capability("docs-b", "search")
        );
    }

    #[test]
    fn unicode_equivalent_native_names_are_bound_identically() {
        assert_eq!(
            capability("docs", "caf\u{00e9}").native_identity_digest,
            capability("docs", "cafe\u{0301}").native_identity_digest
        );
    }

    #[test]
    fn alias_does_not_define_identity() {
        let capability = capability("docs", "search");
        assert_ne!(
            capability.digest(),
            Sha256Digest::of_bytes(capability.readable_alias("search"))
        );
    }
}
