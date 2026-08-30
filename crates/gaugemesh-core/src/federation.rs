use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rmcp::model::{
    JsonObject, Prompt, PromptArgument, Resource, ResourceTemplate, Tool, ToolAnnotations,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use thiserror::Error;

use crate::{
    capability::{CapabilityId, CapabilityKind, CapabilityRevision, SourceId},
    context::SideEffectClass,
    digest::Sha256Digest,
};

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedTool {
    pub identity: CapabilityId,
    pub native_name: String,
    pub alias: String,
    pub description: String,
    pub input_schema: Value,
    pub side_effect: SideEffectClass,
    pub fixture_result: Value,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedResource {
    pub identity: CapabilityId,
    pub virtual_uri: String,
    pub native_uri: String,
    pub name: String,
    pub mime_type: String,
    pub contents: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederatedPrompt {
    pub identity: CapabilityId,
    pub native_name: String,
    pub alias: String,
    pub description: String,
    pub arguments: Vec<String>,
    pub template: String,
}

#[derive(Clone, Debug, Default)]
pub struct Federation {
    tools: BTreeMap<String, FederatedTool>,
    resources: BTreeMap<String, FederatedResource>,
    prompts: BTreeMap<String, FederatedPrompt>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationError {
    #[error("GM_CAPABILITY_NOT_FOUND")]
    NotFound,
    #[error("GM_CAPABILITY_ALIAS_COLLISION")]
    AliasCollision,
    #[error("GM_CURSOR_INVALID")]
    CursorInvalid,
    #[error("GM_CURSOR_TOO_LARGE")]
    CursorTooLarge,
}

impl Federation {
    pub fn insert_tool(&mut self, tool: FederatedTool) -> Result<(), FederationError> {
        if self.tools.contains_key(&tool.alias) {
            return Err(FederationError::AliasCollision);
        }
        self.tools.insert(tool.alias.clone(), tool);
        Ok(())
    }

    pub fn insert_resource(&mut self, resource: FederatedResource) -> Result<(), FederationError> {
        if self.resources.contains_key(&resource.virtual_uri) {
            return Err(FederationError::AliasCollision);
        }
        self.resources
            .insert(resource.virtual_uri.clone(), resource);
        Ok(())
    }

    pub fn insert_prompt(&mut self, prompt: FederatedPrompt) -> Result<(), FederationError> {
        if self.prompts.contains_key(&prompt.alias) {
            return Err(FederationError::AliasCollision);
        }
        self.prompts.insert(prompt.alias.clone(), prompt);
        Ok(())
    }

    pub fn tools(&self) -> impl Iterator<Item = &FederatedTool> {
        self.tools.values()
    }

    pub fn resources(&self) -> impl Iterator<Item = &FederatedResource> {
        self.resources.values()
    }

    pub fn prompts(&self) -> impl Iterator<Item = &FederatedPrompt> {
        self.prompts.values()
    }

    pub fn tool(&self, alias: &str) -> Result<&FederatedTool, FederationError> {
        self.tools.get(alias).ok_or(FederationError::NotFound)
    }

    pub fn resource(&self, uri: &str) -> Result<&FederatedResource, FederationError> {
        self.resources.get(uri).ok_or(FederationError::NotFound)
    }

    pub fn prompt(&self, alias: &str) -> Result<&FederatedPrompt, FederationError> {
        self.prompts.get(alias).ok_or(FederationError::NotFound)
    }

    pub fn search(&self, query: &str, limit: usize) -> Vec<&FederatedTool> {
        let query_tokens = tokens(query);
        let mut ranked = self
            .tools
            .values()
            .map(|tool| {
                let haystack = tokens(&format!(
                    "{} {} {} {}",
                    tool.alias, tool.native_name, tool.description, tool.identity.source.0
                ));
                let exact = u32::from(tool.alias.eq_ignore_ascii_case(query)) * 10_000;
                let matches = query_tokens
                    .iter()
                    .filter(|token| haystack.iter().any(|value| value == *token))
                    .count() as u32;
                (std::cmp::Reverse(exact + matches * 100), &tool.alias, tool)
            })
            .filter(|(score, _, _)| score.0 > 0)
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
        ranked
            .into_iter()
            .take(limit.min(32))
            .map(|(_, _, tool)| tool)
            .collect()
    }

    pub fn rmcp_tools(&self) -> Vec<Tool> {
        self.tools
            .values()
            .map(|tool| {
                let mut schema = tool
                    .input_schema
                    .as_object()
                    .cloned()
                    .unwrap_or_else(JsonObject::new);
                schema.entry("type").or_insert(json!("object"));
                Tool::new(
                    tool.alias.clone(),
                    tool.description.clone(),
                    Arc::new(schema),
                )
                .with_annotations(ToolAnnotations::from_raw(
                    None,
                    Some(tool.side_effect == SideEffectClass::ReadOnly),
                    Some(tool.side_effect == SideEffectClass::NonIdempotentWrite),
                    Some(tool.side_effect != SideEffectClass::NonIdempotentWrite),
                    Some(false),
                ))
                .with_meta(rmcp::model::MetaObject(metadata(&tool.identity)))
            })
            .collect()
    }

    pub fn rmcp_resources(&self) -> Vec<Resource> {
        self.resources
            .values()
            .map(|resource| {
                Resource::new(&resource.virtual_uri, &resource.name)
                    .with_mime_type(&resource.mime_type)
                    .with_meta(rmcp::model::MetaObject(metadata(&resource.identity)))
            })
            .collect()
    }

    pub fn rmcp_templates(&self) -> Vec<ResourceTemplate> {
        let sources = self
            .resources
            .values()
            .map(|resource| resource.identity.source.0.clone())
            .collect::<std::collections::BTreeSet<_>>();
        sources
            .into_iter()
            .map(|source| {
                ResourceTemplate::new(
                    format!("gaugemesh://resource/{source}/{{opaque-id}}"),
                    format!("{source} resources"),
                )
            })
            .collect()
    }

    pub fn rmcp_prompts(&self) -> Vec<Prompt> {
        self.prompts
            .values()
            .map(|prompt| {
                Prompt::new(
                    &prompt.alias,
                    Some(&prompt.description),
                    Some(
                        prompt
                            .arguments
                            .iter()
                            .map(|argument| PromptArgument::new(argument).with_required(true))
                            .collect(),
                    ),
                )
                .with_meta(rmcp::model::MetaObject(metadata(&prompt.identity)))
            })
            .collect()
    }

    pub fn demo() -> Self {
        let mut federation = Self::default();
        for (source, result) in [("docs-a", "alpha result"), ("docs-b", "beta result")] {
            let schema = json!({
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": false
            });
            let source_id = SourceId(source.into());
            let identity = CapabilityId::new(
                source_id.clone(),
                CapabilityKind::Tool,
                "search",
                Sha256Digest::of_json(&schema),
                CapabilityRevision("2026-07-28".into()),
                Sha256Digest::of_bytes(format!("fixture:{source}")),
            );
            federation
                .insert_tool(FederatedTool {
                    alias: identity.readable_alias("search"),
                    identity: identity.clone(),
                    native_name: "search".into(),
                    description: format!("Search the deterministic {source} fixture"),
                    input_schema: schema,
                    side_effect: SideEffectClass::ReadOnly,
                    fixture_result: json!({"source": source, "result": result}),
                })
                .expect("fixture aliases are distinct");
            let resource_identity = CapabilityId::new(
                source_id.clone(),
                CapabilityKind::Resource,
                "memo://shared",
                Sha256Digest::of_bytes("text/plain"),
                CapabilityRevision("2026-07-28".into()),
                Sha256Digest::of_bytes(format!("fixture:{source}")),
            );
            federation
                .insert_resource(FederatedResource {
                    virtual_uri: format!(
                        "gaugemesh://resource/{source}/{}",
                        &resource_identity.native_identity_digest.to_string()[7..23]
                    ),
                    identity: resource_identity,
                    native_uri: "memo://shared".into(),
                    name: format!("{source} shared memo"),
                    mime_type: "text/plain".into(),
                    contents: format!("bounded contents from {source}"),
                })
                .expect("fixture resource identities are distinct");
            let prompt_identity = CapabilityId::new(
                source_id,
                CapabilityKind::Prompt,
                "summarize",
                Sha256Digest::of_bytes("topic:string"),
                CapabilityRevision("2026-07-28".into()),
                Sha256Digest::of_bytes(format!("fixture:{source}")),
            );
            federation
                .insert_prompt(FederatedPrompt {
                    alias: prompt_identity.readable_alias("summarize"),
                    identity: prompt_identity,
                    native_name: "summarize".into(),
                    description: format!("Summarize a topic using {source}"),
                    arguments: vec!["topic".into()],
                    template: format!("Summarize {{{{topic}}}} with {source} context."),
                })
                .expect("fixture prompt identities are distinct");
        }
        federation
    }
}

fn metadata(identity: &CapabilityId) -> JsonObject {
    serde_json::from_value(json!({
        "dev.gaugemesh/capability": {
            "id": identity.digest().to_string(),
            "source": identity.source.0,
            "kind": identity.kind,
            "schemaDigest": identity.schema_digest.to_string(),
        }
    }))
    .expect("metadata is an object")
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeCursor {
    pub source_positions: BTreeMap<String, String>,
    pub snapshot_digest: Sha256Digest,
}

pub fn seal_cursor(cursor: &CompositeCursor, key: &[u8]) -> Result<String, FederationError> {
    let body = serde_json::to_vec(cursor).map_err(|_| FederationError::CursorInvalid)?;
    if body.len() > 3_072 {
        return Err(FederationError::CursorTooLarge);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| FederationError::CursorInvalid)?;
    mac.update(&body);
    let tag = mac.finalize().into_bytes();
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(body),
        URL_SAFE_NO_PAD.encode(tag)
    ))
}

pub fn open_cursor(value: &str, key: &[u8]) -> Result<CompositeCursor, FederationError> {
    if value.len() > 4_096 {
        return Err(FederationError::CursorTooLarge);
    }
    let (body, tag) = value
        .split_once('.')
        .ok_or(FederationError::CursorInvalid)?;
    let body = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| FederationError::CursorInvalid)?;
    let tag = URL_SAFE_NO_PAD
        .decode(tag)
        .map_err(|_| FederationError::CursorInvalid)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| FederationError::CursorInvalid)?;
    mac.update(&body);
    mac.verify_slice(&tag)
        .map_err(|_| FederationError::CursorInvalid)?;
    serde_json::from_slice(&body).map_err(|_| FederationError::CursorInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_resource_and_prompt_collisions_remain_distinct() {
        let federation = Federation::demo();
        assert_eq!(federation.tools().count(), 2);
        assert_eq!(federation.resources().count(), 2);
        assert_eq!(federation.prompts().count(), 2);
        assert_ne!(
            federation.tool("docs-a__search").unwrap().identity,
            federation.tool("docs-b__search").unwrap().identity
        );
    }

    #[test]
    fn cursor_tampering_is_rejected() {
        let cursor = CompositeCursor {
            source_positions: BTreeMap::from([("a".into(), "1".into())]),
            snapshot_digest: Sha256Digest::of_bytes("snapshot"),
        };
        let sealed = seal_cursor(&cursor, b"bounded-test-key").unwrap();
        assert_eq!(open_cursor(&sealed, b"bounded-test-key").unwrap(), cursor);
        assert_eq!(
            open_cursor(&(sealed + "x"), b"bounded-test-key"),
            Err(FederationError::CursorInvalid)
        );
    }
}
