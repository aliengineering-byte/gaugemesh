use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::context::CausalId;

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CausalObservation {
    pub id: CausalId,
    pub parent: Option<CausalId>,
    pub kind: String,
    pub evidence_digest: crate::digest::Sha256Digest,
}

#[derive(Clone, Debug, Default)]
pub struct CausalGraph {
    parents: BTreeMap<CausalId, Option<CausalId>>,
    observations: Vec<CausalObservation>,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CausalError {
    #[error("GM_INVARIANT_CAUSALITY_BROKEN:duplicate node")]
    Duplicate,
    #[error("GM_INVARIANT_CAUSALITY_BROKEN:missing parent")]
    MissingParent,
    #[error("GM_INVARIANT_CAUSALITY_BROKEN:cycle")]
    Cycle,
}

impl CausalGraph {
    pub fn append(&mut self, observation: CausalObservation) -> Result<(), CausalError> {
        if self.parents.contains_key(&observation.id) {
            return Err(CausalError::Duplicate);
        }
        if let Some(parent) = &observation.parent {
            if !self.parents.contains_key(parent) {
                return Err(CausalError::MissingParent);
            }
            let mut cursor = Some(parent.clone());
            let mut seen = BTreeSet::new();
            while let Some(node) = cursor {
                if node == observation.id || !seen.insert(node.clone()) {
                    return Err(CausalError::Cycle);
                }
                cursor = self.parents.get(&node).cloned().flatten();
            }
        }
        self.parents
            .insert(observation.id.clone(), observation.parent.clone());
        self.observations.push(observation);
        Ok(())
    }

    pub fn observations(&self) -> &[CausalObservation] {
        &self.observations
    }
}
