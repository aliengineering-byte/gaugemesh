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
            if parent == &observation.id {
                return Err(CausalError::Cycle);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Sha256Digest;

    fn observation(id: &str, parent: Option<&str>) -> CausalObservation {
        CausalObservation {
            id: CausalId(id.into()),
            parent: parent.map(|parent| CausalId(parent.into())),
            kind: "test".into(),
            evidence_digest: Sha256Digest::of_bytes(id),
        }
    }

    #[test]
    fn causal_graph_is_append_only_connected_and_acyclic() {
        let mut graph = CausalGraph::default();
        graph.append(observation("root", None)).unwrap();
        graph.append(observation("child", Some("root"))).unwrap();
        assert_eq!(graph.observations().len(), 2);
        assert_eq!(
            graph.append(observation("child", Some("root"))),
            Err(CausalError::Duplicate)
        );
        assert_eq!(
            graph.append(observation("orphan", Some("missing"))),
            Err(CausalError::MissingParent)
        );
        assert_eq!(graph.observations().len(), 2);
    }

    #[test]
    fn a_self_parent_is_rejected_without_mutating_the_graph() {
        let mut graph = CausalGraph::default();
        assert_eq!(
            graph.append(observation("self", Some("self"))),
            Err(CausalError::Cycle)
        );
        assert!(graph.observations().is_empty());
    }

    #[test]
    fn a_parent_chain_that_reaches_the_new_node_is_rejected() {
        let mut graph = CausalGraph::default();
        graph
            .parents
            .insert(CausalId("root".into()), Some(CausalId("child".into())));

        assert_eq!(
            graph.append(observation("child", Some("root"))),
            Err(CausalError::Cycle)
        );
        assert!(graph.observations().is_empty());
    }
}
