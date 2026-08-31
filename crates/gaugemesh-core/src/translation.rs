use serde::Serialize;
use thiserror::Error;

use crate::{
    context::RequestContext,
    digest::Sha256Digest,
    invariant::{ConservationReport, InvariantErrorCode, SemanticLoss, conserve},
};

pub trait ProtocolAdapter {
    type Input: Serialize;
    type Output: Serialize;

    fn translate(
        &self,
        input: Self::Input,
        context: &RequestContext,
    ) -> Result<(Self::Output, RequestContext, ConservationReport), TranslationError>;
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum TranslationError {
    #[error("{0}")]
    Invariant(InvariantErrorCode),
    #[error("GM_TRANSLATION_LOSS_EXCEEDED:score={score}:limit={limit}")]
    LossExceeded { score: u64, limit: u64 },
    #[error("GM_TRANSLATION_REQUIRED_FIELD_UNREPRESENTABLE:{0}")]
    RequiredField(String),
}

pub fn require_representable(field: &str, representable: bool) -> Result<(), TranslationError> {
    if representable {
        Ok(())
    } else {
        Err(TranslationError::RequiredField(field.into()))
    }
}

pub fn report_translation<I: Serialize, O: Serialize>(
    input: &I,
    output: &O,
    source: &RequestContext,
    target: &RequestContext,
    optional_losses: Vec<SemanticLoss>,
    max_loss: u64,
) -> Result<ConservationReport, TranslationError> {
    let mut report = conserve(source, target);
    if let Some(violation) = report.violations.first() {
        return Err(TranslationError::Invariant(violation.code));
    }
    let score = optional_losses
        .iter()
        .map(|loss| u64::from(loss.weight))
        .sum();
    if score > max_loss {
        return Err(TranslationError::LossExceeded {
            score,
            limit: max_loss,
        });
    }
    report.optional_losses = optional_losses;
    report.semantic_loss_score = score;
    report.source_digest =
        Sha256Digest::of_json(&serde_json::to_value(input).expect("adapter input serializes"));
    report.target_digest = Some(Sha256Digest::of_json(
        &serde_json::to_value(output).expect("adapter output serializes"),
    ));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant::SemanticLoss;
    use serde_json::json;

    #[test]
    fn required_fields_and_excess_optional_loss_are_rejected() {
        assert_eq!(
            require_representable("resultType", false),
            Err(TranslationError::RequiredField("resultType".into()))
        );
        let context = RequestContext::local_fixture();
        assert_eq!(
            report_translation(
                &json!({"input": true}),
                &json!({"output": true}),
                &context,
                &context,
                vec![SemanticLoss {
                    field: "optionalHint".into(),
                    reason: "target revision cannot encode the hint".into(),
                    weight: 5,
                }],
                4,
            ),
            Err(TranslationError::LossExceeded { score: 5, limit: 4 })
        );
    }

    #[test]
    fn optional_loss_equal_to_the_limit_is_accepted() {
        let context = RequestContext::local_fixture();
        let losses = vec![SemanticLoss {
            field: "optionalHint".into(),
            reason: "target revision cannot encode the hint".into(),
            weight: 4,
        }];

        let report = report_translation(
            &json!({"input": true}),
            &json!({"output": true}),
            &context,
            &context,
            losses.clone(),
            4,
        )
        .expect("loss equal to the configured limit remains representable");

        assert_eq!(report.semantic_loss_score, 4);
        assert_eq!(report.optional_losses, losses);
    }
}
