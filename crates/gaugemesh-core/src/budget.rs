use thiserror::Error;

use crate::context::{MoneyBudgetMicros, RequestContext, RetryBudget, TokenBudget};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetDebit {
    pub money_micros: u64,
    pub tokens: u64,
    pub retries: u16,
    pub elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BudgetError {
    #[error("GM_BUDGET_MONEY_EXHAUSTED")]
    Money,
    #[error("GM_BUDGET_TOKEN_EXHAUSTED")]
    Tokens,
    #[error("GM_BUDGET_RETRY_EXHAUSTED")]
    Retries,
    #[error("GM_DEADLINE_EXCEEDED")]
    Deadline,
}

pub fn debit(context: &RequestContext, debit: BudgetDebit) -> Result<RequestContext, BudgetError> {
    let mut output = context.clone();
    output.monetary_budget = MoneyBudgetMicros(
        context
            .monetary_budget
            .0
            .checked_sub(debit.money_micros)
            .ok_or(BudgetError::Money)?,
    );
    output.token_budget = TokenBudget(
        context
            .token_budget
            .0
            .checked_sub(debit.tokens)
            .ok_or(BudgetError::Tokens)?,
    );
    output.retry_budget = RetryBudget(
        context
            .retry_budget
            .0
            .checked_sub(debit.retries)
            .ok_or(BudgetError::Retries)?,
    );
    output.deadline.0 = context
        .deadline
        .0
        .checked_sub(debit.elapsed_ms)
        .ok_or(BudgetError::Deadline)?;
    let debit_digest = crate::digest::Sha256Digest::of_json(&serde_json::json!({
        "moneyMicros": debit.money_micros,
        "tokens": debit.tokens,
        "retries": debit.retries,
        "elapsedMs": debit.elapsed_ms,
        "ordinal": output.budget_debits.len(),
    }));
    output.budget_debits.push(debit_digest);
    for retry in 0..debit.retries {
        output
            .retry_attempts
            .push(crate::digest::Sha256Digest::of_json(&serde_json::json!({
                "debit": debit_digest,
                "retry": retry,
            })));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_successful_debit_only_decreases_budgets_and_records_each_retry() {
        let mut context = RequestContext::local_fixture();
        context.monetary_budget = MoneyBudgetMicros(100);
        context.token_budget = TokenBudget(200);
        context.retry_budget = RetryBudget(3);
        context.deadline.0 = 1_000;
        let output = debit(
            &context,
            BudgetDebit {
                money_micros: 40,
                tokens: 50,
                retries: 2,
                elapsed_ms: 250,
            },
        )
        .unwrap();
        assert_eq!(output.monetary_budget, MoneyBudgetMicros(60));
        assert_eq!(output.token_budget, TokenBudget(150));
        assert_eq!(output.retry_budget, RetryBudget(1));
        assert_eq!(output.deadline.0, 750);
        assert_eq!(output.budget_debits.len(), 1);
        assert_eq!(output.retry_attempts.len(), 2);
    }

    #[test]
    fn an_exhausted_dimension_fails_transactionally() {
        let mut context = RequestContext::local_fixture();
        context.monetary_budget = MoneyBudgetMicros(10);
        context.token_budget = TokenBudget(10);
        context.retry_budget = RetryBudget(1);
        context.deadline.0 = 10;
        let snapshot = context.clone();
        assert_eq!(
            debit(
                &context,
                BudgetDebit {
                    money_micros: 0,
                    tokens: 11,
                    retries: 0,
                    elapsed_ms: 0,
                },
            ),
            Err(BudgetError::Tokens)
        );
        assert_eq!(context, snapshot);
    }
}
