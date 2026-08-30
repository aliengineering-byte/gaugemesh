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
    Ok(output)
}
