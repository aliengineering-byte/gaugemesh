use std::{sync::Arc, time::Duration};

use crate::auth::AuthenticatedIdentity;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response, sse::Event},
    routing::{get, post},
};
use futures_util::{StreamExt as _, stream};
use gaugemesh_core::{
    config::ModelConfig,
    context::{
        CapabilityScope, MoneyBudgetMicros, PrincipalId, RetryBudget, TenantId, TokenBudget,
    },
    digest::Sha256Digest,
    federation::Federation,
    lease::CapabilityLease,
    model::{CostTable, ModelBudget, ModelIdentity, ToolMode, enforce_budget},
    route::{ConstraintResult, RouteCandidate, RouteId, RouteMetricSnapshot, RouteWeights, plan},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_TOOL_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 1024 * 1024;
const COST_TABLE_VERSION: &str = "fixture-2026-08-30";

#[derive(Clone)]
pub struct ModelBroker {
    providers: Arc<Vec<ModelRoute>>,
    federation: Federation,
}

#[derive(Clone)]
struct ModelRoute {
    alias: String,
    provider: Arc<dyn ModelProvider>,
    cost_table: CostTable,
    max_output_tokens: u64,
}

impl ModelBroker {
    fn fixture() -> Self {
        Self {
            providers: Arc::new(vec![ModelRoute {
                alias: "local".into(),
                provider: Arc::new(DeterministicProvider::new()),
                cost_table: CostTable {
                    version: COST_TABLE_VERSION.into(),
                    input_micros_per_million_tokens: 0,
                    output_micros_per_million_tokens: 0,
                },
                max_output_tokens: 1_024,
            }]),
            federation: Federation::demo(),
        }
    }

    async fn configured(models: &[ModelConfig], federation: Federation) -> Result<Self> {
        let mut providers = Vec::with_capacity(models.len());
        for model in models {
            let authorization = model
                .credential_env
                .as_deref()
                .map(|name| {
                    let value =
                        std::env::var(name).with_context(|| "GM_MODEL_CREDENTIAL_ENV_MISSING")?;
                    HeaderValue::from_str(&format!("Bearer {value}"))
                        .context("GM_MODEL_CREDENTIAL_INVALID")
                })
                .transpose()?;
            let provider = OpenAiCompatibleProvider::configured(model, authorization).await?;
            providers.push(ModelRoute {
                alias: model.id.clone(),
                provider: Arc::new(provider),
                cost_table: CostTable {
                    version: model.cost_table.version.clone(),
                    input_micros_per_million_tokens: model
                        .cost_table
                        .input_micros_per_million_tokens,
                    output_micros_per_million_tokens: model
                        .cost_table
                        .output_micros_per_million_tokens,
                },
                max_output_tokens: model.max_output_tokens,
            });
        }
        if providers.is_empty() {
            bail!("GM_MODEL_NO_CONFIGURED_PROVIDER");
        }
        Ok(Self {
            providers: Arc::new(providers),
            federation,
        })
    }
}

pub fn router() -> Router {
    router_for_broker(ModelBroker::fixture())
}

pub async fn router_from_config(models: &[ModelConfig], federation: Federation) -> Result<Router> {
    Ok(router_for_broker(
        ModelBroker::configured(models, federation).await?,
    ))
}

fn router_for_broker(broker: ModelBroker) -> Router {
    Router::new()
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(broker)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Message {
    role: Role,
    content: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    #[serde(default)]
    stream: bool,
    #[serde(default = "default_max_tokens")]
    max_tokens: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponsesRequest {
    model: String,
    input: String,
    #[serde(default)]
    stream: bool,
    #[serde(default = "default_max_tokens")]
    max_output_tokens: u64,
}

fn default_max_tokens() -> u64 {
    256
}

#[derive(Clone, Debug, Serialize)]
struct ProviderOutput {
    text: String,
    input_tokens: u64,
    output_tokens: u64,
    observed_cost_micros: Option<u64>,
}

#[async_trait]
trait ModelProvider: Send + Sync {
    fn identity(&self) -> &ModelIdentity;
    async fn complete(&self, messages: &[Message], max_tokens: u64) -> Result<ProviderOutput>;
}

struct DeterministicProvider {
    identity: ModelIdentity,
}

impl DeterministicProvider {
    fn new() -> Self {
        Self {
            identity: ModelIdentity {
                provider: "fixture".into(),
                endpoint_identity: Sha256Digest::of_bytes("in-process-deterministic-provider"),
                provider_model_id: "gaugemesh-deterministic".into(),
                capability_set: vec!["chat".into(), "responses".into(), "streaming".into()],
                context_limit: 4_096,
                tool_call_support: true,
                structured_output_support: false,
                streaming_support: true,
                cost_table_version: COST_TABLE_VERSION.into(),
                policy_digest: Sha256Digest::of_bytes("local-fixture-policy"),
            },
        }
    }
}

#[async_trait]
impl ModelProvider for DeterministicProvider {
    fn identity(&self) -> &ModelIdentity {
        &self.identity
    }

    async fn complete(&self, messages: &[Message], max_tokens: u64) -> Result<ProviderOutput> {
        let input = messages
            .iter()
            .rev()
            .find(|message| matches!(message.role, Role::User))
            .map(|message| message.content.as_str())
            .unwrap_or("");
        let mut text = format!("fixture: {input}");
        let max_bytes = usize::try_from(max_tokens.saturating_mul(4)).unwrap_or(usize::MAX);
        let mut boundary = max_bytes.min(text.len());
        while !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        text.truncate(boundary);
        Ok(ProviderOutput {
            text: text.clone(),
            input_tokens: approximate_tokens(
                messages.iter().map(|message| message.content.as_str()),
            ),
            output_tokens: approximate_tokens([text.as_str()]),
            observed_cost_micros: Some(0),
        })
    }
}

pub struct OpenAiCompatibleProvider {
    identity: ModelIdentity,
    base_url: Url,
    client: reqwest::Client,
    authorization: Option<HeaderValue>,
}

impl OpenAiCompatibleProvider {
    pub async fn new(
        base_url: Url,
        provider_model_id: String,
        authorization: Option<HeaderValue>,
    ) -> Result<Self> {
        if !matches!(base_url.scheme(), "http" | "https") {
            bail!("GM_MODEL_PROVIDER_SCHEME_DENIED");
        }
        let endpoint_identity = Sha256Digest::of_bytes(base_url.as_str());
        let client = safe_provider_client(&base_url).await?;
        Ok(Self {
            identity: ModelIdentity {
                provider: "openai-compatible".into(),
                endpoint_identity,
                provider_model_id,
                capability_set: vec!["chat".into()],
                context_limit: 128_000,
                tool_call_support: false,
                structured_output_support: false,
                streaming_support: false,
                cost_table_version: "user-supplied".into(),
                policy_digest: Sha256Digest::of_bytes("configured-provider-policy"),
            },
            base_url,
            client,
            authorization,
        })
    }

    async fn configured(config: &ModelConfig, authorization: Option<HeaderValue>) -> Result<Self> {
        let mut provider = Self::new(
            config.base_url.clone(),
            config.provider_model_id.clone(),
            authorization,
        )
        .await?;
        provider.identity.context_limit = config.context_limit;
        provider.identity.cost_table_version = config.cost_table.version.clone();
        provider.identity.policy_digest = Sha256Digest::of_json(&json!({
            "route": config.id,
            "provider": config.provider_model_id,
            "costTable": config.cost_table,
        }));
        Ok(provider)
    }
}

pub async fn inspect_openai_provider(
    base_url: Url,
    provider_model_id: String,
    credential_env: Option<&str>,
) -> Result<Sha256Digest> {
    let authorization = credential_env
        .map(|name| {
            let value = std::env::var(name).with_context(|| "GM_MODEL_CREDENTIAL_ENV_MISSING")?;
            HeaderValue::from_str(&format!("Bearer {value}")).context("GM_MODEL_CREDENTIAL_INVALID")
        })
        .transpose()?;
    let provider =
        OpenAiCompatibleProvider::new(base_url, provider_model_id.clone(), authorization).await?;
    let url = provider
        .base_url
        .join("models")
        .context("GM_MODEL_PROVIDER_URL")?;
    let mut request = provider.client.get(url);
    if let Some(authorization) = &provider.authorization {
        request = request.header(header::AUTHORIZATION, authorization.clone());
    }
    let response = request
        .send()
        .await
        .context("GM_MODEL_PROVIDER_DISCOVERY")?;
    if !response.status().is_success() {
        bail!("GM_MODEL_PROVIDER_STATUS:{}", response.status().as_u16());
    }
    let body = bounded_provider_json(response).await?;
    let found = body
        .get("data")
        .and_then(Value::as_array)
        .is_some_and(|models| {
            models
                .iter()
                .any(|model| model.get("id").and_then(Value::as_str) == Some(&provider_model_id))
        });
    if !found {
        bail!("GM_MODEL_NOT_FOUND");
    }
    Ok(provider.identity.digest())
}

#[async_trait]
impl ModelProvider for OpenAiCompatibleProvider {
    fn identity(&self) -> &ModelIdentity {
        &self.identity
    }

    async fn complete(&self, messages: &[Message], max_tokens: u64) -> Result<ProviderOutput> {
        let url = self
            .base_url
            .join("chat/completions")
            .context("GM_MODEL_PROVIDER_URL")?;
        let mut request = self.client.post(url).json(&json!({
            "model": self.identity.provider_model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": false,
        }));
        if let Some(authorization) = &self.authorization {
            request = request.header(header::AUTHORIZATION, authorization.clone());
        }
        let response = request.send().await.context("GM_MODEL_PROVIDER_REQUEST")?;
        if !response.status().is_success() {
            bail!("GM_MODEL_PROVIDER_STATUS:{}", response.status().as_u16());
        }
        let body = bounded_provider_json(response).await?;
        let text = body
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .context("GM_MODEL_PROVIDER_RESPONSE_SHAPE")?
            .to_owned();
        Ok(ProviderOutput {
            text,
            input_tokens: body
                .pointer("/usage/prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: body
                .pointer("/usage/completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            observed_cost_micros: None,
        })
    }
}

async fn bounded_provider_json(response: reqwest::Response) -> Result<Value> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        bail!("GM_MODEL_PROVIDER_RESPONSE_TOO_LARGE");
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("GM_MODEL_PROVIDER_BODY")?;
        if bytes.len().saturating_add(chunk.len()) > MAX_PROVIDER_RESPONSE_BYTES {
            bail!("GM_MODEL_PROVIDER_RESPONSE_TOO_LARGE");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("GM_MODEL_PROVIDER_JSON")
}

async fn safe_provider_client(base_url: &Url) -> Result<reqwest::Client> {
    let host = base_url
        .host_str()
        .context("GM_MODEL_PROVIDER_URL_INVALID")?;
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !matches!(base_url.scheme(), "http" | "https") || (base_url.scheme() == "http" && !local) {
        bail!("GM_MODEL_PROVIDER_SCHEME_DENIED");
    }
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30));
    if !local {
        let origin = gaugemesh_core::security::ResolvedOrigin::resolve(base_url, false)
            .await
            .context("GM_MODEL_PROVIDER_ORIGIN")?;
        let addresses = origin
            .addresses
            .iter()
            .map(|address| std::net::SocketAddr::new(*address, origin.port))
            .collect::<Vec<_>>();
        builder = builder.resolve_to_addrs(&origin.host, &addresses);
    }
    builder.build().context("GM_MODEL_PROVIDER_CLIENT")
}

async fn list_models(State(broker): State<ModelBroker>) -> Json<Value> {
    let data = broker
        .providers
        .iter()
        .map(|route| {
            let identity = route.provider.identity();
            json!({
                "id": route.alias,
                "object": "model",
                "owned_by": identity.provider,
                "gaugemesh": {
                    "identity": identity.digest().to_string(),
                    "providerModelId": identity.provider_model_id,
                    "capabilities": identity.capability_set,
                    "costTableVersion": route.cost_table.version,
                }
            })
        })
        .collect::<Vec<_>>();
    Json(json!({
        "object": "list",
        "data": data,
    }))
}

async fn chat_completions(
    State(broker): State<ModelBroker>,
    identity: Option<Extension<AuthenticatedIdentity>>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Response {
    let request: ChatRequest = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "GM_OPENAI_UNSUPPORTED_OR_INVALID_FIELD",
                error.to_string(),
            );
        }
    };
    match execute(
        &broker,
        &headers,
        &request.model,
        request.messages,
        request.max_tokens,
        identity.as_deref(),
    )
    .await
    {
        Ok(execution) if request.stream => stream_chat(execution),
        Ok(execution) => json_chat(execution),
        Err(error) => model_error(error),
    }
}

async fn responses(
    State(broker): State<ModelBroker>,
    identity: Option<Extension<AuthenticatedIdentity>>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Response {
    let request: ResponsesRequest = match serde_json::from_value(value) {
        Ok(request) => request,
        Err(error) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "GM_OPENAI_UNSUPPORTED_OR_INVALID_FIELD",
                error.to_string(),
            );
        }
    };
    let messages = vec![Message {
        role: Role::User,
        content: request.input,
    }];
    match execute(
        &broker,
        &headers,
        &request.model,
        messages,
        request.max_output_tokens,
        identity.as_deref(),
    )
    .await
    {
        Ok(execution) if request.stream => stream_response(execution),
        Ok(execution) => json_response(execution),
        Err(error) => model_error(error),
    }
}

struct Execution {
    id: String,
    output: ProviderOutput,
    route_digest: Sha256Digest,
    estimated_cost_micros: u64,
    tool: Option<ToolExecution>,
    model_alias: String,
    cost_table_version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolExecution {
    capability_id: String,
    alias: String,
    causal_child: String,
    result: Value,
}

async fn execute(
    broker: &ModelBroker,
    headers: &HeaderMap,
    model: &str,
    messages: Vec<Message>,
    max_output: u64,
    identity: Option<&AuthenticatedIdentity>,
) -> Result<Execution> {
    let tool_mode = tool_mode(headers)?;
    let estimated_input =
        approximate_tokens(messages.iter().map(|message| message.content.as_str()));
    let budget = request_budget(headers, max_output)?;
    let mut estimated_costs = std::collections::BTreeMap::new();
    let candidates = broker
        .providers
        .iter()
        .map(|route| {
            let identity = route.provider.identity();
            let name_matches =
                model == "auto" || model == route.alias || model == identity.provider_model_id;
            let budget_result = if !name_matches {
                Err(gaugemesh_core::model::ModelRouteError::ModelNotAllowed)
            } else if max_output > route.max_output_tokens {
                Err(gaugemesh_core::model::ModelRouteError::OutputTokens)
            } else {
                enforce_budget(
                    identity,
                    &route.cost_table,
                    &budget,
                    estimated_input,
                    max_output,
                    tool_mode,
                )
            };
            let mut rejections = Vec::new();
            match budget_result {
                Ok(cost) => {
                    estimated_costs.insert(route.alias.clone(), cost);
                }
                Err(error) => rejections.push(error.to_string()),
            }
            RouteCandidate {
                route_id: RouteId(route.alias.clone()),
                endpoint_id: identity.endpoint_identity.to_string(),
                hard_constraints: ConstraintResult {
                    allowed: rejections.is_empty(),
                    rejections,
                },
                metrics: RouteMetricSnapshot {
                    latency: 0,
                    cost: u32::try_from(
                        route
                            .cost_table
                            .input_micros_per_million_tokens
                            .saturating_add(route.cost_table.output_micros_per_million_tokens)
                            .min(10_000),
                    )
                    .expect("bounded cost metric"),
                    failure: 0,
                    pressure: 0,
                    exposure: u32::from(identity.provider != "fixture"),
                    switching: 0,
                },
                semantic_loss: 0,
            }
        })
        .collect::<Vec<_>>();
    if estimated_costs.is_empty() {
        let mut rejections = candidates
            .iter()
            .flat_map(|candidate| candidate.hard_constraints.rejections.iter().cloned())
            .collect::<Vec<_>>();
        rejections.sort();
        rejections.dedup();
        bail!(
            "{}",
            rejections
                .first()
                .map(String::as_str)
                .unwrap_or("GM_MODEL_NOT_FOUND_OR_BUDGET_REJECTED")
        );
    }
    let route_plan = plan(
        candidates,
        RouteWeights {
            latency: 10,
            cost: 30,
            failure: 30,
            semantic_loss: 1_000,
            pressure: 20,
            exposure: 50,
            switching: 10,
        },
    )
    .map_err(|_| anyhow::anyhow!("GM_MODEL_NOT_FOUND_OR_BUDGET_REJECTED"))?;
    let selected = broker
        .providers
        .iter()
        .find(|route| route.alias == route_plan.selected.0)
        .context("GM_MODEL_ROUTE_IDENTITY_LOST")?;
    let estimated_cost_micros = estimated_costs
        .get(&selected.alias)
        .copied()
        .context("GM_MODEL_ROUTE_BUDGET_LOST")?;
    let request_digest = Sha256Digest::of_json(&json!({
        "modelIdentity": selected.provider.identity().digest(),
        "messages": messages,
        "maxOutput": max_output,
        "toolMode": tool_mode,
        "budget": budget,
        "principal": identity.map(|identity| &identity.principal),
        "tenant": identity.map(|identity| &identity.tenant),
        "authScopes": identity.map(|identity| &identity.scopes),
    }));
    let tool = maybe_execute_tool(broker, &messages, tool_mode, request_digest, identity)?;
    let mut provider_messages = messages;
    if let Some(tool) = &tool {
        provider_messages.push(Message {
            role: Role::Tool,
            content: serde_json::to_string(&tool.result)?,
        });
    }
    let output = tokio::time::timeout(
        Duration::from_millis(budget.deadline_remaining_ms),
        selected.provider.complete(&provider_messages, max_output),
    )
    .await
    .context("GM_MODEL_PROVIDER_TIMEOUT")??;
    let route_digest = Sha256Digest::of_json(&json!({
        "plan": route_plan,
        "model": selected.provider.identity(),
        "costTable": selected.cost_table,
        "estimatedInput": estimated_input,
        "maxOutput": max_output,
        "toolMode": tool_mode,
    }));
    Ok(Execution {
        id: format!("gm-{}", &request_digest.to_string()[7..23]),
        output,
        route_digest,
        estimated_cost_micros,
        tool,
        model_alias: selected.alias.clone(),
        cost_table_version: selected.cost_table.version.clone(),
    })
}

fn maybe_execute_tool(
    broker: &ModelBroker,
    messages: &[Message],
    mode: ToolMode,
    causal_parent: Sha256Digest,
    identity: Option<&AuthenticatedIdentity>,
) -> Result<Option<ToolExecution>> {
    if mode == ToolMode::Off {
        return Ok(None);
    }
    let Some(command) = messages
        .iter()
        .rev()
        .find(|message| matches!(message.role, Role::User))
        .and_then(|message| message.content.strip_prefix("tool:"))
    else {
        return Ok(None);
    };
    if command.len() > MAX_TOOL_PAYLOAD_BYTES {
        bail!("GM_TOOL_PAYLOAD_TOO_LARGE");
    }
    let (alias, query) = command.split_once(' ').unwrap_or((command, ""));
    let tool = broker.federation.tool(alias)?;
    if !matches!(
        tool.side_effect,
        gaugemesh_core::context::SideEffectClass::ReadOnly
    ) {
        bail!("GM_TOOL_SIDE_EFFECT_DENIED");
    }
    if mode == ToolMode::Lease {
        let principal = identity
            .map(|identity| identity.principal.clone())
            .unwrap_or_else(|| PrincipalId("local-model-client".into()));
        let tenant = identity
            .map(|identity| identity.tenant.clone())
            .unwrap_or_else(|| TenantId("local".into()));
        let lease = CapabilityLease::issue(
            principal.clone(),
            tenant.clone(),
            causal_parent.to_string(),
            vec![tool.identity.clone()],
            CapabilityScope::default(),
            1_000,
            MoneyBudgetMicros(0),
            TokenBudget(4_096),
            RetryBudget(0),
        );
        lease.authorize_invocation(&principal, &tenant, &tool.identity, tool.side_effect, 0)?;
    }
    let result = json!({"query": query, "fixture": tool.fixture_result});
    if serde_json::to_vec(&result)?.len() > MAX_TOOL_OUTPUT_BYTES {
        bail!("GM_TOOL_RESULT_TOO_LARGE");
    }
    let causal_child = Sha256Digest::of_json(&json!({
        "parent": causal_parent,
        "capability": tool.identity.digest(),
        "arguments": {"query": query},
    }));
    Ok(Some(ToolExecution {
        capability_id: tool.identity.digest().to_string(),
        alias: alias.into(),
        causal_child: causal_child.to_string(),
        result,
    }))
}

fn request_budget(headers: &HeaderMap, max_output: u64) -> Result<ModelBudget> {
    Ok(ModelBudget {
        max_input_tokens: header_u64(headers, "x-gaugemesh-max-input-tokens")?.unwrap_or(4_096),
        max_output_tokens: header_u64(headers, "x-gaugemesh-max-output-tokens")?.unwrap_or(1_024),
        money_micros: header_u64(headers, "x-gaugemesh-money-budget-micros")?.unwrap_or(0),
        deadline_remaining_ms: header_u64(headers, "x-gaugemesh-deadline-ms")?.unwrap_or(30_000),
        tool_loop_limit: u16::try_from(
            header_u64(headers, "x-gaugemesh-max-tool-rounds")?.unwrap_or(1),
        )
        .context("GM_MODEL_TOOL_ROUNDS_INVALID")?,
        retry_limit: u16::try_from(header_u64(headers, "x-gaugemesh-retry-limit")?.unwrap_or(0))
            .context("GM_MODEL_RETRY_LIMIT_INVALID")?,
        provider_allowlist: header_list(headers, "x-gaugemesh-provider-allowlist")?,
        model_allowlist: header_list(headers, "x-gaugemesh-model-allowlist")?,
    })
    .and_then(|budget| {
        if max_output == 0 {
            bail!("GM_MODEL_OUTPUT_TOKEN_BUDGET")
        }
        Ok(budget)
    })
}

fn header_list(headers: &HeaderMap, name: &str) -> Result<Vec<String>> {
    let Some(value) = headers.get(name) else {
        return Ok(Vec::new());
    };
    let values = value
        .to_str()
        .with_context(|| format!("GM_HEADER_INVALID:{name}"))?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.len() > 32 || values.iter().any(|value| value.len() > 128) {
        bail!("GM_HEADER_INVALID:{name}");
    }
    Ok(values)
}

fn tool_mode(headers: &HeaderMap) -> Result<ToolMode> {
    match headers
        .get("x-gaugemesh-tool-mode")
        .map(HeaderValue::to_str)
        .transpose()
        .context("GM_TOOL_MODE_INVALID")?
        .unwrap_or("off")
    {
        "off" => Ok(ToolMode::Off),
        "transparent" => Ok(ToolMode::Transparent),
        "lease" => Ok(ToolMode::Lease),
        _ => bail!("GM_TOOL_MODE_INVALID"),
    }
}

fn header_u64(headers: &HeaderMap, name: &str) -> Result<Option<u64>> {
    headers
        .get(name)
        .map(|value| value.to_str()?.parse::<u64>().map_err(anyhow::Error::from))
        .transpose()
        .with_context(|| format!("GM_HEADER_INVALID:{name}"))
}

fn json_chat(execution: Execution) -> Response {
    let body = json!({
        "id": execution.id,
        "object": "chat.completion",
        "created": 0,
        "model": execution.model_alias,
        "choices": [{"index":0,"message":{"role":"assistant","content":execution.output.text},"finish_reason":"stop"}],
        "usage": {"prompt_tokens":execution.output.input_tokens,"completion_tokens":execution.output.output_tokens,"total_tokens":execution.output.input_tokens + execution.output.output_tokens},
        "gaugemesh": metadata(&execution),
    });
    response_with_route(Json(body).into_response(), &execution)
}

fn json_response(execution: Execution) -> Response {
    let body = json!({
        "id": execution.id,
        "object": "response",
        "created_at": 0,
        "model": execution.model_alias,
        "status": "completed",
        "output": [{"type":"message","role":"assistant","content":[{"type":"output_text","text":execution.output.text}]}],
        "usage": {"input_tokens":execution.output.input_tokens,"output_tokens":execution.output.output_tokens,"total_tokens":execution.output.input_tokens + execution.output.output_tokens},
        "gaugemesh": metadata(&execution),
    });
    response_with_route(Json(body).into_response(), &execution)
}

fn stream_chat(execution: Execution) -> Response {
    let payload = json!({
        "id": execution.id,
        "object":"chat.completion.chunk",
        "created":0,
        "model":execution.model_alias,
        "choices":[{"index":0,"delta":{"content":execution.output.text},"finish_reason":"stop"}]
    });
    sse_response(execution, payload)
}

fn stream_response(execution: Execution) -> Response {
    let payload = json!({
        "type":"response.output_text.delta",
        "item_id":execution.id,
        "delta":execution.output.text
    });
    sse_response(execution, payload)
}

fn sse_response(execution: Execution, payload: Value) -> Response {
    let events = stream::iter([
        Ok::<_, std::convert::Infallible>(Event::default().data(payload.to_string())),
        Ok(Event::default().data("[DONE]")),
    ]);
    let response = axum::response::sse::Sse::new(events)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response();
    response_with_route(response, &execution)
}

fn metadata(execution: &Execution) -> Value {
    json!({
        "routeDigest": execution.route_digest.to_string(),
        "costTableVersion": execution.cost_table_version,
        "estimatedCostMicros": execution.estimated_cost_micros,
        "observedCostMicros": execution.output.observed_cost_micros,
        "tool": execution.tool,
    })
}

fn response_with_route(mut response: Response, execution: &Execution) -> Response {
    response.headers_mut().insert(
        "x-gaugemesh-route-digest",
        HeaderValue::from_str(&execution.route_digest.to_string()).expect("digest header"),
    );
    response
}

fn model_error(error: anyhow::Error) -> Response {
    api_error(
        StatusCode::BAD_REQUEST,
        "GM_MODEL_REQUEST_REJECTED",
        error.to_string(),
    )
}

fn api_error(status: StatusCode, code: &str, message: String) -> Response {
    (
        status,
        Json(json!({"error":{"type":"invalid_request_error","code":code,"message":message}})),
    )
        .into_response()
}

fn approximate_tokens<'a>(values: impl IntoIterator<Item = &'a str>) -> u64 {
    let bytes = values
        .into_iter()
        .fold(0_u64, |sum, value| sum.saturating_add(value.len() as u64));
    bytes.saturating_add(3) / 4
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::routing::{get, post};
    use tower::ServiceExt as _;

    use super::*;

    async fn request(path: &str, body: Value, headers: &[(&str, &str)]) -> Response {
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        router()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn body(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn non_streaming_chat_and_responses_are_compatible_subsets() {
        let chat = request(
            "/v1/chat/completions",
            json!({"model":"local","messages":[{"role":"user","content":"hello"}]}),
            &[],
        )
        .await;
        assert_eq!(chat.status(), StatusCode::OK);
        assert_eq!(
            body(chat)
                .await
                .pointer("/choices/0/message/content")
                .unwrap(),
            "fixture: hello"
        );

        let response = request(
            "/v1/responses",
            json!({"model":"local","input":"hello"}),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body(response)
                .await
                .pointer("/output/0/content/0/text")
                .unwrap(),
            "fixture: hello"
        );
    }

    #[tokio::test]
    async fn streaming_completion_ends_explicitly() {
        let response = request(
            "/v1/chat/completions",
            json!({"model":"local","messages":[{"role":"user","content":"stream"}],"stream":true}),
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/event-stream"
        );
        let bytes = axum::body::to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        assert!(
            String::from_utf8(bytes.to_vec())
                .unwrap()
                .contains("[DONE]")
        );
    }

    #[tokio::test]
    async fn unsupported_fields_and_exhausted_deadline_fail_before_provider() {
        let unsupported = request(
            "/v1/chat/completions",
            json!({"model":"local","messages":[],"temperature":0.1}),
            &[],
        )
        .await;
        assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body(unsupported).await.pointer("/error/code").unwrap(),
            "GM_OPENAI_UNSUPPORTED_OR_INVALID_FIELD"
        );

        let deadline = request(
            "/v1/chat/completions",
            json!({"model":"local","messages":[{"role":"user","content":"hello"}]}),
            &[("x-gaugemesh-deadline-ms", "0")],
        )
        .await;
        assert_eq!(deadline.status(), StatusCode::BAD_REQUEST);
        assert!(
            body(deadline)
                .await
                .pointer("/error/message")
                .unwrap()
                .as_str()
                .unwrap()
                .contains("GM_MODEL_DEADLINE_EXHAUSTED")
        );
    }

    #[tokio::test]
    async fn tool_execution_is_off_by_default_and_lease_binds_the_capability() {
        let request_body = json!({"model":"local","messages":[{"role":"user","content":"tool:docs-a__search invariants"}]});
        let off = body(request("/v1/chat/completions", request_body.clone(), &[]).await).await;
        assert!(off.pointer("/gaugemesh/tool").unwrap().is_null());
        let lease = body(
            request(
                "/v1/chat/completions",
                request_body,
                &[
                    ("x-gaugemesh-tool-mode", "lease"),
                    ("x-gaugemesh-max-tool-rounds", "1"),
                ],
            )
            .await,
        )
        .await;
        assert_eq!(
            lease.pointer("/gaugemesh/tool/alias").unwrap(),
            "docs-a__search"
        );
        assert!(
            lease
                .pointer("/gaugemesh/tool/causalChild")
                .unwrap()
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[tokio::test]
    async fn openai_compatible_provider_adapter_forwards_to_a_real_http_fixture() {
        async fn fixture(headers: HeaderMap, Json(body): Json<Value>) -> Json<Value> {
            assert!(headers.get(header::AUTHORIZATION).is_none());
            assert_eq!(body["model"], "upstream-model");
            Json(
                json!({"choices":[{"message":{"content":"from upstream"}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}),
            )
        }
        async fn models_fixture() -> Json<Value> {
            Json(json!({"object":"list","data":[{"id":"upstream-model"}]}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(
            axum::serve(
                listener,
                Router::new()
                    .route("/v1/chat/completions", post(fixture))
                    .route("/v1/models", get(models_fixture)),
            )
            .into_future(),
        );
        let base_url = Url::parse(&format!("http://{address}/v1/")).unwrap();
        let inspected = inspect_openai_provider(base_url.clone(), "upstream-model".into(), None)
            .await
            .unwrap();
        assert!(inspected.to_string().starts_with("sha256:"));
        let provider =
            OpenAiCompatibleProvider::new(base_url.clone(), "upstream-model".into(), None)
                .await
                .unwrap();
        let output = provider
            .complete(
                &[Message {
                    role: Role::User,
                    content: "hello".into(),
                }],
                10,
            )
            .await
            .unwrap();
        assert_eq!(output.text, "from upstream");
        assert_eq!(output.input_tokens, 3);

        let configured = router_from_config(
            &[ModelConfig {
                id: "reviewed-local".into(),
                base_url,
                provider_model_id: "upstream-model".into(),
                context_limit: 8_192,
                max_output_tokens: 256,
                cost_table: gaugemesh_core::config::ModelCostConfig {
                    version: "test-v1".into(),
                    input_micros_per_million_tokens: 0,
                    output_micros_per_million_tokens: 0,
                },
                credential_env: None,
            }],
            Federation::demo(),
        )
        .await
        .unwrap();
        let response = configured
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer downstream-token")
                    .body(Body::from(
                        json!({"model":"reviewed-local","messages":[{"role":"user","content":"configured"}]})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            body(response)
                .await
                .pointer("/choices/0/message/content")
                .unwrap(),
            "from upstream"
        );
        server.abort();
    }
}
