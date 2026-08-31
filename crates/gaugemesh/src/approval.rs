use std::{io::IsTerminal, time::Duration};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use gaugemesh_core::{config::ApprovalConfig, security::ResolvedOrigin};
use hmac::{Hmac, Mac};
use rmcp::{
    ErrorData as McpError,
    model::{ElicitRequestParams, ElicitResult, ElicitationAction},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    sync::Mutex,
};
use url::Url;
use uuid::Uuid;

const MAX_FORM_BYTES: usize = 16 * 1024;
const MAX_WEBHOOK_BYTES: usize = 64 * 1024;
const LOCAL_CLI_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum WebhookAction {
    Accept,
    Decline,
    Cancel,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookResponse {
    action: WebhookAction,
    #[serde(default)]
    content: Option<Value>,
}

pub(crate) async fn handle(
    approval: &ApprovalConfig,
    request: &ElicitRequestParams,
    cli_lock: &Mutex<()>,
) -> Result<ElicitResult, McpError> {
    let result = match approval {
        ApprovalConfig::Deny => return Ok(decision(ElicitationAction::Decline, None)),
        ApprovalConfig::StaticPolicy { response } => static_policy(request, response),
        ApprovalConfig::LocalCli => local_cli(request, cli_lock).await,
        ApprovalConfig::SignedWebhook {
            url,
            secret_env,
            timeout_ms,
        } => signed_webhook(request, url, secret_env, *timeout_ms).await,
    };
    result.map_err(|error| McpError::invalid_request(error.to_string(), None))
}

fn static_policy(request: &ElicitRequestParams, response: &Value) -> Result<ElicitResult> {
    validate_form_response(request, response)?;
    Ok(decision(ElicitationAction::Accept, Some(response.clone())))
}

async fn local_cli(request: &ElicitRequestParams, cli_lock: &Mutex<()>) -> Result<ElicitResult> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Ok(decision(ElicitationAction::Decline, None));
    }
    let _guard = cli_lock.lock().await;
    let request_json = serde_json::to_string(request).context("GM_APPROVAL_REQUEST_ENCODING")?;
    eprintln!("GaugeMesh approval requested: {request_json}");
    eprintln!("Enter one JSON object to accept, `decline`, or `cancel`:");

    let mut line = String::new();
    let limited = tokio::io::stdin().take((MAX_FORM_BYTES + 1) as u64);
    let read = tokio::time::timeout(
        LOCAL_CLI_TIMEOUT,
        BufReader::new(limited).read_line(&mut line),
    )
    .await
    .context("GM_APPROVAL_LOCAL_TIMEOUT")?
    .context("GM_APPROVAL_LOCAL_READ")?;
    if read == 0 || read > MAX_FORM_BYTES {
        bail!("GM_APPROVAL_LOCAL_SIZE");
    }
    match line.trim() {
        "decline" => Ok(decision(ElicitationAction::Decline, None)),
        "cancel" => Ok(decision(ElicitationAction::Cancel, None)),
        value => {
            let content: Value = serde_json::from_str(value).context("GM_APPROVAL_LOCAL_JSON")?;
            validate_form_response(request, &content)?;
            Ok(decision(ElicitationAction::Accept, Some(content)))
        }
    }
}

async fn signed_webhook(
    request: &ElicitRequestParams,
    url: &Url,
    secret_env: &str,
    timeout_ms: u64,
) -> Result<ElicitResult> {
    let secret = std::env::var(secret_env).context("GM_APPROVAL_WEBHOOK_SECRET_MISSING")?;
    if secret.len() < 32 || secret.len() > 4_096 {
        bail!("GM_APPROVAL_WEBHOOK_SECRET_INVALID");
    }
    let nonce = Uuid::new_v4().to_string();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("GM_APPROVAL_WEBHOOK_CLOCK")?
        .as_secs();
    let body = serde_json::to_vec(&json!({
        "nonce": nonce,
        "request": request,
        "timestamp": timestamp,
    }))
    .context("GM_APPROVAL_REQUEST_ENCODING")?;
    if body.len() > MAX_WEBHOOK_BYTES {
        bail!("GM_APPROVAL_WEBHOOK_REQUEST_SIZE");
    }

    let origin = ResolvedOrigin::resolve(url, false)
        .await
        .context("GM_APPROVAL_WEBHOOK_ORIGIN")?;
    let addresses = origin
        .addresses
        .iter()
        .map(|address| std::net::SocketAddr::new(*address, origin.port))
        .collect::<Vec<_>>();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .resolve_to_addrs(&origin.host, &addresses)
        .build()
        .context("GM_APPROVAL_WEBHOOK_CLIENT")?;
    let timeout = Duration::from_millis(timeout_ms);
    let response = tokio::time::timeout(
        timeout,
        client
            .post(url.clone())
            .header("content-type", "application/json")
            .header("x-gaugemesh-nonce", &nonce)
            .header("x-gaugemesh-timestamp", timestamp.to_string())
            .header("x-gaugemesh-signature", sign(&secret, &body)?)
            .body(body)
            .send(),
    )
    .await
    .context("GM_APPROVAL_WEBHOOK_TIMEOUT")?
    .context("GM_APPROVAL_WEBHOOK_SEND")?;
    if !response.status().is_success() {
        bail!("GM_APPROVAL_WEBHOOK_STATUS");
    }
    let response_nonce = response
        .headers()
        .get("x-gaugemesh-nonce")
        .and_then(|value| value.to_str().ok())
        .context("GM_APPROVAL_WEBHOOK_NONCE_MISSING")?
        .to_owned();
    let signature = response
        .headers()
        .get("x-gaugemesh-signature")
        .and_then(|value| value.to_str().ok())
        .context("GM_APPROVAL_WEBHOOK_SIGNATURE_MISSING")?
        .to_owned();
    if response_nonce != nonce {
        bail!("GM_APPROVAL_WEBHOOK_NONCE_MISMATCH");
    }
    let response_body = bounded_body(response, timeout).await?;
    verify(&secret, &response_body, &signature)?;
    let response: WebhookResponse =
        serde_json::from_slice(&response_body).context("GM_APPROVAL_WEBHOOK_JSON")?;
    match response.action {
        WebhookAction::Accept => {
            let content = response
                .content
                .context("GM_APPROVAL_WEBHOOK_CONTENT_MISSING")?;
            validate_form_response(request, &content)?;
            Ok(decision(ElicitationAction::Accept, Some(content)))
        }
        WebhookAction::Decline if response.content.is_none() => {
            Ok(decision(ElicitationAction::Decline, None))
        }
        WebhookAction::Cancel if response.content.is_none() => {
            Ok(decision(ElicitationAction::Cancel, None))
        }
        WebhookAction::Decline | WebhookAction::Cancel => {
            bail!("GM_APPROVAL_WEBHOOK_UNEXPECTED_CONTENT")
        }
    }
}

async fn bounded_body(response: reqwest::Response, timeout: Duration) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    tokio::time::timeout(timeout, async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("GM_APPROVAL_WEBHOOK_BODY")?;
            if body.len().saturating_add(chunk.len()) > MAX_WEBHOOK_BYTES {
                bail!("GM_APPROVAL_WEBHOOK_RESPONSE_SIZE");
            }
            body.extend_from_slice(&chunk);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("GM_APPROVAL_WEBHOOK_BODY_TIMEOUT")??;
    Ok(body)
}

fn decision(action: ElicitationAction, content: Option<Value>) -> ElicitResult {
    let result = ElicitResult::new(action);
    match content {
        Some(content) => result.with_content(content),
        None => result,
    }
}

fn sign(secret: &str, body: &[u8]) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .context("GM_APPROVAL_WEBHOOK_SECRET_INVALID")?;
    mac.update(body);
    Ok(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

fn verify(secret: &str, body: &[u8], supplied: &str) -> Result<()> {
    let supplied = supplied
        .strip_prefix("sha256=")
        .context("GM_APPROVAL_WEBHOOK_SIGNATURE_INVALID")?;
    let supplied = hex::decode(supplied).context("GM_APPROVAL_WEBHOOK_SIGNATURE_INVALID")?;
    let expected = sign(secret, body)?;
    let expected = hex::decode(
        expected
            .strip_prefix("sha256=")
            .expect("sign always prefixes the digest"),
    )?;
    if supplied.len() != expected.len() || supplied.ct_eq(&expected).unwrap_u8() != 1 {
        bail!("GM_APPROVAL_WEBHOOK_SIGNATURE_INVALID");
    }
    Ok(())
}

fn validate_form_response(request: &ElicitRequestParams, response: &Value) -> Result<()> {
    let encoded = serde_json::to_vec(response).context("GM_APPROVAL_RESPONSE_ENCODING")?;
    if encoded.len() > MAX_FORM_BYTES {
        bail!("GM_APPROVAL_RESPONSE_SIZE");
    }
    let request = serde_json::to_value(request).context("GM_APPROVAL_REQUEST_ENCODING")?;
    if request.get("mode").and_then(Value::as_str) != Some("form") {
        bail!("GM_APPROVAL_URL_ELICITATION_DENIED");
    }
    let schema = request
        .get("requestedSchema")
        .and_then(Value::as_object)
        .context("GM_APPROVAL_SCHEMA_INVALID")?;
    let content = response
        .as_object()
        .context("GM_APPROVAL_RESPONSE_NOT_OBJECT")?;
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .context("GM_APPROVAL_SCHEMA_INVALID")?;

    if content.keys().any(|key| !properties.contains_key(key)) {
        bail!("GM_APPROVAL_RESPONSE_UNKNOWN_PROPERTY");
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        if required
            .iter()
            .filter_map(Value::as_str)
            .any(|key| !content.contains_key(key))
        {
            bail!("GM_APPROVAL_RESPONSE_REQUIRED_PROPERTY");
        }
    }
    for (name, value) in content {
        validate_property(
            properties
                .get(name)
                .and_then(Value::as_object)
                .context("GM_APPROVAL_SCHEMA_INVALID")?,
            value,
        )?;
    }
    Ok(())
}

fn validate_property(schema: &serde_json::Map<String, Value>, value: &Value) -> Result<()> {
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => validate_string(schema, value),
        Some("number") => validate_number(schema, value, false),
        Some("integer") => validate_number(schema, value, true),
        Some("boolean") if value.is_boolean() => Ok(()),
        Some("array") => validate_string_array(schema, value),
        _ => bail!("GM_APPROVAL_RESPONSE_TYPE"),
    }
}

fn validate_string(schema: &serde_json::Map<String, Value>, value: &Value) -> Result<()> {
    let value = value.as_str().context("GM_APPROVAL_RESPONSE_TYPE")?;
    let length = value.chars().count() as u64;
    if schema
        .get("minLength")
        .and_then(Value::as_u64)
        .is_some_and(|minimum| length < minimum)
        || schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
    {
        bail!("GM_APPROVAL_RESPONSE_STRING_LENGTH");
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed
            .iter()
            .any(|candidate| candidate.as_str() == Some(value))
        {
            bail!("GM_APPROVAL_RESPONSE_ENUM");
        }
    }
    if let Some(allowed) = schema.get("oneOf").and_then(Value::as_array) {
        if !allowed
            .iter()
            .any(|candidate| candidate.get("const").and_then(Value::as_str) == Some(value))
        {
            bail!("GM_APPROVAL_RESPONSE_ENUM");
        }
    }
    match schema.get("format").and_then(Value::as_str) {
        Some("email") if !valid_email(value) => bail!("GM_APPROVAL_RESPONSE_FORMAT"),
        Some("uri") if Url::parse(value).is_err() => bail!("GM_APPROVAL_RESPONSE_FORMAT"),
        Some("date") if !valid_date(value) => bail!("GM_APPROVAL_RESPONSE_FORMAT"),
        Some("date-time") if !valid_date_time(value) => bail!("GM_APPROVAL_RESPONSE_FORMAT"),
        _ => Ok(()),
    }
}

fn validate_number(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    integer: bool,
) -> Result<()> {
    let number = value.as_f64().context("GM_APPROVAL_RESPONSE_TYPE")?;
    if !number.is_finite() || (integer && value.as_i64().is_none() && value.as_u64().is_none()) {
        bail!("GM_APPROVAL_RESPONSE_TYPE");
    }
    if schema
        .get("minimum")
        .and_then(Value::as_f64)
        .is_some_and(|minimum| number < minimum)
        || schema
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|maximum| number > maximum)
    {
        bail!("GM_APPROVAL_RESPONSE_RANGE");
    }
    Ok(())
}

fn validate_string_array(schema: &serde_json::Map<String, Value>, value: &Value) -> Result<()> {
    let values = value.as_array().context("GM_APPROVAL_RESPONSE_TYPE")?;
    let length = values.len() as u64;
    if schema
        .get("minItems")
        .and_then(Value::as_u64)
        .is_some_and(|minimum| length < minimum)
        || schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
    {
        bail!("GM_APPROVAL_RESPONSE_ARRAY_LENGTH");
    }
    let items = schema
        .get("items")
        .and_then(Value::as_object)
        .context("GM_APPROVAL_SCHEMA_INVALID")?;
    let allowed = items
        .get("enum")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .or_else(|| {
            items
                .get("anyOf")
                .or_else(|| items.get("oneOf"))
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.get("const").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                })
        })
        .context("GM_APPROVAL_SCHEMA_INVALID")?;
    if values
        .iter()
        .any(|value| value.as_str().is_none_or(|value| !allowed.contains(&value)))
    {
        bail!("GM_APPROVAL_RESPONSE_ENUM");
    }
    Ok(())
}

fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
        && value[5..7]
            .parse::<u8>()
            .is_ok_and(|month| (1..=12).contains(&month))
        && value[8..10]
            .parse::<u8>()
            .is_ok_and(|day| (1..=31).contains(&day))
}

fn valid_date_time(value: &str) -> bool {
    value
        .split_once('T')
        .is_some_and(|(date, time)| valid_date(date) && (time.ends_with('Z') || time.contains('+')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::{
        ElicitRequestParams, ElicitationSchema, PrimitiveSchemaDefinition, StringSchema,
    };

    fn form() -> ElicitRequestParams {
        ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: "Approve a bounded request".into(),
            requested_schema: ElicitationSchema::builder()
                .required_property(
                    "name",
                    PrimitiveSchemaDefinition::String(StringSchema::new().min_length(2)),
                )
                .build()
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn deny_is_the_headless_default() {
        let result = handle(&ApprovalConfig::Deny, &form(), &Mutex::new(()))
            .await
            .unwrap();
        assert_eq!(result.action, ElicitationAction::Decline);
        assert!(result.content.is_none());
    }

    #[test]
    fn static_policy_accepts_only_schema_matching_objects() {
        let accepted = static_policy(&form(), &json!({"name": "Ada"})).unwrap();
        assert_eq!(accepted.action, ElicitationAction::Accept);
        assert!(static_policy(&form(), &json!({"name": "A"})).is_err());
        assert!(static_policy(&form(), &json!({"name": "Ada", "extra": true})).is_err());
    }

    #[test]
    fn webhook_signatures_are_constant_time_verified() {
        let body = br#"{"action":"decline"}"#;
        let signature = sign("a sufficiently long test secret value", body).unwrap();
        verify("a sufficiently long test secret value", body, &signature).unwrap();
        assert!(
            verify(
                "a sufficiently long test secret value",
                b"tampered",
                &signature
            )
            .is_err()
        );
    }
}
