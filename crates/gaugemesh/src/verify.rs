use std::{path::Path, process::Output, time::Duration};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const RESILIREPLAY_VERSION: &str = "0.7.0";
const TEST_TOOL: &str = "docs-a__search";
const TEST_FAULTS: &[Option<&str>] = &[
    None,
    Some("mcp-malformed-tools-list"),
    Some("mcp-renamed-tool"),
    Some("mcp-missing-tool"),
    Some("mcp-incompatible-argument-schema"),
    Some("mcp-tool-timeout"),
    Some("mcp-tool-error"),
    Some("mcp-oversized-content"),
    Some("mcp-protocol-version-mismatch"),
    Some("mcp-invalid-jsonrpc-id"),
    Some("mcp-malicious-canary-instruction"),
    Some("mcp-permission-capability-mismatch"),
    Some("mcp-canary-secret-leakage-attempt"),
];

pub async fn execute(resilireplay: bool) -> Result<()> {
    if !resilireplay {
        bail!("GM_VERIFY_SELECT_ENGINE:use --resilireplay");
    }
    let directory = tempfile::tempdir().context("GM_VERIFY_TEMP_DIRECTORY")?;
    let source = std::env::current_exe().context("GM_VERIFY_CURRENT_EXECUTABLE")?;
    let executable_name = source.file_name().context("GM_VERIFY_EXECUTABLE_NAME")?;
    let executable = directory.path().join(executable_name);
    std::fs::copy(&source, &executable).context("GM_VERIFY_COPY_EXECUTABLE")?;
    make_executable(&executable)?;
    let config = directory.path().join("mcp.json");
    std::fs::write(
        &config,
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "gaugemesh": {
                    "command": executable,
                    "args": ["mcp-stdio"]
                }
            }
        }))?,
    )
    .context("GM_VERIFY_CONFIG_WRITE")?;

    let mut scenarios = Vec::with_capacity(TEST_FAULTS.len());
    for fault in TEST_FAULTS {
        let name = fault.unwrap_or("clean-control");
        let mut common = vec![
            "mcp".into(),
            "test".into(),
            "--config".into(),
            "mcp.json".into(),
            "--server".into(),
            "gaugemesh".into(),
            "--tool".into(),
            TEST_TOOL.into(),
            "--safety".into(),
            "read-only".into(),
            "--retries".into(),
            "1".into(),
            "--timeout".into(),
            "3000".into(),
            "--output".into(),
            format!("evidence/{name}"),
            "--no-regression".into(),
        ];
        if let Some(fault) = fault {
            common.push("--fault".into());
            common.push((*fault).into());
        }
        let dry = run_resilireplay(
            directory.path(),
            &common,
            &["--dry-run".into(), "--json".into()],
        )
        .await?;
        let dry_json = successful_json(dry, &format!("GM_VERIFY_DRY_RUN:{name}"))?;
        let plan = digest_field(&dry_json, "planSha256", "GM_VERIFY_PLAN_DIGEST_MISSING")?;
        let executed = run_resilireplay(
            directory.path(),
            &common,
            &["--approve".into(), plan.into(), "--json".into()],
        )
        .await?;
        let result = bounded_json(executed, &format!("GM_VERIFY_EXECUTION:{name}"))?;
        let recovery_result = result
            .get("result")
            .and_then(Value::as_str)
            .context("GM_VERIFY_RESULT_MISSING")?;
        if result.get("cleanupComplete").and_then(Value::as_bool) != Some(true)
            || result.get("duplicateEffects").and_then(Value::as_u64) != Some(0)
            || (fault.is_some()
                && result.get("faultObserved").and_then(Value::as_bool) != Some(true))
        {
            bail!("GM_VERIFY_RESULT_FAILED:{name}");
        }
        if matches!(
            name,
            "clean-control" | "mcp-tool-timeout" | "mcp-tool-error"
        ) && recovery_result != "PASS"
        {
            bail!("GM_VERIFY_REQUIRED_RECOVERY_FAILED:{name}");
        }
        let evidence = digest_field(
            &result,
            "evidenceSha256",
            "GM_VERIFY_EVIDENCE_DIGEST_MISSING",
        )?;
        scenarios.push(json!({
            "scenario": name,
            "fault": fault,
            "planSha256": plan,
            "evidenceSha256": evidence,
            "recoveryResult": recovery_result,
            "cleanupComplete": true,
            "duplicateEffects": 0,
        }));
    }
    let evidence = gaugemesh_core::digest::Sha256Digest::of_json(&Value::Array(scenarios.clone()));
    let recovery_passes = scenarios
        .iter()
        .filter(|scenario| scenario.get("recoveryResult").and_then(Value::as_str) == Some("PASS"))
        .count();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "resiliReplayVersion": RESILIREPLAY_VERSION,
            "profile": "bounded-mcp-tool-recovery-matrix",
            "subject": format!("GaugeMesh {}", env!("CARGO_PKG_VERSION")),
            "transport": "stdio",
            "tool": TEST_TOOL,
            "scenarios": scenarios,
            "combinedEvidenceSha256": evidence.to_string(),
            "result": if recovery_passes == scenarios.len() { "PASS" } else { "PARTIAL" },
            "recoveryPasses": recovery_passes,
            "recoveryFailures": scenarios.len() - recovery_passes,
            "requiredRecoveryGate": "PASS",
            "cleanupComplete": true,
            "duplicateEffects": 0,
            "mcpRes": null,
            "certification": false
        }))?
    );
    Ok(())
}

fn digest_field<'a>(value: &'a Value, field: &str, missing: &str) -> Result<&'a str> {
    let digest = value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| missing.to_owned())?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("GM_VERIFY_DIGEST_INVALID:{field}");
    }
    Ok(digest)
}

async fn run_resilireplay(directory: &Path, common: &[String], tail: &[String]) -> Result<Output> {
    let npx = std::env::var_os("GAUGEMESH_NPX").unwrap_or_else(|| "npx".into());
    let mut command = tokio::process::Command::new(npx);
    command
        .arg("-y")
        .arg(format!("resilireplay@{RESILIREPLAY_VERSION}"))
        .args(common)
        .args(tail)
        .current_dir(directory)
        .kill_on_drop(true);
    // A clean runner may need to acquire the exact npm release before the
    // bounded campaign starts; keep that acquisition bounded without making
    // the verification depend on a warm npx cache.
    tokio::time::timeout(Duration::from_secs(180), command.output())
        .await
        .context("GM_VERIFY_PROCESS_TIMEOUT")?
        .context("GM_VERIFY_PROCESS_START")
}

fn successful_json(output: Output, phase: &str) -> Result<Value> {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let diagnostic = if stderr.trim().is_empty() {
            &stdout
        } else {
            &stderr
        };
        bail!("{phase}:{}", bounded(diagnostic, 1_024));
    }
    bounded_json(output, phase)
}

fn bounded_json(output: Output, phase: &str) -> Result<Value> {
    if output.stdout.len() > 64 * 1024 {
        bail!("{phase}:GM_VERIFY_OUTPUT_TOO_LARGE");
    }
    serde_json::from_slice(&output.stdout).with_context(|| format!("{phase}:GM_VERIFY_JSON"))
}

fn bounded(value: &str, limit: usize) -> &str {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_output_is_bounded_on_utf8_boundary() {
        let value = "é".repeat(1_000);
        assert!(bounded(&value, 1_023).len() <= 1_023);
        assert!(bounded(&value, 1_023).is_char_boundary(bounded(&value, 1_023).len()));
    }
}
