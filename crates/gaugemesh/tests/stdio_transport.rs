use std::{fs, process::Command};

use rmcp::{
    ClientLifecycleMode, ClientServiceExt, ServiceExt,
    model::{ClientCapabilities, ClientInfo, Implementation, ProtocolVersion},
    transport::TokioChildProcess,
};

#[test]
fn route_explain_preserves_the_v0_bare_plan_shape_by_default() {
    let output = Command::new(env!("CARGO_BIN_EXE_gaugemesh"))
        .args(["route", "explain"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 6);
    assert_eq!(value["selected"], "local-a");
    assert!(value.get("action_score").is_some());
    assert!(value.get("explanation").is_some());
    assert!(value.get("snapshot_digest").is_some());
    assert!(value.get("route_policy_digest").is_some());
    assert!(value.get("metric_snapshot_digest").is_some());
    assert!(value.get("status").is_none());
    assert!(value.get("plan").is_none());
}

#[test]
fn route_explain_emits_an_explicit_no_eligible_decision() {
    let output = Command::new(env!("CARGO_BIN_EXE_gaugemesh"))
        .args(["route", "explain", "--deny-all"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "denied");
    assert_eq!(value["schema_version"], 1);
    assert!(
        value["decision_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(value["denial"]["code"], "GM_ROUTE_NO_ELIGIBLE_CANDIDATE");
    assert!(
        value["denial"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|candidate| candidate["allowed"] == false
                && candidate["terms"].is_null()
                && !candidate["rejections"].as_array().unwrap().is_empty())
    );
}

#[test]
fn route_explain_selected_contract_is_explicitly_opt_in() {
    let output = Command::new(env!("CARGO_BIN_EXE_gaugemesh"))
        .args(["route", "explain", "--decision-contract"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "selected");
    assert_eq!(value["schema_version"], 1);
    assert!(
        value["decision_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(value["plan"]["selected"], "local-a");
}

#[test]
fn route_decision_schema_is_checked_in_and_validation_is_offline() {
    let schema = Command::new(env!("CARGO_BIN_EXE_gaugemesh"))
        .args(["route", "schema"])
        .output()
        .unwrap();
    assert!(schema.status.success());
    let schema_value: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
    assert_eq!(
        schema_value["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );

    let decision = Command::new(env!("CARGO_BIN_EXE_gaugemesh"))
        .args(["route", "explain", "--deny-all"])
        .output()
        .unwrap();
    assert!(decision.status.success());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("decision.json");
    fs::write(&path, &decision.stdout).unwrap();
    let verified = Command::new(env!("CARGO_BIN_EXE_gaugemesh"))
        .arg("route")
        .arg("validate")
        .arg(&path)
        .output()
        .unwrap();
    assert!(verified.status.success());
    let value: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(value["evidence"], "VERIFIED");
    assert_eq!(value["integrity"], "unsigned-recomputable");
    assert_eq!(value["authentication"], "none");

    let mut tampered: serde_json::Value = serde_json::from_slice(&decision.stdout).unwrap();
    tampered["denial"]["candidates"][0]["rejections"][0] = "tampered".into();
    fs::write(&path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_gaugemesh"))
        .arg("route")
        .arg("validate")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("GM_ROUTE_DECISION_DIGEST_MISMATCH"));
}

fn client(version: ProtocolVersion) -> ClientInfo {
    ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new("gaugemesh-test", env!("CARGO_PKG_VERSION")),
    )
    .with_protocol_version(version)
}

fn transport() -> TokioChildProcess {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_gaugemesh"));
    command.arg("mcp-stdio").kill_on_drop(true);
    TokioChildProcess::new(command).expect("spawn MCP fixture")
}

#[tokio::test]
async fn stdio_supports_legacy_initialize_and_stateless_discover() {
    let legacy = client(ProtocolVersion::V_2025_11_25)
        .serve(transport())
        .await
        .unwrap();
    assert_eq!(
        legacy.peer_info().unwrap().protocol_version.as_str(),
        "2025-11-25"
    );
    assert_eq!(legacy.list_all_resources().await.unwrap().len(), 2);
    legacy.cancel().await.unwrap();

    let current = client(ProtocolVersion::V_2026_07_28)
        .serve_with_lifecycle(
            transport(),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        current.peer_info().unwrap().protocol_version.as_str(),
        "2026-07-28"
    );
    assert_eq!(current.list_all_tools().await.unwrap().len(), 7);
    current.cancel().await.unwrap();
}
