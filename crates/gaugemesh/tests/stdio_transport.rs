use rmcp::{
    ClientLifecycleMode, ClientServiceExt, ServiceExt,
    model::{ClientCapabilities, ClientInfo, Implementation, ProtocolVersion},
    transport::TokioChildProcess,
};

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
