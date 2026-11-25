//! Evaluation-only HTTP transport. All policy decisions come from afg-core.

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use afg_core::{BackendKind, Decision, Engine, EvalRequest, Policy};
use anyhow::{Context, ensure};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, clap::Args)]
pub struct GatewayArgs {
    /// Address behind a TLS proxy when used remotely. Defaults to loopback.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
    /// Hash of the policy reviewed by the operator (sha256:...).
    #[arg(long)]
    policy_hash: String,
}

#[derive(Clone)]
struct Gateway {
    cwd: PathBuf,
    root: PathBuf,
    policy_path: PathBuf,
    home: Option<PathBuf>,
    path: Option<OsString>,
    policy_hash: String,
    key: String,
    slots: Arc<tokio::sync::Semaphore>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvaluateInput {
    argv: Vec<String>,
    requested_backend: Option<BackendKind>,
}

impl EvaluateInput {
    fn valid(&self) -> bool {
        !self.argv.is_empty()
            && self.argv.len() <= 256
            && self
                .argv
                .iter()
                .all(|a| a.len() <= 4096 && !a.contains('\0'))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Evaluation {
    schema_version: u8,
    effect: afg_core::Effect,
    backend: Option<BackendKind>,
    rule_id: String,
    reasons: Vec<String>,
    policy_version: &'static str,
    policy_hash: String,
}

impl From<Decision> for Evaluation {
    fn from(d: Decision) -> Self {
        Self {
            schema_version: 1,
            effect: d.effect,
            backend: d.backend,
            rule_id: d.rule_id,
            reasons: d.reasons,
            policy_version: d.policy_version,
            policy_hash: d.policy_hash,
        }
    }
}

fn valid_key(key: &str) -> bool {
    (32..=256).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn key_matches(expected: &str, supplied: &str) -> bool {
    // Compare fixed-length authentication tags in constant time via Mac::verify_slice.
    let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(expected.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(b"afg-gateway-key-v1");
    let tag = mac.finalize().into_bytes();
    let mut candidate = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(supplied.as_bytes())
        .expect("HMAC accepts any key length");
    candidate.update(b"afg-gateway-key-v1");
    candidate.verify_slice(&tag).is_ok()
}

impl Gateway {
    fn engine(&self) -> anyhow::Result<Engine> {
        let src = std::fs::read_to_string(&self.policy_path)?;
        let policy = Policy::from_yaml(&src)?;
        ensure!(
            !afg_core::validate::has_errors(&afg_core::validate::validate(&policy)),
            "invalid policy"
        );
        let engine = Engine::new(policy, &self.root, self.home.as_deref());
        ensure!(
            engine.policy_hash() == self.policy_hash,
            "policy hash changed"
        );
        ensure!(
            !matches!(
                crate::trust::status(
                    self.home.as_deref(),
                    &self.policy_path,
                    engine.policy_hash()
                ),
                crate::trust::Status::Changed { .. }
            ),
            "policy trust changed"
        );
        Ok(engine)
    }
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, Json(serde_json::json!({"error": code}))).into_response()
}

async fn authenticate(State(state): State<Gateway>, request: Request, next: Next) -> Response {
    let values: Vec<_> = request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .collect();
    let supplied = (values.len() == 1)
        .then(|| values[0].to_str().ok())
        .flatten()
        .and_then(|s| s.strip_prefix("Bearer "));
    if !supplied.is_some_and(|key| key_matches(&state.key, key)) {
        return error(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let Ok(_slot) = state.slots.clone().try_acquire_owned() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "busy");
    };
    let mut response = match tokio::time::timeout(Duration::from_secs(10), next.run(request)).await
    {
        Ok(r) => r,
        Err(_) => error(StatusCode::REQUEST_TIMEOUT, "request_timeout"),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

async fn health(State(state): State<Gateway>) -> Response {
    match tokio::task::spawn_blocking(move || state.engine()).await {
        Ok(Ok(_)) => Json(serde_json::json!({"schemaVersion":1,"status":"ok"})).into_response(),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"),
    }
}

async fn evaluate(State(state): State<Gateway>, Json(input): Json<EvaluateInput>) -> Response {
    if !input.valid() {
        return error(StatusCode::BAD_REQUEST, "invalid_argv");
    }
    let result = tokio::task::spawn_blocking(move || {
        let engine = state.engine()?;
        Ok::<_, anyhow::Error>(Evaluation::from(engine.evaluate(&EvalRequest {
            argv: &input.argv,
            cwd: &state.cwd,
            path_env: state.path.as_deref(),
            requested_backend: input.requested_backend,
        })))
    })
    .await;
    match result {
        Ok(Ok(result)) => Json(result).into_response(),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable"),
    }
}

fn router(state: Gateway) -> Router {
    Router::new()
        .route("/v1/evaluate", post(evaluate))
        .route("/v1/health", get(health))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state)
}

pub async fn run(args: GatewayArgs) -> anyhow::Result<ExitCode> {
    let key = std::env::var("AFG_GATEWAY_API_KEY").context("AFG_GATEWAY_API_KEY is required")?;
    ensure!(
        valid_key(&key),
        "API key must be 32–256 ASCII letters, digits, '-' or '_'"
    );
    let cwd = std::env::current_dir()?.canonicalize()?;
    let project = crate::project::load(&cwd)?;
    let state = Gateway {
        cwd,
        root: project.root,
        policy_path: project.policy_path,
        home: crate::project::home_dir(),
        path: std::env::var_os("PATH"),
        policy_hash: args.policy_hash,
        key,
        slots: Arc::new(tokio::sync::Semaphore::new(32)),
    };
    state
        .engine()
        .context("gateway requires the reviewed policy hash and valid trust pin")?;
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!(
        "afg: evaluation gateway listening on {}",
        listener.local_addr()?
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt;

    const KEY: &str = "FAKE-gateway-key-for-unit-tests-00000000";

    fn fixture() -> (tempfile::TempDir, Gateway) {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("repo");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_ed25519"), "FAKE").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(home.join(".ssh/id_ed25519"), cwd.join("innocent.txt")).unwrap();
        let policy_path = cwd.join("agentforge.yaml");
        let src = afg_core::builtin::policy_source("default").unwrap();
        std::fs::write(&policy_path, src).unwrap();
        let policy = Policy::from_yaml(src).unwrap();
        let state = Gateway {
            root: cwd.clone(),
            cwd,
            policy_path,
            home: Some(home),
            path: None,
            policy_hash: afg_core::eval::policy_hash(&policy),
            key: KEY.into(),
            slots: Arc::new(tokio::sync::Semaphore::new(32)),
        };
        (temp, state)
    }

    async fn request(
        state: &Gateway,
        method: &str,
        uri: &str,
        body: String,
        key: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(key) = key {
            request = request.header(header::AUTHORIZATION, format!("Bearer {key}"));
        }
        let response = router(state.clone())
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn gateway_http_fails_closed_and_never_executes() {
        let (_temp, state) = fixture();
        for key in [None, Some("wrong")] {
            let (status, body) = request(&state, "GET", "/v1/health", String::new(), key).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(body.get("effect").is_none());
        }
        let (status, body) = request(&state, "GET", "/v1/health", String::new(), Some(KEY)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        for (argv, effect) in [
            (vec!["git", "status"], "allow"),
            (vec!["terraform", "destroy"], "deny"),
            (
                vec!["kubectl", "apply", "-f", "deployment.yaml"],
                "require-approval",
            ),
            (vec!["sh", "-c", "touch MUST_NOT_EXIST"], "route"),
            (vec!["cat", ".env"], "deny"),
            (vec!["unknown-program"], "deny"),
        ] {
            let (status, body) = request(
                &state,
                "POST",
                "/v1/evaluate",
                serde_json::json!({"argv":argv}).to_string(),
                Some(KEY),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["effect"], effect);
            assert_eq!(body["schemaVersion"], 1);
            assert_eq!(body["policyHash"], state.policy_hash);
            assert!(body.get("normalized").is_none());
        }
        assert!(!state.cwd.join("MUST_NOT_EXIST").exists());
        assert!(!state.cwd.join(".agentforge").exists());
        for body in [
            "{".into(),
            r#"{"argv":[],"cwd":"/"}"#.into(),
            serde_json::json!({"argv":["x".repeat(70000)]}).to_string(),
        ] {
            let (status, json) = request(&state, "POST", "/v1/evaluate", body, Some(KEY)).await;
            assert!(status.is_client_error());
            assert!(json.get("effect").is_none());
        }
        let (status, _) = request(&state, "POST", "/v1/execute", "{}".into(), Some(KEY)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = request(&state, "GET", "/v1/evaluate", "{}".into(), Some(KEY)).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        std::fs::write(&state.policy_path, "invalid").unwrap();
        for uri in ["/v1/evaluate", "/v1/health"] {
            let method = if uri.ends_with("health") {
                "GET"
            } else {
                "POST"
            };
            let (status, body) = request(
                &state,
                method,
                uri,
                r#"{"argv":["git","status"]}"#.into(),
                Some(KEY),
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(body.get("effect").is_none());
        }
    }

    #[tokio::test]
    async fn gateway_policy_and_trust_changes_are_refused() {
        let (_temp, mut state) = fixture();
        std::fs::write(
            &state.policy_path,
            afg_core::builtin::policy_source("strict").unwrap(),
        )
        .unwrap();
        assert!(state.engine().is_err());
        let policy =
            Policy::from_yaml(&std::fs::read_to_string(&state.policy_path).unwrap()).unwrap();
        state.policy_hash = afg_core::eval::policy_hash(&policy);
        assert!(state.engine().is_ok());
        crate::trust::pin(
            state.home.as_deref().unwrap(),
            &state.policy_path,
            "sha256:other",
        )
        .unwrap();
        assert!(state.engine().is_err());
        std::fs::remove_file(&state.policy_path).unwrap();
        assert!(state.engine().is_err());
    }

    #[tokio::test]
    async fn gateway_http_conforms_to_every_shared_fixture() {
        let (_temp, mut state) = fixture();
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut count = 0;
        for dir in ["tests/policy-fixtures", "tests/adversarial"] {
            for entry in std::fs::read_dir(repo.join(dir)).unwrap() {
                let file = entry.unwrap().path();
                if file.extension().is_none_or(|x| x != "yaml") {
                    continue;
                }
                let fx = afg_core::conformance::FixtureFile::from_yaml(
                    &std::fs::read_to_string(file).unwrap(),
                )
                .unwrap();
                let src = fx.policy_source().unwrap();
                std::fs::write(&state.policy_path, &src).unwrap();
                state.policy_hash = afg_core::eval::policy_hash(&Policy::from_yaml(&src).unwrap());
                for case in fx.cases {
                    let argv: Vec<_> = case
                        .argv
                        .iter()
                        .map(|a| {
                            a.replace("$HOME", &state.home.as_ref().unwrap().display().to_string())
                        })
                        .collect();
                    let engine = state.engine().unwrap();
                    let expected = Evaluation::from(engine.evaluate(&EvalRequest {
                        argv: &argv,
                        cwd: &state.cwd,
                        path_env: None,
                        requested_backend: case.requested,
                    }));
                    case.check(expected.effect, expected.backend, &expected.rule_id)
                        .unwrap();
                    let (status, body) = request(
                        &state,
                        "POST",
                        "/v1/evaluate",
                        serde_json::json!({"argv":argv,"requestedBackend":case.requested})
                            .to_string(),
                        Some(KEY),
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK);
                    assert_eq!(body, serde_json::to_value(expected).unwrap());
                    count += 1;
                }
            }
        }
        assert!(
            count >= 140,
            "fixture coverage unexpectedly shrank: {count}"
        );
    }

    #[test]
    fn gateway_rejects_invalid_input_and_overrides() {
        for src in [
            r#"{"argv":[]}"#,
            r#"{"argv":["git"],"cwd":"/"}"#,
            r#"{"argv":["git"],"policy":{}}"#,
            r#"{"argv":"git status"}"#,
            r#"{"argv":["git"],"requestedBackend":"unknown"}"#,
            r#"{"argv":["git","\u0000"]}"#,
        ] {
            let valid = serde_json::from_str::<EvaluateInput>(src).is_ok_and(|input| input.valid());
            assert!(!valid, "must reject {src}");
        }
        let valid: EvaluateInput = serde_json::from_str(r#"{"argv":["git","status"]}"#).unwrap();
        assert!(valid.valid());
    }

    #[test]
    fn gateway_authentication_rejects_missing_wrong_and_short_keys() {
        assert!(!valid_key(""));
        assert!(!valid_key("short"));
        assert!(!valid_key(&" ".repeat(32)));
        let key = "FAKE-gateway-key-for-unit-tests-00000000";
        assert!(valid_key(key));
        assert!(key_matches(key, key));
        assert!(!key_matches(
            key,
            "FAKE-gateway-key-for-unit-tests-00000001"
        ));
        assert!(!key_matches(key, ""));
    }
}
