//! Docker isolation tests (tests/sandbox-isolation/README.md).
//! Run with: cargo test -p afg-executor --test sandbox_isolation -- --ignored

use std::path::PathBuf;
use std::time::Duration;

use afg_core::normalize::resolve_in_path;
use afg_core::paths::ProtectedPaths;
use afg_executor::docker::DOCKER_CLI_ENV;
use afg_executor::snapshot::SnapshotOptions;
use afg_executor::{
    DockerConfig, DockerExecutor, ExecutionError, ExecutionRequest, ExecutionResult, Executor,
    NetworkPolicy, PinnedFile, ResourceLimits,
};

const IMAGE: &str = "debian:stable-slim";

struct Fixture {
    base: PathBuf,
    ws: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!("afg-iso-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("ws/scripts")).unwrap();
        std::fs::create_dir_all(base.join("home/.ssh")).unwrap();
        let base = base.canonicalize().unwrap();
        let (ws, home) = (base.join("ws"), base.join("home"));
        std::fs::write(ws.join(".env"), "AWS_SECRET_ACCESS_KEY=FAKEFAKEFAKEFAKE\n").unwrap();
        std::fs::write(ws.join("hello.txt"), "hello from the snapshot\n").unwrap();
        std::fs::write(
            home.join(".ssh/id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n",
        )
        .unwrap();
        Self { base, ws, home }
    }

    fn executor(&self, memory_mb: u64) -> DockerExecutor {
        let path = std::env::var_os("PATH");
        let docker = resolve_in_path("docker", path.as_deref()).expect("docker CLI on PATH");
        let docker_env = DOCKER_CLI_ENV
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
            .collect();
        DockerExecutor::new(DockerConfig {
            docker,
            docker_env,
            image: IMAGE.into(),
            network: NetworkPolicy::None,
            read_only_rootfs: true,
            limits: ResourceLimits {
                memory_mb,
                cpus: 1.0,
                pids: 128,
            },
            user: DockerExecutor::default_user(),
            snapshot: SnapshotOptions {
                protected: ProtectedPaths::new(Some(&self.home), &self.ws, &[]),
                max_total_bytes: 64 << 20,
                max_files: 10_000,
            },
        })
        .unwrap()
    }

    fn request(&self, id: &str, argv: &[&str]) -> ExecutionRequest {
        ExecutionRequest {
            id: format!("{id}-{}", std::process::id()),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            arg0: None,
            cwd: self.ws.clone(),
            workspace_root: self.ws.clone(),
            env: vec![],
            timeout: Duration::from_secs(60),
            pinned: vec![],
            stream: false,
            capture_limit: 1 << 16,
        }
    }

    async fn run(&self, id: &str, argv: &[&str]) -> ExecutionResult {
        self.executor(256)
            .execute(self.request(id, argv))
            .await
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn out(r: &ExecutionResult) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&r.stdout.bytes),
        String::from_utf8_lossy(&r.stderr.bytes)
    )
}

async fn docker_ps(name: &str) -> String {
    let o = tokio::process::Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("name={name}"),
            "--format",
            "{{.Names}}",
        ])
        .output()
        .await
        .unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn docker_is_available() {
    let f = Fixture::new("avail");
    let v = f
        .executor(256)
        .check_available()
        .await
        .expect("docker daemon");
    assert!(!v.is_empty());
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn workspace_snapshot_visible_but_secrets_are_not() {
    let f = Fixture::new("secrets");
    let r = f.run("ws", &["cat", "/workspace/hello.txt"]).await;
    assert!(r.success(), "{}", out(&r));
    assert_eq!(
        String::from_utf8_lossy(&r.stdout.bytes),
        "hello from the snapshot\n"
    );

    let r = f.run("env", &["cat", "/workspace/.env"]).await;
    assert!(
        !r.success(),
        "the .env file must not be in the snapshot: {}",
        out(&r)
    );

    let host_key = f.home.join(".ssh/id_ed25519").display().to_string();
    let r = f.run("key", &["cat", &host_key]).await;
    assert!(
        !r.success(),
        "the host home must not be mounted: {}",
        out(&r)
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn no_network() {
    let f = Fixture::new("net");
    // Some kernels list inert tunnel devices (gre0, sit0, ...) in
    // /sys/class/net, so the check is that there is no route at all.
    let r = f.run("routes", &["cat", "/proc/net/route"]).await;
    assert!(r.success(), "{}", out(&r));
    let routes = String::from_utf8_lossy(&r.stdout.bytes)
        .lines()
        .skip(1)
        .count();
    assert_eq!(routes, 0, "no IPv4 routes expected: {}", out(&r));
    let r = f
        .run(
            "routes6",
            &["sh", "-c", "grep -v ' lo$' /proc/net/ipv6_route || true"],
        )
        .await;
    assert_eq!(
        String::from_utf8_lossy(&r.stdout.bytes).trim(),
        "",
        "no non-loopback IPv6 routes"
    );
    let r = f
        .run("tcp", &["bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/80"])
        .await;
    assert!(!r.success(), "egress must fail: {}", out(&r));
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn root_filesystem_is_read_only_and_tmp_is_writable() {
    let f = Fixture::new("rofs");
    let r = f.run("etc", &["touch", "/etc/afg-test"]).await;
    assert!(!r.success());
    assert!(out(&r).to_lowercase().contains("read-only"), "{}", out(&r));
    let r = f.run("tmp", &["touch", "/tmp/ok"]).await;
    assert!(r.success(), "{}", out(&r));
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn writes_to_workspace_do_not_reach_the_host() {
    let f = Fixture::new("copy");
    let r = f
        .run(
            "write",
            &[
                "sh",
                "-c",
                "echo pwned > /workspace/hello.txt && touch /workspace/new",
            ],
        )
        .await;
    assert!(r.success(), "{}", out(&r));
    assert_eq!(
        std::fs::read_to_string(f.ws.join("hello.txt")).unwrap(),
        "hello from the snapshot\n"
    );
    assert!(!f.ws.join("new").exists());
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn unprivileged_user_without_capabilities() {
    let f = Fixture::new("caps");
    let r = f.run("id", &["id", "-u"]).await;
    assert!(r.success(), "{}", out(&r));
    assert_ne!(String::from_utf8_lossy(&r.stdout.bytes).trim(), "0");
    let r = f
        .run("capeff", &["grep", "CapEff", "/proc/self/status"])
        .await;
    assert!(out(&r).contains("0000000000000000"), "{}", out(&r));
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn docker_socket_is_absent() {
    let f = Fixture::new("sock");
    for p in ["/var/run/docker.sock", "/run/docker.sock"] {
        let r = f.run("sock", &["test", "-e", p]).await;
        assert_eq!(r.exit_code, Some(1), "{p} must not exist: {}", out(&r));
    }
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn memory_limit_kills() {
    let f = Fixture::new("oom");
    // Build a string far larger than the 64 MB limit.
    let script = "x=$(head -c 300000000 /dev/zero | tr '\\0' a); echo ${#x}";
    let r = f
        .executor(64)
        .execute(f.request("oom", &["bash", "-c", script]))
        .await
        .unwrap();
    assert!(!r.success(), "{}", out(&r));
    assert!(!String::from_utf8_lossy(&r.stdout.bytes).contains("300000000"));
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn timeout_kills_and_removes_container() {
    let f = Fixture::new("timeout");
    let mut req = f.request("sleep", &["sleep", "120"]);
    req.timeout = Duration::from_secs(3);
    let name = DockerExecutor::container_name(&req.id);
    let start = std::time::Instant::now();
    let r = f.executor(256).execute(req).await.unwrap();
    assert!(r.timed_out);
    assert!(start.elapsed() < Duration::from_secs(40));
    assert_eq!(docker_ps(&name).await, "", "container must be removed");
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn swapped_script_is_rejected_before_the_container_starts() {
    let f = Fixture::new("toctou");
    let script = f.ws.join("scripts/check.sh");
    std::fs::write(&script, "echo safe\n").unwrap();
    let pin = PinnedFile::pin(&script).unwrap();
    std::fs::write(&script, "echo swapped\n").unwrap();
    let mut req = f.request("toctou", &["sh", "scripts/check.sh"]);
    req.pinned = vec![pin];
    let e = f.executor(256).execute(req).await.unwrap_err();
    assert!(matches!(e, ExecutionError::Integrity(_)), "{e}");
}
