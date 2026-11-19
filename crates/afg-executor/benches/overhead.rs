//! Executor overhead benchmark (T12.1). Run with: cargo bench -p afg-executor
//! It compares spawning `/usr/bin/true` directly with spawning it through
//! LocalExecutor (cleared env, pinning, capture, process-group kill), and
//! measures snapshot building for container runs.

use std::time::{Duration, Instant};

use afg_core::paths::ProtectedPaths;
use afg_executor::snapshot::{SnapshotOptions, build_snapshot};
use afg_executor::{ExecutionRequest, Executor, LocalExecutor, PinnedFile};

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let tru = if std::path::Path::new("/usr/bin/true").exists() {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let n = 200;

    let mut direct = Vec::new();
    for _ in 0..n {
        let t = Instant::now();
        std::process::Command::new(tru).status().unwrap();
        direct.push(t.elapsed().as_secs_f64() * 1e6);
    }

    let pin = PinnedFile::pin(std::path::Path::new(tru)).unwrap();
    let mut via = Vec::new();
    for i in 0..n {
        let req = ExecutionRequest {
            id: format!("bench-{i}"),
            argv: vec![tru.into()],
            arg0: None,
            cwd: std::env::temp_dir(),
            workspace_root: std::env::temp_dir(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            timeout: Duration::from_secs(10),
            pinned: vec![pin.clone()],
            stream: false,
            capture_limit: 64 * 1024,
        };
        let t = Instant::now();
        LocalExecutor.execute(req).await.unwrap();
        via.push(t.elapsed().as_secs_f64() * 1e6);
    }
    let (d, v) = (median(direct), median(via));
    println!(
        "{:<48} {:>10.0} µs",
        "spawn /usr/bin/true directly (median)", d
    );
    println!("{:<48} {:>10.0} µs", "spawn via LocalExecutor (median)", v);
    println!("{:<48} {:>10.0} µs", "LocalExecutor overhead", v - d);

    // Snapshot of this repository's crates/ directory (the container backend's per-run cost).
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap();
    let opts = SnapshotOptions {
        protected: ProtectedPaths::new(None, &root, &[]),
        max_total_bytes: 1 << 30,
        max_files: 100_000,
    };
    let mut snaps = Vec::new();
    let mut files = 0;
    for _ in 0..5 {
        let t = Instant::now();
        let s = build_snapshot(&root, &opts).unwrap();
        files = s.manifest.entries.len();
        snaps.push(t.elapsed().as_secs_f64() * 1e3);
    }
    println!(
        "{:<48} {:>10.1} ms ({files} files)",
        "snapshot build of crates/ (median)",
        median(snaps)
    );
}
