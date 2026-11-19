//! Building executor configurations from the policy.

use std::path::Path;

use afg_core::Policy;
use afg_core::normalize::resolve_in_path;
use afg_core::paths::ProtectedPaths;
use afg_executor::docker::DOCKER_CLI_ENV;
use afg_executor::snapshot::SnapshotOptions;
use afg_executor::{DockerConfig, DockerExecutor, NetworkPolicy, ResourceLimits};
use anyhow::Context;

/// Snapshot limits for container runs.
pub const SNAPSHOT_MAX_BYTES: u64 = 2 << 30;
pub const SNAPSHOT_MAX_FILES: usize = 200_000;

pub fn docker_executor(
    policy: &Policy,
    root: &Path,
    home: Option<&Path>,
) -> anyhow::Result<DockerExecutor> {
    let c = &policy.execution.backends.container;
    let path = std::env::var_os("PATH");
    let docker = resolve_in_path("docker", path.as_deref())
        .context("the docker CLI was not found on PATH")?;
    let docker_env = DOCKER_CLI_ENV
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    let cfg = DockerConfig {
        docker,
        docker_env,
        image: c.image.clone(),
        network: match c.network {
            afg_core::policy::Network::None => NetworkPolicy::None,
            afg_core::policy::Network::Bridge => NetworkPolicy::Bridge,
        },
        read_only_rootfs: c.read_only_rootfs,
        limits: ResourceLimits {
            memory_mb: c.memory_mb,
            cpus: c.cpus,
            pids: c.pids_limit,
        },
        user: DockerExecutor::default_user(),
        snapshot: SnapshotOptions {
            protected: ProtectedPaths::new(home, root, &policy.protected_paths),
            max_total_bytes: SNAPSHOT_MAX_BYTES,
            max_files: SNAPSHOT_MAX_FILES,
        },
    };
    Ok(DockerExecutor::new(cfg)?)
}
