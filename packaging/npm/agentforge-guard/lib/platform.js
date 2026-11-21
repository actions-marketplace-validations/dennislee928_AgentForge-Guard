'use strict';

// Release targets, keyed by Node's `${process.platform}-${process.arch}`.
// Each maps to the optional npm package that ships that target's `afg` binary.
const TARGETS = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'linux-arm64': 'aarch64-unknown-linux-gnu',
  'linux-x64': 'x86_64-unknown-linux-gnu',
  'win32-x64': 'x86_64-pc-windows-msvc',
};

/**
 * The platform package and binary path for this machine, or an Error explaining
 * why there is none. `glibc` is false on musl Linux (Alpine), where the
 * glibc-linked release binaries cannot run.
 */
function resolvePlatform(platform, arch, glibc = true) {
  const key = `${platform}-${arch}`;
  if (!TARGETS[key]) {
    return new Error(
      `agentforge-guard has no prebuilt binary for ${key}. ` +
        `Supported: ${Object.keys(TARGETS).join(', ')}. Install from source with: cargo install agentforge-guard`,
    );
  }
  if (platform === 'linux' && !glibc) {
    return new Error(
      'agentforge-guard ships glibc Linux binaries; this system uses musl. Install from source with: cargo install agentforge-guard',
    );
  }
  return {
    pkg: `agentforge-guard-${key}`,
    target: TARGETS[key],
    bin: platform === 'win32' ? 'bin/afg.exe' : 'bin/afg',
  };
}

module.exports = { TARGETS, resolvePlatform };
