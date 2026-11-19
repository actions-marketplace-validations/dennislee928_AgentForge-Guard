# Homebrew formula template for a tap (for example agentforge-guard/homebrew-tap).
# The release workflow publishes the tarballs and SHA256SUMS; replace VERSION
# and each sha256 from that file when you update the tap.
class Afg < Formula
  desc "Policy-driven execution guard for AI coding agents"
  homepage "https://github.com/agentforge-guard/agentforge-guard"
  version "VERSION"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/agentforge-guard/agentforge-guard/releases/download/v#{version}/afg-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "SHA256_AARCH64_APPLE_DARWIN"
    end
    on_intel do
      url "https://github.com/agentforge-guard/agentforge-guard/releases/download/v#{version}/afg-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "SHA256_X86_64_APPLE_DARWIN"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/agentforge-guard/agentforge-guard/releases/download/v#{version}/afg-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "SHA256_AARCH64_UNKNOWN_LINUX_GNU"
    end
    on_intel do
      url "https://github.com/agentforge-guard/agentforge-guard/releases/download/v#{version}/afg-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "SHA256_X86_64_UNKNOWN_LINUX_GNU"
    end
  end

  def install
    bin.install "afg"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/afg --version")
    (testpath/"agentforge.yaml").write <<~YAML
      apiVersion: agentforge.dev/v1
      kind: AgentPolicy
      project: { name: t }
    YAML
    ENV["AFG_NO_TTY"] = "1"
    assert_match "deny", shell_output("#{bin}/afg policy explain -- terraform destroy")
  end
end
