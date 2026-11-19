# Sandbox image for the AgentForge Guard Cloudflare backend.
# Needs only coreutils (timeout, mkdir, chown) and tar. Add your toolchains.
FROM debian:stable-slim
RUN useradd --uid 65534 --no-create-home --shell /usr/sbin/nologin sandbox 2>/dev/null || true
# Keep the container alive; afg runs commands with exec().
ENTRYPOINT ["sleep", "infinity"]
