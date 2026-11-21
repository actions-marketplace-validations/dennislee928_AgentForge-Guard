# Homebrew

`afg.rb` is a formula template for a Homebrew **tap** (a separate repository,
for example `dennislee928/homebrew-tap`). The tap doesn't exist yet. After
a release:

1. Copy `afg.rb` into the tap's `Formula/` directory.
2. Set `version` and the four `sha256` values from the release's `SHA256SUMS`.
3. Before committing, verify the release signatures:
   `cosign verify-blob --bundle <file>.sigstore.json --certificate-identity-regexp 'github.com/dennislee928/AgentForge-Guard/' --certificate-oidc-issuer https://token.actions.githubusercontent.com <file>`.
4. Run `brew install --build-from-source ./Formula/afg.rb && brew test afg`.

Users then install with `brew install dennislee928/tap/afg`.
