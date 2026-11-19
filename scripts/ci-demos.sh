#!/usr/bin/env bash
# README demos 2 and 3, run as CI checks (docs/plan.md T6.2).
#   2. `terraform destroy` is denied, with audit evidence.
#   3. An untrusted script runs in a Docker sandbox, cannot read the host's
#      test credentials and cannot reach the network.
# Usage: scripts/ci-demos.sh <path-to-afg-binary>
set -euo pipefail

AFG="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
export AFG_NO_TTY=1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp -R "$(dirname "$0")/../examples/polyglot-monorepo/." "$WORK/"
cd "$WORK"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "--- demo 2: terraform destroy is denied"
set +e
"$AFG" run -- terraform destroy -auto-approve
code=$?
set -e
[ "$code" -eq 126 ] || fail "expected exit 126, got $code"
rec="$("$AFG" audit tail --json -n 1)"
echo "$rec" | grep -q '"effect":"deny"' || fail "audit record is not a deny: $rec"
echo "$rec" | grep -q '"ruleId":"destructive-operations"' || fail "wrong rule: $rec"
echo "ok: denied by destructive-operations, audited"

echo "--- demo 3: untrusted script in the container sandbox"
# Fake host credentials that the script must not be able to read.
echo "AWS_SECRET_ACCESS_KEY=FAKEFAKEFAKEFAKE" > .env
out="$("$AFG" run -- sh scripts/untrusted.sh)"
echo "$out"
if echo "$out" | grep -q LEAK; then fail "sandbox leak"; fi
[ "$(echo "$out" | grep -c '^ok:')" -eq 4 ] || fail "expected 4 ok probes"
rec="$("$AFG" audit tail --json -n 1)"
echo "$rec" | grep -q '"backend":"container"' || fail "did not run in a container: $rec"
if echo "$rec" | grep -q FAKEFAKEFAKEFAKE; then fail "secret in audit log"; fi
echo "ok: untrusted script isolated"
