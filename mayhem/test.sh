#!/usr/bin/env bash
#
# ms-tpm-20-ref/mayhem/test.sh — run the self-contained golden ORACLE built by mayhem/build.sh and
# emit a CTRF summary. exit 0 iff every oracle check passed.
#
# ORACLE path (state which): ms-tpm-20-ref's full integration tests need a TPM client/transport
# (tpm2-tools over a socket), which is not self-contained. Instead the oracle (/mayhem/tpm_oracle)
# drives the SAME fuzzed surface as the libFuzzer harness — _plat__RunCommand()->ExecuteCommand(),
# the command dispatcher/parser — with KNOWN inputs and asserts the parsed response code:
#   * TPM2_Startup(CLEAR)   -> must return TPM_RC_SUCCESS
#   * TPM2_GetCapability    -> must return TPM_RC_SUCCESS
#   * a malformed command   -> must return a NON-success (error) response code
# This is a genuine differential oracle on the dispatcher's output, not a no-op stub: a "return
# success" patch fails the malformed case; a "reject everything" patch fails the good cases.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

ORACLE=/mayhem/tpm_oracle

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "tpm-oracle" 0 1 0; exit 2
fi

echo "=== running TPM dispatcher oracle: $ORACLE ==="
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

# Parse "ORACLE_SUMMARY passed=N failed=M" if present; otherwise fall back to the exit code.
PASSED="$(printf '%s\n' "$out" | sed -n 's/.*ORACLE_SUMMARY passed=\([0-9][0-9]*\) failed=[0-9][0-9]*.*/\1/p' | tail -1)"
FAILED="$(printf '%s\n' "$out" | sed -n 's/.*ORACLE_SUMMARY passed=[0-9][0-9]* failed=\([0-9][0-9]*\).*/\1/p' | tail -1)"

if [ -z "$PASSED" ] || [ -z "$FAILED" ]; then
  echo "could not parse oracle summary; using exit code $rc" >&2
  if [ "$rc" -eq 0 ]; then emit_ctrf "tpm-oracle" 1 0 0; exit 0; fi
  emit_ctrf "tpm-oracle" 0 1 0; exit 1
fi

emit_ctrf "tpm-oracle" "$PASSED" "$FAILED" 0
