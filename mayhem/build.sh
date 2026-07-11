#!/usr/bin/env bash
#
# ms-tpm-20-ref/mayhem/build.sh — build the TPM 2.0 reference implementation's command-dispatch
# fuzzer (OSS-Fuzz harness by Tamas K Lengyel) as a sanitized libFuzzer target (+ a standalone
# reproducer), and a small self-contained golden ORACLE binary used by mayhem/test.sh.
#
# Fuzzed surface: the harness feeds attacker-controlled TPM 2.0 command byte streams (TPM_ST tag +
# size + command code + body) to _plat__RunCommand() -> ExecuteCommand(), the TPM command
# dispatcher/parser. The harness manufactures + powers on a TPM, then replays each input through
# Startup/Shutdown cycles so the parser is exercised in several TPM states.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/
# STANDALONE_FUZZ_MAIN/SRC). We compile the TPM library + platform code WITH $SANITIZER_FLAGS so the
# parser/dispatcher (not just the harness) is instrumented.
#
# We keep the upstream tree additive: the OSS-Fuzz autotools wiring (Makefile.am/configure.ac hunks +
# the fuzzer/tpm_cmd.c harness) lives in mayhem/ and is APPLIED at build time, never committed as a
# modification of upstream files.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS: explicit DWARF-3 so Mayhem's triage reads symbols (clang-19 plain -g emits DWARF-5).
# Thread this after $SANITIZER_FLAGS in every fuzz/standalone/oracle compile (§6.2 item 10).
: "${DEBUG_FLAGS=-gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

OUT=/mayhem
MAYHEM_DIR="$SRC/mayhem"
TPMCMD="$SRC/TPMCmd"

# Relax ONE benign UBSan sub-check: -fsanitize=function. The TPM command dispatcher
# (tpm/src/main/CommandDispatcher.c) intentionally dispatches every command through a single
# generic function-pointer type, so -fsanitize=function fires a "call through pointer to incorrect
# function type" on the normal dispatch path for *every* command — it would flood both the oracle
# and the fuzzer with non-bug reports. We keep all other ASan+UBSan checks halting. Only add this
# when the active flags actually request UBSan's function check (i.e. a real sanitizer build).
case " ${SANITIZER_FLAGS:-} " in
  *undefined*|*function*) SANITIZER_FLAGS="${SANITIZER_FLAGS} -fno-sanitize=function" ;;
esac

# ── 1) Stage the OSS-Fuzz harness + autotools wiring into the upstream tree (build-time only) ──────
# The patch adds fuzzer/tpm_cmd.c and the LIBFUZZER/COVERAGE Makefile.am conditionals; we apply only
# the Makefile.am hunk (which still applies) and inject the configure.ac AC_ARG_ENABLE blocks
# ourselves (the patch's configure.ac context drifted from current upstream). Provenance of the
# harness is our committed mayhem/harnesses/ copy.
#
# IDEMPOTENCY: restore the upstream versions of patched files before (re-)applying modifications
# so that a second build.sh run on an already-built tree succeeds (§6.2 item 9 / §6.5).
( cd "$SRC" && git checkout HEAD -- TPMCmd/Makefile.am TPMCmd/configure.ac )
mkdir -p "$TPMCMD/fuzzer"
cp "$MAYHEM_DIR/harnesses/tpm_cmd.c" "$TPMCMD/fuzzer/tpm_cmd.c"
( cd "$SRC" && git apply --include='TPMCmd/Makefile.am' "$MAYHEM_DIR/libfuzzer.patch" )

# Inject the --enable-libfuzzer / --enable-coverage autoconf options + conditionals just before the
# final AC_OUTPUT (idempotent: skip if already present).
if ! grep -q 'AC_ARG_ENABLE(libfuzzer' "$TPMCMD/configure.ac"; then
  python3 - "$TPMCMD/configure.ac" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
block = """
AC_ARG_ENABLE(libfuzzer,
    AS_HELP_STRING([--enable-libfuzzer],
    [Build libfuzzer driver with ASAN/UBSAN/LEAKSAN]))
AM_CONDITIONAL([LIBFUZZER], [test x$enable_libfuzzer = xyes])

AS_IF([test "x$enable_libfuzzer" = "xyes"], [
    ADD_COMPILER_FLAG([-DNDEBUG])
])

AC_ARG_ENABLE(coverage,
    AS_HELP_STRING([--enable-coverage],
    [Build tpm_cmd with coverage]))
AM_CONDITIONAL([COVERAGE], [test x$enable_coverage = xyes])

AS_IF([test "x$enable_coverage" = "xyes"], [
    ADD_COMPILER_FLAG([-DNDEBUG])
])

"""
marker = "AC_OUTPUT"
idx = s.rindex(marker)
s = s[:idx] + block + s[idx:]
open(p, "w").write(s)
print("injected libfuzzer/coverage autoconf options")
PY
fi

# ── 2) Compile the libFuzzer target ────────────────────────────────────────────────────────────────
# The harness's LDFLAGS in the patch hardcode `-fsanitize=fuzzer`; we instead drive the build with our
# $SANITIZER_FLAGS (ASan+UBSan, halting) baked into EXTRA_CFLAGS and link the fuzzing engine via
# fuzzer_tpm_cmd_LDFLAGS. -fsanitize=fuzzer-no-link on the library objects gives coverage feedback.
# The Ossl/TpmBigNum math binding hard-#errors "Untested OpenSSL version" for OPENSSL_VERSION_NUMBER
# >= 0x30100000L, and otherwise (>= 1.1) provides its own `struct bignum_st { d; top; dmax; neg;
# flags; }` matching OpenSSL's internal bn layout. That layout is unchanged across OpenSSL 3.x
# (3.0..3.5), so we raise the guard threshold in the STAGED tree to treat our base's OpenSSL 3.5 the
# same as 3.0 (build-time only — the committed upstream tree is untouched).
GUARD="$TPMCMD/tpm/cryptolibs/Ossl/include/Ossl/BnToOsslMath.h"
if grep -q '0x30100000L' "$GUARD"; then
  sed -i 's/#if OPENSSL_VERSION_NUMBER >= 0x30100000L/#if OPENSSL_VERSION_NUMBER >= 0x30600000L/' "$GUARD"
fi

cd "$TPMCMD"
./bootstrap

# The OSS-Fuzz harness includes "TpmBuildSwitches.h" and "Platform_fp.h" unqualified. TpmBuildSwitches.h
# lives in the nested TpmConfiguration/TpmConfiguration/ dir (not covered by -I TpmConfiguration).
# "Platform_fp.h" no longer exists in current upstream (the harness was written against an older
# layout where it was a thin platform-prototypes header). We must NOT include the full Platform.h here
# because it pulls in the TPM type headers that already define TPM_ST_* and the TPM_CC_* constants,
# which collide with the harness's own enum tpm_cc / #defines. Instead provide a minimal, self-
# contained compat Platform_fp.h declaring exactly the platform entry points the harness/oracle call.
SHIM="$TPMCMD/mayhem-compat-include"
mkdir -p "$SHIM"
cat > "$SHIM/Platform_fp.h" <<'EOF'
/* build-time compat shim: minimal platform prototypes the fuzzer/oracle call.
 * Self-contained on purpose so it does not pull in the TPM type headers (which would
 * collide with the harness's own TPM structure-tag and command-code definitions). */
#ifndef MAYHEM_COMPAT_PLATFORM_FP_H
#define MAYHEM_COMPAT_PLATFORM_FP_H
#include <stdint.h>
int  _plat__NVEnable(void* platParameter);
int  _plat__Signal_PowerOn(void);
int  _plat__Signal_Reset(void);
void _plat__SetNvAvail(void);
void _plat__ClearNvAvail(void);
void _plat__LocalitySet(unsigned char locality);
void _plat__RunCommand(uint32_t requestSize, unsigned char* request,
                       uint32_t* responseSize, unsigned char** response);
#endif
EOF
EXTRA_INC="-I$TPMCMD/TpmConfiguration/TpmConfiguration -I$SHIM"

build_target() {
  # $1 = mode label (libfuzzer|coverage), $2 = output binary path, $3 = fuzzer LDFLAGS
  local enable="$1" outbin="$2" fzldflags="$3"
  make distclean >/dev/null 2>&1 || true
  ./configure --enable-"$enable" \
    EXTRA_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $EXTRA_INC" \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $EXTRA_INC" \
    fuzzer_tpm_cmd_LDFLAGS="$fzldflags"
  # Override the hardcoded -fsanitize=fuzzer LDFLAGS from the patch at make time.
  make -j"$MAYHEM_JOBS" fuzzer_tpm_cmd_LDFLAGS="$fzldflags"
  cp fuzzer/tpm_cmd "$outbin"
  make distclean >/dev/null 2>&1 || true
}

# libFuzzer target -> /mayhem/tpm_cmd
build_target libfuzzer "$OUT/tpm_cmd" "$SANITIZER_FLAGS $LIB_FUZZING_ENGINE"

# Standalone reproducer (no libFuzzer runtime): the harness already ships a `main()` under
# #ifdef COVERAGE that reads a single input file and calls LLVMFuzzerInitialize + one input.
build_target coverage "$OUT/tpm_cmd-standalone" "$SANITIZER_FLAGS"

cp "$MAYHEM_DIR/tpm_cmd.options" "$OUT/tpm_cmd.options" 2>/dev/null || true

# ── 3) Build the self-contained golden ORACLE for mayhem/test.sh ───────────────────────────────────
# This compiles the SAME library + a tiny driver (mayhem/harnesses/tpm_oracle.c) that drives the
# fuzzed _plat__RunCommand()->ExecuteCommand() path with known-good and malformed TPM2 commands and
# asserts the response codes. We reuse the autotools-built static libs to get all the generated
# config headers / source lists right, then link our oracle against them.
cd "$TPMCMD"
make distclean >/dev/null 2>&1 || true
./configure --enable-coverage \
  EXTRA_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $EXTRA_INC" \
  CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $EXTRA_INC"
# Build only the static libraries (libplatform.a + libtpm.a), not the harness program.
make -j"$MAYHEM_JOBS" Platform/src/libplatform.a tpm/src/libtpm.a

INC="-I Platform/include -I Platform/include/prototypes \
  -I tpm/include -I tpm/include/platform_interface \
  -I tpm/include/platform_interface/prototypes \
  -I tpm/include/private -I tpm/include/private/prototypes \
  -I tpm/include/public -I tpm/cryptolibs -I tpm/cryptolibs/common/include \
  -I tpm/cryptolibs/Ossl/include -I tpm/cryptolibs/TpmBigNum/include \
  -I TpmConfiguration -I TpmConfiguration/TpmConfiguration -I$SHIM"

LIBCRYPTO_CFLAGS="$(pkg-config --cflags libcrypto 2>/dev/null || true)"
LIBCRYPTO_LIBS="$(pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto)"

# duplicate libplatform to break the libplatform<->libtpm circular dependency (as upstream does).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC $LIBCRYPTO_CFLAGS \
  "$MAYHEM_DIR/harnesses/tpm_oracle.c" \
  Platform/src/libplatform.a tpm/src/libtpm.a Platform/src/libplatform.a \
  $LIBCRYPTO_LIBS -lpthread -o "$OUT/tpm_oracle"
make distclean >/dev/null 2>&1 || true

echo "build.sh complete:"
ls -la "$OUT/tpm_cmd" "$OUT/tpm_cmd-standalone" "$OUT/tpm_oracle" 2>&1 || true
