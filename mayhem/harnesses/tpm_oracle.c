// ms-tpm-20-ref/mayhem/harnesses/tpm_oracle.c
//
// Self-contained golden ORACLE over the SAME fuzzed path as the libFuzzer harness
// (_plat__RunCommand() -> ExecuteCommand(), the TPM 2.0 command dispatcher/parser).
//
// It manufactures + powers on a TPM exactly like LLVMFuzzerInitialize, then:
//   (1) sends a well-formed TPM2_Startup(CLEAR) and asserts responseCode == TPM_RC_SUCCESS (0),
//   (2) sends a well-formed TPM2_GetCapability and asserts responseCode == TPM_RC_SUCCESS,
//   (3) sends a MALFORMED command (a bogus/unsupported command code) and asserts the dispatcher
//       returns a NON-zero error responseCode (i.e. it rejected the bad command rather than
//       succeeding or crashing).
//
// This is a real differential check on the parsed response code — a no-op / "return success"
// stub of ExecuteCommand would fail step (3); a parser that rejects everything would fail (1)/(2).
//
// A TPM2 response is:  tag(2) | size(4) | responseCode(4) | ... , all big-endian.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// TpmBuildSwitches.h defines LIB_EXPORT / BOOL used by the prototype headers below.
#include "TpmBuildSwitches.h"
#include "Manufacture_fp.h"
#include "Platform_fp.h"

// TPM_RC_SUCCESS is 0x000 in the TPM 2.0 spec.
#define TPM_RC_SUCCESS 0x00000000u

static uint32_t responseCode(const unsigned char* resp)
{
    // bytes 6..9 are the 32-bit big-endian response code.
    return ((uint32_t)resp[6] << 24) | ((uint32_t)resp[7] << 16)
         | ((uint32_t)resp[8] << 8) | (uint32_t)resp[9];
}

// TPM2_Startup(CLEAR):  tag=TPM_ST_NO_SESSIONS(0x8001) size=0x0c cc=TPM_CC_Startup(0x144) su=TPM_SU_CLEAR(0x0000)
static unsigned char cmd_startup_clear[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00
};

// TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES, property=TPM_PT_MANUFACTURER(0x105), propertyCount=1):
//   tag=0x8001 size=0x16 cc=TPM_CC_GetCapability(0x17a) cap=0x00000006 prop=0x00000105 count=0x00000001
static unsigned char cmd_getcap[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x7a,
    0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01
};

// Malformed: well-formed header framing but an unsupported/garbage command code (0xDEADBEEF).
//   tag=0x8001 size=0x0a cc=0xDEADBEEF
static unsigned char cmd_bad_cc[] = {
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0xde, 0xad, 0xbe, 0xef
};

static unsigned char response[4096];

static uint32_t run(unsigned char* cmd, uint32_t size)
{
    uint32_t responseSize = sizeof(response);
    unsigned char* r = &response[0];
    unsigned char** resp = &r;
    memset(response, 0, sizeof(response));
    _plat__RunCommand(size, cmd, &responseSize, resp);
    return responseCode(*resp);
}

int main(void)
{
    _plat__NVEnable(NULL);
    if(TPM_Manufacture(1) != 0)
    {
        fprintf(stderr, "ORACLE: TPM_Manufacture failed\n");
        return 2;
    }
    _plat__Signal_PowerOn();
    _plat__Signal_Reset();
    _plat__SetNvAvail();
    _plat__LocalitySet(3);

    int failures = 0;

    uint32_t rc = run(cmd_startup_clear, sizeof(cmd_startup_clear));
    if(rc == TPM_RC_SUCCESS)
        printf("ORACLE PASS startup_clear rc=0x%08x\n", rc);
    else
    {
        printf("ORACLE FAIL startup_clear expected success got rc=0x%08x\n", rc);
        failures++;
    }

    rc = run(cmd_getcap, sizeof(cmd_getcap));
    if(rc == TPM_RC_SUCCESS)
        printf("ORACLE PASS getcapability rc=0x%08x\n", rc);
    else
    {
        printf("ORACLE FAIL getcapability expected success got rc=0x%08x\n", rc);
        failures++;
    }

    rc = run(cmd_bad_cc, sizeof(cmd_bad_cc));
    if(rc != TPM_RC_SUCCESS)
        printf("ORACLE PASS malformed_command rejected rc=0x%08x\n", rc);
    else
    {
        printf("ORACLE FAIL malformed_command unexpectedly succeeded rc=0x%08x\n", rc);
        failures++;
    }

    _plat__ClearNvAvail();

    printf("ORACLE_SUMMARY passed=%d failed=%d\n", 3 - failures, failures);
    return failures == 0 ? 0 : 1;
}
