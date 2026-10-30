/* ============================================================================
 *  thumbgen_vuln.c  —  DELIBERATELY VULNERABLE (LAB-ONLY) reference build
 * ----------------------------------------------------------------------------
 *  CWE-120 / CWE-787: Classic stack buffer overflow.
 *
 *  This file exists ONLY so the sprint can demonstrate the vulnerability and
 *  its fix side by side (see docs/SECURITY_IMPLEMENTATION.md). It is NEVER
 *  loaded by the running web application — app/native.py loads the SECURE
 *  build only. Do not deploy.
 *
 *  THE BUG:
 *    `make_preview` copies `in_len` bytes into a fixed 64-byte stack buffer
 *    using memcpy WITHOUT checking in_len against the buffer size. It trusts a
 *    caller-supplied length — the cardinal memory-safety sin. A caller passing
 *    in_len > 64 overflows `buf`, corrupting the saved frame (return address /
 *    stack canary) and influencing control flow.
 * ==========================================================================*/
#include <string.h>
#include <stdio.h>
#include "thumbgen.h"

int make_preview(const char *in, size_t in_len, char *out, size_t out_cap)
{
    char buf[THUMB_OUT_LEN];           /* 64-byte stack buffer            */

    /* VULNERABLE: in_len is attacker-controlled and never bounded.       */
    memcpy(buf, in, in_len);           /* <-- overflow when in_len > 64   */
    buf[THUMB_OUT_LEN - 1] = '\0';     /* false sense of safety           */

    /* VULNERABLE: unbounded string copy into caller buffer.              */
    strcpy(out, buf);                  /* <-- ignores out_cap             */
    (void)out_cap;
    return 0;
}

#ifdef THUMB_DEMO_MAIN
/* Standalone PoC harness: feed an oversized input to trigger the overflow.
 * Build:  gcc -fno-stack-protector -z execstack -O0 -g \
 *             -DTHUMB_DEMO_MAIN thumbgen_vuln.c -o thumb_vuln_poc
 * Run under ASAN to see the overflow precisely:
 *         gcc -fsanitize=address -O0 -g -DTHUMB_DEMO_MAIN \
 *             thumbgen_vuln.c -o thumb_vuln_asan && ./thumb_vuln_asan
 */
int main(void)
{
    char out[THUMB_OUT_LEN];
    char attacker[256];
    memset(attacker, 'A', sizeof(attacker));   /* 256 'A's >> 64-byte buf */
    make_preview(attacker, sizeof(attacker), out, sizeof(out));
    printf("preview: %s\n", out);              /* likely never reached    */
    return 0;
}
#endif
