/* ============================================================================
 *  thumbgen_secure.c  —  SECURE build loaded by the web application
 * ----------------------------------------------------------------------------
 *  Remediation of CWE-120/CWE-787 in thumbgen_vuln.c.
 *
 *  Fixes applied:
 *    1. The input length is clamped to the buffer capacity BEFORE any copy
 *       (never trust a caller-supplied size).
 *    2. memcpy writes at most (THUMB_OUT_LEN - 1) bytes; the result is always
 *       NUL-terminated within bounds.
 *    3. Output is produced with snprintf, bounded by out_cap.
 *    4. Non-printable bytes are sanitised to '.' so the preview is safe text.
 *
 *  Recommended build flags (see Makefile / build.ps1):
 *    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -Wall -Wextra
 *  ASLR + NX/DEP are enabled by the OS/loader for the shared library.
 * ==========================================================================*/
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "thumbgen.h"

int make_preview(const char *in, size_t in_len, char *out, size_t out_cap)
{
    char buf[THUMB_OUT_LEN];
    size_t i;

    if (in == NULL || out == NULL || out_cap == 0) {
        return 1;                      /* defensive null/zero checks       */
    }

    /* FIX #1: clamp the copy length to what actually fits, leaving room
     * for the NUL terminator. The caller's size never drives the copy.   */
    size_t n = in_len;
    if (n > THUMB_OUT_LEN - 1) {
        n = THUMB_OUT_LEN - 1;
    }

    /* FIX #2: bounded copy + in-bounds NUL. */
    memcpy(buf, in, n);
    buf[n] = '\0';

    /* FIX #4: sanitise to printable ASCII. */
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (!isprint(c)) {
            buf[i] = '.';
        }
    }

    /* FIX #3: bounded write into the caller buffer. */
    snprintf(out, out_cap, "%s", buf);
    return 0;
}

#ifdef THUMB_DEMO_MAIN
int main(void)
{
    char out[THUMB_OUT_LEN];
    char attacker[256];
    memset(attacker, 'A', sizeof(attacker));
    int rc = make_preview(attacker, sizeof(attacker), out, sizeof(out));
    printf("rc=%d preview=%s (len=%zu)\n", rc, out, strlen(out));
    return 0;                          /* returns cleanly: no overflow     */
}
#endif
