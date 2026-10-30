/* thumbgen.h — shared interface for the native preview helper.
 *
 * THUMB_OUT_LEN must stay in sync with _PREVIEW_LEN in app/native.py.
 */
#ifndef THUMBGEN_H
#define THUMBGEN_H

#include <stddef.h>

#define THUMB_OUT_LEN 64

/* make_preview: build a printable ASCII preview of the first bytes of a file.
 *
 *   in      : input bytes (file header)
 *   in_len  : number of valid bytes in `in`
 *   out     : caller-allocated output buffer
 *   out_cap : capacity of `out` in bytes (must be >= 1)
 *
 * Returns 0 on success, non-zero on error.
 */
int make_preview(const char *in, size_t in_len, char *out, size_t out_cap);

#endif /* THUMBGEN_H */
