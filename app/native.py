"""Safe wrapper around the native C thumbnail/preview helper.

The SECURE build (native/thumbgen_secure.c) performs strict bounds checking.
This wrapper additionally:
  * validates the input length on the Python side (never trusts a
    client-supplied size),
  * loads the compiled library by absolute path,
  * degrades gracefully to a pure-Python preview if the library is not
    compiled on this host (so the web app always runs for the demo).

The deliberately vulnerable counterpart (native/thumbgen_vuln.c) is used
only by vulnerable_demo/ and is never loaded here.
"""
import ctypes
import os
import sys

_LIB = None
_PREVIEW_LEN = 64  # must match THUMB_OUT_LEN in the C header


def _lib_path() -> str:
    base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "native")
    name = "thumbgen_secure.dll" if sys.platform.startswith("win") else "thumbgen_secure.so"
    return os.path.join(base, name)


def _load():
    global _LIB
    if _LIB is not None:
        return _LIB
    path = _lib_path()
    if os.path.exists(path):
        _LIB = ctypes.CDLL(path)
        # int make_preview(const char *in, size_t in_len, char *out, size_t out_cap)
        _LIB.make_preview.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                      ctypes.c_char_p, ctypes.c_size_t]
        _LIB.make_preview.restype = ctypes.c_int
    return _LIB


def make_preview(data: bytes) -> str:
    """Return a short printable preview string for uploaded file bytes.

    Length is bounded on BOTH sides (Python + C). A client cannot drive a
    buffer overflow through this path.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    header = bytes(data[:256])  # only the first 256 bytes ever reach native code

    lib = _load()
    if lib is None:
        # Pure-Python fallback (safe) when the .so/.dll is not built.
        printable = bytes(b if 32 <= b < 127 else ord(".") for b in header[:_PREVIEW_LEN - 1])
        return printable.decode("ascii", "replace")

    out = ctypes.create_string_buffer(_PREVIEW_LEN)
    rc = lib.make_preview(header, len(header), out, _PREVIEW_LEN)
    if rc != 0:
        return "[preview unavailable]"
    return out.value.decode("ascii", "replace")
