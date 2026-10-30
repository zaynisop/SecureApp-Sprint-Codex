# Native helper build (Linux/macOS). Used by CI and local Unix builds.
CC      ?= gcc
SECFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -Wall -Wextra -fPIC
ASANFLAGS = -fsanitize=address -O0 -g

.PHONY: all secure vuln-poc asan clean

all: secure

# Shared library loaded by the web app (SECURE, hardened).
secure: thumbgen_secure.c thumbgen.h
	$(CC) $(SECFLAGS) -shared -o thumbgen_secure.so thumbgen_secure.c

# Lab-only PoC executable that triggers the overflow (mitigations OFF).
vuln-poc: thumbgen_vuln.c thumbgen.h
	$(CC) -fno-stack-protector -O0 -g -DTHUMB_DEMO_MAIN \
		thumbgen_vuln.c -o thumb_vuln_poc

# Same PoC under AddressSanitizer -> precise overflow report (evidence).
asan: thumbgen_vuln.c thumbgen.h
	$(CC) $(ASANFLAGS) -DTHUMB_DEMO_MAIN thumbgen_vuln.c -o thumb_vuln_asan

clean:
	rm -f *.so *.o thumb_vuln_poc thumb_vuln_asan
