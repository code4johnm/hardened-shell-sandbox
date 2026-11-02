# Build the sandbox-run launcher, its helpers, hss-status and the probes.
# Requires libseccomp-dev (libseccomp.so / seccomp.h) for sandbox-run.
CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDLIBS   ?= -lseccomp

HELPERS_C   = hss_fd.c hss_state.c
HELPERS_ASM = hss_x86_64.S hss_state_x86_64.S
HELPERS     = $(HELPERS_C) $(HELPERS_ASM)

all: sandbox-run ../tools/hss-status

sandbox-run: sandbox-run.c $(HELPERS) hss.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ sandbox-run.c $(HELPERS) $(LDFLAGS) $(LDLIBS)

../tools/hss-status: ../tools/hss-status.c $(HELPERS) hss.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ ../tools/hss-status.c $(HELPERS) $(LDFLAGS)

../tests/escape_probe: ../tests/escape_probe.c hss_x86_64.S
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ ../tests/escape_probe.c hss_x86_64.S $(LDFLAGS)

../tests/helper_selftest: ../tests/helper_selftest.c $(HELPERS) hss.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ ../tests/helper_selftest.c $(HELPERS) $(LDFLAGS)

clean:
	rm -f sandbox-run ../tools/hss-status ../tests/escape_probe ../tests/helper_selftest

.PHONY: all clean
